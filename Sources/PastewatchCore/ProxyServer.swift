#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

// MARK: - Timeout constants

/// Default idle timeout for streaming responses (seconds). Resets on each received chunk.
/// A truly stalled upstream will be killed after this window of silence.
let proxyStreamIdleTimeoutSeconds: Double = 60

/// Total-duration ceiling for non-streaming (buffered) responses (seconds).
let proxyNonStreamTotalTimeoutSeconds: Double = 600

/// WO-401: URLSession resource timeout must not preempt long progressing streams.
let proxyURLSessionResourceTimeoutSeconds = Double(curlStreamMaxTimeSeconds)

/// WO-267: while waiting on a non-streaming URLSession completion, poll shutdown
/// state so stop() cannot wait for the full 600s ceiling if a task misses cancellation.
let proxyNonStreamShutdownPollMilliseconds = 100

/// Minimum upstream bytes-per-second for curl's speed-based idle detection.
let curlMinSpeedBytesPerSecond = 1

/// Idle window for curl's --speed-time: upstream must send at least 1 byte/s
/// within this window or the request is aborted.
let curlSpeedTimeSeconds = 60

/// WO-346: header-arrival deadline before streaming body bytes begin.
let curlHeaderTimeoutSeconds = 30

/// Large maximum time for curl (non-streaming path). Zero = no cap.
let curlMaxTimeSeconds = 600

/// WO-343: hard ceiling for Linux streaming curl sessions that slow-drip forever.
let curlStreamMaxTimeSeconds = 7_200

/// WO-280: shared per-call recv/send timeout for client sockets (seconds).
let proxyClientSocketTimeoutSeconds = 30

/// WO-312: per-recv scratch buffer; accumulated request bytes grow separately.
let proxyHTTPRequestReadBufferBytes = 64 * 1024

/// WO-323: local single-user proxy active connection ceiling.
let proxyMaxActiveConnections = 4

/// WO-323: bounded wait for a saturated admission slot before rejecting the client.
let proxyAdmissionQueueTimeoutMilliseconds = 250

/// WO-335: rejected sockets are written on the accept loop; keep that send bounded.
let proxyRejectedSocketSendTimeoutSeconds = 2

/// WO-486: audit request targets are bounded independently from forwarded targets.
let proxyAuditPathMaxCharacters = 512

// MARK: - ProxyServer

/// Minimal HTTP proxy that scans and redacts secrets from API request bodies.
/// Listens on localhost, forwards to upstream API after redacting sensitive data.
public final class ProxyServer {
    // WO-315: request header terminators used by the CRLF-first parser.
    private static let requestCRLFHeaderTerminator = Data([0x0D, 0x0A, 0x0D, 0x0A]) // \r\n\r\n
    private static let requestCRLFLineSeparator = Data([0x0D, 0x0A]) // \r\n
    private static let requestLFHeaderTerminator = Data([0x0A, 0x0A]) // \n\n

    private let port: UInt16
    private let upstream: URL
    private let forwardProxy: URL?
    private let config: PastewatchConfig
    private let customRules: [CustomRule] // WO-473: one precompiled set for every proxy scan path.
    private let customRuleStartupError: Error? // WO-473: direct server users fail before socket creation.
    private let severity: Severity
    private let auditLogPath: String?
    public private(set) var injectAlert: Bool
    private let quietLog: Bool
    private let streamDebugSink: StreamDebugSink? // WO-514: explicit local-only streaming evidence sink.
    /// WO-143: PEM CA bundle trusted (in addition to system roots) for the
    /// proxy's upstream TLS handshake. Governs only the proxy-to-upstream leg.
    let caCertPath: String?
    /// WO-143: when true, the proxy skips upstream TLS verification entirely.
    let insecureTLS: Bool
    private var serverSocket: Int32 = -1
    private let queue = DispatchQueue(label: "com.pastewatch.proxy", attributes: .concurrent)
    /// WO-323: hard active-connection gate; queued clients wait for a bounded deadline only.
    private let admissionSlots = DispatchSemaphore(value: proxyMaxActiveConnections)
    /// WO-323: protects observable admission counters.
    private let admissionLock = NSLock()
    private var activeConnections = 0
    private var queuedConnections = 0
    private var rejectedConnections = 0
    /// WO-160: guards all mutations of `stats` from concurrent connection handlers.
    private let statsLock = NSLock()
    /// WO-217: serial queue for audit log file I/O. Decouples slow disk writes from
    /// statsLock so concurrent handlers do not serialize behind file operations.
    private let logQueue = DispatchQueue(label: "com.pastewatch.proxy.auditlog")
    /// WO-302/WO-311: reuse one formatter and include fractional seconds for audit ordering.
    /// WO-395: Apple guarantees modern date-formatter reads, but swift-corelibs lazily
    /// initializes its cached CF formatter. Serialize all access so first use cannot race;
    /// formatter configuration remains frozen after initialization.
    private let iso8601Formatter: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter
    }()
    private let iso8601FormatterLock = NSLock() // WO-395: guards Linux lazy cache initialization.
    /// WO-234: barrier group lets stop() wait for in-flight handlers before draining logQueue.
    /// Each dispatched handler enters the group; stop() barrier-waits so logQueue.sync sees
    /// all handler-enqueued audit writes, not just the ones enqueued before stop() was called.
    private let handlerGroup = DispatchGroup()
    /// WO-258: guards cross-thread reads/writes of _running. Plain var Bool is a data race
    /// when written by stop() and read by the accept-loop poll on different threads. NSLock is
    /// consistent with statsLock / socketWriteLock / signalLock already in this file.
    private let runningLock = NSLock()
    private var _running = false
    private var running: Bool {
        get { runningLock.lock(); defer { runningLock.unlock() }; return _running }
        set { runningLock.lock(); defer { runningLock.unlock() }; _running = newValue }
    }
    #if canImport(Darwin)
    /// WO-305/WO-306: share the TLS trust policy between buffered URLSession
    /// tasks and streaming tasks without lazy initialization races on the
    /// concurrent connection queue.
    private let tlsTrustDelegate: TLSTrustDelegate?
    #endif
    private let urlSession: URLSession
    /// WO-452: injectable serializer makes the fail-closed branch deterministic in tests.
    var requestBodySerializer: ([String: Any]) throws -> Data = {
        try JSONSerialization.data(withJSONObject: $0, options: [])
    }

    public struct RedactionStats {
        public var requestsProcessed: Int = 0
        public var refusedRequests: Int = 0 // WO-442: aggregate fail-closed 415 refusals.
        public var modelIdentityAdvisories: Int = 0 // WO-430: nonstandard model names are observable, never refusal gates.
        public var redactionFailures: Int = 0 // WO-452: detected mutations blocked by serialization failure.
        public var requestsRedacted: Int = 0
        public var secretsRedacted: Int = 0
        public var advisoryMatches: Int = 0 // WO-353/354/404: advisories are audited separately.
        public var toolCallPayloadMutations: Int = 0 // WO-512: tool arguments remain separately observable.

        // WO-430: surface model-identity drift relative to forwarded requests.
        public var modelIdentityAdvisoryRate: Double {
            guard requestsProcessed > 0 else { return 0 }
            return Double(modelIdentityAdvisories) / Double(requestsProcessed)
        }
    }

    struct StreamingAuditStats {
        let path: String
        let bodyCount: Int
        let bodyTypes: [String]
        let streamCount: Int // WO-353/354/404: mutation-safe stream redactions delivered to the client.
        let streamTypes: [String]
        let advisoryCount: Int // WO-353/354: advisory-only stream matches delivered to the client.
        let advisoryTypes: [String]
        let toolCallCount: Int // WO-512: subset of streamCount originating in tool arguments.

        init(
            path: String,
            bodyCount: Int,
            bodyTypes: [String],
            streamCount: Int,
            streamTypes: [String],
            advisoryCount: Int,
            advisoryTypes: [String],
            toolCallCount: Int = 0
        ) {
            self.path = path
            self.bodyCount = bodyCount
            self.bodyTypes = bodyTypes
            self.streamCount = streamCount
            self.streamTypes = streamTypes
            self.advisoryCount = advisoryCount
            self.advisoryTypes = advisoryTypes
            self.toolCallCount = toolCallCount
        }
    }

    public struct ConnectionAdmissionStats: Equatable {
        public let active: Int
        public let queued: Int
        public let rejected: Int
    }

    struct HTTPRequest {
        let method: String
        let path: String
        let headers: [(String, String)]
        let body: String?
        let bodyData: Data
    }

    private struct HTTPHeaderMetadata {
        let method: String
        let path: String
        let headers: [(String, String)]
        let contentLength: Int?
        let hasInvalidContentLength: Bool
        let hasChunkedTransferEncoding: Bool
    }

    private enum BodyFraming {
        case length(Int)
        case malformed
    }

    // WO-273: distinct failure cases so handleConnection can send the correct HTTP status.
    enum ReadResult {
        case success(HTTPRequest)
        case timeout         // EAGAIN / SO_RCVTIMEO — 408 appropriate
        case transportError  // ECONNRESET, EBADF, etc. — peer gone; no HTTP response useful
        case encodingError   // header bytes not valid UTF-8 — 400 appropriate
        case malformedRequest
    }

    /// Bundles the per-request context passed from handleConnection to the platform-specific
    /// forwardDarwinRequest / forwardLinuxRequest helpers, reducing parameter counts.
    private struct ForwardContext {
        let parsed: HTTPRequest
        let upstreamURL: URL
        let forwardHeaders: [(String, String)]
        let requestWantsStream: Bool
        let redactionCount: Int
        let redactedTypes: [String]
        let processedBodyData: Data
        let clientSocket: Int32
    }

    /// Non-streaming buffered response returned to handleConnection for the convergence tail.
    private struct BufferedResponse {
        let status: Int
        let headers: [AnyHashable: Any]
        let body: Data
        let responseRedactionCount: Int // WO-359: Linux binary response body redactions.
        let responseRedactionTypes: [String]
        let responseAdvisoryCount: Int // WO-404: Linux binary response body advisories.
        let responseAdvisoryTypes: [String]

        init(
            status: Int,
            headers: [AnyHashable: Any],
            body: Data,
            responseRedactionCount: Int = 0,
            responseRedactionTypes: [String] = [],
            responseAdvisoryCount: Int = 0,
            responseAdvisoryTypes: [String] = []
        ) {
            self.status = status
            self.headers = headers
            self.body = body
            self.responseRedactionCount = responseRedactionCount
            self.responseRedactionTypes = responseRedactionTypes
            self.responseAdvisoryCount = responseAdvisoryCount
            self.responseAdvisoryTypes = responseAdvisoryTypes
        }
    }

    // WO-267: typed wait result lets shutdown and timeout paths avoid sharing
    // the same 600s semaphore branch.
    enum NonStreamingTaskWaitResult: Equatable {
        case completed
        case timedOut
        case shutdown
    }

    public private(set) var stats = RedactionStats()
    public var connectionAdmissionStats: ConnectionAdmissionStats {
        admissionLock.lock()
        defer { admissionLock.unlock() }
        return ConnectionAdmissionStats(
            active: activeConnections,
            queued: queuedConnections,
            rejected: rejectedConnections
        )
    }

    public init(
        port: UInt16 = 8443,
        upstream: URL = URL(string: "https://api.anthropic.com")!,
        forwardProxy: URL? = nil,
        config: PastewatchConfig = PastewatchConfig.resolve(),
        compiledCustomRules: [CustomRule]? = nil,
        severity: Severity = .high,
        auditLogPath: String? = nil,
        injectAlert: Bool = true,
        quietLog: Bool = false,
        caCertPath: String? = nil,
        insecureTLS: Bool = false,
        streamDebugSink: StreamDebugSink? = nil
    ) {
        self.port = port
        self.upstream = upstream
        self.forwardProxy = forwardProxy
        self.config = config
        if let compiledCustomRules {
            self.customRules = compiledCustomRules
            self.customRuleStartupError = nil
        } else {
            do {
                self.customRules = try CustomRule.compileForProxyStartup(config.customRules)
                self.customRuleStartupError = nil
            } catch {
                self.customRules = []
                self.customRuleStartupError = error
            }
        }
        self.severity = severity
        self.auditLogPath = auditLogPath
        self.injectAlert = injectAlert
        self.quietLog = quietLog
        self.streamDebugSink = streamDebugSink
        self.caCertPath = caCertPath
        self.insecureTLS = insecureTLS
        #if canImport(Darwin)
        let delegate: TLSTrustDelegate? = (caCertPath != nil || insecureTLS)
            ? TLSTrustDelegate(caCertPath: caCertPath, insecure: insecureTLS)
            : nil
        self.tlsTrustDelegate = delegate
        self.urlSession = Self.makeSession(forwardProxy: forwardProxy, tlsTrustDelegate: delegate)
        #else
        self.urlSession = Self.makeSession(forwardProxy: forwardProxy)
        #endif
    }

    public static func bufferModeWarning(config: PastewatchConfig, quiet _: Bool) -> String? {
        // WO-316: buffer mode is a compatibility path; response-body redaction is
        // not yet implemented there, so surface the limitation at startup.
        // WO-365: this is security-relevant and must remain visible under --quiet.
        guard config.responseStreamingRedactionMode == .buffer else { return nil }
        return "WARNING: responseStreamingRedactionMode=buffer does not scan buffered response bodies\n"
    }

    static func makeSessionConfiguration(forwardProxy: URL?) -> URLSessionConfiguration {
        let sessionConfig = URLSessionConfiguration.default
        // WO-401: do not let URLSession's 60s request default preempt the
        // proxy's explicit 600s non-streaming ceiling; resource timeout must
        // also outlive healthy long streaming sessions.
        sessionConfig.timeoutIntervalForRequest = proxyNonStreamTotalTimeoutSeconds
        sessionConfig.timeoutIntervalForResource = proxyURLSessionResourceTimeoutSeconds
        #if canImport(Darwin)
        if let proxy = forwardProxy {
            let proxyHost = proxy.host ?? "127.0.0.1"
            let proxyPort = proxy.port ?? 8080
            sessionConfig.connectionProxyDictionary = [
                kCFNetworkProxiesHTTPEnable: true,
                kCFNetworkProxiesHTTPProxy: proxyHost,
                kCFNetworkProxiesHTTPPort: proxyPort,
                "HTTPSEnable": true,
                "HTTPSProxy": proxyHost,
                "HTTPSPort": proxyPort
            ]
        }
        #else
        if let proxy = forwardProxy {
            let proxyHost = proxy.host ?? "127.0.0.1"
            let proxyPort = proxy.port ?? 8080
            sessionConfig.connectionProxyDictionary = [
                "HTTPEnable": true,
                "HTTPProxy": proxyHost,
                "HTTPPort": proxyPort,
                "HTTPSEnable": true,
                "HTTPSProxy": proxyHost,
                "HTTPSPort": proxyPort
            ]
        }
        #endif
        return sessionConfig
    }

    static func makeSessionDelegateQueue() -> OperationQueue {
        let queue = OperationQueue()
        // WO-333: URLSession's nil delegateQueue is serial; bound callback concurrency
        // to the proxy's connection cap so one slow client write cannot stall all streams.
        queue.name = "com.pastewatch.proxy.urlsession-delegate"
        queue.maxConcurrentOperationCount = proxyMaxActiveConnections
        return queue
    }

    #if canImport(Darwin)
    private static func makeSession(forwardProxy: URL?, tlsTrustDelegate: TLSTrustDelegate?) -> URLSession {
        let sessionConfig = makeSessionConfiguration(forwardProxy: forwardProxy)
        // WO-143: honor --ca-cert / --insecure for the upstream TLS handshake.
        // Only attach a delegate when a flag is set; otherwise behave exactly as
        // before (system trust store, no delegate).
        if let delegate = tlsTrustDelegate {
            return URLSession(
                configuration: sessionConfig,
                delegate: delegate,
                delegateQueue: makeSessionDelegateQueue()
            )
        }
        return URLSession(
            configuration: sessionConfig,
            delegate: nil,
            delegateQueue: makeSessionDelegateQueue()
        )
    }
    #else
    private static func makeSession(forwardProxy: URL?) -> URLSession {
        URLSession(
            configuration: makeSessionConfiguration(forwardProxy: forwardProxy),
            delegate: nil,
            delegateQueue: makeSessionDelegateQueue()
        )
    }
    #endif

    /// Join the upstream base path with the agent's request target, preserving any
    /// non-root base path on `upstream` (e.g. a gateway pass-through like
    /// `/v1/llm-gateway`). The agent sends an absolute request target such as
    /// `/v1/messages`; `URL(string:relativeTo:)` would discard the base path because the
    /// target is absolute, so this joins them explicitly with exactly one slash and
    /// preserves the request query string.
    func resolveUpstreamURL(requestTarget: String) -> URL {
        // Split the request target into path and query.
        let targetPath: String
        let targetQuery: String?
        if let qIndex = requestTarget.firstIndex(of: "?") {
            targetPath = String(requestTarget[..<qIndex])
            targetQuery = String(requestTarget[requestTarget.index(after: qIndex)...])
        } else {
            targetPath = requestTarget
            targetQuery = nil
        }

        var basePath = upstream.path
        while basePath.hasSuffix("/") { basePath.removeLast() }
        var reqPath = targetPath
        if !reqPath.hasPrefix("/") { reqPath = "/" + reqPath }

        // Avoid doubling when the request path already includes the base prefix.
        let joinedPath: String
        if !basePath.isEmpty && (reqPath == basePath || reqPath.hasPrefix(basePath + "/")) {
            joinedPath = reqPath
        } else {
            joinedPath = basePath + reqPath
        }

        var components = URLComponents()
        components.scheme = upstream.scheme
        components.host = upstream.host
        components.port = upstream.port
        components.percentEncodedPath = joinedPath
        components.percentEncodedQuery = targetQuery

        // Fall back to the previous behavior only if component assembly fails.
        return components.url ?? (URL(string: requestTarget, relativeTo: upstream) ?? upstream)
    }

    /// WO-514: debug capture mode is validated before the listening socket is created.
    /// Start the proxy server. Blocks until stop() is called.
    public func start(onListening: (() -> Void)? = nil) throws {
        if let customRuleStartupError {
            throw ProxyError.invalidCustomRules(customRuleStartupError.localizedDescription)
        }
        if streamDebugSink != nil, config.responseStreamingRedactionMode != .perSSEEvent {
            // WO-514: never produce an apparently valid dump without per-frame decisions.
            throw ProxyError.streamDebugDumpRequiresPerSSEEvent
        }
        #if canImport(Darwin)
        let listenSocket = socket(AF_INET, SOCK_STREAM, 0)
        #else
        let listenSocket = socket(AF_INET, Int32(SOCK_STREAM.rawValue), 0)
        #endif
        guard listenSocket >= 0 else {
            throw ProxyError.socketCreationFailed
        }

        var reuse: Int32 = 1
        setsockopt(listenSocket, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size))

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")

        let bindResult = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                bind(listenSocket, sockPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bindResult == 0 else {
            close(listenSocket)
            throw ProxyError.bindFailed(port: port)
        }

        guard listen(listenSocket, 128) == 0 else {
            close(listenSocket)
            throw ProxyError.listenFailed
        }

        // WO-262: publish the stop-visible fd under the same lock stop() uses, then
        // keep the accept loop on the immutable local fd to avoid a stored-property race.
        runningLock.lock()
        serverSocket = listenSocket
        _running = true
        runningLock.unlock()
        // WO-298: signal startup only after listen() succeeded and running is true.
        onListening?()

        while running {
            var clientAddr = sockaddr_in()
            var clientLen = socklen_t(MemoryLayout<sockaddr_in>.size)
            let clientSocket = withUnsafeMutablePointer(to: &clientAddr) { ptr in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                    accept(listenSocket, sockPtr, &clientLen)
                }
            }

            guard clientSocket >= 0 else { continue }

            // WO-323/WO-325: enter before admission so stop() waits for accepted sockets
            // that are queued for a slot as well as handlers already running.
            handlerGroup.enter()
            guard admitConnection(clientSocket) else {
                handlerGroup.leave()
                close(clientSocket)
                if !running { break }
                continue
            }
            // WO-323/WO-325: with at most 4 admitted handlers, shutdown remains bounded while
            // retaining the audit-drain guarantee from handlerGroup.wait().
            queue.async { [self] in
                defer {
                    recordConnectionFinished()
                    admissionSlots.signal()
                    handlerGroup.leave()
                }
                handleConnection(clientSocket)
            }
        }
    }

    private func admitConnection(_ clientSocket: Int32) -> Bool {
        guard running else {
            // WO-392/WO-393: an accepted socket that arrives during shutdown still
            // gets an HTTP status instead of a bare TCP close.
            sendAdmissionRejection(to: clientSocket, message: "Service Unavailable")
            return false
        }
        if admissionSlots.wait(timeout: .now()) == .success {
            guard running else {
                // WO-392: send before releasing the slot so the rejected socket is
                // accounted for before another queued connection can be admitted.
                sendAdmissionRejection(to: clientSocket, message: "Service Unavailable")
                admissionSlots.signal()
                return false
            }
            recordConnectionStarted()
            return true
        }

        recordQueuedConnection(delta: 1)
        defer { recordQueuedConnection(delta: -1) }
        let deadline = DispatchTime.now() + .milliseconds(proxyAdmissionQueueTimeoutMilliseconds)
        guard admissionSlots.wait(timeout: deadline) == .success else {
            if running {
                recordRejectedConnection()
            }
            // WO-392: a queued socket may observe stop() before a slot opens; it
            // still gets an HTTP response instead of a bare TCP close.
            sendAdmissionRejection(
                to: clientSocket,
                message: running ? "Proxy admission timeout" : "Service Unavailable"
            )
            return false
        }

        guard running else {
            // WO-392: queued sockets that win a slot after stop() should receive a
            // normal shutdown response, not a reset from the accept loop close().
            sendAdmissionRejection(to: clientSocket, message: "Service Unavailable")
            admissionSlots.signal()
            return false
        }
        recordConnectionStarted()
        return true
    }

    private func sendAdmissionRejection(to clientSocket: Int32, message: String) {
        guard clientSocket >= 0 else { return }
        // WO-335: this send runs on the accept loop, before handler socket setup.
        var sendTimeout = timeval(tv_sec: proxyRejectedSocketSendTimeoutSeconds, tv_usec: 0)
        if setsockopt(
            clientSocket, SOL_SOCKET, SO_SNDTIMEO,
            &sendTimeout, socklen_t(MemoryLayout<timeval>.size)
        ) != 0 {
            FileHandle.standardError.write(Data(
                "[pastewatch-proxy] rejected socket SO_SNDTIMEO failed: errno \(errno)\n".utf8
            ))
        }
        sendError(to: clientSocket, status: 503, message: message)
    }

    private func recordConnectionStarted() {
        admissionLock.lock()
        activeConnections += 1
        admissionLock.unlock()
    }

    private func recordConnectionFinished() {
        admissionLock.lock()
        activeConnections -= 1
        admissionLock.unlock()
    }

    func admitConnectionForTesting(_ clientSocket: Int32 = -1) -> Bool {
        // WO-347: deterministic coverage for the admission slot/counter contract.
        admitConnection(clientSocket)
    }

    func finishAdmittedConnectionForTesting() {
        // WO-347: mirror the handler defer path for tests that claim slots directly.
        recordConnectionFinished()
        admissionSlots.signal()
    }

    func stopAdmissionForTesting() {
        // WO-392/WO-393: let tests deterministically exercise sockets accepted
        // after shutdown begins without racing the real accept-loop wakeup.
        runningLock.lock()
        _running = false
        runningLock.unlock()
    }

    private func recordQueuedConnection(delta: Int) {
        admissionLock.lock()
        queuedConnections += delta
        admissionLock.unlock()
    }

    private func recordRejectedConnection() {
        admissionLock.lock()
        rejectedConnections += 1
        admissionLock.unlock()
    }

    /// Stop the proxy server.
    public func stop() {
        // WO-262+WO-263: snapshot and clear serverSocket under runningLock.
        // Running the close() outside the lock would race with start()'s accept() thread
        // reading the same var. Snapshotting also makes stop() idempotent: if two threads
        // both call stop(), only the one that atomically swaps fd≥0 → -1 performs the close.
        runningLock.lock()
        _running = false
        let fdToClose = serverSocket
        serverSocket = -1
        runningLock.unlock()
        if fdToClose >= 0 {
            // WO-393: keep the WO-330 wake-before-close ordering because Linux CI
            // does not reliably unblock accept() on cross-thread close alone. Any
            // real client accepted in this small shutdown window is rejected by
            // admitConnection() with a bounded HTTP 503 instead of a bare close.
            wakeAcceptLoop(port: port)
            close(fdToClose)
        }

        // WO-255: no unconditional signal here. WO-247's signal was needed because the
        // blocking wait() could park the thread forever when all 64 slots were occupied at
        // shutdown. The WO-255 100ms poll loop handles that case: the thread sees running=false
        // on the next tick and exits without needing an external wakeup.

        // WO-260: cancel in-flight URLSession tasks so their semaphore.wait(timeout:) unblocks
        // promptly rather than sitting for up to 600 s. Without this, handlerGroup.wait() below
        // stalls for the full non-streaming timeout on every active connection at shutdown.
        // invalidateAndCancel() is safe to call from any thread and is idempotent.
        #if canImport(Darwin)
        urlSession.invalidateAndCancel()
        #else
        // WO-338: Linux uses curl subprocesses instead of URLSession tasks; terminate
        // active processes so handlerGroup.wait() is not bounded by curl's 600s cap.
        CurlHTTPClient.cancelActiveProcesses()
        #endif

        // WO-234: wait for all in-flight handlers before draining logQueue. logQueue.sync {}
        // alone (WO-225) only drains writes already enqueued at this point; handlers still
        // running will enqueue more after the drain returns. handlerGroup.wait() ensures every
        // handler has called handlerGroup.leave() — meaning all their logQueue.async enqueues
        // have fired — before logQueue.sync {} runs the final flush.
        // WO-231: logQueue.sync uses pthread_mutex internally — NOT safe to call from a POSIX
        // signal handler (risk of deadlock). stop() must only be called from a normal thread.
        handlerGroup.wait()
        logQueue.sync {}
    }

    private func wakeAcceptLoop(port: UInt16) {
        // WO-330: Linux does not reliably interrupt a blocking accept() when another
        // thread closes the listening fd, so connect once after running=false to
        // make the accept loop observe shutdown deterministically.
        #if canImport(Darwin)
        let wakeSocket = socket(AF_INET, SOCK_STREAM, 0)
        #else
        let wakeSocket = socket(AF_INET, Int32(SOCK_STREAM.rawValue), 0)
        #endif
        guard wakeSocket >= 0 else { return }
        defer { close(wakeSocket) }

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        _ = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                connect(wakeSocket, sockPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
    }

    // MARK: - Connection handling

    private func handleConnection(_ clientSocket: Int32) {
        defer { close(clientSocket) }

        // WO-259: SO_SNDTIMEO bounds sendAll() so a half-closed TCP client cannot keep the
        // handler alive indefinitely, which would stall handlerGroup.wait() in stop().
        // WO-265: SO_RCVTIMEO is the symmetric receive-side guard. Without it, recv() in
        // readHTTPRequest blocks forever on a client that connects but stalls mid-request,
        // also preventing handlerGroup.wait() from returning. WO-280 keeps this matched to
        // the cumulative EINTR deadline in readHTTPRequest.
        // WO-271: check setsockopt return values — silent failure leaves recv()/sendAll()
        // unbounded, undermining the handlerGroup.wait() shutdown guarantee.
        var sendTimeout = timeval(tv_sec: proxyClientSocketTimeoutSeconds, tv_usec: 0)
        if setsockopt(clientSocket, SOL_SOCKET, SO_SNDTIMEO, &sendTimeout, socklen_t(MemoryLayout<timeval>.size)) != 0 {
            FileHandle.standardError.write(Data("[pastewatch-proxy] setsockopt SO_SNDTIMEO failed: errno \(errno)\n".utf8))
            // WO-297: return a diagnosable HTTP error before closing the client socket.
            sendError(to: clientSocket, status: 503, message: "Proxy configuration error")
            return
        }
        var recvTimeout = timeval(tv_sec: proxyClientSocketTimeoutSeconds, tv_usec: 0)
        if setsockopt(clientSocket, SOL_SOCKET, SO_RCVTIMEO, &recvTimeout, socklen_t(MemoryLayout<timeval>.size)) != 0 {
            FileHandle.standardError.write(Data("[pastewatch-proxy] setsockopt SO_RCVTIMEO failed: errno \(errno)\n".utf8))
            // WO-297: return a diagnosable HTTP error before closing the client socket.
            sendError(to: clientSocket, status: 503, message: "Proxy configuration error")
            return
        }

        // WO-270: send appropriate HTTP error when readHTTPRequest fails.
        // WO-273: ReadResult distinguishes timeout vs transport vs encoding failure.
        let readResult = readHTTPRequest(from: clientSocket)
        let parsed: HTTPRequest
        switch readResult {
        case .success(let request):
            parsed = request
        case .timeout:
            sendError(to: clientSocket, status: 408, message: "Request Timeout")
            return
        case .transportError:
            return  // peer already gone; HTTP response wasted and cannot be delivered
        case .encodingError, .malformedRequest:
            sendError(to: clientSocket, status: 400, message: "Bad Request")
            return
        }

        // WO-408/WO-432: fail closed on unsupported upstream body shapes. The scan path
        // below only redacts supported Anthropic-shaped POSTs; any other POST body - notably
        // OpenAI /v1/chat/completions - would otherwise be forwarded UNSCANNED, a silent
        // no-op that makes users believe traffic was redacted when it was not. Refuse an
        // unrecognized shape rather than forward it. Runs for ALL POSTs before scanning.
        if case .refuse(let reason) = upstreamBodyShapeVerdict(
            method: parsed.method, path: parsed.path, bodyData: parsed.bodyData
        ) {
            recordRefusedRequest()
            logUnsupportedBodyShapeRefusal(path: parsed.path, reason: reason)
            sendError(to: clientSocket, status: 415, message: "Unsupported upstream body shape")
            return
        }
        let modelIdentityAdvisory = modelIdentityAdvisory(
            method: parsed.method,
            path: parsed.path,
            bodyData: parsed.bodyData
        )

        // Only scan supported Anthropic-shaped POSTs (the endpoints that carry tool results).
        var processedBody = parsed.body
        var processedBodyData = parsed.bodyData
        var redactionCount = 0
        var redactedTypes: [String] = []
        var bodyAdvisoryCount = 0
        var bodyAdvisoryTypes: [String] = []
        if isCanonicalScannablePostMethod(parsed.method) && isSupportedAnthropicPostPath(parsed.path) {
            // WO-429: malformed/non-UTF-8 supported-path bodies are already refused by
            // upstreamBodyShapeVerdict, so the scanner only receives valid UTF-8 JSON.
            if let body = parsed.body {
                let result = scanAndRedactBody(body)
                // WO-478: malformed recognized private-key material cannot be
                // contained reliably, so refuse before resolving the upstream URL.
                if result.blockingAdvisory == .malformedPrivateKey {
                    recordRefusedRequest()
                    logUnsafeBodyRefusal(path: parsed.path, reason: "malformed private key block")
                    sendError(to: clientSocket, status: 400, message: "Unsafe request body")
                    return
                }
                redactionCount = result.redacted
                redactedTypes = result.redactedTypes
                bodyAdvisoryCount = result.advisoryCount
                bodyAdvisoryTypes = result.advisoryTypes
                // WO-452/WO-458: preserve all scan evidence, but never forward the
                // original body when an authorized mutation cannot be serialized.
                if result.serializationFailed {
                    recordRedactionFailure()
                    logRedactionFailure(path: parsed.path, count: redactionCount, types: redactedTypes)
                    recordBodyAdvisoryStats(
                        path: parsed.path,
                        count: bodyAdvisoryCount,
                        types: bodyAdvisoryTypes
                    )
                    sendError(to: clientSocket, status: 500, message: "Proxy redaction error")
                    return
                }
                processedBody = result.body
                processedBodyData = Data(result.body.utf8)
            }
        }

        let upstreamURL = resolveUpstreamURL(requestTarget: parsed.path)

        guard let forwardHeaders = buildForwardHeaders(from: parsed.headers, bodyLength: processedBodyData.count) else {
            // WO-310: malformed upstream URL must not silently forward `Host: `.
            sendError(to: clientSocket, status: 503, message: "Invalid upstream URL")
            return
        }

        let requestWantsStream = requestWantsStreamingResponse(
            processedBody: processedBody,
            bodyData: processedBodyData
        )
        let deferForwardedRedactionStats = shouldDeferForwardedRedactionStats(
            requestWantsStream: requestWantsStream
        )

        recordInitialRequestStats(
            redactionCount: redactionCount,
            countForwardedRedaction: !deferForwardedRedactionStats
        )
        if let modelIdentityAdvisory {
            recordModelIdentityAdvisory(path: parsed.path, dedupKey: modelIdentityAdvisory.dedupKey)
        }

        if shouldLogBodyRedactionBeforeForwarding(
            redactionCount: redactionCount,
            requestWantsStream: requestWantsStream
        ) {
            logRedaction(path: parsed.path, count: redactionCount, types: redactedTypes)
        }
        recordBodyAdvisoryStats(path: parsed.path, count: bodyAdvisoryCount, types: bodyAdvisoryTypes)

        // Platform dispatch: returns a BufferedResponse for the convergence tail,
        // or nil when the response was fully handled (streamed or error sent to client).
        let ctx = ForwardContext(
            parsed: parsed, upstreamURL: upstreamURL, forwardHeaders: forwardHeaders,
            requestWantsStream: requestWantsStream, redactionCount: redactionCount,
            redactedTypes: redactedTypes, processedBodyData: processedBodyData, clientSocket: clientSocket
        )
        guard let buffered = forwardRequest(ctx) else { return }

        let finalBody = bufferedResponseBodyForClient(
            buffered,
            path: parsed.path,
            requestRedactionCount: redactionCount,
            requestRedactedTypes: redactedTypes
        )
        sendResponse(to: clientSocket, status: buffered.status, headers: buffered.headers, body: finalBody)
    }

    // WO-359: include response-body redactions in buffered stats, audit, and alert injection.
    private func bufferedResponseBodyForClient(
        _ buffered: BufferedResponse,
        path: String,
        requestRedactionCount: Int,
        requestRedactedTypes: [String]
    ) -> Data {
        var finalBody = buffered.body
        recordBufferedResponseRedactionStats(
            requestRedactionCount: requestRedactionCount,
            responseRedactionCount: buffered.responseRedactionCount
        )
        if buffered.responseRedactionCount > 0 {
            logRedaction(
                path: path,
                count: buffered.responseRedactionCount,
                types: buffered.responseRedactionTypes,
                source: .response
            )
        }
        recordResponseAdvisoryStats(
            path: path,
            count: buffered.responseAdvisoryCount,
            types: buffered.responseAdvisoryTypes
        )

        let alertRedactionCount = requestRedactionCount + buffered.responseRedactionCount
        let alertTypes = requestRedactedTypes + buffered.responseRedactionTypes
        if alertRedactionCount > 0 && injectAlert {
            // WO-331: JSON response alert injection must not silently no-op on raw SSE bodies.
            if shouldInjectAlertIntoBufferedResponse(headers: buffered.headers) {
                finalBody = injectAlertIntoResponse(
                    buffered.body,
                    redactionCount: alertRedactionCount,
                    types: alertTypes
                )
            } else if shouldInjectAlertIntoBufferedSSEResponse(headers: buffered.headers),
                      let comment = buildAlertSSECommentData(redactionCount: alertRedactionCount, types: alertTypes) {
                // WO-334: buffered SSE responses cannot use JSON alert injection, but
                // an SSE comment preserves protocol framing and operator-visible alert bytes.
                var bodyWithComment = comment
                bodyWithComment.append(buffered.body)
                finalBody = bodyWithComment
                logAlertInjectedAsSSEComment(path: path)
            } else {
                logAlertInjectionSkipped(path: path, contentType: responseContentType(buffered.headers))
            }
        }

        return finalBody
    }

    /// Platform-specific upstream request dispatch. Returns a BufferedResponse for the
    /// convergence tail, or nil when the response was fully handled (streamed or error sent).
    private func forwardRequest(_ ctx: ForwardContext) -> BufferedResponse? {
        #if canImport(Darwin)
        return forwardDarwinRequest(ctx)
        #else
        return forwardLinuxRequest(ctx)
        #endif
    }

    #if canImport(Darwin)
    private func forwardDarwinRequest(_ ctx: ForwardContext) -> BufferedResponse? {
        var upstreamRequest = URLRequest(url: ctx.upstreamURL)
        upstreamRequest.httpMethod = ctx.parsed.method
        upstreamRequest.httpBody = ctx.processedBodyData
        for (key, value) in ctx.forwardHeaders {
            upstreamRequest.setValue(value, forHTTPHeaderField: key)
        }
        let streamingMode = config.responseStreamingRedactionMode
        if ctx.requestWantsStream && streamingMode != .buffer {
            forwardStreamingRequest(
                upstreamRequest, to: ctx.clientSocket,
                redactionCount: ctx.redactionCount, redactedTypes: ctx.redactedTypes, mode: streamingMode
            )
            return nil
        }
        // Non-streaming / buffer mode: buffer full response, then scan+send.
        let semaphore = DispatchSemaphore(value: 0)
        var responseData: Data?
        var httpResponse: HTTPURLResponse?
        let task = urlSession.dataTask(with: upstreamRequest) { data, response, _ in
            responseData = data
            httpResponse = response as? HTTPURLResponse
            semaphore.signal()
        }
        // WO-267: defer cancel covers both paths. On the .timedOut path it terminates the
        // in-flight request. On the .success path it is a no-op (task already completed).
        // Without this, a task created between invalidateAndCancel()'s cancel sweep and
        // task.resume() may never have its completion handler called on some OS versions,
        // leaving semaphore.signal() unfired and blocking handlerGroup.wait() for 600 s.
        defer { task.cancel() }
        task.resume()
        switch waitForNonStreamingTaskCompletion(semaphore: semaphore, task: task) {
        case .completed:
            break
        case .timedOut:
            sendError(to: ctx.clientSocket, status: 504, message: "Gateway Timeout")
            return nil
        case .shutdown:
            return nil
        }
        guard let resp = httpResponse, let data = responseData else {
            sendError(to: ctx.clientSocket, status: 502, message: "Bad Gateway")
            return nil
        }
        return BufferedResponse(status: resp.statusCode, headers: resp.allHeaderFields, body: data)
    }

    func waitForNonStreamingTaskCompletion(
        semaphore: DispatchSemaphore,
        task: URLSessionTask,
        totalTimeoutSeconds: Double = proxyNonStreamTotalTimeoutSeconds,
        pollMilliseconds: Int = proxyNonStreamShutdownPollMilliseconds
    ) -> NonStreamingTaskWaitResult {
        let deadline = DispatchTime.now() + totalTimeoutSeconds
        let pollNanoseconds = UInt64(max(1, pollMilliseconds)) * 1_000_000
        while true {
            guard running else {
                // WO-267: stop() may invalidate before this task reaches URLSession's
                // outstanding-task registry. Cancel and return instead of parking 600s.
                task.cancel()
                return .shutdown
            }

            let now = DispatchTime.now()
            guard now.uptimeNanoseconds < deadline.uptimeNanoseconds else {
                task.cancel()
                return .timedOut
            }

            let remainingNanoseconds = deadline.uptimeNanoseconds - now.uptimeNanoseconds
            let waitNanoseconds = min(remainingNanoseconds, pollNanoseconds)
            if semaphore.wait(timeout: now + .nanoseconds(Int(waitNanoseconds))) == .success {
                return .completed
            }
        }
    }
    #else
    private func forwardLinuxRequest(_ ctx: ForwardContext) -> BufferedResponse? {
        let streamingMode = config.responseStreamingRedactionMode
        // WO-286: buffer mode must keep the legacy full-response path on Linux too.
        let shouldStream = ctx.requestWantsStream && streamingMode != .buffer
        // WO-192: lazy closure evaluated at [DONE] time with accumulated stream counts so
        // stream-only secrets (body-clean request) also trigger the [PASTEWATCH] alert on Linux.
        // WO-202: [weak self] guards against retain cycle if the Linux path ever becomes async.
        let alertBeforeDone = buildLinuxAlertClosure(
            redactionCount: ctx.redactionCount, redactedTypes: ctx.redactedTypes
        )
        let curlResponse: CurlHTTPClient.Response
        do {
            curlResponse = try CurlHTTPClient.execute(
                method: ctx.parsed.method, url: ctx.upstreamURL, headers: ctx.forwardHeaders,
                body: ctx.processedBodyData, caCertPath: caCertPath,
                insecure: insecureTLS, streaming: shouldStream,
                clientSocket: ctx.clientSocket, sendFlags: sendFlags,
                streamingRedactionMode: streamingMode,
                proxyConfig: config, proxyCustomRules: customRules,
                proxySeverity: severity, streamDebugSink: streamDebugSink,
                alertBeforeDone: alertBeforeDone
            )
        } catch CurlHTTPClient.ExecuteError.timeout {
            // WO-386: curl exit 28 is an upstream timeout, not a bad gateway.
            if shouldStream && ctx.redactionCount > 0 {
                logRedaction(path: ctx.parsed.path, count: ctx.redactionCount, types: ctx.redactedTypes)
            }
            sendError(to: ctx.clientSocket, status: 504, message: "Gateway Timeout")
            return nil
        } catch {
            // WO-304: Linux streaming can fail before CurlHTTPClient returns stream
            // stats; log body redactions here so the audit trail is not silent.
            if shouldStream && ctx.redactionCount > 0 {
                logRedaction(path: ctx.parsed.path, count: ctx.redactionCount, types: ctx.redactedTypes)
            }
            sendError(to: ctx.clientSocket, status: 502, message: "Bad Gateway")
            return nil
        }
        if curlResponse.wasStreamed {
            // WO-158: wire Linux streaming redaction stats into audit log and proxy stats.
            recordLinuxStreamStats(StreamingAuditStats(
                path: ctx.parsed.path,
                bodyCount: ctx.redactionCount,
                bodyTypes: ctx.redactedTypes,
                streamCount: curlResponse.streamRedactionCount,
                streamTypes: curlResponse.streamRedactionTypes,
                advisoryCount: curlResponse.streamAdvisoryCount,
                advisoryTypes: curlResponse.streamAdvisoryTypes,
                toolCallCount: curlResponse.streamToolCallRedactionCount
            ))
            return nil
        }
        return BufferedResponse(
            status: curlResponse.statusCode,
            headers: curlResponse.headers as [AnyHashable: Any],
            body: curlResponse.body,
            responseRedactionCount: curlResponse.responseRedactionCount,
            responseRedactionTypes: curlResponse.responseRedactionTypes,
            responseAdvisoryCount: curlResponse.responseAdvisoryCount,
            responseAdvisoryTypes: curlResponse.responseAdvisoryTypes
        )
    }

    private func buildLinuxAlertClosure(
        redactionCount: Int,
        redactedTypes: [String]
    ) -> ((
        _ streamCount: Int,
        _ streamTypes: [String],
        _ advisoryCount: Int,
        _ advisoryTypes: [String]
    ) -> Data?)? {
        guard injectAlert else { return nil }
        return { [weak self] streamCount, streamTypes, advisoryCount, advisoryTypes in
            guard let self = self else { return nil }
            let total = redactionCount + streamCount
            let totalTypes = redactedTypes + streamTypes
            var data = Data()
            if total > 0, let alert = self.buildAlertSSEData(redactionCount: total, types: totalTypes) {
                data.append(alert)
            }
            if advisoryCount > 0,
               let advisory = self.buildAdvisorySSEData(advisoryCount: advisoryCount, types: advisoryTypes) {
                data.append(advisory)
            }
            return data.isEmpty ? nil : data
        }
    }

    private func recordLinuxStreamStats(_ summary: StreamingAuditStats) {
        recordStreamingAuditStats(summary)
    }
    #endif

    // MARK: - Request scanning

    struct ScanResult {
        let body: String
        let redacted: Int
        let redactedTypes: [String]
        let advisoryCount: Int
        let advisoryTypes: [String]
        let serializationFailed: Bool // WO-452: caller must block forwarding on failure.
        let blockingAdvisory: DetectionAdvisory? // WO-478: fail-closed request evidence.
    }

    // WO-478: malformed recognized key containers fail closed before mutation.
    func scanAndRedactBody(_ body: String) -> ScanResult {
        guard let data = body.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return ScanResult(
                body: body, redacted: 0, redactedTypes: [],
                advisoryCount: 0, advisoryTypes: [], serializationFailed: false,
                blockingAdvisory: nil
            )
        }

        // WO-478: preflight the raw JSON text so malformed PEM markers remain
        // visible even when they occur in a structured field not rewritten below.
        if scanProxyText(body).contains(where: { $0.advisory == .malformedPrivateKey }) {
            return ScanResult(
                body: body, redacted: 0, redactedTypes: [],
                advisoryCount: 1, advisoryTypes: ["Malformed private key"],
                serializationFailed: false, blockingAdvisory: .malformedPrivateKey
            )
        }

        var redacted = 0
        var types: [String] = []
        var advisoryCount = 0
        var advisoryTypes: [String] = []
        let processed: [String: Any]
        if json["requests"] != nil {
            processed = redactBatchRequestMessages(
                json,
                redacted: &redacted,
                types: &types,
                advisoryCount: &advisoryCount,
                advisoryTypes: &advisoryTypes
            )
        } else {
            processed = redactRequestPayload(
                json,
                redacted: &redacted,
                types: &types,
                advisoryCount: &advisoryCount,
                advisoryTypes: &advisoryTypes
            )
        }

        guard redacted > 0 else {
            return ScanResult(
                body: body, redacted: 0, redactedTypes: [],
                advisoryCount: advisoryCount, advisoryTypes: advisoryTypes,
                serializationFailed: false, blockingAdvisory: nil
            )
        }
        guard let resultData = try? requestBodySerializer(processed),
              let resultString = String(data: resultData, encoding: .utf8) else {
            return ScanResult(
                body: body, redacted: redacted, redactedTypes: types,
                advisoryCount: advisoryCount, advisoryTypes: advisoryTypes,
                serializationFailed: true, blockingAdvisory: nil
            )
        }

        return ScanResult(
            body: resultString, redacted: redacted, redactedTypes: types,
            advisoryCount: advisoryCount, advisoryTypes: advisoryTypes,
            serializationFailed: false, blockingAdvisory: nil
        )
    }

    // WO-408: outcome of the fail-closed upstream body-shape check.
    enum BodyShapeVerdict: Equatable {
        case allow
        case refuse(String)
    }

    // WO-408/WO-411/WO-412: decide whether a request body is a shape pastewatch can
    // redact. JSON POSTs to unsupported upstream paths are refused rather than silently
    // forwarded unscanned. Pure and socket-free so it is unit-testable directly.
    func upstreamBodyShapeVerdict(method: String, path: String, bodyData: Data) -> BodyShapeVerdict {
        // WO-422: only canonical POST has a request-body scanner. Refuse every
        // other non-empty method body instead of admitting bytes the scan branch skips.
        guard isCanonicalScannablePostMethod(method) else {
            return bodyData.isEmpty ? .allow : .refuse("unsupported request method with body")
        }
        let supportedAnthropicPath = isSupportedAnthropicPostPath(path)
        // WO-433: an empty POST body carries no unscanned JSON shape or credential-bearing
        // request body, so it should reach upstream instead of being refused as malformed.
        guard !bodyData.isEmpty else { return .allow }
        // WO-425: malformed supported-path bodies are not safe passthrough. The downstream
        // scanner only understands valid Anthropic JSON, so fail closed instead of forwarding
        // an unscanned /v1/messages body.
        guard let jsonValue = try? JSONSerialization.jsonObject(with: bodyData, options: [.fragmentsAllowed]) else {
            let reason = supportedAnthropicPath
                ? "malformed Anthropic JSON body"
                : "unsupported non-JSON POST body"
            return .refuse(reason)
        }
        // WO-422: parseable JSON arrays/scalars are JSON bodies, not opaque transport bytes.
        // Refuse malformed Anthropic JSON on supported paths and any JSON body on unsupported
        // paths instead of silently forwarding it unscanned.
        guard let json = jsonValue as? [String: Any] else {
            let reason = supportedAnthropicPath
                ? "malformed Anthropic JSON body"
                : "unsupported JSON POST body"
            return .refuse(reason)
        }
        guard supportedAnthropicPath else {
            return .refuse("unsupported JSON POST body")
        }
        if isSupportedAnthropicBatchesPath(path) {
            // WO-432: batch requests carry Messages params under requests[].params.
            return isAnthropicBatchShape(json)
                ? .allow
                : .refuse("malformed Anthropic batch body")
        }
        let hasMessages = json["messages"] is [Any]
        // WO-425/WO-437: Messages and Count Tokens both require a messages array.
        // The prior count_tokens exception admitted arbitrary unscanned JSON objects.
        guard hasMessages else {
            let endpoint = isSupportedAnthropicCountTokensPath(path) ? "count_tokens" : "messages"
            return .refuse("malformed Anthropic \(endpoint) body")
        }
        return isAnthropicMessagesShape(json)
            ? .allow
            : .refuse("non-Anthropic messages schema")
    }

    // WO-422: admission and scanning must use one exact method predicate.
    private func isCanonicalScannablePostMethod(_ method: String) -> Bool {
        method == "POST"
    }

    // WO-411/WO-412: path allowlist for JSON POST bodies the proxy understands.
    // WO-419: match the /v1/messages endpoint as a path SUFFIX, not an exact string, so a
    // gateway-fronted upstream (WO-142) whose request target embeds a base path — e.g.
    // /v1/llm-gateway/v1/messages or /anthropic/v1/messages — is still recognized as the
    // Anthropic Messages endpoint and allowed, while /v1/chat/completions, /v1/responses,
    // and other non-Anthropic JSON POSTs remain refused.
    func isSupportedAnthropicPostPath(_ path: String) -> Bool {
        let pathOnly = requestPathWithoutQuery(path)
        return pathOnly == "/v1/messages"
            || pathOnly == "/v1/messages/count_tokens"
            || pathOnly == "/v1/messages/batches"
            || pathOnly.hasSuffix("/v1/messages")
            || pathOnly.hasSuffix("/v1/messages/count_tokens")
            || pathOnly.hasSuffix("/v1/messages/batches")
    }

    // WO-425: count-token endpoints share the supported Anthropic path family but can have
    // request shapes that are not scanned as Messages tool-result bodies.
    private func isSupportedAnthropicCountTokensPath(_ path: String) -> Bool {
        let pathOnly = requestPathWithoutQuery(path)
        return pathOnly == "/v1/messages/count_tokens"
            || pathOnly.hasSuffix("/v1/messages/count_tokens")
    }

    // WO-432: the Message Batches create endpoint is a supported Anthropic request shape,
    // while batch-result retrieval is not a JSON POST body the request scanner understands.
    private func isSupportedAnthropicBatchesPath(_ path: String) -> Bool {
        let pathOnly = requestPathWithoutQuery(path)
        return pathOnly == "/v1/messages/batches"
            || pathOnly.hasSuffix("/v1/messages/batches")
    }

    // WO-425: classify gateway paths without letting query strings affect endpoint shape.
    private func requestPathWithoutQuery(_ path: String) -> String {
        var pathOnly = path.split(separator: "?", maxSplits: 1, omittingEmptySubsequences: false).first
            .map(String.init) ?? path
        // WO-436: gateway/client-normalized trailing slashes still identify the
        // same Anthropic endpoints and should not trip fail-closed shape refusal.
        while pathOnly.count > 1 && pathOnly.hasSuffix("/") {
            pathOnly.removeLast()
        }
        return pathOnly
    }

    // WO-408/WO-430: identify the Messages wire shape, not the model vendor. Model names
    // are sender-mutable and may name Anthropic-compatible providers, so only structural
    // OpenAI siblings participate in refusal.
    func isAnthropicMessagesShape(_ json: [String: Any]) -> Bool {
        guard let messages = json["messages"] as? [[String: Any]] else { return false }
        guard hasValidAnthropicTools(json["tools"]),
              hasValidStopSequences(json["stop_sequences"]) else { return false }
        for message in messages {
            guard message["role"] is String else { return false }
            // OpenAI /v1/chat/completions carries tool_calls / function_call on messages;
            // their presence is a high-signal marker that this is not an Anthropic body.
            if hasNonNullJSONField("tool_calls", in: message)
                || hasNonNullJSONField("function_call", in: message) {
                return false
            }
            if let content = message["content"] {
                if content is NSNull { continue } // WO-427: JSON null is equivalent to absent content.
                if content is String { continue }
                guard let blocks = content as? [[String: Any]] else { return false }
                for block in blocks where !(block["type"] is String) { return false }
            }
        }
        return true
    }

    // WO-456: malformed tool containers cannot bypass the request scanner.
    private func hasValidAnthropicTools(_ value: Any?) -> Bool {
        guard let value else { return true }
        guard !(value is NSNull), let tools = value as? [[String: Any]] else { return false }
        return tools.allSatisfy { tool in
            guard let name = tool["name"] as? String, !name.isEmpty,
                  tool["input_schema"] is [String: Any] else { return false }
            if let description = tool["description"], !(description is String) { return false }
            if let examples = tool["input_examples"], !(examples is [Any]) { return false }
            return true
        }
    }

    // WO-457: stop sequences are scannable strings, never an opaque mixed array.
    private func hasValidStopSequences(_ value: Any?) -> Bool {
        guard let value else { return true }
        guard !(value is NSNull), let sequences = value as? [Any] else { return false }
        return sequences.allSatisfy { $0 is String }
    }

    // WO-432: Anthropic Message Batches wrap normal Messages params in requests[].params.
    func isAnthropicBatchShape(_ json: [String: Any]) -> Bool {
        guard let requests = json["requests"] as? [[String: Any]] else { return false }
        return requests.allSatisfy { request in
            guard let params = request["params"] as? [String: Any] else { return false }
            return isAnthropicMessagesShape(params)
        }
    }

    // WO-431: JSON null means the OpenAI-only key is explicitly empty, not present.
    private func hasNonNullJSONField(_ key: String, in json: [String: Any]) -> Bool {
        guard let value = json[key] else { return false }
        return !(value is NSNull)
    }

    // WO-430: retain known foreign families only for advisory classification, never
    // refusal. Keep o-family matches dash-scoped so telemetry remains deterministic.
    private static let knownForeignMessagesModelPrefixes = [
        "gpt-", "chatgpt-", "o1-", "o2-", "o3-", "o4-", "o5-", "o6-",
        "gemini-", "mistral-", "llama-", "grok-",
    ]

    private func isKnownForeignMessagesModel(_ model: String) -> Bool {
        let lower = model.lowercased()
        return Self.knownForeignMessagesModelPrefixes.contains { lower.hasPrefix($0) }
    }

    // WO-445: retain model identity only in the in-memory dedup key; audit output stays opaque.
    private struct ModelIdentityAdvisory {
        let dedupKey: String
    }

    // WO-430/WO-446: model identity is advisory telemetry. A request that speaks the
    // supported wire shape remains allowed, and each batch payload is classified independently.
    func modelIdentityAdvisoryNeeded(method: String, path: String, bodyData: Data) -> Bool {
        modelIdentityAdvisory(method: method, path: path, bodyData: bodyData) != nil
    }

    private func modelIdentityAdvisory(method: String, path: String, bodyData: Data) -> ModelIdentityAdvisory? {
        guard isCanonicalScannablePostMethod(method), isSupportedAnthropicPostPath(path),
              let json = try? JSONSerialization.jsonObject(with: bodyData) as? [String: Any] else {
            return nil
        }
        let payloads: [[String: Any]]
        if isSupportedAnthropicBatchesPath(path) {
            let requests = json["requests"] as? [[String: Any]] ?? []
            payloads = requests.compactMap { $0["params"] as? [String: Any] }
        } else {
            payloads = [json]
        }
        guard !payloads.isEmpty else { return nil }
        let identities = payloads.compactMap { payload -> String? in
            guard !containsToolResult(payload) else { return nil }
            guard let model = payload["model"] as? String else { return "missing" }
            guard isKnownForeignMessagesModel(model) || !isRecognizedAnthropicModelName(model) else {
                return nil
            }
            return "model:\(model.utf8.count):\(model)"
        }
        guard !identities.isEmpty else { return nil }
        let dedupKey = Array(Set(identities)).sorted().joined(separator: "|")
        return ModelIdentityAdvisory(dedupKey: dedupKey)
    }

    // WO-430: telemetry applies only when no request payload was scanned as tool_result.
    private func containsToolResult(_ json: [String: Any]) -> Bool {
        guard let messages = json["messages"] as? [[String: Any]] else { return false }
        return messages.contains { message in
            guard let content = message["content"] as? [[String: Any]] else { return false }
            return content.contains { ($0["type"] as? String) == "tool_result" }
        }
    }

    // WO-430: recognized names suppress advisory noise but never decide admission.
    private func isRecognizedAnthropicModelName(_ model: String) -> Bool {
        let lower = model.lowercased()
        return lower.hasPrefix("claude-") || lower.hasPrefix("anthropic.")
    }

    // WO-408/WO-413/WO-440: audit fail-closed refusals without repeating identical noise.
    private func logUnsupportedBodyShapeRefusal(path: String, reason: String) {
        logBodyRefusal(path: path, reason: reason, description: "unsupported upstream body shape")
    }

    // WO-478: malformed secret-container refusals are audited without recording
    // any marker payload or request-body bytes.
    private func logUnsafeBodyRefusal(path: String, reason: String) {
        logBodyRefusal(path: path, reason: reason, description: "unsafe request body")
    }

    // WO-494: refusal categories share one dedup and cross-chain reset state machine.
    // WO-492: dedup on the full-target digest, not the sanitized display path, so
    // distinct request targets are not collapsed into one refusal audit entry.
    private func logBodyRefusal(path: String, reason: String, description: String) {
        let safePath = auditSafePath(path)
        // WO-492: dedup on the full-target digest, not the sanitized display path.
        let signature = "refused:\(auditDedupPathIdentity(path)):\(reason)"
        statsLock.lock()
        let isRepeat = signature == lastRefusalLogSignature
        lastRefusalLogSignature = signature
        // WO-443/WO-448: an emitted refusal breaks every other audit dedup chain.
        if !isRepeat {
            lastRedactionLogSignatures.removeAll()
            lastAdvisoryLogSignatures.removeAll()
            lastModelIdentityAdvisorySignature = nil
        }
        statsLock.unlock()
        guard !isRepeat else { return }

        let line = "[\(formatAuditTimestamp(Date()))] PROXY REFUSED \(description) in \(safePath) (\(reason))\n"
        if !quietLog {
            FileHandle.standardError.write(Data(line.utf8))
        }
        if let logPath = auditLogPath {
            logQueue.async {
                if let handle = FileHandle(forWritingAtPath: logPath) {
                    handle.seekToEndOfFile()
                    handle.write(Data(line.utf8))
                    handle.closeFile()
                } else {
                    FileManager.default.createFile(atPath: logPath, contents: Data(line.utf8))
                }
            }
        }
    }

    // WO-486: request targets are forwarded verbatim but audit output never includes
    // query values or terminal/log control bytes.
    func auditSafePath(_ rawPath: String) -> String {
        let pathOnly = rawPath.split(separator: "?", maxSplits: 1, omittingEmptySubsequences: false)
            .first.map(String.init) ?? rawPath
        let sanitized = pathOnly.unicodeScalars.map { scalar -> String in
            let value = scalar.value
            let isControl = value <= 0x1f || (0x7f...0x9f).contains(value)
            return isControl ? "_" : String(scalar)
        }.joined()
        guard sanitized.count > proxyAuditPathMaxCharacters else { return sanitized }
        return String(sanitized.prefix(proxyAuditPathMaxCharacters)) + "..."
    }

    // WO-492: display paths omit query values, while this ephemeral digest preserves
    // exact request-target identity without retaining those values in dedup state.
    private func auditDedupPathIdentity(_ rawPath: String) -> String {
        let digest = SHA256.hash(data: Data(rawPath.utf8))
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    private func scanProxyText(_ text: String) -> [DetectedMatch] {
        // WO-402: proxy body scans must honor custom rules, matching streaming scans.
        DetectionRules.scan(
            text,
            config: config,
            customRules: customRules
        )
    }

    // WO-444/WO-447: count_tokens and batch params can carry system text as either a
    // string or typed text blocks; preserve all non-text block metadata.
    private func redactTopLevelStringFields(
        _ json: [String: Any],
        redacted: inout Int,
        types: inout [String],
        advisoryCount: inout Int,
        advisoryTypes: inout [String]
    ) -> [String: Any] {
        var result = json
        for field in ["system"] {
            if let value = json[field] as? String {
                result[field] = redactScannableText(
                    value,
                    site: .proxySystem,
                    redacted: &redacted,
                    types: &types,
                    advisoryCount: &advisoryCount,
                    advisoryTypes: &advisoryTypes
                )
                continue
            }
            guard var blocks = json[field] as? [[String: Any]] else { continue }
            for index in blocks.indices {
                guard blocks[index]["type"] as? String == "text",
                      let text = blocks[index]["text"] as? String else { continue }
                blocks[index]["text"] = redactScannableText(
                    text,
                    site: .proxySystem,
                    redacted: &redacted,
                    types: &types,
                    advisoryCount: &advisoryCount,
                    advisoryTypes: &advisoryTypes
                )
            }
            result[field] = blocks
        }
        return result
    }

    // WO-444/WO-447: keep certainty-gated mutation and advisory accounting identical
    // across string and block-array system representations.
    // swiftlint:disable:next function_parameter_count
    private func redactScannableText(
        _ value: String,
        site: MutationSite,
        redacted: inout Int,
        types: inout [String],
        advisoryCount: inout Int,
        advisoryTypes: inout [String]
    ) -> String {
        let matches = scanProxyText(value)
        let outcome = applyAuthorizedMutations(
            to: value,
            matches: matches,
            site: site,
            minAdvisorySeverity: severity
        )
        advisoryCount += outcome.advisory.count
        advisoryTypes.append(contentsOf: outcome.advisory.map { $0.displayName })
        redacted += outcome.mutated.count
        types.append(contentsOf: outcome.mutated.map { $0.displayName })
        return outcome.text
    }

    // WO-454/WO-461: recursively scan structured values without changing keys or
    // non-string leaves; the caller supplies the evidence-reporting site.
    // swiftlint:disable:next function_parameter_count
    private func redactJSONStrings(
        _ value: Any,
        site: MutationSite,
        redacted: inout Int,
        types: inout [String],
        advisoryCount: inout Int,
        advisoryTypes: inout [String]
    ) -> Any {
        if let text = value as? String {
            return redactScannableText(
                text,
                site: site,
                redacted: &redacted,
                types: &types,
                advisoryCount: &advisoryCount,
                advisoryTypes: &advisoryTypes
            )
        }
        if let array = value as? [Any] {
            return array.map {
                redactJSONStrings(
                    $0, site: site, redacted: &redacted, types: &types,
                    advisoryCount: &advisoryCount, advisoryTypes: &advisoryTypes
                )
            }
        }
        if let object = value as? [String: Any] {
            return object.mapValues {
                redactJSONStrings(
                    $0, site: site, redacted: &redacted, types: &types,
                    advisoryCount: &advisoryCount, advisoryTypes: &advisoryTypes
                )
            }
        }
        return value
    }

    // WO-460 and WO-506: replay-sensitive blocks expose only explicitly documented plaintext.
    // swiftlint:disable:next function_parameter_count
    private func redactReplayContentBlock(
        _ object: [String: Any],
        site: MutationSite,
        redacted: inout Int,
        types: inout [String],
        advisoryCount: inout Int,
        advisoryTypes: inout [String]
    ) -> [String: Any]? {
        switch object["type"] as? String {
        case "image", "thinking", "redacted_thinking":
            return object
        case "encrypted_code_execution_result":
            guard let stderr = object["stderr"] as? String else { return object }
            var result = object
            result["stderr"] = redactScannableText(
                stderr, site: site, redacted: &redacted, types: &types,
                advisoryCount: &advisoryCount, advisoryTypes: &advisoryTypes
            )
            return result
        case "code_execution_tool_result":
            guard let content = object["content"] else { return object }
            var result = object
            result["content"] = redactContentPayloadStrings(
                content, site: site, redacted: &redacted, types: &types,
                advisoryCount: &advisoryCount, advisoryTypes: &advisoryTypes
            )
            return result
        default:
            return nil
        }
    }

    // WO-503: unknown content blocks may carry plaintext, but protocol discriminators
    // and base64 payload bytes must remain structurally intact.
    // swiftlint:disable:next function_parameter_count
    private func redactContentPayloadStrings(
        _ value: Any,
        site: MutationSite,
        redacted: inout Int,
        types: inout [String],
        advisoryCount: inout Int,
        advisoryTypes: inout [String]
    ) -> Any {
        // WO-460: traverse documented plaintext fields while preserving protocol metadata.
        if let text = value as? String {
            return redactScannableText(
                text, site: site, redacted: &redacted, types: &types,
                advisoryCount: &advisoryCount, advisoryTypes: &advisoryTypes
            )
        }
        if let array = value as? [Any] {
            return array.map {
                redactContentPayloadStrings(
                    $0, site: site, redacted: &redacted, types: &types,
                    advisoryCount: &advisoryCount, advisoryTypes: &advisoryTypes
                )
            }
        }
        if let object = value as? [String: Any] {
            let blockType = object["type"] as? String
            if blockType == "text" {
                guard let text = object["text"] as? String else { return object }
                var result = object
                result["text"] = redactScannableText(
                    text, site: site, redacted: &redacted, types: &types,
                    advisoryCount: &advisoryCount, advisoryTypes: &advisoryTypes
                )
                return result
            }
            if let replayBlock = redactReplayContentBlock(
                object, site: site, redacted: &redacted, types: &types,
                advisoryCount: &advisoryCount, advisoryTypes: &advisoryTypes
            ) {
                return replayBlock
            }
            if blockType == "document", var source = object["source"] as? [String: Any] {
                switch source["type"] as? String {
                case "text":
                    if let text = source["data"] as? String {
                        source["data"] = redactScannableText(
                            text, site: site, redacted: &redacted, types: &types,
                            advisoryCount: &advisoryCount, advisoryTypes: &advisoryTypes
                        )
                    }
                case "content":
                    if let content = source["content"] {
                        source["content"] = redactContentPayloadStrings(
                            content, site: site, redacted: &redacted, types: &types,
                            advisoryCount: &advisoryCount, advisoryTypes: &advisoryTypes
                        )
                    }
                default:
                    break
                }
                var result = object
                result["source"] = source
                return result
            }
            if blockType == "search_result", let content = object["content"] {
                var result = object
                result["content"] = redactContentPayloadStrings(
                    content, site: site, redacted: &redacted, types: &types,
                    advisoryCount: &advisoryCount, advisoryTypes: &advisoryTypes
                )
                return result
            }
            let containsBase64Data = (object["type"] as? String) == "base64"
            var result = object
            for (key, nestedValue) in object {
                if key == "type" || key == "media_type" || (containsBase64Data && key == "data") {
                    continue
                }
                result[key] = redactContentPayloadStrings(
                    nestedValue, site: site, redacted: &redacted, types: &types,
                    advisoryCount: &advisoryCount, advisoryTypes: &advisoryTypes
                )
            }
            return result
        }
        return value
    }

    // WO-454/WO-461: tool contracts and examples are visible to the scanner and
    // use explicit sites; evidence, not field context, controls replacement.
    private func redactTools(
        _ json: [String: Any],
        redacted: inout Int,
        types: inout [String],
        advisoryCount: inout Int,
        advisoryTypes: inout [String]
    ) -> [String: Any] {
        var result = json
        guard var tools = json["tools"] as? [[String: Any]] else { return result }
        for index in tools.indices {
            if let description = tools[index]["description"] as? String {
                tools[index]["description"] = redactScannableText(
                    description, site: .proxyToolDescription,
                    redacted: &redacted, types: &types,
                    advisoryCount: &advisoryCount, advisoryTypes: &advisoryTypes
                )
            }
            if let schema = tools[index]["input_schema"] {
                tools[index]["input_schema"] = redactJSONStrings(
                    schema, site: .proxyInputSchema,
                    redacted: &redacted, types: &types,
                    advisoryCount: &advisoryCount, advisoryTypes: &advisoryTypes
                )
            }
            if let examples = tools[index]["input_examples"] {
                tools[index]["input_examples"] = redactJSONStrings(
                    examples, site: .proxyToolInputExample,
                    redacted: &redacted, types: &types,
                    advisoryCount: &advisoryCount, advisoryTypes: &advisoryTypes
                )
            }
        }
        result["tools"] = tools
        return result
    }

    /// WO-454: scan authored text and execution payloads with explicit sites.
    private func redactContentArray(
        _ json: [String: Any],
        redacted: inout Int,
        types: inout [String],
        advisoryCount: inout Int,
        advisoryTypes: inout [String]
    ) -> [String: Any] {
        var result = json

        guard var messages = json["messages"] as? [[String: Any]] else {
            return result
        }

        for index in messages.indices {
            let role = messages[index]["role"] as? String
            let textSite: MutationSite = role == "user" ? .proxyUserText : .proxyAssistantText
            if let text = messages[index]["content"] as? String {
                messages[index]["content"] = redactScannableText(
                    text, site: textSite, redacted: &redacted, types: &types,
                    advisoryCount: &advisoryCount, advisoryTypes: &advisoryTypes
                )
                continue
            }
            guard var blocks = messages[index]["content"] as? [[String: Any]] else { continue }
            for blockIndex in blocks.indices {
                let blockType = blocks[blockIndex]["type"] as? String
                if blockType == "tool_result", let content = blocks[blockIndex]["content"] {
                    // WO-460: tool results can nest document and search-result blocks.
                    blocks[blockIndex]["content"] = redactContentPayloadStrings(
                        content, site: .proxyToolResult,
                        redacted: &redacted, types: &types,
                        advisoryCount: &advisoryCount, advisoryTypes: &advisoryTypes
                    )
                } else if blockType == "tool_use", let input = blocks[blockIndex]["input"] {
                    blocks[blockIndex]["input"] = redactJSONStrings(
                        input, site: .proxyToolUseInput,
                        redacted: &redacted, types: &types,
                        advisoryCount: &advisoryCount, advisoryTypes: &advisoryTypes
                    )
                } else {
                    // WO-503: scan every non-tool payload, including blocks that also carry text.
                    blocks[blockIndex] = redactContentPayloadStrings(
                        blocks[blockIndex], site: textSite,
                        redacted: &redacted, types: &types,
                        advisoryCount: &advisoryCount, advisoryTypes: &advisoryTypes
                    ) as? [String: Any] ?? blocks[blockIndex]
                }
            }
            messages[index]["content"] = blocks
        }

        result["messages"] = messages
        return result
    }

    // WO-454/WO-457: one request-body walk covers ordinary and batch params.
    private func redactRequestPayload(
        _ json: [String: Any],
        redacted: inout Int,
        types: inout [String],
        advisoryCount: inout Int,
        advisoryTypes: inout [String]
    ) -> [String: Any] {
        var result = redactTopLevelStringFields(
            json, redacted: &redacted, types: &types,
            advisoryCount: &advisoryCount, advisoryTypes: &advisoryTypes
        )
        result = redactTools(
            result, redacted: &redacted, types: &types,
            advisoryCount: &advisoryCount, advisoryTypes: &advisoryTypes
        )
        if let sequences = result["stop_sequences"] as? [String] {
            result["stop_sequences"] = sequences.map {
                redactScannableText(
                    $0, site: .proxyStopSequence,
                    redacted: &redacted, types: &types,
                    advisoryCount: &advisoryCount, advisoryTypes: &advisoryTypes
                )
            }
        }
        return redactContentArray(
            result, redacted: &redacted, types: &types,
            advisoryCount: &advisoryCount, advisoryTypes: &advisoryTypes
        )
    }

    // WO-432: scan nested Message Batch params with the same certainty gate used for
    // ordinary /v1/messages bodies.
    private func redactBatchRequestMessages(
        _ json: [String: Any],
        redacted: inout Int,
        types: inout [String],
        advisoryCount: inout Int,
        advisoryTypes: inout [String]
    ) -> [String: Any] {
        var result = json
        guard var requests = json["requests"] as? [[String: Any]] else {
            return result
        }

        for index in requests.indices {
            guard let params = requests[index]["params"] as? [String: Any] else { continue }
            requests[index]["params"] = redactRequestPayload(
                params, redacted: &redacted, types: &types,
                advisoryCount: &advisoryCount, advisoryTypes: &advisoryTypes
            )
        }

        result["requests"] = requests
        return result
    }

    // MARK: - Streaming helpers

    /// True if the request JSON body contains "stream":true.
    func isStreamingRequest(_ body: String) -> Bool {
        guard let data = body.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return false
        }
        return json["stream"] as? Bool == true
    }

    func requestWantsStreamingResponse(processedBody: String?, bodyData: Data) -> Bool {
        if let processedBody {
            return isStreamingRequest(processedBody)
        }
        guard !bodyData.isEmpty else { return false }
        // WO-307: malformed UTF-8 can still be structurally valid JSON after
        // replacement; use the same lossy view as redaction so stream routing
        // does not fall back to the 600s buffered path.
        // swiftlint:disable:next optional_data_string_conversion
        let lossyBody = String(decoding: bodyData, as: UTF8.self)
        return isStreamingRequest(lossyBody)
    }

    func shouldLogBodyRedactionBeforeForwarding(
        redactionCount: Int,
        requestWantsStream: Bool
    ) -> Bool {
        guard redactionCount > 0 else { return false }
        // WO-304: non-streaming and buffer-mode body redactions must be logged
        // before forwarding so upstream failures cannot hide them. Streaming
        // mode defers the body count so body + SSE redactions are logged once.
        return !(requestWantsStream && config.responseStreamingRedactionMode != .buffer)
    }

    func shouldDeferForwardedRedactionStats(requestWantsStream: Bool) -> Bool {
        #if canImport(Darwin)
        // WO-340: Darwin streaming can still reject before URLSession task creation
        // when stop() has begun; count forwarded redactions only after task acceptance.
        return requestWantsStream && config.responseStreamingRedactionMode != .buffer
        #else
        return false
        #endif
    }

    func recordInitialRequestStats(
        redactionCount: Int,
        countForwardedRedaction: Bool = true
    ) {
        statsLock.lock()
        stats.requestsProcessed += 1
        if redactionCount > 0 && countForwardedRedaction {
            stats.requestsRedacted += 1
            stats.secretsRedacted += redactionCount
        }
        statsLock.unlock()
    }

    // WO-442: refusals are not processed requests, but operators still need an aggregate count.
    private func recordRefusedRequest() {
        statsLock.lock()
        stats.refusedRequests += 1
        statsLock.unlock()
    }

    // WO-452: failure accounting is distinct from successfully forwarded redactions.
    private func recordRedactionFailure() {
        statsLock.lock()
        stats.redactionFailures += 1
        statsLock.unlock()
    }

    // WO-430/WO-445: preserve compatible traffic while making model drift measurable
    // and deduplicating only identical path-and-model advisories.
    private func recordModelIdentityAdvisory(path: String, dedupKey: String) {
        statsLock.lock()
        stats.modelIdentityAdvisories += 1
        let advisoryCount = stats.modelIdentityAdvisories
        let requestCount = stats.requestsProcessed
        statsLock.unlock()
        logModelIdentityAdvisory(
            path: path,
            dedupKey: dedupKey,
            advisoryCount: advisoryCount,
            requestCount: requestCount
        )
    }

    func recordForwardedBodyRedactionStats(redactionCount: Int) {
        guard redactionCount > 0 else { return }
        statsLock.lock()
        stats.requestsRedacted += 1
        stats.secretsRedacted += redactionCount
        statsLock.unlock()
    }

    func recordBufferedResponseRedactionStats(requestRedactionCount: Int, responseRedactionCount: Int) {
        guard responseRedactionCount > 0 else { return }
        statsLock.lock()
        if requestRedactionCount == 0 {
            stats.requestsRedacted += 1
        }
        stats.secretsRedacted += responseRedactionCount
        statsLock.unlock()
    }

    func recordBufferedResponseRedactionAuditForTesting(path: String, count: Int, types: [String]) {
        // WO-378: exercise the same response-source audit path used by buffered responses.
        logRedaction(path: path, count: count, types: types, source: .response)
    }

    func recordBodyAdvisoryStats(path: String, count: Int, types: [String]) {
        recordAdvisoryStats(path: path, count: count, types: types, source: .request)
    }

    private func recordResponseAdvisoryStats(path: String, count: Int, types: [String]) {
        recordAdvisoryStats(path: path, count: count, types: types, source: .response)
    }

    private func recordAdvisoryStats(path: String, count: Int, types: [String], source: RedactionLogSource) {
        guard count > 0 else { return }
        statsLock.lock()
        stats.advisoryMatches += count
        statsLock.unlock()
        logAdvisory(path: path, count: count, types: types, source: source)
    }

    // WO-512: aggregate and expose tool payload mutations separately from ordinary stream text.
    func recordStreamingAuditStats(_ summary: StreamingAuditStats) {
        let totalCount = summary.bodyCount + summary.streamCount
        let totalTypes = summary.bodyTypes + summary.streamTypes
        if summary.streamCount > 0 || summary.advisoryCount > 0 {
            statsLock.lock()
            if summary.streamCount > 0 {
                // WO-353: mirror existing body+stream request coalescing (also revises WO-354).
                if summary.bodyCount == 0 { stats.requestsRedacted += 1 }
                stats.secretsRedacted += summary.streamCount
            }
            if summary.advisoryCount > 0 {
                stats.advisoryMatches += summary.advisoryCount
            }
            stats.toolCallPayloadMutations += summary.toolCallCount
            statsLock.unlock()
        }
        // WO-184: log body+stream redactions and stream advisories independently
        // (also revises WO-353 and WO-354).
        if totalCount > 0 {
            logRedaction(path: summary.path, count: totalCount, types: totalTypes)
        }
        if summary.advisoryCount > 0 {
            logAdvisory(path: summary.path, count: summary.advisoryCount, types: summary.advisoryTypes, source: .response)
        }
        if summary.toolCallCount > 0 {
            logToolCallMutation(path: summary.path, count: summary.toolCallCount)
        }
    }

    func responseContentType(_ headers: [AnyHashable: Any]) -> String {
        for (key, value) in headers where "\(key)".lowercased() == "content-type" {
            return "\(value)"
        }
        return ""
    }

    func shouldInjectAlertIntoBufferedResponse(headers: [AnyHashable: Any]) -> Bool {
        // WO-331: injectAlertIntoResponse parses JSON; only call it for JSON response bodies.
        responseContentType(headers).lowercased().contains("application/json")
    }

    func shouldInjectAlertIntoBufferedSSEResponse(headers: [AnyHashable: Any]) -> Bool {
        responseContentType(headers).lowercased().contains("text/event-stream")
    }

    public static func upstreamHostHeader(for upstream: URL) -> String? {
        guard let host = upstream.host, !host.isEmpty else { return nil }
        return host
    }

    func buildForwardHeaders(from headers: [(String, String)], bodyLength: Int) -> [(String, String)]? {
        guard let upstreamHost = Self.upstreamHostHeader(for: upstream) else { return nil }
        var forwardHeaders: [(String, String)] = []
        for (key, value) in headers {
            let lower = key.lowercased()
            guard lower != "host", lower != "content-length", lower != "accept-encoding" else {
                continue
            }
            forwardHeaders.append((key, value))
        }
        // WO-303: force identity encoding so SSE redaction sees plaintext bytes.
        forwardHeaders.append(("Accept-Encoding", "identity"))
        forwardHeaders.append(("Host", upstreamHost))
        forwardHeaders.append(("Content-Length", String(bodyLength)))
        return forwardHeaders
    }

    // WO-395: serialize swift-corelibs lazy cache initialization and subsequent formatting.
    func formatAuditTimestamp(_ date: Date) -> String {
        iso8601FormatterLock.lock()
        defer { iso8601FormatterLock.unlock() }
        return iso8601Formatter.string(from: date)
    }

    #if canImport(Darwin)
    /// Forward a streaming (SSE) response to the client socket incrementally.
    /// Uses URLSessionDataDelegate so each upstream chunk is written to the
    /// client immediately, without buffering the full response.
    private func forwardStreamingRequest(
        _ request: URLRequest,
        to clientSocket: Int32,
        redactionCount: Int,
        redactedTypes: [String],
        mode: StreamingRedactionMode
    ) {
        guard let task = makeStreamingTaskIfRunning(for: request) else {
            // WO-314: stop() may invalidate the shared URLSession while a handler is
            // about to create its streaming task; return a shutdown status instead
            // of calling dataTask() on an invalidated session.
            recordRejectedStreamingBodyRedactionIfNeeded(
                path: request.url?.path ?? "/",
                redactionCount: redactionCount,
                redactedTypes: redactedTypes
            )
            sendError(to: clientSocket, status: 503, message: "Service Unavailable")
            return
        }
        recordForwardedBodyRedactionStats(redactionCount: redactionCount)

        let relay = SSEStreamRelay(
            clientSocket: clientSocket,
            sendFlags: sendFlags,
            redactionMode: mode,
            config: config,
            customRules: customRules,
            severity: severity,
            idleTimeoutSeconds: proxyStreamIdleTimeoutSeconds,
            tlsChallengeHandler: tlsTrustDelegate.map { delegate in
                { _, challenge, completionHandler in
                    delegate.handle(challenge: challenge, completionHandler: completionHandler)
                }
            },
            streamDebugSink: streamDebugSink
        )

        // WO-182: inject the alert frame immediately before [DONE] so SSE consumers
        // (which stop reading at [DONE]) see it. The closure is evaluated with stream-only
        // counts at [DONE] time; body counts are captured from local scope.
        // WO-195: body counts captured directly — no relay property assignment needed.
        if injectAlert {
            relay.buildAlertBeforeDone = { [weak self] streamCount, streamTypes, advisoryCount, advisoryTypes in
                guard let self = self else { return nil }
                let total = redactionCount + streamCount
                let totalTypes = redactedTypes + streamTypes
                var data = Data()
                if total > 0, let alert = self.buildAlertSSEData(redactionCount: total, types: totalTypes) {
                    data.append(alert)
                }
                if advisoryCount > 0,
                   let advisory = self.buildAdvisorySSEData(advisoryCount: advisoryCount, types: advisoryTypes) {
                    data.append(advisory)
                }
                return data.isEmpty ? nil : data
            }
        }

        relay.execute(task: task, session: urlSession)

        // WO-153: account for secrets redacted from SSE frames in the stream.
        let streamStats = relay.snapshotStreamStats()
        recordStreamingAuditStats(StreamingAuditStats(
            path: request.url?.path ?? "/",
            bodyCount: redactionCount,
            bodyTypes: redactedTypes,
            streamCount: streamStats.redactionCount,
            streamTypes: streamStats.redactionTypes,
            advisoryCount: streamStats.advisoryCount,
            advisoryTypes: streamStats.advisoryTypes,
            toolCallCount: streamStats.toolCallRedactionCount
        ))
    }

    private func makeStreamingTaskIfRunning(for request: URLRequest) -> URLSessionDataTask? {
        // WO-314: serialize the running check with stop()'s _running=false write so
        // task creation cannot happen after invalidateAndCancel() has been reached.
        runningLock.lock()
        defer { runningLock.unlock() }
        guard _running else { return nil }
        return urlSession.dataTask(with: request)
    }
    #endif

    func recordRejectedStreamingBodyRedactionIfNeeded(
        path: String,
        redactionCount: Int,
        redactedTypes: [String]
    ) {
        guard redactionCount > 0 else { return }
        // WO-344: streaming request-body redaction stats are normally deferred
        // until a URLSession task is accepted; the server-stopping branch also
        // needs an audit/stat record before returning 503.
        recordForwardedBodyRedactionStats(redactionCount: redactionCount)
        logRedaction(path: path, count: redactionCount, types: redactedTypes)
    }

    // MARK: - Raw socket I/O

    /// Send flags: MSG_NOSIGNAL on Linux prevents per-send SIGPIPE delivery.
    /// On macOS we rely on process-level signal(SIGPIPE, SIG_IGN) set by the caller.
    #if canImport(Darwin)
    private let sendFlags: Int32 = 0
    #else
    private let sendFlags: Int32 = Int32(MSG_NOSIGNAL)
    #endif

    func readHTTPRequest(from socket: Int32) -> ReadResult {
        var buffer = [UInt8](repeating: 0, count: proxyHTTPRequestReadBufferBytes)
        var accumulated = Data()
        // WO-272: nil = Content-Length header absent; 0 = "Content-Length: 0" (zero body expected).
        // The previous Int default of 0 made bodyReceived >= contentLength always true after the
        // separator was found, truncating the body for requests without Content-Length.
        var contentLength: Int?
        var headerEnd = false
        var headerEndIndex = 0
        var headerMetadata: HTTPHeaderMetadata?

        // WO-274: monotonic deadline bounds the total function wall-clock time regardless of
        // how many EINTR retries occur. SO_RCVTIMEO is per-call; WO-280 keeps this deadline
        // matched to the socket receive timeout.
        let deadline = DispatchTime.now() + .seconds(proxyClientSocketTimeoutSeconds)

        let headerSeparatorOverlap = Self.requestCRLFHeaderTerminator.count - 1
        var sawCRLFHeaderLine = false
        while true {
            let prevCount = accumulated.count
            let bytesRead = recv(socket, &buffer, buffer.count, 0)
            // WO-265: EAGAIN fires when SO_RCVTIMEO expires — return .timeout so handleConnection
            // sends 408 and exits, releasing the handlerGroup entry.
            // WO-268: EINTR means a signal interrupted recv() — the connection is healthy;
            // retry. Mirrors sendAll()'s EINTR loop (WO-214). All other negatives are errors.
            if bytesRead < 0 {
                if errno == EINTR {
                    // WO-274: check cumulative deadline on every EINTR so a stream of signals
                    // cannot hold the handlerGroup entry beyond the intended 30s window.
                    if DispatchTime.now() > deadline { return .timeout }
                    continue
                }
                // WO-273: EAGAIN = SO_RCVTIMEO expired; all other errors = transport failure.
                return errno == EAGAIN ? .timeout : .transportError
            }
            guard bytesRead > 0 else { break }
            accumulated.append(contentsOf: buffer[0..<bytesRead])

            // WO-269: search for \r\n\r\n at the byte level so headerEndIndex is a byte
            // offset consistent with accumulated.count. str.distance() counts Unicode
            // grapheme clusters — diverges from byte count for any non-ASCII header value.
            // WO-276: windowed search — separator can only straddle the boundary between old
            // and new bytes, so start 3 bytes before the new data (separator is 4 bytes).
            // Reduces total scan work from O(n×chunks) to O(n).
            if !headerEnd {
                let searchStart = max(0, prevCount - headerSeparatorOverlap)
                let searchRange = searchStart..<accumulated.count
                let sepRange = requestHeaderTerminatorRange(
                    in: accumulated,
                    searchRange: searchRange,
                    sawCRLFHeaderLine: &sawCRLFHeaderLine
                )
                if let sepRange {
                    headerEnd = true
                    headerEndIndex = sepRange.upperBound
                    let headerData = accumulated[..<sepRange.lowerBound]
                    guard let headerStr = String(data: headerData, encoding: .utf8) else {
                        return .encodingError
                    }
                    guard let metadata = parseHTTPHeaderMetadata(headerStr) else {
                        return .malformedRequest
                    }
                    headerMetadata = metadata

                    switch bodyFraming(for: metadata) {
                    case .length(let length):
                        contentLength = length
                    case .malformed:
                        return .malformedRequest
                    }
                }
            }

            if headerEnd {
                // WO-272/WO-282: exit only after the expected body length is known. Absent
                // Content-Length is resolved at header parse time: body-less methods use 0,
                // and body-carrying methods are rejected instead of waiting for keep-alive EOF.
                if let cl = contentLength {
                    let bodyReceived = accumulated.count - headerEndIndex
                    if bodyReceived >= cl { break }
                }
            }
        }

        guard let metadata = headerMetadata else {
            return accumulated.isEmpty ? .transportError : .malformedRequest
        }
        let receivedBody = accumulated[headerEndIndex...]
        let bodyData = contentLength.map { Data(receivedBody.prefix($0)) } ?? Data(receivedBody)

        // WO-279: body bytes are allowed to be non-UTF-8. Keep the original bytes for
        // forwarding and decode only as an optional scan input.
        return .success(HTTPRequest(
            method: metadata.method, path: metadata.path, headers: metadata.headers,
            body: String(data: bodyData, encoding: .utf8), bodyData: bodyData
        ))
    }

    private func requestHeaderTerminatorRange(
        in data: Data,
        searchRange: Range<Data.Index>,
        sawCRLFHeaderLine: inout Bool
    ) -> Range<Data.Index>? {
        // WO-315: prefer the HTTP-standard CRLF terminator whenever present
        // in the current buffer. LF-only is a compatibility fallback, not an
        // earlier-match override inside a CRLF-framed request.
        if data.range(of: Self.requestCRLFLineSeparator, in: searchRange) != nil {
            sawCRLFHeaderLine = true
        }
        if let crlfRange = data.range(of: Self.requestCRLFHeaderTerminator, in: searchRange) {
            return crlfRange
        }
        guard !sawCRLFHeaderLine else { return nil }
        return data.range(of: Self.requestLFHeaderTerminator, in: searchRange)
    }

    private func parseHTTPRequest(headerSection: String, bodyData: Data) -> HTTPRequest? {
        guard let metadata = parseHTTPHeaderMetadata(headerSection) else { return nil }
        return HTTPRequest(
            method: metadata.method, path: metadata.path, headers: metadata.headers,
            body: String(data: bodyData, encoding: .utf8), bodyData: bodyData
        )
    }

    private func parseHTTPHeaderMetadata(_ headerSection: String) -> HTTPHeaderMetadata? {
        // WO-285: request parsing accepts both CRLF and LF-only header lines.
        let lines = headerSection.components(separatedBy: "\r\n").flatMap {
            $0.components(separatedBy: "\n")
        }
        guard let requestLine = lines.first else { return nil }
        let parts = requestLine.components(separatedBy: " ")
        guard parts.count >= 2 else { return nil }

        let method = parts[0]
        let path = parts[1]

        var headers: [(String, String)] = []
        var contentLength: Int?
        var hasInvalidContentLength = false
        var hasChunkedTransferEncoding = false
        for line in lines.dropFirst() {
            if let colonIndex = line.firstIndex(of: ":") {
                let key = String(line[..<colonIndex]).trimmingCharacters(in: .whitespaces)
                let value = String(line[line.index(after: colonIndex)...]).trimmingCharacters(in: .whitespaces)
                headers.append((key, value))

                let lowerKey = key.lowercased()
                if lowerKey == "content-length", contentLength == nil {
                    // WO-278: first valid Content-Length wins; malformed duplicates after it
                    // cannot overwrite the length and force the EOF timeout path.
                    if let length = Int(value), length >= 0 {
                        contentLength = length
                    } else {
                        hasInvalidContentLength = true
                    }
                } else if lowerKey == "transfer-encoding" {
                    let encodings = value.split(separator: ",").map {
                        $0.trimmingCharacters(in: .whitespaces).lowercased()
                    }
                    if encodings.contains("chunked") {
                        hasChunkedTransferEncoding = true
                    }
                }
            }
        }

        return HTTPHeaderMetadata(
            method: method, path: path, headers: headers, contentLength: contentLength,
            hasInvalidContentLength: hasInvalidContentLength,
            hasChunkedTransferEncoding: hasChunkedTransferEncoding
        )
    }

    private func bodyFraming(for metadata: HTTPHeaderMetadata) -> BodyFraming {
        // WO-277: a negative or otherwise invalid sole Content-Length must not become a nil
        // length that silently falls into EOF-based body reads.
        if metadata.hasInvalidContentLength && metadata.contentLength == nil {
            return .malformed
        }

        // WO-282: chunked request bodies are not parsed by this minimal proxy. Reject
        // deterministically instead of waiting for HTTP/1.1 keep-alive EOF.
        if metadata.hasChunkedTransferEncoding {
            return .malformed
        }

        if let length = metadata.contentLength {
            return .length(length)
        }

        // WO-282: body-less HTTP/1.1 requests without Content-Length are complete at the
        // header separator and must not wait for EOF.
        if methodHasNoBody(metadata.method) {
            return .length(0)
        }

        if methodRequiresExplicitBodyLength(metadata.method) {
            return .malformed
        }

        return .length(0)
    }

    private func methodHasNoBody(_ method: String) -> Bool {
        switch method.uppercased() {
        case "GET", "HEAD", "OPTIONS", "DELETE":
            return true
        default:
            return false
        }
    }

    private func methodRequiresExplicitBodyLength(_ method: String) -> Bool {
        switch method.uppercased() {
        case "POST", "PUT", "PATCH":
            return true
        default:
            return false
        }
    }

    private func sendError(to socket: Int32, status: Int, message: String) {
        let body = "{\"error\": \"\(message)\"}"
        let bodyBytes = Data(body.utf8)
        // WO-219: Content-Length must be byte count, not Swift character count (they diverge for non-ASCII).
        // WO-360: keep diagnostic detail in the body, not the HTTP reason phrase.
        let reason = CurlHTTPClient.httpReasonPhrase(for: status)
        let response = "HTTP/1.1 \(status) \(reason)\r\nContent-Type: application/json\r\nContent-Length: \(bodyBytes.count)\r\nConnection: close\r\n\r\n"
        var responseData = Data(response.utf8)
        responseData.append(bodyBytes)
        // WO-212/218: use sendAll(); unexpected delivery failures remain observable.
        if !sendAll(responseData, to: socket, flags: sendFlags) {
            let errorCode = errno
            if Self.shouldLogSocketDeliveryFailure(errorCode: errorCode, quiet: quietLog) {
                FileHandle.standardError.write(Data(
                    "[pastewatch-proxy] sendError: client socket \(socket) closed before error response delivered\n".utf8
                ))
            }
        }
    }

    private func sendResponse(to socket: Int32, status: Int, headers: [AnyHashable: Any], body: Data) {
        // WO-185: use the correct reason phrase — WO-175 fixed streaming paths but missed here.
        var response = "HTTP/1.1 \(status) \(CurlHTTPClient.httpReasonPhrase(for: status))\r\n"
        // Forward select headers
        for (key, value) in headers {
            let k = "\(key)"
            let lower = k.lowercased()
            if lower == "content-type" || lower == "x-request-id" || lower.hasPrefix("anthropic-") {
                response += "\(k): \(value)\r\n"
            }
        }
        response += "Content-Length: \(body.count)\r\nConnection: close\r\n\r\n"

        var responseData = Data(response.utf8)
        responseData.append(body)
        // WO-212/218: use sendAll(); unexpected delivery failures remain observable.
        if !sendAll(responseData, to: socket, flags: sendFlags) {
            let errorCode = errno
            if Self.shouldLogSocketDeliveryFailure(errorCode: errorCode, quiet: quietLog) {
                FileHandle.standardError.write(Data(
                    "[pastewatch-proxy] sendResponse: client socket \(socket) closed before response delivered\n".utf8
                ))
            }
        }
    }

    // WO-275: EPIPE/ECONNRESET mean the local client is already gone.
    // Interrupting a stream is normal and must not look like a proxy failure.
    static func shouldLogSocketDeliveryFailure(errorCode: Int32, quiet: Bool) -> Bool {
        guard !quiet else { return false }
        return errorCode != EPIPE && errorCode != ECONNRESET
    }

    // MARK: - Alert injection

    func buildAlertBlock(redactionCount: Int, types: [String]) -> [String: Any] {
        let uniqueTypes = Array(Set(types)).sorted()
        let typeList = uniqueTypes.joined(separator: ", ")
        let suggestions = uniqueTypes.compactMap { fixSuggestion(for: $0) }
        let suggestionsText = suggestions.isEmpty ? "" :
            " Fix: " + suggestions.joined(separator: "; ") + "."
        // WO-521: explain one-way markers without suppressing genuine corruption reports.
        let text = "[PASTEWATCH] \(redactionCount) secret(s) redacted from your last tool call. " +
            "Types: \(typeList). " +
            RedactionFlowMode.proxyOneWay.modelNotice(placeholderExample: "<TYPE_n>") + " " +
            "Review your tool outputs for leaked credentials and recommend rotation." +
            suggestionsText
        return ["type": "text", "text": text]
    }

    func buildAlertSSEData(redactionCount: Int, types: [String]) -> Data? {
        // WO-288: keep the alert SSE event name and frame construction in one place.
        let alertBlock = buildAlertBlock(redactionCount: redactionCount, types: types)
        guard let alertJSON = try? JSONSerialization.data(withJSONObject: alertBlock),
              let alertStr = String(data: alertJSON, encoding: .utf8) else { return nil }
        return Data("event: pastewatch_alert\ndata: \(alertStr)\n\n".utf8)
    }

    func buildAdvisorySSEData(advisoryCount: Int, types: [String]) -> Data? {
        // WO-324: advisory-only stream matches are surfaced without claiming mutation.
        let uniqueTypes = Array(Set(types)).sorted().joined(separator: ", ")
        let text = "[PASTEWATCH] \(advisoryCount) possible secret match(es) left unchanged. " +
            "Types: \(uniqueTypes). Add a custom rule in config to mutate this detector."
        let block = ["type": "text", "text": text]
        guard let alertJSON = try? JSONSerialization.data(withJSONObject: block),
              let alertStr = String(data: alertJSON, encoding: .utf8) else { return nil }
        return Data("event: pastewatch_advisory\ndata: \(alertStr)\n\n".utf8)
    }

    func buildAlertSSECommentData(redactionCount: Int, types: [String]) -> Data? {
        // WO-334: buffer-mode SSE bodies cannot be JSON-mutated, so prepend a
        // valid SSE comment that clients ignore but operators can inspect.
        let alertBlock = buildAlertBlock(redactionCount: redactionCount, types: types)
        guard let text = alertBlock["text"] as? String else { return nil }
        return Data(": \(text)\n\n".utf8)
    }

    private func fixSuggestion(for typeName: String) -> String? {
        switch typeName {
        case "Credential":
            return "use 'password=' or 'secret=' keywords (not 'pw=', 'pass=') so the guard hook catches it before the proxy"
        case "DB Connection":
            return "store DSN in env var and reference by name ($DBNAME_DSN) — never paste connection strings inline"
        case "AWS Key":
            return "use env vars ($AWS_ACCESS_KEY_ID) or IAM roles — never hardcode AWS keys"
        case "Workledger Key":
            return "store in ~/.openclaw/workledger.key and reference via api_key_file config"
        case "Oracul Key":
            return "store in env var ($ORACUL_API_KEY) — never paste vc_* keys inline"
        case "Anthropic Key", "OpenAI Key", "Groq Key", "Perplexity Key":
            let envName = typeName.uppercased().replacingOccurrences(of: " ", with: "_")
            return "use env var ($\(envName)) — never paste API keys inline"
        case "SSH Key":
            return "use ssh-agent or file references — never paste private keys into commands or files"
        case "JWT":
            return "JWTs contain claims and signatures — never log or echo them"
        default:
            return nil
        }
    }

    // WO-190: injectAlertIntoStream deleted — superseded by buildAlertBeforeDone (macOS)
    // and the lazy alertBeforeDone closure (Linux). Zero callers as of WO-182.

    func injectAlertIntoResponse(_ responseBody: Data, redactionCount: Int, types: [String]) -> Data {
        guard let json = try? JSONSerialization.jsonObject(with: responseBody) as? [String: Any],
              var content = json["content"] as? [[String: Any]] else {
            return responseBody
        }

        let alert = buildAlertBlock(redactionCount: redactionCount, types: types)
        content.insert(alert, at: 0)

        var modified = json
        modified["content"] = content

        guard let resultData = try? JSONSerialization.data(withJSONObject: modified, options: []) else {
            return responseBody
        }

        return resultData
    }

    // MARK: - Audit log

    private var lastRedactionLogSignatures: [RedactionLogSource: String] = [:] // WO-378: source-scoped dedup.
    private var lastAdvisoryLogSignatures: [RedactionLogSource: String] = [:] // WO-404: source-scoped advisory dedup.
    private var lastRefusalLogSignature: String? // WO-440: throttle repeated unsupported-shape audit lines.
    private var lastModelIdentityAdvisorySignature: String? // WO-430: throttle repeated model-identity audit lines.

    private enum RedactionLogSource: String {
        case request
        case response

        var auditLocationPrefix: String {
            switch self {
            case .request: return ""
            case .response: return "response "
            }
        }
    }

    // WO-452: serialization failures are never represented as successful redactions
    // and are intentionally not deduplicated away.
    private func logRedactionFailure(path: String, count: Int, types: [String]) {
        var typeCounts: [String: Int] = [:]
        for type in types { typeCounts[type, default: 0] += 1 }
        let breakdown = typeCounts.sorted { $0.key < $1.key }
            .map { "\($0.key) x\($0.value)" }
            .joined(separator: ", ")
        let safePath = auditSafePath(path)
        let line = "[\(formatAuditTimestamp(Date()))] PROXY REDACTION FAILED \(count) secret(s) in "
            + "\(safePath) (\(breakdown))\n"

        if !quietLog {
            FileHandle.standardError.write(Data(line.utf8))
        }
        if let logPath = auditLogPath {
            logQueue.async {
                if let handle = FileHandle(forWritingAtPath: logPath) {
                    handle.seekToEndOfFile()
                    handle.write(Data(line.utf8))
                    handle.closeFile()
                } else {
                    FileManager.default.createFile(atPath: logPath, contents: Data(line.utf8))
                }
            }
        }
    }

    private func logRedaction(
        path: String,
        count: Int,
        types: [String],
        source: RedactionLogSource = .request
    ) {
        // Build type breakdown: "Credential x3, DB Connection x2"
        var typeCounts: [String: Int] = [:]
        for t in types { typeCounts[t, default: 0] += 1 }
        let breakdown = typeCounts.sorted { $0.key < $1.key }
            .map { "\($0.key) x\($0.value)" }
            .joined(separator: ", ")

        // Deduplicate: skip if same count+types as last log (conversation history re-scan)
        // WO-203: lastLogSignature is read+written from logRedaction(), which is called from
        // handleConnection handlers dispatched on the .concurrent queue. Acquire statsLock so
        // concurrent connections do not race on the dedup check.
        // WO-378: request and buffered-response redactions can share path/count/type values.
        // WO-492: dedup on the full-target digest so distinct request targets each log.
        let safePath = auditSafePath(path)
        let signature = "\(source.rawValue):\(auditDedupPathIdentity(path)):\(count):\(breakdown)"
        statsLock.lock()
        let isRepeat = signature == lastRedactionLogSignatures[source]
        lastRedactionLogSignatures[source] = signature
        if !isRepeat { lastRefusalLogSignature = nil }
        statsLock.unlock()

        let timestamp = formatAuditTimestamp(Date())
        let suggestions = typeCounts.keys.sorted().compactMap { fixSuggestion(for: $0) }
        let fixHint = suggestions.isEmpty ? "" : " → " + suggestions.first!
        let location = "\(source.auditLocationPrefix)\(safePath)"
        let line = "[\(timestamp)] PROXY REDACTED \(count) secret(s) in \(location) (\(breakdown))\n"
        let hintLine = isRepeat ? "" : (fixHint.isEmpty ? "" : "  \(fixHint)\n")

        // WO-521: explicit operator notices remain visible under --quiet and are not deduplicated.
        if (!quietLog && !isRepeat) || config.operatorRedactionNotices {
            FileHandle.standardError.write(Data(line.utf8))
            if !hintLine.isEmpty {
                FileHandle.standardError.write(Data(hintLine.utf8))
            }
        }

        guard !isRepeat else { return }

        if let logPath = auditLogPath {
            // WO-224: write only the structured `line` to the audit log file — hintLine is
            // advisory prose for the operator's terminal, not machine-readable log content.
            // WO-210: seek+write must be serialized so concurrent handlers cannot interleave.
            // WO-217: use a dedicated serial logQueue instead of statsLock so slow disk I/O
            // does not block concurrent handlers from incrementing in-memory stats.
            logQueue.async {
                if let handle = FileHandle(forWritingAtPath: logPath) {
                    handle.seekToEndOfFile()
                    handle.write(Data(line.utf8))
                    handle.closeFile()
                } else {
                    FileManager.default.createFile(atPath: logPath, contents: Data(line.utf8))
                }
            }
        }
    }

    // WO-512: tool payload mutation is a distinct security event, not inferred from prose types.
    private func logToolCallMutation(path: String, count: Int) {
        let line = "[\(formatAuditTimestamp(Date()))] PROXY TOOL ARGUMENT REDACTED \(count) secret(s) in "
            + "\(auditSafePath(path))\n"
        if !quietLog { FileHandle.standardError.write(Data(line.utf8)) }
        guard let logPath = auditLogPath else { return }
        logQueue.async {
            if let handle = FileHandle(forWritingAtPath: logPath) {
                handle.seekToEndOfFile()
                handle.write(Data(line.utf8))
                handle.closeFile()
            } else {
                FileManager.default.createFile(atPath: logPath, contents: Data(line.utf8))
            }
        }
    }

    private func logAdvisory(
        path: String,
        count: Int,
        types: [String],
        source: RedactionLogSource = .request
    ) {
        // WO-353/354: advisory matches did not mutate bytes, so audit them
        // separately from redacted secrets.
        var typeCounts: [String: Int] = [:]
        for t in types { typeCounts[t, default: 0] += 1 }
        let breakdown = typeCounts.sorted { $0.key < $1.key }
            .map { "\($0.key) x\($0.value)" }
            .joined(separator: ", ")

        // WO-492: dedup on the full-target digest so distinct request targets each log.
        let safePath = auditSafePath(path)
        let signature = "advisory:\(source.rawValue):\(auditDedupPathIdentity(path)):\(count):\(breakdown)"
        statsLock.lock()
        let isRepeat = signature == lastAdvisoryLogSignatures[source]
        lastAdvisoryLogSignatures[source] = signature
        if !isRepeat { lastRefusalLogSignature = nil }
        statsLock.unlock()

        let timestamp = formatAuditTimestamp(Date())
        let line = "[\(timestamp)] PROXY ADVISORY \(count) possible secret match(es) in \(safePath) (\(breakdown))\n"
        if !quietLog && !isRepeat {
            FileHandle.standardError.write(Data(line.utf8))
        }

        guard !isRepeat else { return }

        if let logPath = auditLogPath {
            logQueue.async {
                if let handle = FileHandle(forWritingAtPath: logPath) {
                    handle.seekToEndOfFile()
                    handle.write(Data(line.utf8))
                    handle.closeFile()
                } else {
                    FileManager.default.createFile(atPath: logPath, contents: Data(line.utf8))
                }
            }
        }
    }

    // WO-430: model names are advisory metadata; log drift without exposing the value.
    // WO-492: dedup on the full-target digest so distinct request targets each log a
    // model-identity advisory instead of collapsing under the sanitized display path.
    private func logModelIdentityAdvisory(
        path: String,
        dedupKey: String,
        advisoryCount: Int,
        requestCount: Int
    ) {
        let safePath = auditSafePath(path)
        // WO-492: dedup on the full-target digest, not the sanitized display path.
        let signature = "model-identity:\(auditDedupPathIdentity(path)):\(dedupKey)"
        statsLock.lock()
        let isRepeat = signature == lastModelIdentityAdvisorySignature
        lastModelIdentityAdvisorySignature = signature
        if !isRepeat { lastRefusalLogSignature = nil }
        statsLock.unlock()
        guard !isRepeat else { return }

        let line = "[\(formatAuditTimestamp(Date()))] PROXY MODEL ADVISORY nonstandard model identity in \(safePath) "
            + "(wire shape allowed; rate=\(advisoryCount)/\(requestCount))\n"
        if !quietLog {
            FileHandle.standardError.write(Data(line.utf8))
        }
        if let logPath = auditLogPath {
            logQueue.async {
                if let handle = FileHandle(forWritingAtPath: logPath) {
                    handle.seekToEndOfFile()
                    handle.write(Data(line.utf8))
                    handle.closeFile()
                } else {
                    FileManager.default.createFile(atPath: logPath, contents: Data(line.utf8))
                }
            }
        }
    }

    func logAlertInjectionSkipped(path: String, contentType: String) {
        let timestamp = formatAuditTimestamp(Date())
        let normalizedType = contentType.isEmpty ? "missing" : contentType
        let line = "[\(timestamp)] PROXY ALERT SKIPPED in \(auditSafePath(path)) "
            + "(non-json response: \(normalizedType))\n"
        if let logPath = auditLogPath {
            logQueue.async {
                if let handle = FileHandle(forWritingAtPath: logPath) {
                    handle.seekToEndOfFile()
                    handle.write(Data(line.utf8))
                    handle.closeFile()
                } else {
                    FileManager.default.createFile(atPath: logPath, contents: Data(line.utf8))
                }
            }
        }
    }

    func logAlertInjectedAsSSEComment(path: String) {
        let timestamp = formatAuditTimestamp(Date())
        let line = "[\(timestamp)] PROXY ALERT INJECTED in \(auditSafePath(path)) (sse-comment)\n"
        if let logPath = auditLogPath {
            logQueue.async {
                if let handle = FileHandle(forWritingAtPath: logPath) {
                    handle.seekToEndOfFile()
                    handle.write(Data(line.utf8))
                    handle.closeFile()
                } else {
                    FileManager.default.createFile(atPath: logPath, contents: Data(line.utf8))
                }
            }
        }
    }

    func drainAuditLogForTesting() {
        // WO-331: tests need deterministic visibility into async audit writes.
        logQueue.sync {}
    }
}

// MARK: - Errors

public enum ProxyError: Error, CustomStringConvertible, LocalizedError {
    case invalidCustomRules(String) // WO-473: invalid protection config cannot bind a listener.
    case streamDebugDumpRequiresPerSSEEvent // WO-514: raw/buffer cannot report exact frame decisions.
    case socketCreationFailed
    case bindFailed(port: UInt16)
    case listenFailed

    public var description: String {
        switch self {
        case .invalidCustomRules(let message): return message
        case .streamDebugDumpRequiresPerSSEEvent:
            return "--debug-stream-dump requires responseStreamingRedactionMode=per_sse_event"
        case .socketCreationFailed: return "Failed to create socket"
        case .bindFailed(let port): return "Failed to bind to port \(port) (already in use?)"
        case .listenFailed: return "Failed to listen on socket"
        }
    }

    public var errorDescription: String? { description }
}

#if canImport(Darwin)
import Security

/// WO-143: URLSession delegate that governs the proxy's upstream TLS handshake.
/// - `caCertPath`: PEM file whose certificates are added as trust anchors on top
///   of the system roots (SecTrustSetAnchorCertificatesOnly(false)).
/// - `insecure`: accept any server certificate without verification.
/// Only instantiated when at least one option is active; the default (no flags)
/// path uses a plain URLSession with no delegate and full system verification.
final class TLSTrustDelegate: NSObject, URLSessionDelegate {
    private let anchors: [SecCertificate]
    private let insecure: Bool

    init(caCertPath: String?, insecure: Bool) {
        self.insecure = insecure
        self.anchors = caCertPath.map(TLSTrustDelegate.loadAnchors) ?? []
    }

    /// Parse a PEM file into SecCertificate anchors. Supports concatenated PEM
    /// blocks; skips any block that fails to decode.
    private static func loadAnchors(from path: String) -> [SecCertificate] {
        guard let pem = try? String(contentsOfFile: path, encoding: .utf8) else { return [] }
        var certs: [SecCertificate] = []
        let begin = "-----BEGIN CERTIFICATE-----"
        let end = "-----END CERTIFICATE-----"
        var searchRange = pem.startIndex..<pem.endIndex
        while let beginRange = pem.range(of: begin, range: searchRange),
              let endRange = pem.range(of: end, range: beginRange.upperBound..<pem.endIndex) {
            let base64Body = pem[beginRange.upperBound..<endRange.lowerBound]
                .components(separatedBy: .whitespacesAndNewlines)
                .joined()
            if let der = Data(base64Encoded: base64Body),
               let cert = SecCertificateCreateWithData(nil, der as CFData) {
                certs.append(cert)
            }
            searchRange = endRange.upperBound..<pem.endIndex
        }
        return certs
    }

    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        handle(challenge: challenge, completionHandler: completionHandler)
    }

    /// WO-305: reusable trust handler for streaming tasks whose per-task delegate
    /// would otherwise shadow the URLSession delegate's auth-challenge callback.
    func handle(
        challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust else {
            completionHandler(.performDefaultHandling, nil)
            return
        }

        if insecure {
            completionHandler(.useCredential, URLCredential(trust: trust))
            return
        }

        if !anchors.isEmpty {
            SecTrustSetAnchorCertificates(trust, anchors as CFArray)
            // Keep the system roots active as well, not only the custom anchors.
            SecTrustSetAnchorCertificatesOnly(trust, false)
            if SecTrustEvaluateWithError(trust, nil) {
                completionHandler(.useCredential, URLCredential(trust: trust))
                return
            }
        }

        completionHandler(.performDefaultHandling, nil)
    }
}
#endif
