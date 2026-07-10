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

/// WO-267: while waiting on a non-streaming URLSession completion, poll shutdown
/// state so stop() cannot wait for the full 600s ceiling if a task misses cancellation.
let proxyNonStreamShutdownPollMilliseconds = 100

/// Minimum upstream bytes-per-second for curl's speed-based idle detection.
let curlMinSpeedBytesPerSecond = 1

/// Idle window for curl's --speed-time: upstream must send at least 1 byte/s
/// within this window or the request is aborted.
let curlSpeedTimeSeconds = 60

/// Large maximum time for curl (non-streaming path). Zero = no cap.
let curlMaxTimeSeconds = 600

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
    private let severity: Severity
    private let auditLogPath: String?
    public private(set) var injectAlert: Bool
    private let quietLog: Bool
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
    private let iso8601Formatter: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter
    }()
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

    public struct RedactionStats {
        public var requestsProcessed: Int = 0
        public var requestsRedacted: Int = 0
        public var secretsRedacted: Int = 0
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
        severity: Severity = .high,
        auditLogPath: String? = nil,
        injectAlert: Bool = true,
        quietLog: Bool = false,
        caCertPath: String? = nil,
        insecureTLS: Bool = false
    ) {
        self.port = port
        self.upstream = upstream
        self.forwardProxy = forwardProxy
        self.config = config
        self.severity = severity
        self.auditLogPath = auditLogPath
        self.injectAlert = injectAlert
        self.quietLog = quietLog
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

    public static func bufferModeWarning(config: PastewatchConfig, quiet: Bool) -> String? {
        // WO-316: buffer mode is a compatibility path; response-body redaction is
        // not yet implemented there, so surface the limitation at startup.
        guard !quiet, config.responseStreamingRedactionMode == .buffer else { return nil }
        return "WARNING: responseStreamingRedactionMode=buffer does not scan buffered response bodies\n"
    }

    private static func makeSessionConfiguration(forwardProxy: URL?) -> URLSessionConfiguration {
        let sessionConfig = URLSessionConfiguration.default
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

    /// Start the proxy server. Blocks until stop() is called.
    public func start(onListening: (() -> Void)? = nil) throws {
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
                recordConnectionStarted()
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
        guard running else { return false }
        if admissionSlots.wait(timeout: .now()) == .success {
            guard running else {
                admissionSlots.signal()
                return false
            }
            return true
        }

        recordQueuedConnection(delta: 1)
        defer { recordQueuedConnection(delta: -1) }
        let deadline = DispatchTime.now() + .milliseconds(proxyAdmissionQueueTimeoutMilliseconds)
        guard admissionSlots.wait(timeout: deadline) == .success else {
            if running {
                recordRejectedConnection()
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
                sendError(to: clientSocket, status: 503, message: "Proxy admission timeout")
            }
            return false
        }

        guard running else {
            admissionSlots.signal()
            return false
        }
        return true
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

        // Only scan POST /v1/messages (the endpoint that carries tool results)
        var processedBody = parsed.body
        var processedBodyData = parsed.bodyData
        var redactionCount = 0
        var redactedTypes: [String] = []
        var shouldBlockNonUTF8Forwarding = false
        if parsed.method == "POST" && parsed.path.contains("/v1/messages") {
            if let body = parsed.body {
                let result = scanAndRedactBody(body)
                processedBody = result.body
                processedBodyData = Data(result.body.utf8)
                redactionCount = result.redacted
                redactedTypes = result.redactedTypes
            } else {
                // WO-296: scan a lossy text view of non-UTF-8 bodies for audit
                // coverage, then fail closed if a secret is detected.
                let result = scanNonUTF8BodyForRedactions(processedBodyData)
                redactionCount = result.redacted
                redactedTypes = result.redactedTypes
                shouldBlockNonUTF8Forwarding = result.shouldBlockForwarding
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
            shouldBlockNonUTF8Forwarding: shouldBlockNonUTF8Forwarding,
            countForwardedRedaction: !deferForwardedRedactionStats
        )

        if shouldLogBodyRedactionBeforeForwarding(
            redactionCount: redactionCount,
            requestWantsStream: requestWantsStream,
            shouldBlockNonUTF8Forwarding: shouldBlockNonUTF8Forwarding
        ) {
            logRedaction(path: parsed.path, count: redactionCount, types: redactedTypes)
        }
        if shouldBlockNonUTF8Forwarding {
            // WO-296: /v1/messages bodies are UTF-8 JSON by contract; if a lossy
            // scan finds a secret in malformed bytes, fail closed instead of
            // forwarding the original credential upstream.
            sendError(to: clientSocket, status: 400, message: "Bad Request")
            return
        }

        // Platform dispatch: returns a BufferedResponse for the convergence tail,
        // or nil when the response was fully handled (streamed or error sent to client).
        let ctx = ForwardContext(
            parsed: parsed, upstreamURL: upstreamURL, forwardHeaders: forwardHeaders,
            requestWantsStream: requestWantsStream, redactionCount: redactionCount,
            redactedTypes: redactedTypes, processedBodyData: processedBodyData, clientSocket: clientSocket
        )
        guard let buffered = forwardRequest(ctx) else { return }

        var finalBody = buffered.body
        if redactionCount > 0 && injectAlert {
            // WO-331: JSON response alert injection must not silently no-op on raw SSE bodies.
            if shouldInjectAlertIntoBufferedResponse(headers: buffered.headers) {
                finalBody = injectAlertIntoResponse(
                    buffered.body,
                    redactionCount: redactionCount,
                    types: redactedTypes
                )
            } else if shouldInjectAlertIntoBufferedSSEResponse(headers: buffered.headers),
                      let comment = buildAlertSSECommentData(redactionCount: redactionCount, types: redactedTypes) {
                // WO-334: buffered SSE responses cannot use JSON alert injection, but
                // an SSE comment preserves protocol framing and operator-visible alert bytes.
                var bodyWithComment = comment
                bodyWithComment.append(buffered.body)
                finalBody = bodyWithComment
                logAlertInjectedAsSSEComment(path: parsed.path)
            } else {
                logAlertInjectionSkipped(path: parsed.path, contentType: responseContentType(buffered.headers))
            }
        }

        sendResponse(to: clientSocket, status: buffered.status, headers: buffered.headers, body: finalBody)
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
        guard let curlResponse = CurlHTTPClient.execute(
            method: ctx.parsed.method, url: ctx.upstreamURL, headers: ctx.forwardHeaders,
            body: ctx.processedBodyData, caCertPath: caCertPath,
            insecure: insecureTLS, streaming: shouldStream,
            clientSocket: ctx.clientSocket, sendFlags: sendFlags,
            streamingRedactionMode: streamingMode,
            proxyConfig: config, proxySeverity: severity, alertBeforeDone: alertBeforeDone
        ) else {
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
            recordLinuxStreamStats(
                path: ctx.parsed.path, bodyCount: ctx.redactionCount, bodyTypes: ctx.redactedTypes,
                streamCount: curlResponse.streamRedactionCount,
                streamTypes: curlResponse.streamRedactionTypes
            )
            return nil
        }
        return BufferedResponse(
            status: curlResponse.statusCode,
            headers: curlResponse.headers as [AnyHashable: Any],
            body: curlResponse.body
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

    private func recordLinuxStreamStats(
        path: String, bodyCount: Int, bodyTypes: [String],
        streamCount: Int, streamTypes: [String]
    ) {
        let totalCount = bodyCount + streamCount
        let totalTypes = bodyTypes + streamTypes
        if streamCount > 0 {
            statsLock.lock()
            // WO-174: only increment requestsRedacted when body scan did NOT already count this.
            if bodyCount == 0 { stats.requestsRedacted += 1 }
            stats.secretsRedacted += streamCount
            statsLock.unlock()
        }
        // WO-184: log combined totals (body log suppressed above for streaming).
        if totalCount > 0 {
            logRedaction(path: path, count: totalCount, types: totalTypes)
        }
    }
    #endif

    // MARK: - Request scanning

    private struct ScanResult {
        let body: String
        let redacted: Int
        let redactedTypes: [String]
    }

    struct RedactionDetectionSummary {
        let redacted: Int
        let redactedTypes: [String]
        let shouldBlockForwarding: Bool
    }

    private func scanAndRedactBody(_ body: String) -> ScanResult {
        guard let data = body.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return ScanResult(body: body, redacted: 0, redactedTypes: [])
        }

        var redacted = 0
        var types: [String] = []
        let processed = redactContentArray(json, redacted: &redacted, types: &types)

        guard redacted > 0,
              let resultData = try? JSONSerialization.data(withJSONObject: processed, options: []),
              let resultString = String(data: resultData, encoding: .utf8) else {
            return ScanResult(body: body, redacted: 0, redactedTypes: [])
        }

        return ScanResult(body: resultString, redacted: redacted, redactedTypes: types)
    }

    func scanNonUTF8BodyForRedactions(_ bodyData: Data) -> RedactionDetectionSummary {
        guard !bodyData.isEmpty else {
            return RedactionDetectionSummary(redacted: 0, redactedTypes: [], shouldBlockForwarding: false)
        }
        // swiftlint:disable:next optional_data_string_conversion
        let lossyBody = String(decoding: bodyData, as: UTF8.self)
        let matches = DetectionRules.scan(lossyBody, config: config)
        let filtered = matches.filter { $0.effectiveSeverity >= severity }
        return RedactionDetectionSummary(
            redacted: filtered.count,
            redactedTypes: filtered.map { $0.displayName },
            shouldBlockForwarding: !filtered.isEmpty
        )
    }

    /// Walk the messages array looking for tool_result content to scan.
    private func redactContentArray(_ json: [String: Any], redacted: inout Int, types: inout [String]) -> [String: Any] {
        var result = json

        guard var messages = json["messages"] as? [[String: Any]] else {
            return result
        }

        for i in 0..<messages.count {
            let msg = messages[i]
            guard let role = msg["role"] as? String, role == "user" else { continue }

            if let content = msg["content"] as? [[String: Any]] {
                var newContent: [[String: Any]] = []
                for block in content {
                    if let type = block["type"] as? String, type == "tool_result",
                       let blockContent = block["content"] as? String {
                        let matches = DetectionRules.scan(blockContent, config: config)
                        let filtered = matches.filter { $0.effectiveSeverity >= severity }
                        if !filtered.isEmpty {
                            let obfuscated = Obfuscator.obfuscate(blockContent, matches: filtered)
                            var newBlock = block
                            newBlock["content"] = obfuscated
                            newContent.append(newBlock)
                            redacted += filtered.count
                            types.append(contentsOf: filtered.map { $0.displayName })
                        } else {
                            newContent.append(block)
                        }
                    } else if let type = block["type"] as? String, type == "tool_result",
                              let nestedContent = block["content"] as? [[String: Any]] {
                        // Content can be array of {type: "text", text: "..."} blocks
                        var newNested: [[String: Any]] = []
                        for nested in nestedContent {
                            if let nType = nested["type"] as? String, nType == "text",
                               let text = nested["text"] as? String {
                                let matches = DetectionRules.scan(text, config: config)
                                let filtered = matches.filter { $0.effectiveSeverity >= severity }
                                if !filtered.isEmpty {
                                    let obfuscated = Obfuscator.obfuscate(text, matches: filtered)
                                    var newNest = nested
                                    newNest["text"] = obfuscated
                                    newNested.append(newNest)
                                    redacted += filtered.count
                                    types.append(contentsOf: filtered.map { $0.displayName })
                                } else {
                                    newNested.append(nested)
                                }
                            } else {
                                newNested.append(nested)
                            }
                        }
                        var newBlock = block
                        newBlock["content"] = newNested
                        newContent.append(newBlock)
                    } else {
                        newContent.append(block)
                    }
                }
                messages[i]["content"] = newContent
            }
        }

        result["messages"] = messages
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
        requestWantsStream: Bool,
        shouldBlockNonUTF8Forwarding: Bool
    ) -> Bool {
        guard redactionCount > 0 else { return false }
        // WO-304/WO-307: if malformed bytes caused a fail-closed request, no
        // streaming relay will run later, so the request-body redaction must be
        // audited before returning 400.
        if shouldBlockNonUTF8Forwarding {
            return true
        }

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
        shouldBlockNonUTF8Forwarding: Bool,
        countForwardedRedaction: Bool = true
    ) {
        // WO-317: a fail-closed malformed body is audited but was never forwarded
        // with redacted bytes, so it must not inflate requestsRedacted/secretsRedacted.
        statsLock.lock()
        stats.requestsProcessed += 1
        if redactionCount > 0 && !shouldBlockNonUTF8Forwarding && countForwardedRedaction {
            stats.requestsRedacted += 1
            stats.secretsRedacted += redactionCount
        }
        statsLock.unlock()
    }

    func recordForwardedBodyRedactionStats(redactionCount: Int) {
        guard redactionCount > 0 else { return }
        statsLock.lock()
        stats.requestsRedacted += 1
        stats.secretsRedacted += redactionCount
        statsLock.unlock()
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

    func formatAuditTimestamp(_ date: Date) -> String {
        iso8601Formatter.string(from: date)
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
            sendError(to: clientSocket, status: 503, message: "Service Unavailable")
            return
        }
        recordForwardedBodyRedactionStats(redactionCount: redactionCount)

        let relay = SSEStreamRelay(
            clientSocket: clientSocket,
            sendFlags: sendFlags,
            redactionMode: mode,
            config: config,
            severity: severity,
            idleTimeoutSeconds: proxyStreamIdleTimeoutSeconds,
            tlsChallengeHandler: tlsTrustDelegate.map { delegate in
                { _, challenge, completionHandler in
                    delegate.handle(challenge: challenge, completionHandler: completionHandler)
                }
            }
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
        let totalCount = redactionCount + relay.streamRedactionCount
        let totalTypes = redactedTypes + relay.streamRedactionTypes
        // WO-197: gate on totalCount (body + stream) so body-only streaming redactions
        // (stream returns 0 but body had secrets) are not silently unlogged.
        if totalCount > 0 {
            if relay.streamRedactionCount > 0 {
                statsLock.lock()
                // WO-181: mirror WO-174 — only increment requestsRedacted when the body scan did
                // NOT already count this request (redactionCount == 0). Body + stream = 1 request.
                if redactionCount == 0 {
                    stats.requestsRedacted += 1
                }
                stats.secretsRedacted += relay.streamRedactionCount
                statsLock.unlock()
            }
            logRedaction(path: request.url?.path ?? "/", count: totalCount, types: totalTypes)
        }
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
        let response = "HTTP/1.1 \(status) \(message)\r\nContent-Type: application/json\r\nContent-Length: \(bodyBytes.count)\r\nConnection: close\r\n\r\n"
        var responseData = Data(response.utf8)
        responseData.append(bodyBytes)
        // WO-212/218: use sendAll(); log to stderr on delivery failure so the failure is observable.
        if !sendAll(responseData, to: socket, flags: sendFlags) {
            FileHandle.standardError.write(Data("[pastewatch-proxy] sendError: client socket \(socket) closed before error response delivered\n".utf8))
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
        // WO-212/218: use sendAll(); log to stderr on delivery failure so the failure is observable.
        if !sendAll(responseData, to: socket, flags: sendFlags) {
            FileHandle.standardError.write(Data("[pastewatch-proxy] sendResponse: client socket \(socket) closed before response delivered\n".utf8))
        }
    }

    // MARK: - Alert injection

    func buildAlertBlock(redactionCount: Int, types: [String]) -> [String: Any] {
        let uniqueTypes = Array(Set(types)).sorted()
        let typeList = uniqueTypes.joined(separator: ", ")
        let suggestions = uniqueTypes.compactMap { fixSuggestion(for: $0) }
        let suggestionsText = suggestions.isEmpty ? "" :
            " Fix: " + suggestions.joined(separator: "; ") + "."
        let text = "[PASTEWATCH] \(redactionCount) secret(s) redacted from your last tool call. " +
            "Types: \(typeList). " +
            "The original values were replaced with placeholders before reaching the API. " +
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
            "Types: \(uniqueTypes). Configure an allowlist or promote the detector to critical before redacting."
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

    private var lastLogSignature = ""

    private func logRedaction(path: String, count: Int, types: [String]) {
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
        let signature = "\(count):\(breakdown)"
        statsLock.lock()
        let isRepeat = signature == lastLogSignature
        lastLogSignature = signature
        statsLock.unlock()

        let timestamp = formatAuditTimestamp(Date())
        let suggestions = typeCounts.keys.sorted().compactMap { fixSuggestion(for: $0) }
        let fixHint = suggestions.isEmpty ? "" : " → " + suggestions.first!
        let line = "[\(timestamp)] PROXY REDACTED \(count) secret(s) in \(path) (\(breakdown))\n"
        let hintLine = isRepeat ? "" : (fixHint.isEmpty ? "" : "  \(fixHint)\n")

        if !quietLog && !isRepeat {
            FileHandle.standardError.write(Data(line.utf8))
            if !hintLine.isEmpty {
                FileHandle.standardError.write(Data(hintLine.utf8))
            }
        }

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

    func logAlertInjectionSkipped(path: String, contentType: String) {
        let timestamp = formatAuditTimestamp(Date())
        let normalizedType = contentType.isEmpty ? "missing" : contentType
        let line = "[\(timestamp)] PROXY ALERT SKIPPED in \(path) (non-json response: \(normalizedType))\n"
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
        let line = "[\(timestamp)] PROXY ALERT INJECTED in \(path) (sse-comment)\n"
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

public enum ProxyError: Error, CustomStringConvertible {
    case socketCreationFailed
    case bindFailed(port: UInt16)
    case listenFailed

    public var description: String {
        switch self {
        case .socketCreationFailed: return "Failed to create socket"
        case .bindFailed(let port): return "Failed to bind to port \(port) (already in use?)"
        case .listenFailed: return "Failed to listen on socket"
        }
    }
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
