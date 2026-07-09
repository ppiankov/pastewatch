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

/// Minimum upstream bytes-per-second for curl's speed-based idle detection.
let curlMinSpeedBytesPerSecond = 1

/// Idle window for curl's --speed-time: upstream must send at least 1 byte/s
/// within this window or the request is aborted.
let curlSpeedTimeSeconds = 60

/// Large maximum time for curl (non-streaming path). Zero = no cap.
let curlMaxTimeSeconds = 600

// MARK: - ProxyServer

/// Minimal HTTP proxy that scans and redacts secrets from API request bodies.
/// Listens on localhost, forwards to upstream API after redacting sensitive data.
public final class ProxyServer {
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
    /// WO-245: cap concurrent connections so an adversarial slow upstream cannot pin an
    /// unbounded number of threads indefinitely. Each accepted connection acquires one slot;
    /// accept() blocks when the cap is reached. Set to 64 (well above any realistic workload
    /// and far below the default system thread cap, which defaults to ~512).
    private let connectionSlots = DispatchSemaphore(value: 64)
    /// WO-160: guards all mutations of `stats` from concurrent connection handlers.
    private let statsLock = NSLock()
    /// WO-217: serial queue for audit log file I/O. Decouples slow disk writes from
    /// statsLock so concurrent handlers do not serialize behind file operations.
    private let logQueue = DispatchQueue(label: "com.pastewatch.proxy.auditlog")
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
    private lazy var urlSession: URLSession = makeSession()

    public struct RedactionStats {
        public var requestsProcessed: Int = 0
        public var requestsRedacted: Int = 0
        public var secretsRedacted: Int = 0
    }

    private struct HTTPRequest {
        let method: String
        let path: String
        let headers: [(String, String)]
        let body: String
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
        let processedBody: String
        let clientSocket: Int32
    }

    /// Non-streaming buffered response returned to handleConnection for the convergence tail.
    private struct BufferedResponse {
        let status: Int
        let headers: [AnyHashable: Any]
        let body: Data
    }

    public private(set) var stats = RedactionStats()

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
    }

    private func makeSession() -> URLSession {
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
        #if canImport(Darwin)
        // WO-143: honor --ca-cert / --insecure for the upstream TLS handshake.
        // Only attach a delegate when a flag is set; otherwise behave exactly as
        // before (system trust store, no delegate).
        if caCertPath != nil || insecureTLS {
            let delegate = TLSTrustDelegate(caCertPath: caCertPath, insecure: insecureTLS)
            return URLSession(configuration: sessionConfig, delegate: delegate, delegateQueue: nil)
        }
        #endif
        return URLSession(configuration: sessionConfig)
    }

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
    public func start() throws {
        #if canImport(Darwin)
        serverSocket = socket(AF_INET, SOCK_STREAM, 0)
        #else
        serverSocket = socket(AF_INET, Int32(SOCK_STREAM.rawValue), 0)
        #endif
        guard serverSocket >= 0 else {
            throw ProxyError.socketCreationFailed
        }

        var reuse: Int32 = 1
        setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size))

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")

        let bindResult = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                bind(serverSocket, sockPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bindResult == 0 else {
            close(serverSocket)
            throw ProxyError.bindFailed(port: port)
        }

        guard listen(serverSocket, 128) == 0 else {
            close(serverSocket)
            throw ProxyError.listenFailed
        }

        running = true

        while running {
            var clientAddr = sockaddr_in()
            var clientLen = socklen_t(MemoryLayout<sockaddr_in>.size)
            let clientSocket = withUnsafeMutablePointer(to: &clientAddr) { ptr in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                    accept(serverSocket, sockPtr, &clientLen)
                }
            }

            guard clientSocket >= 0 else { continue }

            // WO-245: acquire before dispatching so we do not exceed the connection cap.
            // WO-247: re-check running after acquiring so a stale fd is not dispatched.
            // WO-253: signal() before break so the consumed slot is returned.
            // WO-255: poll with a 100ms timeout instead of blocking indefinitely.
            // A blocking wait() required stop() to signal unconditionally (WO-247), but that
            // inflated the semaphore count when accept() returned EBADF (the common shutdown
            // case) — the thread never called wait() at all, so the signal leaked. Polling
            // lets the thread notice running=false within 100ms without a phantom signal.
            var gotSlot = false
            while running {
                if connectionSlots.wait(timeout: .now() + 0.1) == .success {
                    gotSlot = true; break
                }
            }
            // WO-261: enter handlerGroup BEFORE checking running so stop()'s handlerGroup.wait()
            // cannot drain and return while this thread is between the running check and enter().
            // handlerGroup.leave() is called below if we decide not to dispatch.
            // WO-266: invariant — gotSlot=false implies running=false was observed in the poll
            // loop above (running is monotonically false-once-set). Guard A (guard running) fires
            // first in that case, so a separate guard gotSlot branch is unreachable dead code.
            if gotSlot { handlerGroup.enter() }
            guard running else {
                if gotSlot { handlerGroup.leave(); connectionSlots.signal() }
                close(clientSocket)
                break
            }
            // WO-257: [self] strong capture keeps connectionSlots alive so signal() fires
            // unconditionally even if ProxyServer is released during teardown.
            // WO-264: slots alias removed; [self] strong capture makes it redundant.
            // WO-234: handlerGroup entered above; stop() barrier-waits for all handlers
            // so logQueue.sync sees all handler-enqueued audit writes before draining.
            queue.async { [self] in
                defer { connectionSlots.signal(); handlerGroup.leave() }
                handleConnection(clientSocket)
            }
        }
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
        if fdToClose >= 0 { close(fdToClose) }

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

    // MARK: - Connection handling

    private func handleConnection(_ clientSocket: Int32) {
        defer { close(clientSocket) }

        // WO-259: SO_SNDTIMEO bounds sendAll() so a half-closed TCP client cannot keep the
        // handler alive indefinitely, which would stall handlerGroup.wait() in stop().
        // WO-265: SO_RCVTIMEO is the symmetric receive-side guard. Without it, recv() in
        // readHTTPRequest blocks forever on a client that connects but stalls mid-request,
        // also preventing handlerGroup.wait() from returning. 30 s matches SO_SNDTIMEO.
        var sendTimeout = timeval(tv_sec: 30, tv_usec: 0)
        setsockopt(clientSocket, SOL_SOCKET, SO_SNDTIMEO, &sendTimeout, socklen_t(MemoryLayout<timeval>.size))
        var recvTimeout = timeval(tv_sec: 30, tv_usec: 0)
        setsockopt(clientSocket, SOL_SOCKET, SO_RCVTIMEO, &recvTimeout, socklen_t(MemoryLayout<timeval>.size))

        guard let request = readHTTPRequest(from: clientSocket) else { return }

        guard let parsed = parseHTTPRequest(request) else {
            sendError(to: clientSocket, status: 400, message: "Bad Request")
            return
        }

        // Only scan POST /v1/messages (the endpoint that carries tool results)
        var processedBody = parsed.body
        var redactionCount = 0
        var redactedTypes: [String] = []
        if parsed.method == "POST" && parsed.path.contains("/v1/messages") {
            let result = scanAndRedactBody(parsed.body)
            processedBody = result.body
            redactionCount = result.redacted
            redactedTypes = result.redactedTypes
        }

        let upstreamURL = resolveUpstreamURL(requestTarget: parsed.path)

        var forwardHeaders: [(String, String)] = []
        for (key, value) in parsed.headers where key.lowercased() != "host" && key.lowercased() != "content-length" {
            forwardHeaders.append((key, value))
        }
        forwardHeaders.append(("Host", upstream.host ?? ""))
        if let bodyData = processedBody.data(using: .utf8) {
            forwardHeaders.append(("Content-Length", String(bodyData.count)))
        }

        let requestWantsStream = isStreamingRequest(processedBody)

        // WO-160: statsLock guards concurrent mutations from the .concurrent queue.
        statsLock.lock()
        stats.requestsProcessed += 1
        if redactionCount > 0 {
            stats.requestsRedacted += 1
            stats.secretsRedacted += redactionCount
        }
        statsLock.unlock()

        // Platform dispatch: returns a BufferedResponse for the convergence tail,
        // or nil when the response was fully handled (streamed or error sent to client).
        let ctx = ForwardContext(
            parsed: parsed, upstreamURL: upstreamURL, forwardHeaders: forwardHeaders,
            requestWantsStream: requestWantsStream, redactionCount: redactionCount,
            redactedTypes: redactedTypes, processedBody: processedBody, clientSocket: clientSocket
        )
        guard let buffered = forwardRequest(ctx) else { return }

        // WO-184/WO-189/WO-198: log body redactions at the convergence point for
        // non-streaming and buffer-mode requests.
        if redactionCount > 0 {
            logRedaction(path: parsed.path, count: redactionCount, types: redactedTypes)
        }

        var finalBody = buffered.body
        if redactionCount > 0 && injectAlert {
            finalBody = injectAlertIntoResponse(buffered.body, redactionCount: redactionCount, types: redactedTypes)
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
        upstreamRequest.httpBody = ctx.processedBody.data(using: .utf8)
        for (key, value) in ctx.forwardHeaders {
            upstreamRequest.setValue(value, forHTTPHeaderField: key)
        }
        let streamingMode = config.responseStreamingRedactionMode
        if ctx.requestWantsStream && streamingMode != "buffer" {
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
        guard semaphore.wait(timeout: .now() + proxyNonStreamTotalTimeoutSeconds) == .success else {
            sendError(to: ctx.clientSocket, status: 504, message: "Gateway Timeout")
            return nil
        }
        guard let resp = httpResponse, let data = responseData else {
            sendError(to: ctx.clientSocket, status: 502, message: "Bad Gateway")
            return nil
        }
        return BufferedResponse(status: resp.statusCode, headers: resp.allHeaderFields, body: data)
    }
    #else
    private func forwardLinuxRequest(_ ctx: ForwardContext) -> BufferedResponse? {
        // WO-192: lazy closure evaluated at [DONE] time with accumulated stream counts so
        // stream-only secrets (body-clean request) also trigger the [PASTEWATCH] alert on Linux.
        // WO-202: [weak self] guards against retain cycle if the Linux path ever becomes async.
        let alertBeforeDone = buildLinuxAlertClosure(
            redactionCount: ctx.redactionCount, redactedTypes: ctx.redactedTypes
        )
        guard let curlResponse = CurlHTTPClient.execute(
            method: ctx.parsed.method, url: ctx.upstreamURL, headers: ctx.forwardHeaders,
            body: ctx.processedBody.data(using: .utf8), caCertPath: caCertPath,
            insecure: insecureTLS, streaming: ctx.requestWantsStream,
            clientSocket: ctx.clientSocket, sendFlags: sendFlags,
            streamingRedactionMode: config.responseStreamingRedactionMode,
            proxyConfig: config, proxySeverity: severity, alertBeforeDone: alertBeforeDone
        ) else {
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
    ) -> ((_ streamCount: Int, _ streamTypes: [String]) -> Data?)? {
        guard injectAlert else { return nil }
        return { [weak self] streamCount, streamTypes in
            guard let self = self else { return nil }
            let total = redactionCount + streamCount
            guard total > 0 else { return nil }
            let totalTypes = redactedTypes + streamTypes
            let alertBlock = self.buildAlertBlock(redactionCount: total, types: totalTypes)
            guard let alertJSON = try? JSONSerialization.data(withJSONObject: alertBlock),
                  let alertStr = String(data: alertJSON, encoding: .utf8) else { return nil }
            return Data("event: pastewatch_alert\ndata: \(alertStr)\n\n".utf8)
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

    #if canImport(Darwin)
    /// Forward a streaming (SSE) response to the client socket incrementally.
    /// Uses URLSessionDataDelegate so each upstream chunk is written to the
    /// client immediately, without buffering the full response.
    private func forwardStreamingRequest(
        _ request: URLRequest,
        to clientSocket: Int32,
        redactionCount: Int,
        redactedTypes: [String],
        mode: String
    ) {
        let relay = SSEStreamRelay(
            clientSocket: clientSocket,
            sendFlags: sendFlags,
            redactionMode: mode,
            config: config,
            severity: severity,
            idleTimeoutSeconds: proxyStreamIdleTimeoutSeconds
        )

        // WO-182: inject the alert frame immediately before [DONE] so SSE consumers
        // (which stop reading at [DONE]) see it. The closure is evaluated with stream-only
        // counts at [DONE] time; body counts are captured from local scope.
        // WO-195: body counts captured directly — no relay property assignment needed.
        if injectAlert {
            relay.buildAlertBeforeDone = { [weak self] streamCount, streamTypes in
                guard let self = self else { return nil }
                let total = redactionCount + streamCount
                guard total > 0 else { return nil }
                let totalTypes = redactedTypes + streamTypes
                let alertBlock = self.buildAlertBlock(redactionCount: total, types: totalTypes)
                guard let alertJSON = try? JSONSerialization.data(withJSONObject: alertBlock),
                      let alertStr = String(data: alertJSON, encoding: .utf8) else { return nil }
                return Data("event: pastewatch_alert\ndata: \(alertStr)\n\n".utf8)
            }
        }

        relay.execute(request: request, session: urlSession)

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
    #endif

    // MARK: - Raw socket I/O

    /// Send flags: MSG_NOSIGNAL on Linux prevents per-send SIGPIPE delivery.
    /// On macOS we rely on process-level signal(SIGPIPE, SIG_IGN) set by the caller.
    #if canImport(Darwin)
    private let sendFlags: Int32 = 0
    #else
    private let sendFlags: Int32 = Int32(MSG_NOSIGNAL)
    #endif

    private func readHTTPRequest(from socket: Int32) -> String? {
        var buffer = [UInt8](repeating: 0, count: 1_048_576) // 1MB max
        var accumulated = Data()
        var contentLength = 0
        var headerEnd = false
        var headerEndIndex = 0

        while true {
            let bytesRead = recv(socket, &buffer, buffer.count, 0)
            // WO-265: EAGAIN fires when SO_RCVTIMEO expires — treat as connection error so
            // readHTTPRequest returns nil and handleConnection returns, allowing the handler's
            // defer to call handlerGroup.leave(). Plain bytesRead==0 means orderly EOF.
            if bytesRead < 0 { return nil }
            guard bytesRead > 0 else { break }
            accumulated.append(contentsOf: buffer[0..<bytesRead])

            if !headerEnd, let str = String(data: accumulated, encoding: .utf8),
               let range = str.range(of: "\r\n\r\n") {
                headerEnd = true
                headerEndIndex = str.distance(from: str.startIndex, to: range.upperBound)
                // Extract Content-Length
                let headerStr = String(str[..<range.lowerBound])
                for line in headerStr.components(separatedBy: "\r\n") where line.lowercased().hasPrefix("content-length:") {
                    let val = line.dropFirst("content-length:".count).trimmingCharacters(in: .whitespaces)
                    contentLength = Int(val) ?? 0
                }
            }

            if headerEnd {
                let bodyReceived = accumulated.count - headerEndIndex
                if bodyReceived >= contentLength { break }
            }
        }

        return String(data: accumulated, encoding: .utf8)
    }

    private func parseHTTPRequest(_ raw: String) -> HTTPRequest? {
        guard let headerEnd = raw.range(of: "\r\n\r\n") else { return nil }
        let headerSection = String(raw[..<headerEnd.lowerBound])
        let body = String(raw[headerEnd.upperBound...])

        let lines = headerSection.components(separatedBy: "\r\n")
        guard let requestLine = lines.first else { return nil }
        let parts = requestLine.components(separatedBy: " ")
        guard parts.count >= 2 else { return nil }

        let method = parts[0]
        let path = parts[1]

        var headers: [(String, String)] = []
        for line in lines.dropFirst() {
            if let colonIndex = line.firstIndex(of: ":") {
                let key = String(line[..<colonIndex]).trimmingCharacters(in: .whitespaces)
                let value = String(line[line.index(after: colonIndex)...]).trimmingCharacters(in: .whitespaces)
                headers.append((key, value))
            }
        }

        return HTTPRequest(method: method, path: path, headers: headers, body: body)
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

        let timestamp = ISO8601DateFormatter().string(from: Date())
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
