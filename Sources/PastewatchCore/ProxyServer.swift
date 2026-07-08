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
    /// WO-160: guards all mutations of `stats` from concurrent connection handlers.
    private let statsLock = NSLock()
    private var running = false
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

            queue.async { [weak self] in
                self?.handleConnection(clientSocket)
            }
        }
    }

    /// Stop the proxy server.
    public func stop() {
        running = false
        if serverSocket >= 0 {
            close(serverSocket)
            serverSocket = -1
        }
    }

    // MARK: - Connection handling

    private func handleConnection(_ clientSocket: Int32) {
        defer { close(clientSocket) }

        guard let request = readHTTPRequest(from: clientSocket) else { return }

        // Parse the request
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

        // Forward to upstream
        let upstreamURL = resolveUpstreamURL(requestTarget: parsed.path)

        // Build header list for both paths
        var forwardHeaders: [(String, String)] = []
        for (key, value) in parsed.headers where key.lowercased() != "host" && key.lowercased() != "content-length" {
            forwardHeaders.append((key, value))
        }
        forwardHeaders.append(("Host", upstream.host ?? ""))
        if let bodyData = processedBody.data(using: .utf8) {
            forwardHeaders.append(("Content-Length", String(bodyData.count)))
        }

        // Detect whether the request is a streaming call (stream:true in body).
        let requestWantsStream = isStreamingRequest(processedBody)

        // WO-160: statsLock guards concurrent mutations from the .concurrent queue.
        statsLock.lock()
        stats.requestsProcessed += 1
        if redactionCount > 0 {
            stats.requestsRedacted += 1
            stats.secretsRedacted += redactionCount
        }
        statsLock.unlock()
        #if canImport(Darwin)
        // macOS: URLSession is reliable.
        var upstreamRequest = URLRequest(url: upstreamURL)
        upstreamRequest.httpMethod = parsed.method
        upstreamRequest.httpBody = processedBody.data(using: .utf8)
        for (key, value) in forwardHeaders {
            upstreamRequest.setValue(value, forHTTPHeaderField: key)
        }

        let streamingMode = config.responseStreamingRedactionMode

        // Use URLSessionDataDelegate for streaming; buffering dataTask for non-streaming or buffer mode.
        if requestWantsStream && streamingMode != "buffer" {
            forwardStreamingRequest(
                upstreamRequest,
                to: clientSocket,
                redactionCount: redactionCount,
                redactedTypes: redactedTypes,
                mode: streamingMode
            )
            return
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
        task.resume()
        let timeout = semaphore.wait(timeout: .now() + proxyNonStreamTotalTimeoutSeconds)

        guard timeout == .success else {
            task.cancel()
            sendError(to: clientSocket, status: 504, message: "Gateway Timeout")
            return
        }

        guard let resp = httpResponse, let data = responseData else {
            sendError(to: clientSocket, status: 502, message: "Bad Gateway")
            return
        }

        let upstreamStatus = resp.statusCode
        let upstreamHeaders = resp.allHeaderFields
        let upstreamBody = data
        #else
        // Linux: URLSession/FoundationNetworking is unreliable on arm64.
        // Use Process + curl which handles TLS, chunked encoding, and streaming correctly.
        // WO-192: lazy closure evaluated at [DONE] time with accumulated stream counts so
        // stream-only secrets (body-clean request) also trigger the [PASTEWATCH] alert on Linux.
        // WO-202: [weak self] mirrors macOS closure; guards against retain cycle if the Linux
        // path ever becomes async. Closure returns nil on dealloc rather than crashing.
        let linuxAlertBeforeDone: ((_ streamCount: Int, _ streamTypes: [String]) -> Data?)? = injectAlert
            ? { [weak self] streamCount, streamTypes in
                guard let self = self else { return nil }
                let total = redactionCount + streamCount
                guard total > 0 else { return nil }
                let totalTypes = redactedTypes + streamTypes
                let alertBlock = self.buildAlertBlock(redactionCount: total, types: totalTypes)
                guard let alertJSON = try? JSONSerialization.data(withJSONObject: alertBlock),
                      let alertStr = String(data: alertJSON, encoding: .utf8) else { return nil }
                return Data("event: pastewatch_alert\ndata: \(alertStr)\n\n".utf8)
            }
            : nil
        guard let curlResponse = CurlHTTPClient.execute(
            method: parsed.method,
            url: upstreamURL,
            headers: forwardHeaders,
            body: processedBody.data(using: .utf8),
            caCertPath: caCertPath,
            insecure: insecureTLS,
            streaming: requestWantsStream,
            clientSocket: clientSocket,
            sendFlags: sendFlags,
            streamingRedactionMode: config.responseStreamingRedactionMode,
            proxyConfig: config,
            proxySeverity: severity,
            alertBeforeDone: linuxAlertBeforeDone
        ) else {
            sendError(to: clientSocket, status: 502, message: "Bad Gateway")
            return
        }

        if curlResponse.wasStreamed {
            // WO-158: wire Linux streaming redaction stats into audit log and proxy stats.
            let streamCount = curlResponse.streamRedactionCount
            let streamTypes = curlResponse.streamRedactionTypes
            let totalCount = redactionCount + streamCount
            let totalTypes = redactedTypes + streamTypes
            if streamCount > 0 {
                statsLock.lock()
                // WO-174: only increment requestsRedacted when the body scan did NOT already
                // count this request (redactionCount == 0). Body + stream secrets = 1 request.
                if redactionCount == 0 {
                    stats.requestsRedacted += 1
                }
                stats.secretsRedacted += streamCount
                statsLock.unlock()
            }
            // WO-184: log combined totals here (body log was suppressed above for streaming).
            // Guard: totalCount > 0 covers body-only, stream-only, and combined cases.
            if totalCount > 0 {
                logRedaction(path: parsed.path, count: totalCount, types: totalTypes)
            }
            // WO-182: alert was injected before [DONE] by relayBodyChunks; no trailing call.
            return
        }

        let upstreamStatus = curlResponse.statusCode
        let upstreamHeaders = curlResponse.headers as [AnyHashable: Any]
        let upstreamBody = curlResponse.body
        #endif

        // WO-184/WO-189/WO-198: log body redactions here, after both platform paths converge for
        // non-streaming and buffer-mode requests. Streaming requests return early above (macOS via
        // forwardStreamingRequest, Linux via curlResponse.wasStreamed) and log combined totals there.
        if redactionCount > 0 {
            logRedaction(path: parsed.path, count: redactionCount, types: redactedTypes)
        }

        var finalBody = upstreamBody
        if redactionCount > 0 && injectAlert {
            finalBody = injectAlertIntoResponse(upstreamBody, redactionCount: redactionCount, types: redactedTypes)
        }

        sendResponse(to: clientSocket, status: upstreamStatus, headers: upstreamHeaders, body: finalBody)
    }

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
        let response = "HTTP/1.1 \(status) \(message)\r\nContent-Type: application/json\r\nContent-Length: \(body.count)\r\nConnection: close\r\n\r\n\(body)"
        response.withCString { ptr in
            let sent = send(socket, ptr, strlen(ptr), sendFlags)
            if sent < 0 {
                // Client disconnected — nothing to do, connection will be closed by defer
                return
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
        responseData.withUnsafeBytes { ptr in
            let sent = send(socket, ptr.baseAddress, ptr.count, sendFlags)
            if sent < 0 {
                // Client disconnected mid-response — logged for observability
                let errCode = errno
                FileHandle.standardError.write(
                    Data("proxy: send failed (errno \(errCode)), client disconnected\n".utf8)
                )
            }
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
