import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

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
    private var serverSocket: Int32 = -1
    private let queue = DispatchQueue(label: "com.pastewatch.proxy", attributes: .concurrent)
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
        quietLog: Bool = false
    ) {
        self.port = port
        self.upstream = upstream
        self.forwardProxy = forwardProxy
        self.config = config
        self.severity = severity
        self.auditLogPath = auditLogPath
        self.injectAlert = injectAlert
        self.quietLog = quietLog
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
        return URLSession(configuration: sessionConfig)
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

        stats.requestsProcessed += 1
        if redactionCount > 0 {
            stats.requestsRedacted += 1
            stats.secretsRedacted += redactionCount
            logRedaction(path: parsed.path, count: redactionCount, types: redactedTypes)
        }

        // Forward to upstream
        let upstreamURL = URL(string: parsed.path, relativeTo: upstream) ?? upstream.appendingPathComponent(parsed.path)
        var upstreamRequest = URLRequest(url: upstreamURL)
        upstreamRequest.httpMethod = parsed.method
        upstreamRequest.httpBody = processedBody.data(using: .utf8)

        // Copy headers (except Host, which we set to upstream)
        for (key, value) in parsed.headers where key.lowercased() != "host" && key.lowercased() != "content-length" {
            upstreamRequest.setValue(value, forHTTPHeaderField: key)
        }
        upstreamRequest.setValue(upstream.host, forHTTPHeaderField: "Host")
        if let bodyData = processedBody.data(using: .utf8) {
            upstreamRequest.setValue(String(bodyData.count), forHTTPHeaderField: "Content-Length")
        }

        // Synchronous request to upstream
        let semaphore = DispatchSemaphore(value: 0)
        var responseData: Data?
        var httpResponse: HTTPURLResponse?

        let task = urlSession.dataTask(with: upstreamRequest) { data, response, _ in
            responseData = data
            httpResponse = response as? HTTPURLResponse
            semaphore.signal()
        }
        task.resume()
        let timeout = semaphore.wait(timeout: .now() + 120) // 2 minute upstream timeout

        guard timeout == .success else {
            task.cancel()
            sendError(to: clientSocket, status: 504, message: "Gateway Timeout")
            return
        }

        // Send response back to client
        guard let resp = httpResponse, let data = responseData else {
            sendError(to: clientSocket, status: 502, message: "Bad Gateway")
            return
        }

        var finalBody = data
        if redactionCount > 0 && injectAlert {
            finalBody = injectAlertIntoResponse(data, redactionCount: redactionCount, types: redactedTypes)
        }

        sendResponse(to: clientSocket, status: resp.statusCode, headers: resp.allHeaderFields, body: finalBody)
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
        var response = "HTTP/1.1 \(status) OK\r\n"
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
        let signature = "\(count):\(breakdown)"
        let isRepeat = signature == lastLogSignature
        lastLogSignature = signature

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
