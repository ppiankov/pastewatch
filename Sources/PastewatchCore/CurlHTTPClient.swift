import Foundation

/// HTTP client using Process + curl for Linux where URLSession/FoundationNetworking
/// is unreliable (arm64 dataTask completion handler never fires).
/// On macOS this file compiles but is not used — ProxyServer uses URLSession there.
struct CurlHTTPClient {
    struct Response {
        let statusCode: Int
        let headers: [String: String]
        let body: Data
        /// True when the response was streamed directly to a client socket (no body buffered).
        let wasStreamed: Bool

        init(statusCode: Int, headers: [String: String], body: Data, wasStreamed: Bool = false) {
            self.statusCode = statusCode
            self.headers = headers
            self.body = body
            self.wasStreamed = wasStreamed
        }
    }

    /// WO-143: build the curl TLS-trust arguments. `--insecure` (-k) wins over
    /// `--cacert` when both are supplied. Returns an empty array when neither is
    /// set (default full verification). Extracted for unit testing.
    static func tlsArgs(caCertPath: String?, insecure: Bool) -> [String] {
        if insecure {
            return ["-k"]
        }
        if let caCertPath = caCertPath {
            return ["--cacert", caCertPath]
        }
        return []
    }

    /// Execute an HTTP request via /usr/bin/curl.
    /// Returns nil if curl is not available or the process fails.
    ///
    /// For non-streaming responses: uses a large total timeout ceiling.
    /// For streaming responses: uses idle-based (--speed-time/--speed-limit) timeout
    /// so long-but-progressing streams are not killed by a fixed total cap.
    static func execute(
        method: String,
        url: URL,
        headers: [(String, String)],
        body: Data?,
        caCertPath: String? = nil,
        insecure: Bool = false,
        streaming: Bool = false,
        clientSocket: Int32 = -1,
        sendFlags: Int32 = 0,
        streamingRedactionMode: String = "per_sse_event",
        proxyConfig: PastewatchConfig = PastewatchConfig.defaultConfig,
        proxySeverity: Severity = .high
    ) -> Response? {
        let curlPath = "/usr/bin/curl"
        guard FileManager.default.fileExists(atPath: curlPath) else { return nil }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: curlPath)

        var args = buildBaseArgs(method: method, url: url, streaming: streaming)

        // WO-143: upstream TLS trust. --insecure wins over --cacert if both set.
        args.append(contentsOf: Self.tlsArgs(caCertPath: caCertPath, insecure: insecure))

        for (key, value) in headers {
            args.append(contentsOf: ["-H", "\(key): \(value)"])
        }

        // Write body to a temp file to avoid argument length limits
        var tempFile: String?
        if let body = body {
            let path = "/tmp/pw-proxy-\(ProcessInfo.processInfo.processIdentifier)-\(Thread.current.hash).body"
            FileManager.default.createFile(atPath: path, contents: body)
            args.append(contentsOf: ["-d", "@\(path)"])
            tempFile = path
        }

        process.arguments = args

        let bodyPipe = Pipe()
        let headerPipe = Pipe()
        process.standardOutput = bodyPipe
        process.standardError = headerPipe

        defer {
            if let path = tempFile {
                try? FileManager.default.removeItem(atPath: path)
            }
        }

        do {
            try process.run()
        } catch {
            return nil
        }

        if streaming && clientSocket >= 0 {
            // Streaming path: relay curl output to the client socket as it arrives.
            // Headers arrive via the headerPipe (stderr -D /dev/stderr).
            // We relay the body pipe chunks directly without buffering the whole response.
            let ctx = StreamContext(
                clientSocket: clientSocket,
                sendFlags: sendFlags,
                redactionMode: streamingRedactionMode,
                config: proxyConfig,
                severity: proxySeverity
            )
            return relayStreamingResponse(process: process, bodyPipe: bodyPipe, headerPipe: headerPipe, ctx: ctx)
        }

        process.waitUntilExit()

        guard process.terminationStatus == 0 else { return nil }

        let rawOutput = bodyPipe.fileHandleForReading.readDataToEndOfFile()
        let headerData = headerPipe.fileHandleForReading.readDataToEndOfFile()

        // Parse status code from the appended marker
        guard let outputStr = String(data: rawOutput, encoding: .utf8) else { return nil }
        let marker = "__HTTP_STATUS__"
        guard let markerRange = outputStr.range(of: marker, options: .backwards) else { return nil }

        let statusStr = String(outputStr[markerRange.upperBound...]).trimmingCharacters(in: .whitespacesAndNewlines)
        guard let statusCode = Int(statusStr) else { return nil }

        // Body is everything before the marker (minus the preceding newline)
        var bodyEnd = markerRange.lowerBound
        if bodyEnd > outputStr.startIndex {
            let before = outputStr.index(before: bodyEnd)
            if outputStr[before] == "\n" {
                bodyEnd = before
            }
        }
        let bodyStr = String(outputStr[..<bodyEnd])
        let responseBody = bodyStr.data(using: .utf8) ?? Data()

        // Parse response headers from stderr
        var responseHeaders: [String: String] = [:]
        if let headerStr = String(data: headerData, encoding: .utf8) {
            for line in headerStr.components(separatedBy: "\r\n") {
                if let colonIdx = line.firstIndex(of: ":") {
                    let key = String(line[..<colonIdx]).trimmingCharacters(in: .whitespaces)
                    let value = String(line[line.index(after: colonIdx)...]).trimmingCharacters(in: .whitespaces)
                    responseHeaders[key] = value
                }
            }
        }

        return Response(statusCode: statusCode, headers: responseHeaders, body: responseBody)
    }

    /// Relay a streaming (SSE) curl response incrementally to the client socket.
    /// Reads chunks from the body pipe as curl writes them, forwarding each immediately.
    private static func buildBaseArgs(method: String, url: URL, streaming: Bool) -> [String] {
        var args: [String] = ["-s", "-S", "-X", method, "-D", "/dev/stderr"]
        // Idle floor: fail only when no bytes arrive for the speed-time window.
        args += ["--speed-limit", String(curlMinSpeedBytesPerSecond), "--speed-time", String(curlSpeedTimeSeconds)]
        if !streaming {
            // Non-streaming: add a large total ceiling as a backstop.
            args += ["--max-time", String(curlMaxTimeSeconds)]
        }
        args += ["-w", "\n__HTTP_STATUS__%{http_code}", url.absoluteString]
        return args
    }

    struct StreamContext {
        let clientSocket: Int32
        let sendFlags: Int32
        let redactionMode: String
        let config: PastewatchConfig
        let severity: Severity
    }

    private static func relayStreamingResponse(
        process: Process,
        bodyPipe: Pipe,
        headerPipe: Pipe,
        ctx: StreamContext
    ) -> Response? {
        let clientSocket = ctx.clientSocket
        let sendFlags = ctx.sendFlags
        let redactionMode = ctx.redactionMode
        let config = ctx.config
        let severity = ctx.severity
        // Collect headers from stderr (written when curl receives the response head).
        // We read them in a background thread while streaming the body.
        var parsedHeaders: [String: String] = [:]
        var parsedStatus = 200
        let headerGroup = DispatchGroup()
        headerGroup.enter()
        DispatchQueue.global().async {
            let headerData = headerPipe.fileHandleForReading.readDataToEndOfFile()
            if let headerStr = String(data: headerData, encoding: .utf8) {
                for line in headerStr.components(separatedBy: "\r\n") {
                    if line.hasPrefix("HTTP/") {
                        let parts = line.components(separatedBy: " ")
                        if parts.count >= 2, let code = Int(parts[1]) {
                            parsedStatus = code
                        }
                    } else if let colonIdx = line.firstIndex(of: ":") {
                        let key = String(line[..<colonIdx]).trimmingCharacters(in: .whitespaces)
                        let value = String(line[line.index(after: colonIdx)...]).trimmingCharacters(in: .whitespaces)
                        parsedHeaders[key] = value
                    }
                }
            }
            headerGroup.leave()
        }

        // Build and send streaming response headers to client.
        // We send them before reading the body since curl will write them to stderr
        // before the body bytes arrive.
        let streamingHeaderStr = buildStreamingResponseHeaders(status: parsedStatus, upstreamHeaders: parsedHeaders)
        streamingHeaderStr.withCString { ptr in
            _ = send(clientSocket, ptr, strlen(ptr), sendFlags)
        }

        var parser = SSEFrameParser()
        let bodyHandle = bodyPipe.fileHandleForReading

        // Read chunks until curl exits.
        while process.isRunning {
            let chunk = bodyHandle.availableData
            guard !chunk.isEmpty else {
                // No data yet; yield briefly to avoid busy-spin.
                Thread.sleep(forTimeInterval: 0.005)
                continue
            }
            let outData: Data
            if redactionMode == "per_sse_event" {
                let result = parser.feed(chunk)
                if result.overflowFlushed {
                    outData = result.overflowBytes
                } else {
                    var assembled = Data()
                    for frame in result.frames {
                        assembled.append(frame.raw)
                    }
                    outData = assembled
                }
            } else {
                outData = chunk
            }
            outData.withUnsafeBytes { ptr in
                guard let base = ptr.baseAddress else { return }
                _ = send(clientSocket, base, ptr.count, sendFlags)
            }
        }

        // Drain any remaining body bytes after process exit.
        let remaining = bodyHandle.readDataToEndOfFile()
        if !remaining.isEmpty {
            remaining.withUnsafeBytes { ptr in
                guard let base = ptr.baseAddress else { return }
                _ = send(clientSocket, base, ptr.count, sendFlags)
            }
        }

        // Wait for header thread.
        headerGroup.wait()

        return Response(statusCode: parsedStatus, headers: parsedHeaders, body: Data(), wasStreamed: true)
    }

    private static func buildStreamingResponseHeaders(status: Int, upstreamHeaders: [String: String]) -> String {
        var response = "HTTP/1.1 \(status) OK\r\n"
        let passthrough = ["content-type", "cache-control", "x-request-id"]
        for (key, value) in upstreamHeaders {
            let lower = key.lowercased()
            if lower == "content-length" { continue }
            if passthrough.contains(lower) || lower.hasPrefix("anthropic-") {
                response += "\(key): \(value)\r\n"
            }
        }
        response += "Transfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n"
        return response
    }
}
