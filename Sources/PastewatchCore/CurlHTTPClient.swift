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

        // WO-150: collect headers fully before sending anything to the client.
        // headerPipe (stderr) closes when curl finishes writing them, which happens
        // before the first body byte arrives on the body pipe.
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

        // WO-155: relay body via a blocking read loop on a background thread.
        // readDataToEndOfFile() blocks until EOF (curl exit), eliminating the
        // 200 wakeups/sec busy-spin from availableData + Thread.sleep.
        var parser = SSEFrameParser()
        let bodyHandle = bodyPipe.fileHandleForReading
        let bodyGroup = DispatchGroup()
        bodyGroup.enter()

        DispatchQueue.global().async {
            // Block until the pipe has data, then relay it in chunks.
            // We use a chunked blocking read: read up to 64KB at a time so we
            // forward incrementally rather than waiting for the whole body.
            let chunkSize = 65536
            var buf = [UInt8](repeating: 0, count: chunkSize)
            let fd = bodyHandle.fileDescriptor
            while true {
                let n = Foundation.read(fd, &buf, chunkSize)
                guard n > 0 else { break }
                let chunk = Data(buf[0..<n])
                let outData: Data
                if redactionMode == "per_sse_event" {
                    let result = parser.feed(chunk)
                    if result.overflowFlushed {
                        outData = result.overflowBytes
                    } else {
                        // WO-152: redact each parsed frame instead of forwarding frame.raw.
                        var assembled = Data()
                        for frame in result.frames {
                            assembled.append(redactStreamFrame(frame, config: config, severity: severity))
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

            // Flush any partial SSE remainder at EOF.
            if redactionMode == "per_sse_event" {
                let rem = parser.remainingBytes
                if !rem.isEmpty {
                    rem.withUnsafeBytes { ptr in
                        guard let base = ptr.baseAddress else { return }
                        _ = send(clientSocket, base, ptr.count, sendFlags)
                    }
                }
            }
            bodyGroup.leave()
        }

        // WO-150 cont.: wait for headers before sending them; by the time headerGroup
        // finishes, curl has already started writing the body, so there is no latency cost.
        headerGroup.wait()
        let streamingHeaderStr = buildStreamingResponseHeaders(status: parsedStatus, upstreamHeaders: parsedHeaders)
        streamingHeaderStr.withCString { ptr in
            _ = send(clientSocket, ptr, strlen(ptr), sendFlags)
        }

        // Wait for body relay to finish.
        bodyGroup.wait()
        process.waitUntilExit()

        return Response(statusCode: parsedStatus, headers: parsedHeaders, body: Data(), wasStreamed: true)
    }

    /// WO-152: per-frame redaction for the Linux curl streaming path.
    private static func redactStreamFrame(
        _ frame: SSEFrameParser.Frame,
        config: PastewatchConfig,
        severity: Severity
    ) -> Data {
        guard let dataPayload = frame.data, dataPayload != "[DONE]" else {
            return frame.raw
        }
        guard let jsonData = dataPayload.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: jsonData) as? [String: Any] else {
            return frame.raw
        }
        // Extract text from Anthropic SSE delta.
        guard let delta = json["delta"] as? [String: Any],
              let text = delta["text"] as? String else {
            return frame.raw
        }
        let matches = DetectionRules.scan(text, config: config)
        let filtered = matches.filter { $0.effectiveSeverity >= severity }
        guard !filtered.isEmpty else { return frame.raw }
        let obfuscated = Obfuscator.obfuscate(text, matches: filtered)
        var modifiedDelta = delta
        modifiedDelta["text"] = obfuscated
        var modifiedJson = json
        modifiedJson["delta"] = modifiedDelta
        guard let resultData = try? JSONSerialization.data(withJSONObject: modifiedJson),
              let resultStr = String(data: resultData, encoding: .utf8) else {
            return frame.raw
        }
        return frame.reserializedWith(data: resultStr)
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
