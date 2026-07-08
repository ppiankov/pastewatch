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
        /// WO-158: count of secrets redacted from SSE frames during streaming (Linux path).
        let streamRedactionCount: Int
        /// WO-158: type names of secrets redacted during streaming (Linux path).
        let streamRedactionTypes: [String]

        init(statusCode: Int, headers: [String: String], body: Data, wasStreamed: Bool = false,
             streamRedactionCount: Int = 0, streamRedactionTypes: [String] = []) {
            self.statusCode = statusCode
            self.headers = headers
            self.body = body
            self.wasStreamed = wasStreamed
            self.streamRedactionCount = streamRedactionCount
            self.streamRedactionTypes = streamRedactionTypes
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
            // Non-streaming: add a large total ceiling as a backstop and a status marker for parsing.
            args += ["--max-time", String(curlMaxTimeSeconds)]
            // WO-157: only append the status marker for non-streaming paths. The streaming relay
            // forwards raw bytes directly to the client socket and cannot strip this trailer.
            args += ["-w", "\n__HTTP_STATUS__%{http_code}"]
        }
        args += [url.absoluteString]
        return args
    }

    struct StreamContext {
        let clientSocket: Int32
        let sendFlags: Int32
        let redactionMode: String
        let config: PastewatchConfig
        let severity: Severity
    }

    /// Result of per-frame redaction: output bytes + stats.
    private struct FrameRedactionResult {
        let data: Data
        let count: Int
        let types: [String]
    }

    private static func relayStreamingResponse(
        process: Process,
        bodyPipe: Pipe,
        headerPipe: Pipe,
        ctx: StreamContext
    ) -> Response? {
        // WO-156: read headers incrementally until we see the blank line that marks
        // end-of-headers, then signal headerGroup immediately without waiting for curl to exit.
        // The old approach used readDataToEndOfFile() on the stderr pipe, which blocks until
        // the pipe's write-end closes — that only happens when curl exits after relaying the
        // full body, so headers were sent AFTER the entire body had already been forwarded.
        var parsedHeaders: [String: String] = [:]
        var parsedStatus = 200
        let headerGroup = DispatchGroup()
        headerGroup.enter()
        DispatchQueue.global().async {
            let fd = headerPipe.fileHandleForReading.fileDescriptor
            var accumulated = Data()
            var headersDone = false
            var oneByte = [UInt8](repeating: 0, count: 1)
            while !headersDone {
                let n = Foundation.read(fd, &oneByte, 1)
                guard n > 0 else { break }
                accumulated.append(oneByte[0])
                // HTTP headers end with \r\n\r\n
                if accumulated.count >= 4 {
                    let tail = accumulated.suffix(4)
                    if tail == Data([0x0D, 0x0A, 0x0D, 0x0A]) {
                        headersDone = true
                    }
                }
            }
            if let headerStr = String(data: accumulated, encoding: .utf8) {
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

        // WO-155/WO-158: relay body on a background thread via blocking read; accumulate stats.
        var relayRedactionCount = 0
        var relayRedactionTypes: [String] = []
        let bodyGroup = DispatchGroup()
        bodyGroup.enter()
        DispatchQueue.global().async {
            let (count, types) = Self.relayBodyChunks(from: bodyPipe, ctx: ctx)
            relayRedactionCount = count
            relayRedactionTypes = types
            bodyGroup.leave()
        }

        // WO-156 cont.: headers are ready as soon as the blank header line is read,
        // not when curl exits. Send them before any body bytes arrive.
        headerGroup.wait()
        let streamingHeaderStr = buildStreamingResponseHeaders(status: parsedStatus, upstreamHeaders: parsedHeaders)
        streamingHeaderStr.withCString { ptr in
            _ = send(ctx.clientSocket, ptr, strlen(ptr), ctx.sendFlags)
        }

        // Wait for body relay to finish.
        bodyGroup.wait()
        process.waitUntilExit()

        return Response(
            statusCode: parsedStatus, headers: parsedHeaders, body: Data(), wasStreamed: true,
            streamRedactionCount: relayRedactionCount, streamRedactionTypes: relayRedactionTypes
        )
    }

    /// WO-155: blocking read loop that relays body pipe chunks to the client socket.
    /// Returns accumulated redaction stats (count, type names) for audit logging.
    private static func relayBodyChunks(from bodyPipe: Pipe, ctx: StreamContext) -> (Int, [String]) {
        var parser = SSEFrameParser()
        let fd = bodyPipe.fileHandleForReading.fileDescriptor
        let chunkSize = 65536
        var buf = [UInt8](repeating: 0, count: chunkSize)
        var totalCount = 0
        var totalTypes: [String] = []

        while true {
            let n = Foundation.read(fd, &buf, chunkSize)
            guard n > 0 else { break }
            let chunk = Data(buf[0..<n])
            let outData: Data
            if ctx.redactionMode == "per_sse_event" {
                let result = parser.feed(chunk)
                if result.overflowFlushed {
                    outData = result.overflowBytes
                } else {
                    var assembled = Data()
                    for frame in result.frames {
                        let r = redactStreamFrame(frame, config: ctx.config, severity: ctx.severity)
                        assembled.append(r.data)
                        totalCount += r.count
                        totalTypes.append(contentsOf: r.types)
                    }
                    outData = assembled
                }
            } else {
                outData = chunk
            }
            outData.withUnsafeBytes { ptr in
                guard let base = ptr.baseAddress else { return }
                _ = send(ctx.clientSocket, base, ptr.count, ctx.sendFlags)
            }
        }

        // Flush partial SSE remainder at EOF.
        if ctx.redactionMode == "per_sse_event" {
            let rem = parser.remainingBytes
            if !rem.isEmpty {
                rem.withUnsafeBytes { ptr in
                    guard let base = ptr.baseAddress else { return }
                    _ = send(ctx.clientSocket, base, ptr.count, ctx.sendFlags)
                }
            }
        }
        return (totalCount, totalTypes)
    }

    /// WO-152: per-frame redaction for the Linux curl streaming path.
    /// WO-158: returns FrameRedactionResult with stats so callers can surface them
    ///         in audit logs and [PASTEWATCH] alerts.
    private static func redactStreamFrame(
        _ frame: SSEFrameParser.Frame,
        config: PastewatchConfig,
        severity: Severity
    ) -> FrameRedactionResult {
        guard let dataPayload = frame.data, dataPayload != "[DONE]" else {
            return FrameRedactionResult(data: frame.raw, count: 0, types: [])
        }
        guard let jsonData = dataPayload.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: jsonData) as? [String: Any] else {
            return FrameRedactionResult(data: frame.raw, count: 0, types: [])
        }
        // Extract text from Anthropic SSE delta.
        guard let delta = json["delta"] as? [String: Any],
              let text = delta["text"] as? String else {
            return FrameRedactionResult(data: frame.raw, count: 0, types: [])
        }
        let matches = DetectionRules.scan(text, config: config)
        let filtered = matches.filter { $0.effectiveSeverity >= severity }
        guard !filtered.isEmpty else {
            return FrameRedactionResult(data: frame.raw, count: 0, types: [])
        }
        let obfuscated = Obfuscator.obfuscate(text, matches: filtered)
        var modifiedDelta = delta
        modifiedDelta["text"] = obfuscated
        var modifiedJson = json
        modifiedJson["delta"] = modifiedDelta
        let types = filtered.map { $0.displayName }
        guard let resultData = try? JSONSerialization.data(withJSONObject: modifiedJson),
              let resultStr = String(data: resultData, encoding: .utf8) else {
            return FrameRedactionResult(data: frame.raw, count: filtered.count, types: types)
        }
        return FrameRedactionResult(data: frame.reserializedWith(data: resultStr), count: filtered.count, types: types)
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
