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
        proxySeverity: Severity = .high,
        /// WO-182: SSE frame bytes to inject before [DONE]. Nil = no alert injection.
        alertBeforeDone: Data? = nil
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
                severity: proxySeverity,
                alertBeforeDone: alertBeforeDone
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
        /// WO-182: SSE frame bytes to inject before the [DONE] sentinel.
        var alertBeforeDone: Data? = nil
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
            var oneByte = [UInt8](repeating: 0, count: 1)
            // WO-165/WO-166: loop over header blocks, skipping 1xx interim responses,
            // and recognize both \r\n\r\n (CRLF) and \n\n (LF-only) terminators.
            while true {
                var blockDone = false
                while !blockDone {
                    let n = Foundation.read(fd, &oneByte, 1)
                    guard n > 0 else { blockDone = true; break }
                    accumulated.append(oneByte[0])
                    let c = accumulated.count
                    if c >= 4 {
                        let tail4 = accumulated.suffix(4)
                        if tail4 == Data([0x0D, 0x0A, 0x0D, 0x0A]) { blockDone = true; break }
                    }
                    if c >= 2 {
                        let tail2 = accumulated.suffix(2)
                        if tail2 == Data([0x0A, 0x0A]) { blockDone = true; break }
                    }
                }
                // Parse the block to extract status.
                var blockStatus = 0
                var blockHeaders: [String: String] = [:]
                if let headerStr = String(data: accumulated, encoding: .utf8) {
                    for line in headerStr.components(separatedBy: "\r\n").flatMap({ $0.components(separatedBy: "\n") }) {
                        if line.hasPrefix("HTTP/") {
                            let parts = line.components(separatedBy: " ")
                            if parts.count >= 2, let code = Int(parts[1]) { blockStatus = code }
                        } else if let colonIdx = line.firstIndex(of: ":") {
                            let key = String(line[..<colonIdx]).trimmingCharacters(in: .whitespaces)
                            let value = String(line[line.index(after: colonIdx)...]).trimmingCharacters(in: .whitespaces)
                            blockHeaders[key] = value
                        }
                    }
                }
                // WO-165: skip 1xx interim blocks (e.g. 100 Continue) and read next block.
                if blockStatus >= 100 && blockStatus < 200 {
                    accumulated = Data()
                    continue
                }
                // WO-183: if blockStatus==0 we hit EOF after a 1xx interim (100-Continue +
                // upstream drop). Do not fabricate 200; surface as 502.
                parsedStatus = (blockStatus == 0) ? 502 : blockStatus
                parsedHeaders = blockHeaders
                break
            }
            headerGroup.leave()
        }

        // WO-156 cont.: headers are ready as soon as the blank header line is read,
        // not when curl exits. Send them before any body bytes arrive.
        headerGroup.wait()
        let streamingHeaderStr = buildStreamingResponseHeaders(status: parsedStatus, upstreamHeaders: parsedHeaders)
        streamingHeaderStr.withCString { ptr in
            _ = send(ctx.clientSocket, ptr, strlen(ptr), ctx.sendFlags)
        }

        // WO-162: start body relay AFTER headers have been sent so the client always
        // receives the HTTP status line and headers before any body bytes.
        var relayRedactionCount = 0
        var relayRedactionTypes: [String] = []
        let bodyGroup = DispatchGroup()
        bodyGroup.enter()
        DispatchQueue.global().async {
            let (count, types) = Self.relayBodyChunks(from: bodyPipe, ctx: ctx, alertBeforeDone: ctx.alertBeforeDone)
            relayRedactionCount = count
            relayRedactionTypes = types
            bodyGroup.leave()
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
    /// WO-182: alertBeforeDone is injected immediately before the [DONE] SSE sentinel so
    /// SSE consumers (which stop reading at [DONE]) see the alert before the stream ends.
    private static func relayBodyChunks(from bodyPipe: Pipe, ctx: StreamContext, alertBeforeDone: Data? = nil) -> (Int, [String]) {
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
                    // WO-164: a 4MB+ frame bypassed the normal per-frame path; redact it
                    // as raw text rather than forwarding secrets unscanned.
                    let r = redactRawBytes(result.overflowBytes, config: ctx.config, severity: ctx.severity)
                    totalCount += r.count
                    totalTypes.append(contentsOf: r.types)
                    outData = r.data
                } else {
                    var assembled = Data()
                    for frame in result.frames {
                        // WO-182: inject alert before [DONE] so SSE consumers see it.
                        if frame.data == "[DONE]", let alert = alertBeforeDone {
                            assembled.append(alert)
                        }
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
        // WO-172: redact before sending — a partial frame may contain a mid-stream credential
        // that was split across chunk boundaries and never reached the per-frame redaction path.
        if ctx.redactionMode == "per_sse_event" {
            let rem = parser.remainingBytes
            if !rem.isEmpty {
                let r = redactRawBytes(rem, config: ctx.config, severity: ctx.severity)
                totalCount += r.count
                totalTypes.append(contentsOf: r.types)
                r.data.withUnsafeBytes { ptr in
                    guard let base = ptr.baseAddress else { return }
                    _ = send(ctx.clientSocket, base, ptr.count, ctx.sendFlags)
                }
            }
        }
        return (totalCount, totalTypes)
    }

    /// WO-164: redact raw bytes that bypassed the SSE frame parser (overflow path).
    /// Treats the whole buffer as plain text, scans it, and obfuscates in-place.
    private static func redactRawBytes(_ raw: Data, config: PastewatchConfig, severity: Severity) -> FrameRedactionResult {
        guard let text = String(data: raw, encoding: .utf8) else {
            return FrameRedactionResult(data: raw, count: 0, types: [])
        }
        let matches = DetectionRules.scan(text, config: config)
        let filtered = matches.filter { $0.effectiveSeverity >= severity }
        guard !filtered.isEmpty else {
            return FrameRedactionResult(data: raw, count: 0, types: [])
        }
        let obfuscated = Obfuscator.obfuscate(text, matches: filtered)
        let types = filtered.map { $0.displayName }
        return FrameRedactionResult(data: Data(obfuscated.utf8), count: filtered.count, types: types)
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
        // WO-175: use the correct reason phrase so upstream 429/502/503 reaches the client
        // as "HTTP/1.1 429 Too Many Requests" rather than "HTTP/1.1 429 OK".
        var response = "HTTP/1.1 \(status) \(httpReasonPhrase(for: status))\r\n"
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

    /// WO-175: map common HTTP status codes to their canonical reason phrase.
    static func httpReasonPhrase(for status: Int) -> String {
        switch status {
        case 200: return "OK"
        case 201: return "Created"
        case 204: return "No Content"
        case 206: return "Partial Content"
        case 301: return "Moved Permanently"
        case 302: return "Found"
        case 304: return "Not Modified"
        case 400: return "Bad Request"
        case 401: return "Unauthorized"
        case 403: return "Forbidden"
        case 404: return "Not Found"
        case 405: return "Method Not Allowed"
        case 408: return "Request Timeout"
        case 409: return "Conflict"
        case 429: return "Too Many Requests"
        case 500: return "Internal Server Error"
        case 502: return "Bad Gateway"
        case 503: return "Service Unavailable"
        case 504: return "Gateway Timeout"
        default: return "Unknown"
        }
    }
}
