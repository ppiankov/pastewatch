import Foundation

/// HTTP client using Process + curl for Linux where URLSession/FoundationNetworking
/// is unreliable (arm64 dataTask completion handler never fires).
/// On macOS this file compiles but is not used — ProxyServer uses URLSession there.
struct CurlHTTPClient {
    private static let responseHeaderReadChunkSize = 256
    private static let maxHeaderTerminatorOverlapBytes = 3
    private static let crlfHeaderTerminator = Data([0x0D, 0x0A, 0x0D, 0x0A])
    private static let lfHeaderTerminator = Data([0x0A, 0x0A])

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
        streamingRedactionMode: StreamingRedactionMode = .perSSEEvent,
        proxyConfig: PastewatchConfig = PastewatchConfig.defaultConfig,
        proxySeverity: Severity = .high,
        /// WO-192: closure called at [DONE] time with accumulated stream counts so stream-only
        /// secrets (no body redaction) also trigger the alert. Nil = no alert injection.
        alertBeforeDone: ((_ streamCount: Int, _ streamTypes: [String]) -> Data?)? = nil
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
            let path = Self.temporaryBodyPath()
            FileManager.default.createFile(atPath: path, contents: body)
            args.append(contentsOf: Self.bodyUploadArgs(forTempFile: path))
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
            // WO-196: alertBeforeDone passed directly, not through StreamContext.
            return relayStreamingResponse(process: process, bodyPipe: bodyPipe, headerPipe: headerPipe, ctx: ctx, alertBeforeDone: alertBeforeDone)
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

    /// WO-293: preserve request body bytes exactly; curl -d treats @file as form data.
    static func bodyUploadArgs(forTempFile path: String) -> [String] {
        ["--data-binary", "@\(path)"]
    }

    /// WO-294: per-call unique path so concurrent curl uploads cannot share a body file.
    static func temporaryBodyPath() -> String {
        "/tmp/pw-proxy-\(ProcessInfo.processInfo.processIdentifier)-\(UUID().uuidString).body"
    }

    struct StreamContext {
        let clientSocket: Int32
        let sendFlags: Int32
        let redactionMode: StreamingRedactionMode
        let config: PastewatchConfig
        let severity: Severity
    }

    /// Result of per-frame redaction: output bytes + stats.
    private struct FrameRedactionResult {
        let data: Data
        let count: Int
        let types: [String]
    }

    /// WO-196: alertBeforeDone passed directly rather than via StreamContext to avoid
    /// silent nil-default divergence when StreamContext is constructed without it.
    private static func relayStreamingResponse(
        process: Process,
        bodyPipe: Pipe,
        headerPipe: Pipe,
        ctx: StreamContext,
        alertBeforeDone: ((_ streamCount: Int, _ streamTypes: [String]) -> Data?)? = nil
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
            var bufferedHeaderBytes = Data()
            // WO-165/WO-166: loop over header blocks, skipping 1xx interim responses,
            // and recognize both \r\n\r\n (CRLF) and \n\n (LF-only) terminators.
            while true {
                // WO-300: read in chunks and search the appended window instead of
                // issuing one syscall and Data.suffix allocation per header byte.
                guard let headerBlock = Self.readResponseHeaderBlock(from: fd, buffered: &bufferedHeaderBytes) else {
                    parsedStatus = 502
                    parsedHeaders = [:]
                    break
                }
                // Parse the block to extract status.
                var blockStatus = 0
                var blockHeaders: [String: String] = [:]
                if let headerStr = String(data: headerBlock, encoding: .utf8) {
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
        // WO-204: --speed-limit/--speed-time activate only once data flows; they do not fire
        // during TCP-connected-but-no-headers phase, so headerGroup.wait() can block the proxy
        // thread indefinitely against a server that accepts TCP but stalls before sending headers.
        // Use an explicit deadline equal to curlSpeedTimeSeconds (the same idle budget curl uses
        // once data starts); terminate curl and return nil on timeout.
        let headerDeadline = DispatchTime.now() + .seconds(curlSpeedTimeSeconds)
        if headerGroup.wait(timeout: headerDeadline) == .timedOut {
            process.terminate()
            // WO-208: wait after terminate so the kernel reaps the child and no zombie lingers.
            process.waitUntilExit()
            // WO-213: after curl exits, its write-end of headerPipe closes at the OS level,
            // but the async block still holds a reference to headerPipe (and thus its write-end
            // FileHandle) via closure capture. Foundation.read() inside the block blocks until
            // that write-end is closed, pinning the GCD thread permanently.
            // Close the write-end explicitly so Foundation.read() returns 0 (EOF) and the
            // block can call headerGroup.leave() and release the thread.
            headerPipe.fileHandleForWriting.closeFile()
            _ = headerGroup.wait(timeout: .now() + 5)
            return nil
        }
        let streamingHeaderStr = buildStreamingResponseHeaders(status: parsedStatus, upstreamHeaders: parsedHeaders)
        // WO-191/WO-200/WO-206: shared sendAll() from SocketHelpers.swift.
        // WO-211: check return — if the client disconnected before headers arrived, skip body relay.
        // WO-226: emit stderr diagnostic so the disconnect is observable in proxy logs.
        guard sendAll(Data(streamingHeaderStr.utf8), to: ctx.clientSocket, flags: ctx.sendFlags) else {
            FileHandle.standardError.write(Data("[pastewatch-proxy] relayStreamingResponse: client socket \(ctx.clientSocket) closed before streaming headers delivered\n".utf8))
            process.terminate()
            process.waitUntilExit()
            // WO-236: unlike the timeout branch (WO-213), the GCD header-reader block has already
            // exited by this point. This guard is only reached after headerGroup.wait() returned
            // .success, which requires headerGroup.leave() to have been called — meaning the block
            // already finished Foundation.read() and returned. No thread is pinned; no cleanup needed.
            return nil
        }

        // WO-162: start body relay AFTER headers have been sent so the client always
        // receives the HTTP status line and headers before any body bytes.
        var relayRedactionCount = 0
        var relayRedactionTypes: [String] = []
        let bodyGroup = DispatchGroup()
        bodyGroup.enter()
        DispatchQueue.global().async {
            // WO-196: alertBeforeDone passed directly from caller scope, not from StreamContext.
            let (count, types) = Self.relayBodyChunks(from: bodyPipe, ctx: ctx, alertBeforeDone: alertBeforeDone)
            relayRedactionCount = count
            relayRedactionTypes = types
            bodyGroup.leave()
        }

        // Wait for body relay to finish.
        bodyGroup.wait()
        // WO-207: terminate before waitUntilExit() so that an EPIPE break in relayBodyChunks
        // (which exits the read loop early, leaving bodyPipe's write-end full) does not deadlock
        // here: curl blocks on the full pipe, waitUntilExit() blocks on curl — cycle.
        // terminate() sends SIGTERM so curl closes the pipe and exits cleanly.
        // This is safe even when curl has already exited (terminate() is a no-op then).
        process.terminate()
        process.waitUntilExit()

        return Response(
            statusCode: parsedStatus, headers: parsedHeaders, body: Data(), wasStreamed: true,
            streamRedactionCount: relayRedactionCount, streamRedactionTypes: relayRedactionTypes
        )
    }

    static func readResponseHeaderBlock(from fd: Int32, buffered: inout Data) -> Data? {
        while true {
            if let range = headerTerminatorRange(in: buffered, searchRange: 0..<buffered.count) {
                let block = Data(buffered[..<range.upperBound])
                buffered.removeSubrange(..<range.upperBound)
                return block
            }

            var readBuffer = [UInt8](repeating: 0, count: responseHeaderReadChunkSize)
            let previousCount = buffered.count
            let n = Foundation.read(fd, &readBuffer, readBuffer.count)
            guard n > 0 else {
                guard !buffered.isEmpty else { return nil }
                let block = buffered
                buffered = Data()
                return block
            }

            buffered.append(contentsOf: readBuffer[..<n])
            let searchStart = max(0, previousCount - maxHeaderTerminatorOverlapBytes)
            let searchRange = searchStart..<buffered.count
            if let range = headerTerminatorRange(in: buffered, searchRange: searchRange) {
                let block = Data(buffered[..<range.upperBound])
                buffered.removeSubrange(..<range.upperBound)
                return block
            }
        }
    }

    private static func headerTerminatorRange(in data: Data, searchRange: Range<Data.Index>) -> Range<Data.Index>? {
        data.range(of: crlfHeaderTerminator, options: [], in: searchRange) ??
            data.range(of: lfHeaderTerminator, options: [], in: searchRange)
    }

    /// WO-155: blocking read loop that relays body pipe chunks to the client socket.
    /// Returns accumulated redaction stats (count, type names) for audit logging.
    /// WO-182/WO-192: alertBeforeDone closure is evaluated at [DONE] time with accumulated stream
    /// counts so stream-only secrets also produce an alert. Nil = no alert injection.
    private static func relayBodyChunks(
        from bodyPipe: Pipe,
        ctx: StreamContext,
        alertBeforeDone: ((_ streamCount: Int, _ streamTypes: [String]) -> Data?)? = nil
    ) -> (Int, [String]) {
        var parser = SSEFrameParser()
        let fd = bodyPipe.fileHandleForReading.fileDescriptor
        let chunkSize = 65536
        var buf = [UInt8](repeating: 0, count: chunkSize)
        var totalCount = 0
        var totalTypes: [String] = []
        // WO-216: track how the read loop exited so we know whether to flush the remainder.
        var clientEpipe = false

        while true {
            let n = Foundation.read(fd, &buf, chunkSize)
            guard n > 0 else { break }
            let chunk = Data(buf[0..<n])
            let outData: Data
            switch ctx.redactionMode {
            case .perSSEEvent:
                let result = parser.feed(chunk)
                if result.overflowFlushed {
                    // WO-164: a 4MB+ frame bypassed the normal per-frame path; redact it
                    // as raw text rather than forwarding secrets unscanned.
                    let r = redactRawBytes(result.overflowBytes, config: ctx.config, severity: ctx.severity)
                    outData = r.data
                    // WO-256: record detections before sendAll() — if the client EPIPEs, the
                    // credential was still present in the stream and was redacted from the bytes
                    // we attempted to send. Consistent with the assembled-frames path (WO-250)
                    // and macOS redactRawBytes(). Chosen policy: always-record on detect.
                    totalCount += r.count
                    totalTypes.append(contentsOf: r.types)
                    if sendAll(outData, to: ctx.clientSocket, flags: ctx.sendFlags) {
                        continue
                    } else {
                        clientEpipe = true
                        break
                    }
                } else {
                    // WO-243: build assembled data and a parallel pending-stats buffer. Apply
                    // stats only after sendAll() succeeds so EPIPE frames are not counted.
                    var assembled = Data()
                    var pendingCount = 0
                    var pendingTypes: [String] = []
                    for frame in result.frames {
                        // WO-182/WO-192: evaluate alert closure at [DONE] time with live stream
                        // counts so stream-only secrets (body-clean request) also trigger alert.
                        // WO-248: pass totalCount+pendingCount (not totalCount alone) — when the
                        // only credential in the stream arrives in the same chunk as [DONE], it is
                        // in pendingTypes but not yet merged into totalTypes. Passing pre-merge
                        // totals causes builder(0, []) → guard total>0 fails → alert suppressed.
                        if frame.data == "[DONE]",
                           let builder = alertBeforeDone,
                           let alert = builder(totalCount + pendingCount, totalTypes + pendingTypes) {
                            assembled.append(alert)
                        }
                        // WO-201: skip redactSSEFrame for [DONE] — its first guard already
                        // returns frame.raw for it, but the call is an always-no-op; avoid confusion.
                        // WO-220: use shared redactSSEFrame() from SocketHelpers.swift.
                        guard frame.data != "[DONE]" else { assembled.append(frame.raw); continue }
                        let r = redactSSEFrame(frame, config: ctx.config, severity: ctx.severity)
                        assembled.append(r.data)
                        pendingCount += r.count
                        pendingTypes.append(contentsOf: r.types)
                    }
                    outData = assembled
                    if sendAll(outData, to: ctx.clientSocket, flags: ctx.sendFlags) {
                        totalCount += pendingCount
                        totalTypes.append(contentsOf: pendingTypes)
                        continue
                    } else {
                        // WO-250: credential was detected and redacted (pendingCount > 0) even
                        // though the send failed. Record the detection so the audit log is not
                        // silent about secrets that were present in the stream, regardless of
                        // whether the redacted bytes reached the client.
                        totalCount += pendingCount
                        totalTypes.append(contentsOf: pendingTypes)
                        clientEpipe = true
                        break
                    }
                }
            case .rawStream, .buffer:
                outData = chunk
            }
            // WO-191/WO-200/WO-206: shared sendAll() from SocketHelpers.swift.
            // WO-205: check return value — on EPIPE the client disconnected; draining the rest
            // of the upstream pipe burns CPU and blocks the connection thread unnecessarily.
            if !sendAll(outData, to: ctx.clientSocket, flags: ctx.sendFlags) {
                clientEpipe = true
                break
            }
        }

        // Flush partial SSE remainder at EOF only — skip on EPIPE.
        // WO-172: redact before sending — a partial frame may contain a mid-stream credential
        // that was split across chunk boundaries and never reached the per-frame redaction path.
        // WO-216: on EPIPE the client is gone; scanning the remainder burns CPU and inflates
        // stats with secrets that were never actually delivered or redacted to anyone.
        if !clientEpipe && ctx.redactionMode == .perSSEEvent {
            let rem = parser.remainingBytes
            if !rem.isEmpty {
                let r = redactRawBytes(rem, config: ctx.config, severity: ctx.severity)
                totalCount += r.count
                totalTypes.append(contentsOf: r.types)
                // WO-191/WO-200/WO-205: retry until all bytes sent; skip on EPIPE.
                _ = sendAll(r.data, to: ctx.clientSocket, flags: ctx.sendFlags)
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

    /// WO-290: shared close-delimited streaming headers for Linux and macOS relay paths.
    static func buildStreamingResponseHeaders(status: Int, upstreamHeaders: [String: String]) -> String {
        buildStreamingResponseHeaders(
            status: status,
            upstreamHeaders: upstreamHeaders.map { ($0.key, $0.value) }
        )
    }

    static func buildStreamingResponseHeaders(status: Int, upstreamHeaders: [AnyHashable: Any]) -> String {
        buildStreamingResponseHeaders(
            status: status,
            upstreamHeaders: upstreamHeaders.map { ("\($0.key)", "\($0.value)") }
        )
    }

    private static func buildStreamingResponseHeaders(status: Int, upstreamHeaders: [(String, String)]) -> String {
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
        // WO-290: body bytes are relayed raw, not chunk-encoded. Use close-delimited
        // streaming and let the caller close the client socket when upstream ends.
        response += "Connection: close\r\n\r\n"
        return response
    }

    /// WO-175: map common HTTP status codes to their canonical reason phrase.
    static func httpReasonPhrase(for status: Int) -> String {
        let phrases: [Int: String] = [
            200: "OK", 201: "Created", 204: "No Content", 206: "Partial Content",
            301: "Moved Permanently", 302: "Found", 304: "Not Modified",
            400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
            404: "Not Found", 405: "Method Not Allowed", 408: "Request Timeout",
            409: "Conflict", 429: "Too Many Requests",
            500: "Internal Server Error", 502: "Bad Gateway",
            503: "Service Unavailable", 504: "Gateway Timeout"
        ]
        return phrases[status] ?? "Unknown"
    }
}
