import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// HTTP client using Process + curl for Linux where URLSession/FoundationNetworking
/// is unreliable (arm64 dataTask completion handler never fires).
/// On macOS this file compiles but is not used — ProxyServer uses URLSession there.
struct CurlHTTPClient {
    typealias StreamAlertBuilder = (
        _ streamCount: Int,
        _ streamTypes: [String],
        _ advisoryCount: Int,
        _ advisoryTypes: [String]
    ) -> Data?

    private static let responseHeaderReadChunkSize = 256
    private static let maxHeaderTerminatorOverlapBytes = 3
    private static let crlfHeaderTerminator = Data([0x0D, 0x0A, 0x0D, 0x0A])
    private static let lfHeaderTerminator = Data([0x0A, 0x0A])
    // WO-313: byte marker for curl's appended non-streaming status trailer.
    private static let nonStreamingStatusMarker = Data("\n__HTTP_STATUS__".utf8)
    private static let curlOperationTimedOutExitCode: Int32 = 28 // WO-386: CURLE_OPERATION_TIMEDOUT.
    // WO-338: live curl subprocesses must be cancellable during ProxyServer.stop().
    private static let activeProcessLock = NSLock()
    private static var activeProcesses: [ObjectIdentifier: Process] = [:]
    private static let utf8ContinuationByteMask: UInt8 = 0xC0
    private static let utf8ContinuationBytePrefix: UInt8 = 0x80
    private static let maxUTF8ContinuationBytes = 3

    enum ExecuteError: Error, Equatable {
        case timeout // WO-386: curl exit 28 maps to HTTP 504, not generic 502.
        case failure
    }

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
        /// WO-336: advisory-only matches detected during streaming (Linux path).
        let streamAdvisoryCount: Int
        /// WO-336: advisory-only type names detected during streaming (Linux path).
        let streamAdvisoryTypes: [String]
        let streamToolCallRedactionCount: Int // WO-512: subset of streaming mutations from tool arguments.
        /// WO-359: non-UTF-8 buffered response redactions detected on the Linux curl path.
        let responseRedactionCount: Int
        let responseRedactionTypes: [String]
        /// WO-404: non-mutating buffered response advisories detected on the Linux curl path.
        let responseAdvisoryCount: Int
        let responseAdvisoryTypes: [String]

        init(statusCode: Int, headers: [String: String], body: Data, wasStreamed: Bool = false,
             streamRedactionCount: Int = 0, streamRedactionTypes: [String] = [],
             streamAdvisoryCount: Int = 0, streamAdvisoryTypes: [String] = [],
             streamToolCallRedactionCount: Int = 0,
             responseRedactionCount: Int = 0, responseRedactionTypes: [String] = [],
             responseAdvisoryCount: Int = 0, responseAdvisoryTypes: [String] = []) {
            self.statusCode = statusCode
            self.headers = headers
            self.body = body
            self.wasStreamed = wasStreamed
            self.streamRedactionCount = streamRedactionCount
            self.streamRedactionTypes = streamRedactionTypes
            self.streamAdvisoryCount = streamAdvisoryCount
            self.streamAdvisoryTypes = streamAdvisoryTypes
            self.streamToolCallRedactionCount = streamToolCallRedactionCount
            self.responseRedactionCount = responseRedactionCount
            self.responseRedactionTypes = responseRedactionTypes
            self.responseAdvisoryCount = responseAdvisoryCount
            self.responseAdvisoryTypes = responseAdvisoryTypes
        }
    }

    private struct NonUTF8ResponseReplacement {
        let range: Range<Data.Index> // WO-359: byte range to redact in original body.
        let placeholder: Data // WO-359: ASCII placeholder replacing the matched bytes.
        let type: String // WO-359: detection type recorded for audit stats.
    }

    /// WO-313: byte-preserving parsed curl output for non-streaming responses.
    struct ParsedNonStreamingOutput {
        let statusCode: Int
        let body: Data
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
    /// Throws if curl is not available or the process fails.
    ///
    /// For non-streaming responses: uses a large total timeout ceiling.
    /// For streaming responses: uses an idle timeout plus a larger hard ceiling
    /// so slow-drip streams cannot run forever.
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
        proxyCustomRules: [CustomRule]? = nil,
        proxySeverity: Severity = .high,
        streamDebugSink: StreamDebugSink? = nil,
        /// WO-192: closure called at [DONE] time with accumulated stream counts so stream-only
        /// secrets (no body redaction) also trigger the alert. Nil = no alert injection.
        alertBeforeDone: StreamAlertBuilder? = nil
    ) throws -> Response {
        let curlPath = "/usr/bin/curl"
        guard FileManager.default.fileExists(atPath: curlPath) else { throw ExecuteError.failure }
        let customRules = proxyCustomRules ?? CustomRule.compileValid(proxyConfig.customRules)

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
            guard let path = Self.writeTemporaryBodyFile(body) else { throw ExecuteError.failure }
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
            try startAndRegisterActiveProcess(process)
        } catch {
            throw ExecuteError.failure
        }
        defer { unregisterActiveProcess(process) }

        if streaming && clientSocket >= 0 {
            // Streaming path: relay curl output to the client socket as it arrives.
            // Headers arrive via the headerPipe (stderr -D /dev/stderr).
            // We relay the body pipe chunks directly without buffering the whole response.
            let ctx = StreamContext(
                clientSocket: clientSocket,
                sendFlags: sendFlags,
                redactionMode: streamingRedactionMode,
                config: proxyConfig,
                customRules: customRules,
                severity: proxySeverity,
                debugSink: streamDebugSink
            )
            // WO-196: alertBeforeDone passed directly, not through StreamContext.
            guard let response = relayStreamingResponse(
                process: process,
                bodyPipe: bodyPipe,
                headerPipe: headerPipe,
                ctx: ctx,
                alertBeforeDone: alertBeforeDone
            ) else {
                throw ExecuteError.failure
            }
            return response
        }

        // WO-396: drain stdout/stderr while curl is running so large buffered
        // responses cannot fill the OS pipe and deadlock waitUntilExit().
        let collectedOutput = collectNonStreamingProcessOutput(
            process: process,
            bodyPipe: bodyPipe,
            headerPipe: headerPipe
        )

        guard process.terminationStatus == 0 else {
            throw executeError(forTerminationStatus: process.terminationStatus)
        }

        let rawOutput = collectedOutput.body
        let headerData = collectedOutput.headers

        // WO-313: parse the curl status trailer at the byte level so a binary
        // upstream body is forwarded unchanged instead of failing the whole request.
        guard let parsedOutput = parseNonStreamingOutput(rawOutput) else { throw ExecuteError.failure }
        var responseBody = parsedOutput.body
        var responseRedaction = SSEFrameRedactionResult(data: responseBody, count: 0, types: [])
        if String(data: parsedOutput.body, encoding: .utf8) == nil, !parsedOutput.body.isEmpty {
            responseRedaction = redactNonUTF8ResponseBody(
                parsedOutput.body,
                config: proxyConfig,
                severity: proxySeverity,
                customRules: customRules
            )
            responseBody = responseRedaction.data
            FileHandle.standardError.write(Data(
                "[pastewatch-proxy] non-UTF-8 response body, redacted \(responseRedaction.count) match(es)\n".utf8
            ))
        }

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

        return Response(
            statusCode: parsedOutput.statusCode,
            headers: responseHeaders,
            body: responseBody,
            responseRedactionCount: responseRedaction.count,
            responseRedactionTypes: responseRedaction.types,
            responseAdvisoryCount: responseRedaction.advisoryCount,
            responseAdvisoryTypes: responseRedaction.advisoryTypes
        )
    }

    static func executeError(forTerminationStatus status: Int32) -> ExecuteError {
        status == curlOperationTimedOutExitCode ? .timeout : .failure
    }

    struct CollectedProcessOutput {
        let body: Data
        let headers: Data
    }

    static func collectNonStreamingProcessOutput(
        process: Process,
        bodyPipe: Pipe,
        headerPipe: Pipe
    ) -> CollectedProcessOutput {
        let group = DispatchGroup()
        let lock = NSLock()
        var bodyData = Data()
        var headerData = Data()

        group.enter()
        DispatchQueue.global(qos: .utility).async {
            let data = bodyPipe.fileHandleForReading.readDataToEndOfFile()
            lock.lock()
            bodyData = data
            lock.unlock()
            group.leave()
        }

        group.enter()
        DispatchQueue.global(qos: .utility).async {
            let data = headerPipe.fileHandleForReading.readDataToEndOfFile()
            lock.lock()
            headerData = data
            lock.unlock()
            group.leave()
        }

        bodyPipe.fileHandleForWriting.closeFile()
        headerPipe.fileHandleForWriting.closeFile()
        process.waitUntilExit()
        group.wait()

        lock.lock()
        defer { lock.unlock() }
        return CollectedProcessOutput(body: bodyData, headers: headerData)
    }

    /// Relay a streaming (SSE) curl response incrementally to the client socket.
    /// Reads chunks from the body pipe as curl writes them, forwarding each immediately.
    static func buildBaseArgs(method: String, url: URL, streaming: Bool) -> [String] {
        var args: [String] = ["-s", "-S", "-X", method, "-D", "/dev/stderr"]
        // Idle floor: fail only when no bytes arrive for the speed-time window.
        args += ["--speed-limit", String(curlMinSpeedBytesPerSecond), "--speed-time", String(curlSpeedTimeSeconds)]
        if streaming {
            // WO-343: slow-drip streams can satisfy --speed-time forever; keep a
            // separate total-session ceiling for Linux curl streaming.
            args += ["--max-time", String(curlStreamMaxTimeSeconds)]
        } else {
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

    /// WO-367: create request body files with owner-only permissions from the start.
    static func writeTemporaryBodyFile(_ body: Data) -> String? {
        let path = temporaryBodyPath()
        let fd = open(path, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR)
        guard fd >= 0 else { return nil }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        handle.write(body)
        handle.closeFile()
        return path
    }

    static func parseNonStreamingOutput(_ rawOutput: Data) -> ParsedNonStreamingOutput? {
        // WO-329: the curl status trailer must be the final marker plus exactly 3 digits.
        let statusDigitCount = 3
        let trailerLength = nonStreamingStatusMarker.count + statusDigitCount
        guard rawOutput.count >= trailerLength else { return nil }
        let markerStart = rawOutput.count - trailerLength
        let statusStart = rawOutput.count - statusDigitCount
        let markerRange = markerStart..<statusStart
        guard rawOutput[markerRange].elementsEqual(nonStreamingStatusMarker) else { return nil }

        let statusBytes = rawOutput[statusStart..<rawOutput.count]
        guard statusBytes.allSatisfy({ $0 >= 48 && $0 <= 57 }) else { return nil }
        guard let statusString = String(data: statusBytes, encoding: .utf8),
              let statusCode = Int(statusString) else {
            return nil
        }
        return ParsedNonStreamingOutput(
            statusCode: statusCode,
            body: Data(rawOutput[..<markerStart])
        )
    }

    struct StreamContext {
        let clientSocket: Int32
        let sendFlags: Int32
        let redactionMode: StreamingRedactionMode
        let config: PastewatchConfig
        let customRules: [CustomRule] // WO-473: startup-validated rules shared by Linux relay paths.
        let severity: Severity
        let debugSink: StreamDebugSink? // WO-514: explicit local dump sink, nil by default.

        init(
            clientSocket: Int32,
            sendFlags: Int32,
            redactionMode: StreamingRedactionMode,
            config: PastewatchConfig,
            customRules: [CustomRule]? = nil,
            severity: Severity,
            debugSink: StreamDebugSink? = nil
        ) {
            self.clientSocket = clientSocket
            self.sendFlags = sendFlags
            self.redactionMode = redactionMode
            self.config = config
            self.customRules = customRules ?? CustomRule.compileValid(config.customRules)
            self.severity = severity
            self.debugSink = debugSink
        }
    }

    /// WO-336/WO-404: named Linux relay result carries mutation-safe and advisory stream totals.
    struct StreamRelayResult {
        let redactionCount: Int
        let redactionTypes: [String]
        let advisoryCount: Int
        let advisoryTypes: [String]
        let toolCallRedactionCount: Int // WO-512: separate signal for tool payload mutations.
    }

    /// WO-336/WO-404: keep raw-stream mutation-safe/advisory counters together across helpers.
    private struct StreamScanTotals {
        var redactionCount = 0
        var redactionTypes: [String] = []
        var advisoryCount = 0
        var advisoryTypes: [String] = []
        var toolCallRedactionCount = 0 // WO-512: included in redactionCount, also reported separately.

        mutating func record(_ redaction: SSEFrameRedactionResult) {
            recordCritical(redaction)
            recordAdvisory(count: redaction.advisoryCount, types: redaction.advisoryTypes)
        }

        mutating func recordCritical(_ redaction: SSEFrameRedactionResult) {
            redactionCount += redaction.count
            redactionTypes.append(contentsOf: redaction.types)
            toolCallRedactionCount += redaction.toolCallRedactionCount
        }

        mutating func recordAdvisory(count: Int, types: [String]) {
            advisoryCount += count
            advisoryTypes.append(contentsOf: types)
        }

        mutating func recordAdvisoryIfDelivered(_ delivered: Bool, count: Int, types: [String]) {
            guard delivered else { return } // WO-348: advisory-only matches are delivery-scoped.
            recordAdvisory(count: count, types: types)
        }
    }

    /// WO-348: raw-stream helpers return pending advisory stats so callers can
    /// commit them only after the socket write succeeds.
    private struct StreamChunkRelayResult {
        let data: Data
        let advisoryCount: Int
        let advisoryTypes: [String]
    }

    private struct RawStreamAlertContext {
        let stream: StreamContext
        let alertBeforeDone: StreamAlertBuilder?
    }

    // WO-509: bundle immutable per-event relay inputs so extraction does not grow parameter lists.
    private struct PerSSEEventRelayContext {
        let stream: StreamContext
        let alertBeforeDone: StreamAlertBuilder?
    }

    private enum PerSSEEventRelayOutcome {
        case continueRelay
        case clientEpipe
        case policyTerminated
    }

    /// WO-351: raw_stream alert detection keeps only a small [DONE] lookbehind
    /// instead of buffering arbitrary partial SSE frames.
    private struct RawStreamAlertState {
        var pending = Data()
        var sawDone = false
        var advisoryScanTail = Data()
        // WO-377: absolute_offset = advisoryScanBaseOffset + UTF-8 offset inside advisoryScanTail.
        var advisoryScanBaseOffset = 0
        var seenAdvisorySignatures: Set<String> = []
    }

    private static let rawStreamDoneLine = Data("data: [DONE]".utf8)
    private static let rawStreamScanOverlapBytes = 4_096
    private static let rawStreamAdvisoryScanWindowBytes = rawStreamScanOverlapBytes
    private static let rawStreamDeliveryLookbehindBytes = rawStreamScanOverlapBytes

    static func utf8AlignedTrimOffset(in data: Data, minimumOffset: Int) -> Int {
        // WO-387: a sliding advisory scan window must not start on a UTF-8 continuation byte.
        // WO-397: bound the scan to the maximum continuation span in a valid UTF-8 scalar.
        let rawOffset = min(max(0, minimumOffset), data.count)
        guard rawOffset < data.count,
              isUTF8ContinuationByte(data[data.index(data.startIndex, offsetBy: rawOffset)]) else {
            return rawOffset
        }
        return utf8ScalarEndOffset(containingContinuationAt: rawOffset, in: data) ?? rawOffset
    }

    private static func isUTF8ContinuationByte(_ byte: UInt8) -> Bool {
        (byte & utf8ContinuationByteMask) == utf8ContinuationBytePrefix
    }

    private static func utf8ScalarEndOffset(containingContinuationAt offset: Int, in data: Data) -> Int? {
        var leadOffset = offset
        var bytesWalked = 0
        while leadOffset > 0 && bytesWalked < maxUTF8ContinuationBytes {
            leadOffset -= 1
            bytesWalked += 1
            let candidate = data[data.index(data.startIndex, offsetBy: leadOffset)]
            if !isUTF8ContinuationByte(candidate) {
                break
            }
        }

        let lead = data[data.index(data.startIndex, offsetBy: leadOffset)]
        guard !isUTF8ContinuationByte(lead),
              let scalarLength = utf8ScalarLength(forLeadByte: lead),
              offset > leadOffset,
              offset < leadOffset + scalarLength else {
            return nil
        }
        return min(leadOffset + scalarLength, data.count)
    }

    private static func utf8ScalarLength(forLeadByte byte: UInt8) -> Int? {
        switch byte {
        case 0xC2...0xDF:
            return 2
        case 0xE0...0xEF:
            return 3
        case 0xF0...0xF4:
            return 4
        default:
            return nil
        }
    }

    static func cancelActiveProcesses() {
        activeProcessLock.lock()
        let processes = Array(activeProcesses.values)
        activeProcessLock.unlock()

        for process in processes where process.isRunning {
            process.terminate()
        }
    }

    private static func startAndRegisterActiveProcess(_ process: Process) throws {
        activeProcessLock.lock()
        defer { activeProcessLock.unlock() }
        // WO-338: hold the registry lock across spawn+register so stop() cannot
        // snapshot active curl processes in the gap after run() but before registration.
        try process.run()
        activeProcesses[ObjectIdentifier(process)] = process
    }

    private static func unregisterActiveProcess(_ process: Process) {
        activeProcessLock.lock()
        activeProcesses.removeValue(forKey: ObjectIdentifier(process))
        activeProcessLock.unlock()
    }

    static func registerActiveProcessForTesting(_ process: Process) {
        // WO-370: tests need deterministic coverage for stop-driven curl cancellation.
        activeProcessLock.lock()
        activeProcesses[ObjectIdentifier(process)] = process
        activeProcessLock.unlock()
    }

    static func unregisterActiveProcessForTesting(_ process: Process) {
        activeProcessLock.lock()
        activeProcesses.removeValue(forKey: ObjectIdentifier(process))
        activeProcessLock.unlock()
    }

    /// WO-196: alertBeforeDone passed directly rather than via StreamContext to avoid
    /// silent nil-default divergence when StreamContext is constructed without it.
    static func relayStreamingResponse(
        process: Process,
        bodyPipe: Pipe,
        headerPipe: Pipe,
        ctx: StreamContext,
        alertBeforeDone: ((
            _ streamCount: Int,
            _ streamTypes: [String],
            _ advisoryCount: Int,
            _ advisoryTypes: [String]
        ) -> Data?)? = nil,
        headerTimeout: DispatchTimeInterval = .seconds(curlHeaderTimeoutSeconds)
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
        // WO-346: header arrival and post-header idle-data are separate timeout
        // concerns; keep this deadline independently tunable from --speed-time.
        // WO-370: timeout interval is injectable for focused Linux relay tests.
        let headerDeadline = DispatchTime.now() + headerTimeout
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
        var relayResult = StreamRelayResult(
            redactionCount: 0, redactionTypes: [],
            advisoryCount: 0, advisoryTypes: [],
            toolCallRedactionCount: 0
        )
        let bodyGroup = DispatchGroup()
        bodyGroup.enter()
        DispatchQueue.global().async {
            // WO-196: alertBeforeDone passed directly from caller scope, not from StreamContext.
            relayResult = Self.relayBodyChunks(from: bodyPipe, ctx: ctx, alertBeforeDone: alertBeforeDone)
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
            streamRedactionCount: relayResult.redactionCount,
            streamRedactionTypes: relayResult.redactionTypes,
            streamAdvisoryCount: relayResult.advisoryCount,
            streamAdvisoryTypes: relayResult.advisoryTypes,
            streamToolCallRedactionCount: relayResult.toolCallRedactionCount
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
                // WO-339: EOF before a blank-line terminator means truncated headers.
                buffered = Data()
                return nil
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
    static func relayBodyChunks(
        from bodyPipe: Pipe,
        ctx: StreamContext,
        alertBeforeDone: StreamAlertBuilder? = nil
    ) -> StreamRelayResult {
        var parser = SSEFrameParser()
        let fd = bodyPipe.fileHandleForReading.fileDescriptor
        let chunkSize = 65536
        var buf = [UInt8](repeating: 0, count: chunkSize)
        var totals = StreamScanTotals()
        // WO-509: Linux shares the protocol-aware state machine used by URLSession.
        var toolCallRedactor = ToolCallStreamRedactor(
            config: ctx.config,
            customRules: ctx.customRules,
            severity: ctx.severity,
            debugSink: ctx.debugSink
        )
        // WO-216: track how the read loop exited so we know whether to flush the remainder.
        var clientEpipe = false
        var policyTerminated = false // WO-511: bounded tool buffers stop upstream relay without an EPIPE.
        var rawStreamAlertState = RawStreamAlertState()
        let rawAlert = RawStreamAlertContext(stream: ctx, alertBeforeDone: alertBeforeDone)

        readLoop: while true {
            let n = Foundation.read(fd, &buf, chunkSize)
            guard n > 0 else { break }
            let chunk = Data(buf[0..<n])
            let outData: Data
            var deliveryScopedAdvisoryCount = 0
            var deliveryScopedAdvisoryTypes: [String] = []
            switch ctx.redactionMode {
            case .perSSEEvent:
                let outcome = relayPerSSEEventChunk(
                    chunk,
                    parser: &parser,
                    toolCallRedactor: &toolCallRedactor,
                    totals: &totals,
                    context: PerSSEEventRelayContext(stream: ctx, alertBeforeDone: alertBeforeDone)
                )
                switch outcome {
                case .continueRelay:
                    continue readLoop
                case .clientEpipe:
                    clientEpipe = true
                    break readLoop
                case .policyTerminated:
                    policyTerminated = true
                    break readLoop
                }
            case .rawStream:
                guard let rawOutput = relayRawStreamChunk(
                    chunk,
                    parser: &parser,
                    alert: rawAlert,
                    totals: &totals,
                    alertState: &rawStreamAlertState
                ) else { continue readLoop }
                outData = rawOutput.data
                deliveryScopedAdvisoryCount = rawOutput.advisoryCount
                deliveryScopedAdvisoryTypes = rawOutput.advisoryTypes
            case .buffer:
                outData = chunk
            }
            // WO-191/WO-200/WO-206: shared sendAll() from SocketHelpers.swift.
            // WO-205: check return value — on EPIPE the client disconnected; draining the rest
            // of the upstream pipe burns CPU and blocks the connection thread unnecessarily.
            if sendAll(outData, to: ctx.clientSocket, flags: ctx.sendFlags) {
                // WO-348: raw_stream advisory counts describe delivered bytes only.
                totals.recordAdvisory(count: deliveryScopedAdvisoryCount, types: deliveryScopedAdvisoryTypes)
            } else {
                clientEpipe = true
                break
            }
        }

        if !clientEpipe && !policyTerminated {
            flushRelayRemainder(
                parser: &parser,
                toolCallRedactor: &toolCallRedactor,
                alert: rawAlert,
                totals: &totals,
                rawStreamAlertState: &rawStreamAlertState
            )
        }
        return StreamRelayResult(
            redactionCount: totals.redactionCount,
            redactionTypes: totals.redactionTypes,
            advisoryCount: totals.advisoryCount,
            advisoryTypes: totals.advisoryTypes,
            toolCallRedactionCount: totals.toolCallRedactionCount
        )
    }

    // WO-509: isolate stateful per-event assembly from the generic curl read loop.
    // WO-243, WO-248, WO-250, WO-256, and WO-345: retain pending-stat, alert,
    // failed-send, overflow-attempt, and delivery-scoped advisory semantics.
    private static func relayPerSSEEventChunk(
        _ chunk: Data,
        parser: inout SSEFrameParser,
        toolCallRedactor: inout ToolCallStreamRedactor,
        totals: inout StreamScanTotals,
        context: PerSSEEventRelayContext
    ) -> PerSSEEventRelayOutcome {
        let parsed = parser.feed(chunk)
        if parsed.overflowFlushed {
            if let blocked = toolCallRedactor.blockForParserOverflow(parsed.overflowBytes) {
                let output = blocked.frames.reduce(into: Data()) { $0.append($1.data) }
                let delivered = sendAll(
                    output,
                    to: context.stream.clientSocket,
                    flags: context.stream.sendFlags
                )
                return delivered ? .policyTerminated : .clientEpipe
            }
            let redaction = redactRawBytes(
                parsed.overflowBytes,
                config: context.stream.config,
                severity: context.stream.severity,
                customRules: context.stream.customRules
            )
            // WO-256: overflow detections are recorded even when the client write fails.
            totals.recordCritical(redaction)
            let delivered = sendAll(
                redaction.data,
                to: context.stream.clientSocket,
                flags: context.stream.sendFlags
            )
            totals.recordAdvisoryIfDelivered(
                delivered,
                count: redaction.advisoryCount,
                types: redaction.advisoryTypes
            )
            return delivered ? .continueRelay : .clientEpipe
        }

        // WO-243: hold frame bytes and statistics together until the batch write resolves.
        var output = Data()
        var pending = StreamScanTotals()
        var policyTerminated = false
        for frame in parsed.frames {
            if frame.data == "[DONE]" {
                let tail = toolCallRedactor.finish()
                for redaction in tail.frames {
                    output.append(redaction.data)
                    pending.record(redaction)
                }
                if tail.terminateStream {
                    policyTerminated = true
                    break
                }
                // WO-248: include this batch's pending detections in the terminal alert.
                if let alert = context.alertBeforeDone?(
                    totals.redactionCount + pending.redactionCount,
                    totals.redactionTypes + pending.redactionTypes,
                    totals.advisoryCount + pending.advisoryCount,
                    totals.advisoryTypes + pending.advisoryTypes
                ) {
                    output.append(alert)
                }
                output.append(frame.raw)
                continue
            }

            let transformed = toolCallRedactor.process(frame)
            for redaction in transformed.frames {
                output.append(redaction.data)
                pending.record(redaction)
            }
            if transformed.terminateStream {
                policyTerminated = true
                break
            }
        }

        let delivered = sendAll(output, to: context.stream.clientSocket, flags: context.stream.sendFlags)
        // WO-250: attempted mutations remain observable even when the client write fails.
        totals.redactionCount += pending.redactionCount
        totals.redactionTypes.append(contentsOf: pending.redactionTypes)
        totals.toolCallRedactionCount += pending.toolCallRedactionCount
        if delivered {
            totals.advisoryCount += pending.advisoryCount
            totals.advisoryTypes.append(contentsOf: pending.advisoryTypes)
        }
        guard delivered else { return .clientEpipe }
        return policyTerminated ? .policyTerminated : .continueRelay
    }

    private static func flushRelayRemainder(
        parser: inout SSEFrameParser,
        toolCallRedactor: inout ToolCallStreamRedactor,
        alert: RawStreamAlertContext,
        totals: inout StreamScanTotals,
        rawStreamAlertState: inout RawStreamAlertState
    ) {
        // Flush partial SSE remainder at EOF only — skip on EPIPE.
        // WO-172: redact before sending — a partial frame may contain a mid-stream credential
        // that was split across chunk boundaries and never reached the per-frame redaction path.
        // WO-216: on EPIPE the client is gone; scanning the remainder burns CPU and inflates
        // stats with secrets that were never actually delivered or redacted to anyone.
        if alert.stream.redactionMode == .perSSEEvent {
            flushPerSSEEventRemainder(
                parser: &parser,
                toolCallRedactor: &toolCallRedactor,
                ctx: alert.stream,
                alertBeforeDone: alert.alertBeforeDone,
                totals: &totals
            )
        } else if alert.stream.redactionMode == .rawStream && alert.alertBeforeDone != nil {
            flushRawStreamRemainder(
                parser: &parser,
                state: &rawStreamAlertState,
                ctx: alert.stream,
                alertBeforeDone: alert.alertBeforeDone,
                totals: &totals
            )
        }
    }

    private static func flushPerSSEEventRemainder(
        parser: inout SSEFrameParser,
        toolCallRedactor: inout ToolCallStreamRedactor,
        ctx: StreamContext,
        alertBeforeDone: StreamAlertBuilder?,
        totals: inout StreamScanTotals
    ) {
        let tail = toolCallRedactor.finish()
        var output = Data()
        var tailAdvisoryCount = 0
        var tailAdvisoryTypes: [String] = []
        for redaction in tail.frames {
            output.append(redaction.data)
            totals.recordCritical(redaction)
            tailAdvisoryCount += redaction.advisoryCount
            tailAdvisoryTypes.append(contentsOf: redaction.advisoryTypes)
        }
        if tail.terminateStream {
            _ = sendAll(output, to: ctx.clientSocket, flags: ctx.sendFlags)
            return
        }
        let rem = parser.remainingBytes
        guard !rem.isEmpty else {
            if !output.isEmpty {
                let delivered = sendAll(output, to: ctx.clientSocket, flags: ctx.sendFlags)
                totals.recordAdvisoryIfDelivered(
                    delivered,
                    count: tailAdvisoryCount,
                    types: tailAdvisoryTypes
                )
            }
            return
        }
        let redaction = redactRawBytes(
            rem, config: ctx.config, severity: ctx.severity, customRules: ctx.customRules
        )
        totals.recordCritical(redaction)
        // WO-191, WO-200, and WO-205: retry until all bytes sent; skip on EPIPE.
        let alert = alertBeforeDone?(
            totals.redactionCount,
            totals.redactionTypes,
            totals.advisoryCount + tailAdvisoryCount + redaction.advisoryCount,
            totals.advisoryTypes + tailAdvisoryTypes + redaction.advisoryTypes
        )
        output.append(insertingSSEDataBeforeDone(alert, into: redaction.data))
        let delivered = sendAll(
            output,
            to: ctx.clientSocket,
            flags: ctx.sendFlags
        )
        totals.recordAdvisoryIfDelivered(
            delivered,
            count: tailAdvisoryCount + redaction.advisoryCount,
            types: tailAdvisoryTypes + redaction.advisoryTypes
        )
    }

    private static func flushRawStreamRemainder(
        parser: inout SSEFrameParser,
        state: inout RawStreamAlertState,
        ctx: StreamContext,
        alertBeforeDone: StreamAlertBuilder?,
        totals: inout StreamScanTotals
    ) {
        guard let rawOutput = relayRawStreamEOF(
            parser: &parser,
            state: &state,
            ctx: ctx,
            alertBeforeDone: alertBeforeDone,
            totals: &totals
        ) else { return }
        let delivered = sendAll(rawOutput.data, to: ctx.clientSocket, flags: ctx.sendFlags)
        totals.recordAdvisoryIfDelivered(
            delivered,
            count: rawOutput.advisoryCount,
            types: rawOutput.advisoryTypes
        )
    }

    private static func relayRawStreamChunk(
        _ chunk: Data,
        parser: inout SSEFrameParser,
        alert: RawStreamAlertContext,
        totals: inout StreamScanTotals,
        alertState: inout RawStreamAlertState
    ) -> StreamChunkRelayResult? {
        if alertState.sawDone {
            // WO-380 and WO-508: keep one-shot alert state while preserving chunk-spanning scans.
            return relayPostDoneRawStreamChunk(
                chunk, parser: &parser, ctx: alert.stream, totals: &totals
            )
        }
        guard alert.alertBeforeDone != nil else {
            // WO-324/WO-404: raw_stream skips SSE parsing but still honors the certainty gate.
            let redaction = redactRawBytes(
                chunk,
                config: alert.stream.config,
                severity: alert.stream.severity,
                customRules: alert.stream.customRules
            )
            totals.recordCritical(redaction)
            return StreamChunkRelayResult(
                data: redaction.data,
                advisoryCount: redaction.advisoryCount,
                advisoryTypes: redaction.advisoryTypes
            )
        }

        _ = parser // WO-351: raw_stream no longer uses frame assembly for delivery.
        alertState.pending.append(chunk)
        if let doneRange = alertState.pending.range(of: rawStreamDoneLine) {
            let data = alertState.pending
            alertState.pending.removeAll(keepingCapacity: true)
            alertState.sawDone = true
            guard let frameEnd = rawStreamDoneFrameEnd(in: data, after: doneRange.upperBound) else {
                return relayRawStreamBufferedData(
                    data,
                    doneLineStart: doneRange.lowerBound,
                    alert: alert,
                    totals: &totals,
                    alertState: &alertState
                )
            }
            let terminal = relayRawStreamBufferedData(
                Data(data[..<frameEnd]),
                doneLineStart: doneRange.lowerBound,
                alert: alert,
                totals: &totals,
                alertState: &alertState
            )
            let trailing = Data(data[frameEnd...])
            guard !trailing.isEmpty,
                  let postDone = relayPostDoneRawStreamChunk(
                    trailing, parser: &parser, ctx: alert.stream, totals: &totals
                  ) else {
                return terminal
            }
            var output = terminal.data
            output.append(postDone.data)
            return StreamChunkRelayResult(
                data: output,
                advisoryCount: terminal.advisoryCount + postDone.advisoryCount,
                advisoryTypes: terminal.advisoryTypes + postDone.advisoryTypes
            )
        }

        guard alertState.pending.count > rawStreamDeliveryLookbehindBytes else {
            return nil
        }
        let emitEnd = alertState.pending.index(
            alertState.pending.startIndex,
            offsetBy: alertState.pending.count - rawStreamDeliveryLookbehindBytes
        )
        let data = Data(alertState.pending[..<emitEnd])
        alertState.pending.removeSubrange(..<emitEnd)
        return relayRawStreamBufferedData(
            data,
            doneLineStart: nil,
            alert: alert,
            totals: &totals,
            alertState: &alertState
        )
    }

    private static func relayRawStreamBufferedData(
        _ data: Data,
        doneLineStart: Data.Index?,
        alert: RawStreamAlertContext,
        totals: inout StreamScanTotals,
        alertState: inout RawStreamAlertState
    ) -> StreamChunkRelayResult {
        let redaction = redactRawBytes(
            data,
            config: alert.stream.config,
            severity: alert.stream.severity,
            customRules: alert.stream.customRules
        )
        totals.recordCritical(redaction)
        let advisory = detectNewRawStreamAdvisories(
            data,
            state: &alertState,
            config: alert.stream.config,
            severity: alert.stream.severity,
            customRules: alert.stream.customRules
        )
        var output = redaction.data
        if doneLineStart != nil,
           let doneRange = output.range(of: rawStreamDoneLine),
           let alertData = alert.alertBeforeDone?(
            totals.redactionCount,
            totals.redactionTypes,
            totals.advisoryCount + advisory.count,
            totals.advisoryTypes + advisory.types
           ) {
            let frameStart = rawStreamFrameStart(in: output, before: doneRange.lowerBound)
            output.insert(contentsOf: alertData, at: frameStart)
        }
        return StreamChunkRelayResult(
            data: output,
            advisoryCount: advisory.count,
            advisoryTypes: advisory.types
        )
    }

    // WO-508: malformed trailing SSE still receives bounded, cross-chunk redaction.
    private static func relayPostDoneRawStreamChunk(
        _ chunk: Data,
        parser: inout SSEFrameParser,
        ctx: StreamContext,
        totals: inout StreamScanTotals
    ) -> StreamChunkRelayResult? {
        let result = parser.feed(chunk)
        let data: Data
        if result.overflowFlushed {
            data = result.overflowBytes
        } else {
            var frames = Data()
            for frame in result.frames {
                frames.append(frame.raw)
            }
            guard !frames.isEmpty else { return nil }
            data = frames
        }
        let redaction = redactRawBytes(
            data, config: ctx.config, severity: ctx.severity, customRules: ctx.customRules
        )
        totals.recordCritical(redaction)
        return StreamChunkRelayResult(
            data: redaction.data,
            advisoryCount: redaction.advisoryCount,
            advisoryTypes: redaction.advisoryTypes
        )
    }

    private static func relayRawStreamEOF(
        parser: inout SSEFrameParser,
        state: inout RawStreamAlertState,
        ctx: StreamContext,
        alertBeforeDone: StreamAlertBuilder?,
        totals: inout StreamScanTotals
    ) -> StreamChunkRelayResult? {
        if state.sawDone {
            // WO-508: flush a final partial post-DONE frame without rebuilding the alert.
            let data = parser.remainingBytes
            guard !data.isEmpty else { return nil }
            let redaction = redactRawBytes(
                data, config: ctx.config, severity: ctx.severity, customRules: ctx.customRules
            )
            totals.recordCritical(redaction)
            return StreamChunkRelayResult(
                data: redaction.data,
                advisoryCount: redaction.advisoryCount,
                advisoryTypes: redaction.advisoryTypes
            )
        }
        if state.pending.isEmpty {
            guard let alert = alertBeforeDone?(
                totals.redactionCount,
                totals.redactionTypes,
                totals.advisoryCount,
                totals.advisoryTypes
            ) else { return nil }
            return StreamChunkRelayResult(data: alert, advisoryCount: 0, advisoryTypes: [])
        }

        let data = state.pending
        state.pending.removeAll(keepingCapacity: true)
        let redaction = redactRawBytes(
            data, config: ctx.config, severity: ctx.severity, customRules: ctx.customRules
        )
        totals.recordCritical(redaction)
        let advisory = detectNewRawStreamAdvisories(
            data,
            state: &state,
            config: ctx.config,
            severity: ctx.severity,
            customRules: ctx.customRules
        )
        var output = redaction.data
        // WO-352: no [DONE] arrived, so deliver the advisory event after the final bytes.
        if let alert = alertBeforeDone?(
            totals.redactionCount,
            totals.redactionTypes,
            totals.advisoryCount + advisory.count,
            totals.advisoryTypes + advisory.types
        ) {
            output.append(alert)
        }
        return StreamChunkRelayResult(
            data: output,
            advisoryCount: advisory.count,
            advisoryTypes: advisory.types
        )
    }

    private static func detectNewRawStreamAdvisories(
        _ delivered: Data,
        state: inout RawStreamAlertState,
        config: PastewatchConfig,
        severity: Severity,
        customRules: [CustomRule]
    ) -> (count: Int, types: [String]) {
        guard !delivered.isEmpty else { return (0, []) }
        state.advisoryScanTail.append(delivered)
        if state.advisoryScanTail.count > rawStreamAdvisoryScanWindowBytes {
            let overflow = state.advisoryScanTail.count - rawStreamAdvisoryScanWindowBytes
            let trimOffset = utf8AlignedTrimOffset(in: state.advisoryScanTail, minimumOffset: overflow)
            let trimEnd = state.advisoryScanTail.index(
                state.advisoryScanTail.startIndex,
                offsetBy: trimOffset
            )
            // WO-377/WO-387: advance by the exact removed byte count so later
            // signatures stay absolute even when trim skips UTF-8 continuation bytes.
            state.advisoryScanBaseOffset += trimOffset
            state.advisoryScanTail.removeSubrange(..<trimEnd)
        }

        // swiftlint:disable optional_data_string_conversion
        let text = String(bytes: state.advisoryScanTail, encoding: .utf8) ??
            String(decoding: Array(state.advisoryScanTail), as: UTF8.self)
        // swiftlint:enable optional_data_string_conversion
        let matches = streamAdvisoryMatches(
            scanStreamText(text, config: config, customRules: customRules),
            severity: severity,
            site: .proxyResponse
        )
        var types: [String] = []
        for match in matches {
            let lowerOffset = text[..<match.range.lowerBound].utf8.count
            let upperOffset = text[..<match.range.upperBound].utf8.count
            let signature = [
                match.displayName,
                "\(state.advisoryScanBaseOffset + lowerOffset)",
                "\(state.advisoryScanBaseOffset + upperOffset)",
                match.value
            ].joined(separator: ":")
            guard state.seenAdvisorySignatures.insert(signature).inserted else { continue }
            types.append(match.displayName)
        }
        return (types.count, types)
    }

    private static func rawStreamFrameStart(in data: Data, before doneLineStart: Data.Index) -> Data.Index {
        let prefix = Data(data[..<doneLineStart])
        let crlfTerminator = Data([0x0D, 0x0A, 0x0D, 0x0A])
        let lfTerminator = Data([0x0A, 0x0A])
        let crlfStart = prefix.range(of: crlfTerminator, options: .backwards)?.upperBound
        let lfStart = prefix.range(of: lfTerminator, options: .backwards)?.upperBound
        // WO-368: offsets are measured in delivered bytes before `[DONE]`. The
        // larger upperBound is the closest complete frame delimiter, so advisory
        // insertion lands before the `[DONE]` frame even when CRLF and LF frames mix.
        // WO-384: preserve an unterminated prefix and splice directly at DONE.
        guard crlfStart != nil || lfStart != nil else { return doneLineStart }
        return max(crlfStart ?? 0, lfStart ?? 0)
    }

    // WO-508: bytes after a complete DONE frame belong to the post-DONE parser.
    private static func rawStreamDoneFrameEnd(
        in data: Data,
        after doneLineEnd: Data.Index
    ) -> Data.Index? {
        let trailing = data[doneLineEnd...]
        let crlf = Data([0x0D, 0x0A, 0x0D, 0x0A])
        let lf = Data([0x0A, 0x0A])
        let crlfEnd = trailing.range(of: crlf)?.upperBound
        let lfEnd = trailing.range(of: lf)?.upperBound
        switch (crlfEnd, lfEnd) {
        case let (left?, right?): return min(left, right)
        case let (left?, nil): return left
        case let (nil, right?): return right
        case (nil, nil): return nil
        }
    }

    private static func relayRawStreamOverflow(
        _ data: Data,
        ctx: StreamContext,
        alertBeforeDone: ((
            _ streamCount: Int,
            _ streamTypes: [String],
            _ advisoryCount: Int,
            _ advisoryTypes: [String]
        ) -> Data?)?,
        totals: inout StreamScanTotals
    ) -> StreamChunkRelayResult {
        let redaction = redactRawBytes(
            data, config: ctx.config, severity: ctx.severity, customRules: ctx.customRules
        )
        totals.recordCritical(redaction)
        let alert = alertBeforeDone?(
            totals.redactionCount,
            totals.redactionTypes,
            totals.advisoryCount + redaction.advisoryCount,
            totals.advisoryTypes + redaction.advisoryTypes
        )
        return StreamChunkRelayResult(
            data: insertingSSEDataBeforeDone(alert, into: redaction.data),
            advisoryCount: redaction.advisoryCount,
            advisoryTypes: redaction.advisoryTypes
        )
    }

    /// WO-164: redact raw bytes that bypassed the SSE frame parser (overflow path).
    /// Treats the whole buffer as plain text, scans it, and obfuscates in-place.
    private static func redactRawBytes(
        _ raw: Data,
        config: PastewatchConfig,
        severity: Severity,
        customRules: [CustomRule]
    ) -> SSEFrameRedactionResult {
        redactRawStreamBytes(raw, config: config, severity: severity, customRules: customRules)
    }

    /// WO-359: detect ASCII credentials inside otherwise non-UTF-8 response bodies
    /// without round-tripping the full binary body through a lossy string.
    static func redactNonUTF8ResponseBody(
        _ body: Data,
        config: PastewatchConfig,
        severity: Severity,
        customRules: [CustomRule]? = nil
    ) -> SSEFrameRedactionResult {
        guard !body.isEmpty else {
            return SSEFrameRedactionResult(data: body, count: 0, types: [])
        }
        // swiftlint:disable:next optional_data_string_conversion
        let lossyText = String(decoding: body, as: UTF8.self)
        let matches = DetectionRules.scan(
            lossyText,
            config: config,
            customRules: customRules ?? CustomRule.compileValid(config.customRules)
        )
        let redactionMatches = mutationSafeProxyMatches(matches, site: .proxyResponse)
            .sorted { $0.range.lowerBound < $1.range.lowerBound }
        let advisories = streamAdvisoryMatches(
            matches,
            severity: severity,
            site: .proxyResponse
        )
        let advisoryTypes = advisories.map { $0.displayName }
        guard !redactionMatches.isEmpty else {
            return SSEFrameRedactionResult(
                data: body, count: 0, types: [],
                advisoryCount: advisories.count, advisoryTypes: advisoryTypes
            )
        }

        var replacements: [NonUTF8ResponseReplacement] = []
        var typeCounters: [SensitiveDataType: Int] = [:]
        var searchStart = body.startIndex
        for match in redactionMatches {
            guard match.value.unicodeScalars.allSatisfy({ $0.value <= 0x7F }) else { continue }
            let needle = Data(match.value.utf8)
            guard !needle.isEmpty,
                  let range = body.range(of: needle, options: [], in: searchStart..<body.endIndex) else {
                continue
            }
            let number = (typeCounters[match.type] ?? 0) + 1
            typeCounters[match.type] = number
            let placeholder = Data(Obfuscator.makePlaceholder(type: match.type, number: number).utf8)
            replacements.append(NonUTF8ResponseReplacement(
                range: range,
                placeholder: placeholder,
                type: match.displayName
            ))
            searchStart = range.upperBound
        }
        guard !replacements.isEmpty else {
            return SSEFrameRedactionResult(
                data: body, count: 0, types: [],
                advisoryCount: advisories.count, advisoryTypes: advisoryTypes
            )
        }

        var redacted = body
        for replacement in replacements.reversed() {
            redacted.replaceSubrange(replacement.range, with: replacement.placeholder)
        }
        return SSEFrameRedactionResult(
            data: redacted,
            count: replacements.count,
            types: replacements.map(\.type),
            advisoryCount: advisories.count,
            advisoryTypes: advisoryTypes
        )
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
            200: "OK", 201: "Created", 202: "Accepted", 204: "No Content", 206: "Partial Content",
            301: "Moved Permanently", 302: "Found", 304: "Not Modified",
            400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
            404: "Not Found", 405: "Method Not Allowed", 408: "Request Timeout",
            409: "Conflict", 415: "Unsupported Media Type", 429: "Too Many Requests",
            500: "Internal Server Error", 502: "Bad Gateway",
            503: "Service Unavailable", 504: "Gateway Timeout"
        ]
        return phrases[status] ?? "Unknown"
    }
}
