import Foundation
#if canImport(Darwin)

/// WO-146/147: URLSession-based SSE streaming relay for the macOS proxy path.
/// Replaces the buffering dataTask+semaphore for streaming responses.
/// Each incoming data chunk is immediately forwarded to the client socket,
/// optionally passing through the SSE frame parser for per-event redaction.
final class SSEStreamRelay: NSObject, URLSessionDataDelegate {

    private let clientSocket: Int32
    private let sendFlags: Int32
    private let redactionMode: String
    private let config: PastewatchConfig
    private let severity: Severity
    private let idleTimeoutSeconds: Double

    /// Signals that the upstream response head has been received.
    private let headReceived = DispatchSemaphore(value: 0)
    /// Signals that the full stream has ended (or errored).
    private let streamDone = DispatchSemaphore(value: 0)

    private var responseStatus: Int = 0
    private var responseHeaders: [AnyHashable: Any] = [:]
    private var streamError: Error?

    /// Parser for per-event redaction mode.
    private var parser = SSEFrameParser()
    /// WO-179: guards didWriteHeaders across the caller thread (execute() error paths)
    /// and the URLSession delegate queue (didCompleteWithError / didReceive data).
    private let headersLock = NSLock()
    private var didWriteHeaders = false
    /// WO-170: set by the idle-timer handler before signaling streamDone so that the
    /// async didCompleteWithError callback skips writing headers to the already-closed socket.
    /// WO-178: also gates streamDone signaling — only the first signal goes through.
    private var timerDidFire = false
    /// WO-178: prevents double-signal on streamDone when both the idle timer and
    /// didCompleteWithError reach the signal site.
    private var streamDoneSignaled = false

    /// WO-153: count and type names of secrets redacted from SSE frames.
    private(set) var streamRedactionCount = 0
    private(set) var streamRedactionTypes: [String] = []

    /// WO-182: when non-nil, called just before [DONE] is forwarded to the client socket.
    /// The closure returns an SSE event frame (raw bytes) to inject, or nil to skip.
    /// Invoked on the URLSession delegate queue with the accumulated redaction counts at
    /// that point (body-scan redactions passed in + stream redactions accumulated so far).
    var buildAlertBeforeDone: ((_ bodyCount: Int, _ bodyTypes: [String], _ streamCount: Int, _ streamTypes: [String]) -> Data?)?
    /// WO-182: body-scan counts passed in from the caller so the alert can include them.
    var bodyRedactionCount: Int = 0
    var bodyRedactionTypes: [String] = []

    private var idleTimer: DispatchSourceTimer?
    /// Queue owning the idle timer — schedule/cancel must run here.
    private let timerQueue = DispatchQueue(label: "com.pastewatch.sse-idle-timer")

    init(
        clientSocket: Int32,
        sendFlags: Int32,
        redactionMode: String,
        config: PastewatchConfig,
        severity: Severity,
        idleTimeoutSeconds: Double
    ) {
        self.clientSocket = clientSocket
        self.sendFlags = sendFlags
        self.redactionMode = redactionMode
        self.config = config
        self.severity = severity
        self.idleTimeoutSeconds = idleTimeoutSeconds
    }

    /// Execute the upstream request and relay the response to `clientSocket`.
    /// Blocks until the stream ends, the idle timer fires, or the task fails.
    func execute(request: URLRequest, session: URLSession) {
        let task = session.dataTask(with: request)
        task.delegate = self
        task.resume()
        startIdleTimer(task: task)

        // Wait for the response head (or failure).
        let headWait = headReceived.wait(timeout: .now() + idleTimeoutSeconds)
        guard headWait == .success else {
            task.cancel()
            sendErrorDirect(status: 504, message: "Gateway Timeout (no response head)")
            // WO-171: mark headers written so the async didCompleteWithError callback does not
            // overwrite our error response with a spurious "HTTP/1.1 200 OK" preamble.
            // WO-179: lock because didCompleteWithError reads this from the delegate queue.
            headersLock.lock(); didWriteHeaders = true; headersLock.unlock()
            idleTimer?.cancel()
            // WO-176: wait for the delegate to finish so execute() does not return while
            // didCompleteWithError is still writing to the socket.
            _ = streamDone.wait(timeout: .now() + 5)
            return
        }

        if responseStatus == 0 {
            // Error path: headReceived was signalled via urlSession(_:task:didCompleteWithError:)
            sendErrorDirect(status: 502, message: "Bad Gateway")
            // WO-171: same guard — prevent async didCompleteWithError from corrupting the socket.
            // WO-179: lock because didCompleteWithError reads this from the delegate queue.
            headersLock.lock(); didWriteHeaders = true; headersLock.unlock()
            idleTimer?.cancel()
            // WO-176: wait for delegate to finish before execute() returns.
            _ = streamDone.wait(timeout: .now() + 5)
            return
        }

        // WO-159: do NOT write headers here. didReceive(data:) writes them under headerLock
        // before relaying the first data chunk. This eliminates the race where execute() writes
        // didWriteHeaders = true AFTER wait() returns on a different thread than the delegate
        // queue, causing both to see false and send duplicate HTTP headers.

        // Wait for stream to finish (data is relayed incrementally via delegate callbacks).
        _ = streamDone.wait(timeout: .now() + 3600) // max session length
        idleTimer?.cancel()
    }

    // MARK: - URLSessionDataDelegate

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse, completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        let http = response as? HTTPURLResponse
        responseStatus = http?.statusCode ?? 200
        responseHeaders = http?.allHeaderFields ?? [:]
        idleTimer.map { resetIdleTimer($0, task: dataTask) }
        headReceived.signal()
        completionHandler(.allow)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        // Reset idle timer on each received chunk.
        if let timer = idleTimer {
            resetIdleTimer(timer, task: dataTask)
        }

        // WO-179: lock because execute() error paths also write didWriteHeaders.
        headersLock.lock()
        let needsHeaders = !didWriteHeaders
        if needsHeaders { didWriteHeaders = true }
        headersLock.unlock()
        if needsHeaders {
            writeStreamingHeaders(status: responseStatus, upstreamHeaders: responseHeaders)
        }

        switch redactionMode {
        case "raw_stream":
            // Relay raw — no redaction.
            writeToSocket(data)

        case "per_sse_event":
            let result = parser.feed(data)
            if result.overflowFlushed {
                // WO-164: 4MB+ frame bypassed per-frame path; redact as raw text.
                writeToSocket(redactRawBytes(result.overflowBytes))
                return
            }
            for frame in result.frames {
                // WO-182: inject the alert immediately before [DONE] so SSE consumers
                // (which stop reading at [DONE]) see the alert before the stream ends.
                if frame.data == "[DONE]",
                   let builder = buildAlertBeforeDone,
                   let alertData = builder(bodyRedactionCount, bodyRedactionTypes, streamRedactionCount, streamRedactionTypes) {
                    writeToSocket(alertData)
                }
                let outData = redactFrame(frame)
                writeToSocket(outData)
            }
            // Partial remainder stays in the parser buffer and is flushed at stream end.

        default:
            // Unknown mode: raw relay.
            writeToSocket(data)
        }
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        // WO-177: capture timerDidFire once under the lock; all socket writes below are gated on it.
        headersLock.lock()
        let alreadyWritten = didWriteHeaders
        let timerFired = timerDidFire
        // WO-163: if no data chunk arrived, write headers now. WO-170/177: skip on timer fire.
        if !alreadyWritten && !timerFired {
            writeStreamingHeaders(status: responseStatus == 0 ? 200 : responseStatus, upstreamHeaders: responseHeaders)
            didWriteHeaders = true
        }
        headersLock.unlock()

        // WO-177: guard remainder flush and drop notice behind timerFired — after the idle timer
        // fires the socket is dead; writing to it would corrupt the next connection on that fd.
        if !timerFired {
            // Flush any partial SSE remainder on clean close.
            // WO-172: redact the remainder bytes — a partial frame may contain a mid-stream
            // credential that was split across chunk boundaries and never saw the per-frame path.
            if redactionMode == "per_sse_event" {
                let rem = parser.remainingBytes
                if !rem.isEmpty {
                    writeToSocket(redactRawBytes(rem))
                }
            }

            if let err = error {
                streamError = err
                // Surface mid-stream upstream drop predictably.
                let notice = Data("[PASTEWATCH-STREAM-DROP] upstream disconnect: \(err.localizedDescription)\n\n".utf8)
                writeToSocket(notice)
            }
        }

        // If head was never received (connection refused, DNS fail), signal head too.
        if responseStatus == 0 {
            headReceived.signal()
        }
        // WO-178: guard against double-signal when both the idle timer handler and this
        // callback reach the signal site (timer fires mid-stream, then curl still calls back).
        headersLock.lock()
        let alreadySignaled = streamDoneSignaled
        if !alreadySignaled { streamDoneSignaled = true }
        headersLock.unlock()
        if !alreadySignaled {
            streamDone.signal()
        }
    }

    // MARK: - Private

    private func writeStreamingHeaders(status: Int, upstreamHeaders: [AnyHashable: Any]) {
        // WO-175: use the correct reason phrase for the status code.
        var response = "HTTP/1.1 \(status) \(CurlHTTPClient.httpReasonPhrase(for: status))\r\n"
        // Forward streaming-relevant headers; exclude Content-Length (unknown for SSE).
        let streamingPassthrough = ["content-type", "cache-control", "x-request-id"]
        for (key, value) in upstreamHeaders {
            let k = "\(key)"
            let lower = k.lowercased()
            if lower == "content-length" { continue } // invalid on a streaming response
            if streamingPassthrough.contains(lower) || lower.hasPrefix("anthropic-") {
                response += "\(k): \(value)\r\n"
            }
        }
        response += "Transfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n"
        writeToSocket(Data(response.utf8))
    }

    private func sendErrorDirect(status: Int, message: String) {
        let body = "{\"error\": \"\(message)\"}"
        let response = "HTTP/1.1 \(status) \(message)\r\nContent-Type: application/json\r\nContent-Length: \(body.count)\r\nConnection: close\r\n\r\n\(body)"
        writeToSocket(Data(response.utf8))
    }

    private func writeToSocket(_ data: Data) {
        data.withUnsafeBytes { ptr in
            guard let base = ptr.baseAddress else { return }
            _ = send(clientSocket, base, ptr.count, sendFlags)
        }
    }

    /// WO-164: redact raw bytes that bypassed the SSE frame parser (overflow path).
    private func redactRawBytes(_ raw: Data) -> Data {
        guard let text = String(data: raw, encoding: .utf8) else { return raw }
        let matches = DetectionRules.scan(text, config: config)
        let filtered = matches.filter { $0.effectiveSeverity >= severity }
        guard !filtered.isEmpty else { return raw }
        streamRedactionCount += filtered.count
        streamRedactionTypes.append(contentsOf: filtered.map { $0.displayName })
        let obfuscated = Obfuscator.obfuscate(text, matches: filtered)
        return Data(obfuscated.utf8)
    }

    private func redactFrame(_ frame: SSEFrameParser.Frame) -> Data {
        guard let dataPayload = frame.data, dataPayload != "[DONE]" else {
            return frame.raw
        }
        guard let jsonData = dataPayload.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: jsonData) as? [String: Any],
              let jsonStr = extractTextFromJSON(json) else {
            return frame.raw
        }
        let matches = DetectionRules.scan(jsonStr, config: config)
        let filtered = matches.filter { $0.effectiveSeverity >= severity }
        guard !filtered.isEmpty else { return frame.raw }
        let obfuscated = Obfuscator.obfuscate(jsonStr, matches: filtered)

        // Re-emit with the obfuscated text substituted in.
        // WO-180: accumulate stats only after serialization succeeds — if serialization
        // fails we fall back to the raw frame (secret still in it), so stats must not claim
        // a redaction that did not reach the client.
        if let modifiedPayload = substituteText(in: json, newText: obfuscated),
           let resultData = try? JSONSerialization.data(withJSONObject: modifiedPayload),
           let resultStr = String(data: resultData, encoding: .utf8) {
            // WO-153: accumulate streaming redaction stats.
            streamRedactionCount += filtered.count
            streamRedactionTypes.append(contentsOf: filtered.map { $0.displayName })
            return frame.reserializedWith(data: resultStr)
        }
        return frame.raw
    }

    private func extractTextFromJSON(_ json: [String: Any]) -> String? {
        // Anthropic SSE delta: {"type":"content_block_delta","delta":{"type":"text_delta","text":"..."}}
        if let delta = json["delta"] as? [String: Any],
           let text = delta["text"] as? String {
            return text
        }
        return nil
    }

    private func substituteText(in json: [String: Any], newText: String) -> [String: Any]? {
        var result = json
        if var delta = json["delta"] as? [String: Any], delta["text"] != nil {
            delta["text"] = newText
            result["delta"] = delta
            return result
        }
        return nil
    }

    // MARK: - Idle timer

    private func startIdleTimer(task: URLSessionDataTask) {
        let timer = DispatchSource.makeTimerSource(queue: timerQueue)
        timer.schedule(deadline: .now() + idleTimeoutSeconds, repeating: .never)
        timer.setEventHandler { [weak self, weak task] in
            // WO-170: mark timer fired BEFORE signaling streamDone so that the async
            // didCompleteWithError callback (which runs on the URLSession delegate queue)
            // sees the flag and skips writing headers to the already-closed socket.
            guard let self = self else { return }
            // WO-178: guard against double-signal — didCompleteWithError may also fire.
            self.headersLock.lock()
            self.timerDidFire = true
            let alreadySignaled = self.streamDoneSignaled
            if !alreadySignaled { self.streamDoneSignaled = true }
            self.headersLock.unlock()
            task?.cancel()
            if !alreadySignaled {
                self.streamDone.signal()
            }
        }
        timer.resume()
        idleTimer = timer
    }

    /// WO-154: reset must be dispatched to the timer's own queue (timerQueue),
    /// not called directly from the URLSession delegate queue.
    private func resetIdleTimer(_ timer: DispatchSourceTimer, task: URLSessionTask) {
        timerQueue.async { [weak self] in
            guard let self = self else { return }
            timer.schedule(deadline: .now() + self.idleTimeoutSeconds, repeating: .never)
        }
    }
}

#endif
