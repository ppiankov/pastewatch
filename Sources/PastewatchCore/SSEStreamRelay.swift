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
    private var headersSent = false
    private var streamError: Error?

    /// Parser for per-event redaction mode.
    private var parser = SSEFrameParser()
    /// True once the HTTP response headers have been written to the client socket.
    private var didWriteHeaders = false

    private var lastChunkTime: DispatchTime = .now()
    private var idleTimer: DispatchSourceTimer?

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
            idleTimer?.cancel()
            return
        }

        if responseStatus == 0 {
            // Error path: headReceived was signalled via urlSession(_:task:didCompleteWithError:)
            sendErrorDirect(status: 502, message: "Bad Gateway")
            idleTimer?.cancel()
            return
        }

        // Write streaming response headers once.
        if !didWriteHeaders {
            writeStreamingHeaders(status: responseStatus, upstreamHeaders: responseHeaders)
            didWriteHeaders = true
        }

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

        if !didWriteHeaders {
            writeStreamingHeaders(status: responseStatus, upstreamHeaders: responseHeaders)
            didWriteHeaders = true
        }

        switch redactionMode {
        case "raw_stream":
            // Relay raw — no redaction.
            writeToSocket(data)

        case "per_sse_event":
            let result = parser.feed(data)
            if result.overflowFlushed {
                // Oversized frame: relay raw bytes as fail-safe.
                writeToSocket(result.overflowBytes)
                return
            }
            for frame in result.frames {
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
        // Flush any partial SSE remainder on clean close.
        if redactionMode == "per_sse_event" {
            let rem = parser.remainingBytes
            if !rem.isEmpty {
                writeToSocket(rem)
            }
        }

        if let err = error {
            streamError = err
            // Surface mid-stream upstream drop predictably.
            let notice = Data("[PASTEWATCH-STREAM-DROP] upstream disconnect: \(err.localizedDescription)\n\n".utf8)
            writeToSocket(notice)
        }

        // If head was never received (connection refused, DNS fail), signal head too.
        if responseStatus == 0 {
            headReceived.signal()
        }
        streamDone.signal()
    }

    // MARK: - Private

    private func writeStreamingHeaders(status: Int, upstreamHeaders: [AnyHashable: Any]) {
        var response = "HTTP/1.1 \(status) OK\r\n"
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

    private func redactFrame(_ frame: SSEFrameParser.Frame) -> Data {
        guard let dataPayload = frame.data, dataPayload != "[DONE]" else {
            return frame.raw
        }
        guard let jsonData = dataPayload.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: jsonData) as? [String: Any] else {
            return frame.raw
        }
        // Scan the JSON payload text fields for secrets.
        var redacted = 0
        var types: [String] = []
        _ = scanAndRedactJSON(json, redacted: &redacted, types: &types)
        guard redacted > 0,
              let jsonStr = extractTextFromJSON(json) else {
            return frame.raw
        }
        let matches = DetectionRules.scan(jsonStr, config: config)
        let filtered = matches.filter { $0.effectiveSeverity >= severity }
        guard !filtered.isEmpty else { return frame.raw }
        let obfuscated = Obfuscator.obfuscate(jsonStr, matches: filtered)

        // Re-emit with the obfuscated text substituted in.
        if let modifiedPayload = substituteText(in: json, newText: obfuscated),
           let resultData = try? JSONSerialization.data(withJSONObject: modifiedPayload),
           let resultStr = String(data: resultData, encoding: .utf8) {
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

    private func scanAndRedactJSON(_ json: [String: Any], redacted: inout Int, types: inout [String]) -> [String: Any] {
        if let text = extractTextFromJSON(json) {
            let matches = DetectionRules.scan(text, config: config)
            let filtered = matches.filter { $0.effectiveSeverity >= severity }
            redacted = filtered.count
            types = filtered.map { $0.displayName }
        }
        return json
    }

    // MARK: - Idle timer

    private func startIdleTimer(task: URLSessionDataTask) {
        let timer = DispatchSource.makeTimerSource(queue: DispatchQueue.global())
        timer.schedule(deadline: .now() + idleTimeoutSeconds, repeating: .never)
        timer.setEventHandler { [weak self, weak task] in
            task?.cancel()
            self?.streamDone.signal()
        }
        timer.resume()
        idleTimer = timer
    }

    private func resetIdleTimer(_ timer: DispatchSourceTimer, task: URLSessionTask) {
        timer.schedule(deadline: .now() + idleTimeoutSeconds, repeating: .never)
    }
}

#endif
