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

    /// Parser for per-event redaction mode.
    private var parser = SSEFrameParser()
    /// WO-179: guards didWriteHeaders across execute() error paths and the delegate queue.
    /// WO-194: renamed from headersLock; also protects timerDidFire (checked together with
    /// didWriteHeaders in didCompleteWithError — their coupling is intentional).
    private let socketWriteLock = NSLock()
    private var didWriteHeaders = false
    /// WO-170: set by the idle-timer handler before signaling streamDone so that the
    /// async didCompleteWithError callback skips writing headers to the already-closed socket.
    private var timerDidFire = false
    /// WO-178: prevents double-signal on streamDone when both the idle timer and
    /// didCompleteWithError reach the signal site.
    /// WO-194: separate lock; streamDoneSignaled has no coupling to didWriteHeaders/timerDidFire.
    private let signalLock = NSLock()
    private var streamDoneSignaled = false

    /// WO-153: count and type names of secrets redacted from SSE frames.
    private(set) var streamRedactionCount = 0
    private(set) var streamRedactionTypes: [String] = []

    /// WO-182: when non-nil, called just before [DONE] is forwarded to the client socket.
    /// The closure returns an SSE event frame (raw bytes) to inject, or nil to skip.
    /// Invoked on the URLSession delegate queue with stream-only counts accumulated so far.
    /// WO-195: body-scan counts captured by the closure's own scope (no relay properties needed).
    var buildAlertBeforeDone: ((_ streamCount: Int, _ streamTypes: [String]) -> Data?)?

    /// WO-209/215: retained so EPIPE paths in the frame loop and writeToSocket() can cancel
    /// the task without every call site threading the task reference through.
    private weak var activeTask: URLSessionTask?
    /// WO-227: set to true by any EPIPE path so didCompleteWithError skips the remainder
    /// flush and drop notice — the client is gone and writing burns CPU + inflates stats.
    /// WO-233: all writes go through socketWriteLock (same lock as didWriteHeaders/timerDidFire)
    /// so the connection-thread write in writeToSocket() is visible to delegate-queue readers.
    private var clientEpipe = false
    private var idleTimer: DispatchSourceTimer?
    /// Queue owning the idle timer — create/cancel must run here.
    /// WO-199: timer is cancel-and-recreated on each data chunk so the event handler
    /// (fired from timerQueue) can never fire after a valid chunk arrives. timerQueue.sync
    /// alone is insufficient: if the event handler is already enqueued on timerQueue when
    /// resetIdleTimer's sync block runs, the handler executes AFTER the reschedule completes.
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
        activeTask = task
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
            socketWriteLock.lock(); didWriteHeaders = true; socketWriteLock.unlock()
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
            socketWriteLock.lock(); didWriteHeaders = true; socketWriteLock.unlock()
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
        // WO-199: cancel-and-recreate so any event handler already enqueued before the response
        // head arrived cannot fire spuriously.
        resetIdleTimer(task: dataTask)
        headReceived.signal()
        completionHandler(.allow)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        // WO-230: URLSession may buffer and deliver data chunks after cancel() is called.
        // WO-232: idle timer sets timerDidFire (not clientEpipe) before cancel(); check both so
        // post-timer-cancel chunks do not write to the already-closed clientSocket fd.
        // timerDidFire is written under socketWriteLock; capture it there.
        socketWriteLock.lock()
        let shouldExit = clientEpipe || timerDidFire
        let needsHeaders = !didWriteHeaders
        // WO-241: set didWriteHeaders even when shouldExit=true so didCompleteWithError
        // does not attempt a spurious sendAll() to the already-dead client socket.
        if needsHeaders { didWriteHeaders = true }
        socketWriteLock.unlock()
        guard !shouldExit else { return }

        // WO-199: cancel the old timer and create a fresh one so no previously-enqueued event
        // handler can fire after this data chunk arrived. timerQueue.sync alone is insufficient:
        // a handler already enqueued on timerQueue before the sync block runs will execute after
        // the reschedule completes, producing a spurious timeout.
        resetIdleTimer(task: dataTask)

        // WO-222: propagate header EPIPE — if the client disconnected before we could send
        // the HTTP headers, cancel the task and skip the frame loop entirely.
        // WO-227: also set clientEpipe so didCompleteWithError skips the remainder flush.
        if needsHeaders {
            if !writeStreamingHeaders(status: responseStatus, upstreamHeaders: responseHeaders) {
                clientEpipe = true; activeTask?.cancel()
                return
            }
        }

        switch redactionMode {
        case "raw_stream":
            // Relay raw — no redaction.
            // WO-223/227: propagate EPIPE; set clientEpipe so didCompleteWithError skips remainder.
            if !sendAll(data, to: clientSocket, flags: sendFlags) { clientEpipe = true; activeTask?.cancel() }

        case "per_sse_event":
            let result = parser.feed(data)
            if result.overflowFlushed {
                // WO-164: 4MB+ frame bypassed per-frame path; redact as raw text.
                writeToSocket(redactRawBytes(result.overflowBytes))
                // WO-244: writeToSocket() may have set clientEpipe and cancelled activeTask,
                // but the idle timer is still armed. Cancel it explicitly so execute() does not
                // wait up to 60s for a timer that will fire against a dead connection.
                // timerQueue.async (not sync) to avoid deadlock if this callback fires from timerQueue.
                timerQueue.async { [weak self] in
                    self?.idleTimer?.cancel()
                }
                return
            }
            // WO-215: break out of the frame loop on EPIPE so we do not make redundant
            // kernel send() calls and no-op cancel() calls for the remaining frames.
            var epipe = false
            for frame in result.frames {
                guard !epipe else { break }
                // WO-182: inject the alert immediately before [DONE] so SSE consumers
                // (which stop reading at [DONE]) see the alert before the stream ends.
                // WO-182: invoke closure at [DONE] time with live stream counts.
                // WO-195: body counts are captured in the closure's own scope.
                if frame.data == "[DONE]",
                   let builder = buildAlertBeforeDone,
                   let alertData = builder(streamRedactionCount, streamRedactionTypes) {
                    if !sendAll(alertData, to: clientSocket, flags: sendFlags) {
                        clientEpipe = true; activeTask?.cancel()
                        epipe = true
                        break
                    }
                }
                // WO-201: skip redactFrame for [DONE] — the function's first line already
                // returns frame.raw for it, but the call is an always-no-op; avoid confusion.
                guard frame.data != "[DONE]" else {
                    if !sendAll(frame.raw, to: clientSocket, flags: sendFlags) {
                        clientEpipe = true; activeTask?.cancel()
                        epipe = true
                    }
                    continue
                }
                // WO-220: use shared redactSSEFrame() from SocketHelpers.swift.
                let r = redactSSEFrame(frame, config: config, severity: severity)
                streamRedactionCount += r.count
                streamRedactionTypes.append(contentsOf: r.types)
                if !sendAll(r.data, to: clientSocket, flags: sendFlags) {
                    clientEpipe = true; activeTask?.cancel()
                    epipe = true
                }
            }
            // Partial remainder stays in the parser buffer and is flushed at stream end.

        default:
            // Unknown mode: raw relay.
            // WO-223/227: propagate EPIPE; set clientEpipe so didCompleteWithError skips remainder.
            if !sendAll(data, to: clientSocket, flags: sendFlags) { clientEpipe = true; activeTask?.cancel() }
        }
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        // WO-177: capture timerDidFire once under the lock; all socket writes below are gated on it.
        // WO-194: socketWriteLock guards didWriteHeaders+timerDidFire together (intentional coupling).
        socketWriteLock.lock()
        let alreadyWritten = didWriteHeaders
        let timerFired = timerDidFire
        socketWriteLock.unlock()

        // WO-242: writeStreamingHeaders() calls sendAll(), a potentially-blocking syscall.
        // Holding socketWriteLock across it pins the lock for the full send duration, stalling
        // the idle timer event handler (timerQueue → socketWriteLock.lock()) for that window.
        // Move the header write outside the lock; the alreadyWritten/timerFired snapshot above
        // is stable — this callback and didReceive run on the serial URLSession delegate queue.
        // WO-163: if no data chunk arrived, write headers now. WO-170/177: skip on timer fire.
        // WO-228: check return value — on EPIPE the client is already gone; set clientEpipe so
        // the remainder flush and drop notice below are also skipped (matches WO-222 logic).
        if !alreadyWritten && !timerFired {
            let ok = writeStreamingHeaders(status: responseStatus == 0 ? 200 : responseStatus, upstreamHeaders: responseHeaders)
            socketWriteLock.lock()
            didWriteHeaders = true
            if !ok { clientEpipe = true }
            socketWriteLock.unlock()
        }

        // WO-239: re-snapshot clientEpipe under socketWriteLock. The connection thread
        // (504 timeout: execute() → sendErrorDirect() → writeToSocket()) may have set it
        // between the unlock above and this read. The bare read in the old code was the race.
        socketWriteLock.lock()
        let epipe = clientEpipe
        socketWriteLock.unlock()

        // WO-177: guard remainder flush and drop notice behind timerFired — after the idle timer
        // fires the socket is dead; writing to it would corrupt the next connection on that fd.
        // WO-227: also guard behind clientEpipe — client is gone; flush burns CPU and inflates stats.
        if !timerFired && !epipe {
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
                // WO-237: streamError property removed (was write-only dead state). Surface via socket.
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
        // WO-194: signalLock is independent of socketWriteLock; no coupling to headers/timer.
        signalLock.lock()
        let alreadySignaled = streamDoneSignaled
        if !alreadySignaled { streamDoneSignaled = true }
        signalLock.unlock()
        if !alreadySignaled {
            streamDone.signal()
        }
    }

    // MARK: - Private

    /// WO-222: returns false on EPIPE so callers can cancel the task and skip body relay.
    @discardableResult
    private func writeStreamingHeaders(status: Int, upstreamHeaders: [AnyHashable: Any]) -> Bool {
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
        return sendAll(Data(response.utf8), to: clientSocket, flags: sendFlags)
    }

    private func sendErrorDirect(status: Int, message: String) {
        let body = "{\"error\": \"\(message)\"}"
        let bodyBytes = Data(body.utf8)
        // WO-221: Content-Length must be byte count, not Swift character count.
        let response = "HTTP/1.1 \(status) \(message)\r\nContent-Type: application/json\r\nContent-Length: \(bodyBytes.count)\r\nConnection: close\r\n\r\n"
        var responseData = Data(response.utf8)
        responseData.append(bodyBytes)
        writeToSocket(responseData)
    }

    /// WO-206: delegates to the shared sendAll() in SocketHelpers.swift.
    /// WO-209: check return value — on false (EPIPE) the client disconnected.
    /// Cancel activeTask so the relay stops downloading upstream data instead of
    /// running the stream to completion and silently discarding every chunk.
    /// WO-227: set clientEpipe so didCompleteWithError skips remainder flush and drop notice.
    /// WO-233: clientEpipe written under socketWriteLock so the connection-thread call path
    /// (504 timeout: execute() → sendErrorDirect() → writeToSocket()) is synchronized with
    /// the delegate-queue readers in didReceive (WO-232 snapshot) and didCompleteWithError.
    private func writeToSocket(_ data: Data) {
        if !sendAll(data, to: clientSocket, flags: sendFlags) {
            socketWriteLock.lock()
            clientEpipe = true
            socketWriteLock.unlock()
            activeTask?.cancel()
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

    // MARK: - Idle timer

    private func startIdleTimer(task: URLSessionDataTask) {
        idleTimer = makeIdleTimer(task: task)
    }

    /// WO-199: cancel the current timer and install a fresh one so that any event handler
    /// already enqueued on timerQueue before this call is effectively voided — the old
    /// DispatchSourceTimer is cancelled, and the new one starts fresh with a full deadline.
    /// timerQueue.sync alone is insufficient (WO-187): a handler enqueued before the sync
    /// block runs executes after the reschedule, producing a spurious timeout.
    private func resetIdleTimer(task: URLSessionTask) {
        timerQueue.sync { [weak self] in
            guard let self = self else { return }
            self.idleTimer?.cancel()
            self.idleTimer = self.makeIdleTimerOnQueue(task: task)
        }
    }

    /// Build a new armed DispatchSourceTimer that signals stream timeout.
    /// Must be called from timerQueue (via resetIdleTimer) or before timerQueue is in use
    /// (startIdleTimer, which runs before the delegate queue starts calling back).
    private func makeIdleTimer(task: URLSessionTask) -> DispatchSourceTimer {
        // startIdleTimer is called before any delegate callbacks; no queue requirement yet.
        // Dispatch to timerQueue to keep all timer mutations on one serial queue.
        var timer: DispatchSourceTimer!
        timerQueue.sync { [weak self] in
            guard let self = self else { return }
            timer = self.makeIdleTimerOnQueue(task: task)
        }
        return timer
    }

    private func makeIdleTimerOnQueue(task: URLSessionTask) -> DispatchSourceTimer {
        let timer = DispatchSource.makeTimerSource(queue: timerQueue)
        timer.schedule(deadline: .now() + idleTimeoutSeconds, repeating: .never)
        timer.setEventHandler { [weak self, weak task] in
            // WO-170: mark timer fired BEFORE signaling streamDone so that the async
            // didCompleteWithError callback (which runs on the URLSession delegate queue)
            // sees the flag and skips writing headers to the already-closed socket.
            guard let self = self else { return }
            // WO-194: timerDidFire under socketWriteLock (coupled with didWriteHeaders check
            // in didCompleteWithError). streamDoneSignaled under its own signalLock.
            self.socketWriteLock.lock()
            self.timerDidFire = true
            self.socketWriteLock.unlock()
            self.signalLock.lock()
            let alreadySignaled = self.streamDoneSignaled
            if !alreadySignaled { self.streamDoneSignaled = true }
            self.signalLock.unlock()
            task?.cancel()
            if !alreadySignaled {
                self.streamDone.signal()
            }
        }
        timer.resume()
        return timer
    }
}

#endif
