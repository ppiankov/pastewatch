import Foundation
#if canImport(Darwin)

/// WO-292: hard ceiling for an otherwise-progressing stream session.
let sseStreamMaxSessionSeconds: Double = 3600
/// WO-355: upper bound for delegate-queue drain after URLSession invalidation.
let sseDelegateQueueDrainTimeoutSeconds: Double = 5

/// WO-146/147: URLSession-based SSE streaming relay for the macOS proxy path.
/// Replaces the buffering dataTask+semaphore for streaming responses.
/// Each incoming data chunk is immediately forwarded to the client socket,
/// optionally passing through the SSE frame parser for per-event redaction.
final class SSEStreamRelay: NSObject, URLSessionDataDelegate {
    private static let rawStreamDoneLine = Data("data: [DONE]".utf8) // WO-507: shared overflow latch.

    /// WO-400: consistent connection-thread snapshot of delegate-queue stream stats.
    struct StreamStatsSnapshot {
        let redactionCount: Int
        let redactionTypes: [String]
        let advisoryCount: Int
        let advisoryTypes: [String]
    }

    typealias TLSChallengeHandler = (
        URLSession,
        URLAuthenticationChallenge,
        @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) -> Void

    private let clientSocket: Int32
    private let sendFlags: Int32
    private let redactionMode: StreamingRedactionMode
    private let config: PastewatchConfig
    private let customRules: [CustomRule] // WO-473: validated once before proxy startup.
    private let severity: Severity
    private let idleTimeoutSeconds: Double
    private let maxSessionSeconds: Double // WO-292: hard ceiling before cancelling active stream task
    private let delegateQueueDrainTimeoutSeconds: Double // WO-355: avoid shutdown deadlock on invalidated sessions.
    private let tlsChallengeHandler: TLSChallengeHandler? // WO-305: preserve custom TLS trust policy.

    /// Signals that the upstream response head has been received.
    private let headReceived = DispatchSemaphore(value: 0)
    /// Signals that the full stream has ended (or errored).
    private let streamDone = DispatchSemaphore(value: 0)

    private var responseStatus: Int = 0
    private var responseHeaders: [AnyHashable: Any] = [:]

    /// Parser for per-event redaction mode.
    private var parser = SSEFrameParser()
    /// WO-398: raw_stream EOF without `[DONE]` still needs a final advisory.
    private var rawStreamSawDone = false
    /// WO-394: advisory injection is one-shot even if an upstream repeats `[DONE]`.
    private var sseEventSawDone = false
    /// WO-179: guards didWriteHeaders across execute() error paths and the delegate queue.
    /// WO-194: renamed from headersLock; also protects timerDidFire (checked together with
    /// didWriteHeaders in didCompleteWithError — their coupling is intentional).
    private let socketWriteLock = NSLock()
    private var didWriteHeaders = false
    /// WO-170: set by the idle-timer handler before signaling streamDone so that the
    /// async didCompleteWithError callback skips writing headers to the already-closed socket.
    private var timerDidFire = false
    /// WO-385: set by the max-session ceiling path so it can send one HTTP 504
    /// while still suppressing later delegate writes after task cancellation.
    private var sessionCeilingDidFire = false
    /// WO-178: prevents double-signal on streamDone when both the idle timer and
    /// didCompleteWithError reach the signal site.
    /// WO-194: separate lock; streamDoneSignaled has no coupling to didWriteHeaders/timerDidFire.
    private let signalLock = NSLock()
    private var streamDoneSignaled = false

    /// WO-400: protects stream stats mutated on the delegate queue and read by the connection thread.
    private let streamStatsLock = NSLock()
    /// WO-153: count and type names of secrets redacted from SSE frames.
    private var streamRedactionCountStorage = 0
    private var streamRedactionTypesStorage: [String] = []
    /// WO-324: lower-certainty stream detections are advisory-only and do not mutate bytes.
    private var streamAdvisoryCountStorage = 0
    private var streamAdvisoryTypesStorage: [String] = []
    var streamRedactionCount: Int { snapshotStreamStats().redactionCount }
    var streamRedactionTypes: [String] { snapshotStreamStats().redactionTypes }
    var streamAdvisoryCount: Int { snapshotStreamStats().advisoryCount }
    var streamAdvisoryTypes: [String] { snapshotStreamStats().advisoryTypes }

    /// WO-182: when non-nil, called just before [DONE] is forwarded to the client socket.
    /// The closure returns an SSE event frame (raw bytes) to inject, or nil to skip.
    /// Invoked on the URLSession delegate queue with stream-only counts accumulated so far.
    /// WO-195: body-scan counts captured by the closure's own scope (no relay properties needed).
    var buildAlertBeforeDone: ((
        _ streamCount: Int,
        _ streamTypes: [String],
        _ advisoryCount: Int,
        _ advisoryTypes: [String]
    ) -> Data?)?

    /// WO-209/215: retained so EPIPE paths in the frame loop and writeToSocket() can cancel
    /// the task without every call site threading the task reference through.
    private weak var activeTask: URLSessionTask?
    /// WO-227: set to true by any EPIPE path so didCompleteWithError skips the remainder
    /// flush and drop notice — the client is gone and writing burns CPU + inflates stats.
    /// WO-233: all writes go through socketWriteLock (same lock as didWriteHeaders/timerDidFire)
    /// so the connection-thread write in writeToSocket() is visible to delegate-queue readers.
    private var clientEpipe = false
    private var idleTimer: DispatchSourceTimer?
    /// Queue owning the idle timer — create/cancel/reschedule must run here.
    private let timerQueue = DispatchQueue(label: "com.pastewatch.sse-idle-timer")
    /// WO-301: guards against stale callbacks from an earlier timer deadline.
    private var idleDeadline: DispatchTime?

    init(
        clientSocket: Int32,
        sendFlags: Int32,
        redactionMode: StreamingRedactionMode,
        config: PastewatchConfig,
        customRules: [CustomRule]? = nil,
        severity: Severity,
        idleTimeoutSeconds: Double,
        maxSessionSeconds: Double = sseStreamMaxSessionSeconds,
        delegateQueueDrainTimeoutSeconds: Double = sseDelegateQueueDrainTimeoutSeconds,
        tlsChallengeHandler: TLSChallengeHandler? = nil
    ) {
        self.clientSocket = clientSocket
        self.sendFlags = sendFlags
        self.redactionMode = redactionMode
        self.config = config
        self.customRules = customRules ?? CustomRule.compileValid(config.customRules)
        self.severity = severity
        self.idleTimeoutSeconds = idleTimeoutSeconds
        self.maxSessionSeconds = maxSessionSeconds
        self.delegateQueueDrainTimeoutSeconds = delegateQueueDrainTimeoutSeconds
        self.tlsChallengeHandler = tlsChallengeHandler
    }

    /// Execute the upstream request and relay the response to `clientSocket`.
    /// Blocks until the stream ends, the idle timer fires, or the task fails.
    func execute(request: URLRequest, session: URLSession) {
        let task = session.dataTask(with: request)
        execute(task: task, session: session)
    }

    func snapshotStreamStats() -> StreamStatsSnapshot {
        streamStatsLock.lock()
        defer { streamStatsLock.unlock() }
        return StreamStatsSnapshot(
            redactionCount: streamRedactionCountStorage,
            redactionTypes: streamRedactionTypesStorage,
            advisoryCount: streamAdvisoryCountStorage,
            advisoryTypes: streamAdvisoryTypesStorage
        )
    }

    /// WO-314: let ProxyServer create the task under its shutdown lock, then hand
    /// it here before resume so streaming setup remains otherwise unchanged.
    func execute(task: URLSessionDataTask, session: URLSession) {
        task.delegate = self
        activeTask = task
        startIdleTimer(task: task)
        task.resume()

        // Wait for the response head (or failure).
        let headWait = headReceived.wait(timeout: .now() + idleTimeoutSeconds)
        guard headWait == .success else {
            task.cancel()
            sendErrorDirect(status: 504, message: "Gateway Timeout (no response head)")
            // WO-171: mark headers written so the async didCompleteWithError callback does not
            // overwrite our error response with a spurious "HTTP/1.1 200 OK" preamble.
            // WO-179: lock because didCompleteWithError reads this from the delegate queue.
            socketWriteLock.lock(); didWriteHeaders = true; socketWriteLock.unlock()
            cancelIdleTimerSync()
            // WO-176: wait for the delegate to finish so execute() does not return while
            // didCompleteWithError is still writing to the socket.
            _ = streamDone.wait(timeout: .now() + 5)
            drainDelegateQueue(session)
            return
        }

        if responseStatus == 0 {
            // Error path: headReceived was signalled via urlSession(_:task:didCompleteWithError:)
            sendErrorDirect(status: 502, message: "Bad Gateway")
            // WO-171: same guard — prevent async didCompleteWithError from corrupting the socket.
            // WO-179: lock because didCompleteWithError reads this from the delegate queue.
            socketWriteLock.lock(); didWriteHeaders = true; socketWriteLock.unlock()
            cancelIdleTimerSync()
            // WO-176: wait for delegate to finish before execute() returns.
            _ = streamDone.wait(timeout: .now() + 5)
            drainDelegateQueue(session)
            return
        }

        // WO-159: do NOT write headers here. didReceive(data:) writes them under headerLock
        // before relaying the first data chunk. This eliminates the race where execute() writes
        // didWriteHeaders = true AFTER wait() returns on a different thread than the delegate
        // queue, causing both to see false and send duplicate HTTP headers.

        // Wait for stream to finish (data is relayed incrementally via delegate callbacks).
        let streamWait = streamDone.wait(timeout: .now() + maxSessionSeconds)
        if streamWait == .timedOut {
            // WO-292/WO-385: cancel the task on the hard ceiling while preserving
            // the ability to send one HTTP 504 if no response bytes reached the client.
            markSessionCeilingAndCancelTask()
        }
        // WO-318: cancel the idle timer before draining the delegate queue on the
        // max-session path, so a late timer fire cannot race the shutdown drain.
        cancelIdleTimerSync()
        // WO-284: streamDone can be signaled by the idle timer while didReceive is still
        // finishing on the delegate queue. Drain it before callers read streamRedactionCount.
        drainDelegateQueue(session)
        sendIdleTimeoutErrorIfNeeded()
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
        let terminalTimeout = timerDidFire || sessionCeilingDidFire
        let shouldExit = clientEpipe || terminalTimeout
        let needsHeaders = !didWriteHeaders
        // WO-241/WO-385: only a live relay claims the header slot here. Timeout
        // paths must keep it open so execute() can send the single HTTP 504.
        if needsHeaders && !shouldExit { didWriteHeaders = true }
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
                // WO-283: clientEpipe is shared with writeToSocket() on the connection thread.
                markClientEpipeAndCancelTask()
                return
            }
        }

        switch redactionMode {
        case .rawStream:
            // WO-324/WO-404: raw_stream skips SSE parsing but still honors the certainty gate.
            relayRawRedactedData(data)

        case .perSSEEvent:
            relaySSEEventData(data)

        case .buffer:
            relayRawData(data)
        }
    }

    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard let tlsChallengeHandler else {
            completionHandler(.performDefaultHandling, nil)
            return
        }
        // WO-305: the per-task data delegate receives task-level TLS challenges;
        // forward them to the same trust evaluator used by buffered URLSession tasks.
        tlsChallengeHandler(session, challenge, completionHandler)
    }

    private func relayRawData(_ data: Data) {
        // Relay raw — no redaction.
        // WO-223/227: propagate EPIPE; set clientEpipe so didCompleteWithError skips remainder.
        if !sendAll(data, to: clientSocket, flags: sendFlags) {
            markClientEpipeAndCancelTask()
        }
    }

    private func relayRawRedactedData(_ data: Data) {
        guard buildAlertBeforeDone == nil else {
            relayRawRedactedFrames(data)
            return
        }
        let redaction = redactRawBytes(data)
        recordCriticalStreamScan(redaction)
        let output = insertingAlertBeforeDoneIfNeeded(redaction.data)
        if relayFrameData(output) {
            // WO-381: advisory stats describe bytes delivered to the client.
            recordAdvisoryStreamScan(redaction)
        }
    }

    private func relayRawRedactedFrames(_ data: Data) {
        let result = parser.feed(data)
        if result.overflowFlushed {
            let redaction = redactRawBytes(result.overflowBytes)
            recordCriticalStreamScan(redaction)
            let stats = snapshotStreamStats(adding: redaction)
            let output = insertingRawStreamOverflowAlertIfNeeded(redaction.data, stats: stats)
            if relayFrameData(output) {
                // WO-382: commit advisory stats only after the overflow batch is delivered.
                recordAdvisoryStreamScan(redaction)
            }
            return
        }

        var output = Data()
        var pendingAdvisoryCount = 0
        var pendingAdvisoryTypes: [String] = []
        for frame in result.frames {
            // WO-337: raw_stream preserves raw frame bytes, but still needs a frame-aware
            // [DONE] hook so alert/advisory events survive arbitrary URLSession chunking.
            guard frame.data != "[DONE]" else {
                if !rawStreamSawDone {
                    let stats = snapshotStreamStats(
                        addingAdvisoryCount: pendingAdvisoryCount,
                        advisoryTypes: pendingAdvisoryTypes
                    )
                    if let alert = buildAlertBeforeDoneFrameIfNeeded(stats) {
                        output.append(alert)
                    }
                }
                rawStreamSawDone = true
                // WO-389: [DONE] is a protocol sentinel, not payload; exclude it
                // from scan counts used by the advisory alert built immediately above.
                output.append(frame.raw)
                continue
            }
            let redaction = redactRawBytes(frame.raw)
            recordCriticalStreamScan(redaction)
            pendingAdvisoryCount += redaction.advisoryCount
            pendingAdvisoryTypes.append(contentsOf: redaction.advisoryTypes)
            output.append(redaction.data)
        }
        guard !output.isEmpty else { return }
        if relayFrameData(output) {
            // WO-382: raw alert batches expose advisories only after successful delivery.
            recordAdvisoryStreamScan(
                count: pendingAdvisoryCount,
                types: pendingAdvisoryTypes
            )
        }
    }

    private func relaySSEEventData(_ data: Data) {
        let result = parser.feed(data)
        if result.overflowFlushed {
            // WO-164: 4MB+ frame bypassed per-frame path; redact as raw text.
            let redaction = redactRawBytes(result.overflowBytes)
            recordCriticalStreamScan(redaction)
            if writeToSocket(redaction.data) {
                // WO-381: an EPIPE must not report an undelivered advisory.
                recordAdvisoryStreamScan(redaction)
            }
            // WO-244: writeToSocket() may have set clientEpipe and cancelled activeTask,
            // but the idle timer is still armed. Cancel it explicitly so execute() does not
            // wait up to 60s for a timer that will fire against a dead connection.
            // timerQueue.async (not sync) to avoid deadlock if this callback fires from timerQueue.
            if hasClientEpipe() {
                // WO-350: only clear the timer after an actual EPIPE. A successful
                // overflow relay must keep the active idle timeout armed.
                cancelIdleTimerAsync()
            }
            return
        }
        // WO-215: break out of the frame loop on EPIPE so we do not make redundant
        // kernel send() calls and no-op cancel() calls for the remaining frames.
        for frame in result.frames {
            guard relaySSEFrame(frame) else { break }
        }
        // Partial remainder stays in the parser buffer and is flushed at stream end.
    }

    private func relaySSEFrame(_ frame: SSEFrameParser.Frame) -> Bool {
        // WO-182: inject the alert immediately before [DONE] so SSE consumers
        // (which stop reading at [DONE]) see the alert before the stream ends.
        // WO-182: invoke closure at [DONE] time with live stream counts.
        // WO-195: body counts are captured in the closure's own scope.
        // WO-201: skip redactFrame for [DONE] — the function's first line already
        // returns frame.raw for it, but the call is an always-no-op; avoid confusion.
        // WO-251: combine alert + [DONE] into one sendAll so there is no EPIPE window
        // between them. Two separate sendAll calls could deliver the alert then fail on
        // [DONE], leaving SSE consumers (EventSource, openai-node) hung — they wait for
        // [DONE] to close the stream and never receive it.
        guard frame.data != "[DONE]" else {
            var toSend = Data()
            let stats = snapshotStreamStats()
            if !sseEventSawDone,
               let builder = buildAlertBeforeDone,
               let alertData = builder(
                stats.redactionCount,
                stats.redactionTypes,
                stats.advisoryCount,
                stats.advisoryTypes
               ) {
                toSend.append(alertData)
            }
            sseEventSawDone = true
            toSend.append(frame.raw)
            return relayFrameData(toSend)
        }
        // WO-220: use shared redactSSEFrame() from SocketHelpers.swift.
        let redaction = redactSSEFrame(
            frame,
            config: config,
            severity: severity,
            customRules: customRules
        )
        let delivered = relayFrameData(redaction.data)
        // WO-372/WO-404: mutation-safe redactions stay attempted-detection scoped, but
        // advisory-only matches are in-band guidance and must be delivery-scoped.
        recordCriticalStreamScan(redaction)
        if delivered {
            recordAdvisoryStreamScan(redaction)
        }
        return delivered
    }

    private func recordCriticalStreamScan(_ redaction: SSEFrameRedactionResult) {
        streamStatsLock.lock()
        streamRedactionCountStorage += redaction.count
        streamRedactionTypesStorage.append(contentsOf: redaction.types)
        streamStatsLock.unlock()
    }

    private func recordAdvisoryStreamScan(_ redaction: SSEFrameRedactionResult) {
        recordAdvisoryStreamScan(count: redaction.advisoryCount, types: redaction.advisoryTypes)
    }

    private func recordAdvisoryStreamScan(count: Int, types: [String]) {
        streamStatsLock.lock()
        streamAdvisoryCountStorage += count
        streamAdvisoryTypesStorage.append(contentsOf: types)
        streamStatsLock.unlock()
    }

    private func relayFrameData(_ data: Data) -> Bool {
        // WO-289: match sendAll() polarity: true = success, false = EPIPE.
        if sendAll(data, to: clientSocket, flags: sendFlags) {
            return true
        }
        markClientEpipeAndCancelTask()
        return false
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        // WO-177: capture timerDidFire once under the lock; all socket writes below are gated on it.
        // WO-194: socketWriteLock guards didWriteHeaders+timerDidFire together (intentional coupling).
        socketWriteLock.lock()
        let alreadyWritten = didWriteHeaders
        let terminalTimeout = timerDidFire || sessionCeilingDidFire
        let clientAlreadyDead = clientEpipe
        socketWriteLock.unlock()

        // WO-242: writeStreamingHeaders() calls sendAll(), a potentially-blocking syscall.
        // Holding socketWriteLock across it pins the lock for the full send duration, stalling
        // the idle timer event handler (timerQueue → socketWriteLock.lock()) for that window.
        // Move the header write outside the lock; the alreadyWritten/timerFired snapshot above
        // is stable — this callback and didReceive run on the serial URLSession delegate queue.
        // WO-163: if no data chunk arrived, write headers now. WO-170/177: skip on timer fire.
        // WO-228: check return value — on EPIPE the client is already gone; set clientEpipe so
        // the remainder flush and drop notice below are also skipped (matches WO-222 logic).
        // WO-246: skip when responseStatus==0 (connection failure). execute() will call
        // sendErrorDirect(502) after headReceived.signal(); writing 200 headers here first
        // corrupts the HTTP framing seen by the client.
        // WO-252: the ternary `responseStatus==0?200:responseStatus` is dead code — the guard
        // above requires responseStatus != 0, so the condition can never be true. Simplified.
        if !alreadyWritten && !terminalTimeout && !clientAlreadyDead && responseStatus != 0 {
            let ok = writeStreamingHeaders(status: responseStatus, upstreamHeaders: responseHeaders)
            socketWriteLock.lock()
            didWriteHeaders = true
            if !ok { clientEpipe = true }
            socketWriteLock.unlock()
        }

        // WO-239: re-snapshot clientEpipe under socketWriteLock. The connection thread
        // (504 timeout: execute() → sendErrorDirect() → writeToSocket()) may have set it
        // between the unlock above and this read. The bare read in the old code was the race.
        socketWriteLock.lock()
        let epipe = clientAlreadyDead || clientEpipe
        socketWriteLock.unlock()

        // WO-177: guard remainder flush and drop notice behind timerFired — after the idle timer
        // fires the socket is dead; writing to it would corrupt the next connection on that fd.
        // WO-227: also guard behind clientEpipe — client is gone; flush burns CPU and inflates stats.
        if !terminalTimeout && !epipe {
            // Flush any partial SSE remainder on clean close.
            // WO-172: redact the remainder bytes — a partial frame may contain a mid-stream
            // credential that was split across chunk boundaries and never saw the per-frame path.
            var epipeAfterFlush = false
            if redactionMode == .perSSEEvent {
                let rem = parser.remainingBytes
                if !rem.isEmpty {
                    let redaction = redactRawBytes(rem)
                    recordCriticalStreamScan(redaction)
                    if writeToSocket(redaction.data) {
                        // WO-383: remainder advisories are delivery-scoped on clean close.
                        recordAdvisoryStreamScan(redaction)
                    }
                    // WO-249: re-snapshot clientEpipe under socketWriteLock. writeToSocket()
                    // above may have set it — gate the drop-notice on the fresh value so we do
                    // not fire one wasted sendAll() call against a now-dead socket.
                    // WO-254: snapshot taken inside the flush branch only — no lock needed when
                    // the remainder was empty (no write occurred, epipe cannot have changed).
                    socketWriteLock.lock()
                    epipeAfterFlush = clientEpipe
                    socketWriteLock.unlock()
                }
            } else if redactionMode == .rawStream, buildAlertBeforeDone != nil {
                let rem = parser.remainingBytes
                if !rem.isEmpty {
                    let redaction = redactRawBytes(rem)
                    recordCriticalStreamScan(redaction)
                    let stats = snapshotStreamStats(adding: redaction)
                    let output = insertingAlertBeforeDoneOrEOFIfNeeded(redaction.data, stats: stats)
                    if writeToSocket(output) {
                        // WO-383: do not persist advisory stats for an undelivered tail.
                        recordAdvisoryStreamScan(redaction)
                    }
                    socketWriteLock.lock()
                    epipeAfterFlush = clientEpipe
                    socketWriteLock.unlock()
                } else if let alert = rawStreamEOFAlertIfNeeded() {
                    // WO-398: all frames may already be flushed when an upstream
                    // closes without `[DONE]`; append the advisory as the final event.
                    writeToSocket(alert)
                    socketWriteLock.lock()
                    epipeAfterFlush = clientEpipe
                    socketWriteLock.unlock()
                }
            }

            if let err = error, !epipeAfterFlush, responseStatus != 0 {
                // WO-332: a connection failure with no upstream response head must let
                // execute() send the HTTP 502 status line before any diagnostic body bytes.
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
        let response = CurlHTTPClient.buildStreamingResponseHeaders(
            status: status,
            upstreamHeaders: upstreamHeaders
        )
        return sendAll(Data(response.utf8), to: clientSocket, flags: sendFlags)
    }

    private func sendErrorDirect(status: Int, message: String) {
        let body = "{\"error\": \"\(message)\"}"
        let bodyBytes = Data(body.utf8)
        // WO-221: Content-Length must be byte count, not Swift character count.
        // WO-360: keep diagnostic detail in the body, not the HTTP reason phrase.
        let reason = CurlHTTPClient.httpReasonPhrase(for: status)
        let response = "HTTP/1.1 \(status) \(reason)\r\nContent-Type: application/json\r\nContent-Length: \(bodyBytes.count)\r\nConnection: close\r\n\r\n"
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
    @discardableResult
    private func writeToSocket(_ data: Data) -> Bool {
        if !sendAll(data, to: clientSocket, flags: sendFlags) {
            markClientEpipeAndCancelTask()
            return false
        }
        return true
    }

    private func markClientEpipeAndCancelTask() {
        // WO-283: all clientEpipe mutations are lock-protected to synchronize delegate
        // queue callbacks with the connection thread's timeout/error send path.
        socketWriteLock.lock()
        clientEpipe = true
        socketWriteLock.unlock()
        activeTask?.cancel()
    }

    private func markSessionCeilingAndCancelTask() {
        socketWriteLock.lock()
        sessionCeilingDidFire = true
        socketWriteLock.unlock()
        activeTask?.cancel()
    }

    private func hasClientEpipe() -> Bool {
        socketWriteLock.lock()
        defer { socketWriteLock.unlock() }
        return clientEpipe
    }

    private func drainDelegateQueue(_ session: URLSession) {
        // WO-355: after invalidateAndCancel(), some Foundation versions may stop
        // running newly-added delegateQueue operations. Bound the wait so shutdown
        // cannot deadlock the connection handler forever.
        if !Self.drainOperationQueue(session.delegateQueue, timeoutSeconds: delegateQueueDrainTimeoutSeconds) {
            FileHandle.standardError.write(Data(
                "[pastewatch-proxy] SSE delegate queue drain timed out; continuing shutdown\n".utf8
            ))
        }
    }

    static func drainOperationQueue(_ queue: OperationQueue, timeoutSeconds: Double) -> Bool {
        let drained = DispatchSemaphore(value: 0)
        DispatchQueue.global(qos: .utility).async {
            // WO-355: addOperation itself can block after session invalidation on
            // some Foundation versions, so keep it off the connection handler.
            queue.addOperation {
                drained.signal()
            }
        }
        return drained.wait(timeout: .now() + timeoutSeconds) == .success
    }

    private func insertingAlertBeforeDoneIfNeeded(_ data: Data) -> Data {
        insertingSSEDataBeforeDone(buildAlertBeforeDoneFrameIfNeeded(), into: data)
    }

    private func insertingAlertBeforeDoneIfNeeded(
        _ data: Data,
        stats: StreamStatsSnapshot
    ) -> Data {
        insertingSSEDataBeforeDone(buildAlertBeforeDoneFrameIfNeeded(stats), into: data)
    }

    // WO-507: overflow bypasses frame parsing, so it owns the raw terminal-state latch.
    func insertingRawStreamOverflowAlertIfNeeded(
        _ data: Data,
        stats: StreamStatsSnapshot
    ) -> Data {
        let sawDone = data.range(of: Self.rawStreamDoneLine) != nil
        let output = rawStreamSawDone
            ? data
            : insertingAlertBeforeDoneIfNeeded(data, stats: stats)
        if sawDone {
            rawStreamSawDone = true
        }
        return output
    }

    private func insertingAlertBeforeDoneOrEOFIfNeeded(
        _ data: Data,
        stats: StreamStatsSnapshot
    ) -> Data {
        let output = insertingAlertBeforeDoneIfNeeded(data, stats: stats)
        guard output == data, let alert = rawStreamEOFAlertIfNeeded(stats) else { return output }
        var appended = output
        appended.append(alert)
        return appended
    }

    private func rawStreamEOFAlertIfNeeded() -> Data? {
        rawStreamEOFAlertIfNeeded(snapshotStreamStats())
    }

    private func rawStreamEOFAlertIfNeeded(_ stats: StreamStatsSnapshot) -> Data? {
        guard !rawStreamSawDone,
              stats.redactionCount > 0 || stats.advisoryCount > 0 else {
            return nil
        }
        return buildAlertBeforeDoneFrameIfNeeded(stats)
    }

    private func buildAlertBeforeDoneFrameIfNeeded() -> Data? {
        buildAlertBeforeDoneFrameIfNeeded(snapshotStreamStats())
    }

    private func buildAlertBeforeDoneFrameIfNeeded(_ stats: StreamStatsSnapshot) -> Data? {
        guard let builder = buildAlertBeforeDone else { return nil }
        return builder(
            stats.redactionCount,
            stats.redactionTypes,
            stats.advisoryCount,
            stats.advisoryTypes
        )
    }

    private func snapshotStreamStats(adding redaction: SSEFrameRedactionResult) -> StreamStatsSnapshot {
        snapshotStreamStats(
            addingAdvisoryCount: redaction.advisoryCount,
            advisoryTypes: redaction.advisoryTypes
        )
    }

    private func snapshotStreamStats(
        addingAdvisoryCount count: Int,
        advisoryTypes: [String]
    ) -> StreamStatsSnapshot {
        let current = snapshotStreamStats()
        return StreamStatsSnapshot(
            redactionCount: current.redactionCount,
            redactionTypes: current.redactionTypes,
            advisoryCount: current.advisoryCount + count,
            advisoryTypes: current.advisoryTypes + advisoryTypes
        )
    }

    /// WO-164: redact raw bytes that bypassed the SSE frame parser (overflow path).
    private func redactRawBytes(_ raw: Data) -> SSEFrameRedactionResult {
        redactRawStreamBytes(raw, config: config, severity: severity, customRules: customRules)
    }

    private func sendIdleTimeoutErrorIfNeeded() {
        socketWriteLock.lock()
        // WO-349: a post-header idle timeout before the first body byte used to
        // return with no HTTP status line. Claim the write slot and send 504.
        // WO-385: max-session expiry shares the same single-error-response path.
        let shouldSend = (timerDidFire || sessionCeilingDidFire) &&
            !didWriteHeaders && !clientEpipe && responseStatus != 0
        if shouldSend {
            didWriteHeaders = true
        }
        socketWriteLock.unlock()
        guard shouldSend else { return }
        sendErrorDirect(status: 504, message: "Gateway Timeout")
    }

    // MARK: - Idle timer

    private func startIdleTimer(task: URLSessionDataTask) {
        timerQueue.sync {
            // WO-350: arm before task.resume() and mutate only on timerQueue so
            // fast delegate callbacks cannot race startup into a stale timer object.
            cancelIdleTimerOnQueue()
            idleTimer = makeIdleTimerOnQueue(task: task)
        }
    }

    private func cancelIdleTimerSync() {
        timerQueue.sync {
            cancelIdleTimerOnQueue()
        }
    }

    private func cancelIdleTimerAsync() {
        timerQueue.async { [weak self] in
            self?.cancelIdleTimerOnQueue()
        }
    }

    private func cancelIdleTimerOnQueue() {
        idleTimer?.cancel()
        idleTimer = nil
        idleDeadline = nil
    }

    /// WO-301: reschedule the current timer in place instead of canceling and allocating
    /// a fresh DispatchSourceTimer on every received upstream chunk.
    private func resetIdleTimer(task: URLSessionTask) {
        timerQueue.sync { [weak self] in
            guard let self = self else { return }
            let deadline = DispatchTime.now() + self.idleTimeoutSeconds
            self.idleDeadline = deadline
            if let idleTimer = self.idleTimer {
                idleTimer.schedule(deadline: deadline, repeating: .never)
            } else {
                self.idleTimer = self.makeIdleTimerOnQueue(task: task)
            }
        }
    }

    /// Build a new armed DispatchSourceTimer that signals stream timeout.
    /// Must be called from timerQueue (via resetIdleTimer) or before timerQueue is in use
    /// (startIdleTimer, which runs before the delegate queue starts calling back).
    private func makeIdleTimer(task: URLSessionTask) -> DispatchSourceTimer {
        // startIdleTimer is called before any delegate callbacks; no queue requirement yet.
        // Dispatch to timerQueue to keep all timer mutations on one serial queue.
        // WO-328: return the timer directly from sync; no weak-self IUO nil path.
        timerQueue.sync {
            makeIdleTimerOnQueue(task: task)
        }
    }

    private func makeIdleTimerOnQueue(task: URLSessionTask) -> DispatchSourceTimer {
        let timer = DispatchSource.makeTimerSource(queue: timerQueue)
        let deadline = DispatchTime.now() + idleTimeoutSeconds
        idleDeadline = deadline
        timer.schedule(deadline: deadline, repeating: .never)
        timer.setEventHandler { [weak self, weak task] in
            // WO-170: mark timer fired BEFORE signaling streamDone so that the async
            // didCompleteWithError callback (which runs on the URLSession delegate queue)
            // sees the flag and skips writing headers to the already-closed socket.
            guard let self = self else { return }
            if let idleDeadline = self.idleDeadline,
               DispatchTime.now().uptimeNanoseconds < idleDeadline.uptimeNanoseconds {
                // WO-301: a timer callback queued before a later chunk rescheduled
                // the deadline is stale; the active timer remains armed for the new deadline.
                return
            }
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
