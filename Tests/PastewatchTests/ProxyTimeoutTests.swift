import XCTest
@testable import PastewatchCore

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// WO-148: Verifies timeout constant values and CurlHTTPClient idle-based timeout args.
final class ProxyTimeoutTests: XCTestCase {

    // MARK: - Timeout constant sanity

    func testStreamIdleTimeoutIsReasonable() {
        // Must be > 0 and <= 3600 to be a sensible idle window.
        XCTAssertGreaterThan(proxyStreamIdleTimeoutSeconds, 0)
        XCTAssertLessThanOrEqual(proxyStreamIdleTimeoutSeconds, 3600)
    }

    func testNonStreamTotalTimeoutExceedsOldCap() {
        // The old 120s cap was the problem; new ceiling must be significantly larger.
        XCTAssertGreaterThan(proxyNonStreamTotalTimeoutSeconds, 120)
    }

    func testCurlSpeedTimeIsPositive() {
        XCTAssertGreaterThan(curlSpeedTimeSeconds, 0)
    }

    func testCurlHeaderTimeoutIsIndependentFromSpeedTime() {
        // WO-346: header-arrival and idle-data windows must be independently tunable.
        XCTAssertGreaterThan(curlHeaderTimeoutSeconds, 0)
        XCTAssertNotEqual(curlHeaderTimeoutSeconds, curlSpeedTimeSeconds)
    }

    func testCurlMaxTimeExceedsOldCap() {
        XCTAssertGreaterThan(curlMaxTimeSeconds, 120)
    }

    func testCurlStreamMaxTimeExceedsIdleWindow() {
        // WO-343: streaming curl has a hard ceiling, but it must not replace the idle budget.
        XCTAssertGreaterThan(curlStreamMaxTimeSeconds, curlSpeedTimeSeconds)
    }

    func testClientSocketTimeoutConstantIsNamedThirtySecondWindow() {
        XCTAssertEqual(proxyClientSocketTimeoutSeconds, 30)
        XCTAssertGreaterThan(proxyClientSocketTimeoutSeconds, 0)
    }

    func testCurlCancelActiveProcessesTerminatesRegisteredProcess() throws {
        // WO-370: Linux stop() relies on CurlHTTPClient.cancelActiveProcesses().
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/sleep")
        process.arguments = ["30"]
        try process.run()
        CurlHTTPClient.registerActiveProcessForTesting(process)
        defer {
            CurlHTTPClient.unregisterActiveProcessForTesting(process)
            if process.isRunning {
                process.terminate()
                process.waitUntilExit()
            }
        }

        let start = Date()
        CurlHTTPClient.cancelActiveProcesses()
        process.waitUntilExit()

        XCTAssertFalse(process.isRunning)
        XCTAssertLessThan(Date().timeIntervalSince(start), 2.0)
    }

    func testCurlStreamingHeaderTimeoutTerminatesProcess() throws {
        // WO-370: stalled response headers must terminate curl and return promptly.
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/sleep")
        process.arguments = ["30"]
        let bodyPipe = Pipe()
        let headerPipe = Pipe()
        process.standardOutput = bodyPipe
        process.standardError = headerPipe
        try process.run()
        defer {
            if process.isRunning {
                process.terminate()
                process.waitUntilExit()
            }
        }

        var sockets = [Int32](repeating: 0, count: 2)
        XCTAssertEqual(socketpair(AF_UNIX, timeoutTestSocketStreamType, 0, &sockets), 0)
        defer {
            close(sockets[0])
            close(sockets[1])
        }
        let ctx = CurlHTTPClient.StreamContext(
            clientSocket: sockets[1],
            sendFlags: timeoutTestSendFlags,
            redactionMode: .perSSEEvent,
            config: PastewatchConfig.defaultConfig,
            severity: .high
        )

        let start = Date()
        let response = CurlHTTPClient.relayStreamingResponse(
            process: process,
            bodyPipe: bodyPipe,
            headerPipe: headerPipe,
            ctx: ctx,
            headerTimeout: .milliseconds(20)
        )

        XCTAssertNil(response)
        XCTAssertFalse(process.isRunning)
        XCTAssertLessThan(Date().timeIntervalSince(start), 2.0)
    }

    // MARK: - CurlHTTPClient idle-based args

    func testStreamingCurlArgsContainSpeedBasedIdle() {
        // We can't call the private execute(), but we can verify the public tlsArgs helper
        // and the constants feed through correctly.
        // Verify speed-based constants are self-consistent.
        XCTAssertGreaterThanOrEqual(curlSpeedTimeSeconds, 10,
                                    "Idle window must be generous enough for slow upstreams")
        XCTAssertEqual(curlMinSpeedBytesPerSecond, 1,
                       "Min speed must be 1 byte/s to allow maximally slow progress")
    }

    func testNonStreamingArgsMustNotUseOldFixed120Seconds() {
        // The old code used timeoutSeconds: 120 as a magic number.
        // Confirm the named constant replaces it and is larger.
        XCTAssertNotEqual(Int(proxyNonStreamTotalTimeoutSeconds), 120,
                          "Non-streaming timeout must not be the old 120s fixed cap")
    }

    func testStreamingCurlArgsContainIndependentMaxTime() {
        let args = CurlHTTPClient.buildBaseArgs(
            method: "POST",
            url: URL(string: "https://example.test/stream")!,
            streaming: true
        )

        XCTAssertEqual(argument(after: "--speed-time", in: args), String(curlSpeedTimeSeconds))
        XCTAssertEqual(argument(after: "--max-time", in: args), String(curlStreamMaxTimeSeconds))
        XCTAssertFalse(args.contains("-w"))
    }

    func testNonStreamingCurlArgsKeepStatusMarkerAndMaxTime() {
        let args = CurlHTTPClient.buildBaseArgs(
            method: "POST",
            url: URL(string: "https://example.test/messages")!,
            streaming: false
        )

        XCTAssertEqual(argument(after: "--max-time", in: args), String(curlMaxTimeSeconds))
        XCTAssertEqual(argument(after: "-w", in: args), "\n__HTTP_STATUS__%{http_code}")
    }

    private func argument(after option: String, in args: [String]) -> String? {
        guard let index = args.firstIndex(of: option) else { return nil }
        let valueIndex = args.index(after: index)
        guard valueIndex < args.endIndex else { return nil }
        return args[valueIndex]
    }

    #if canImport(Darwin)
    func testSSEDelegateQueueDrainTimesOutWhenQueueDoesNotRun() {
        let queue = OperationQueue()
        queue.isSuspended = true
        defer { queue.cancelAllOperations() }
        let start = Date()

        let drained = SSEStreamRelay.drainOperationQueue(queue, timeoutSeconds: 0.01)

        XCTAssertFalse(drained)
        XCTAssertLessThan(Date().timeIntervalSince(start), 1.0)
    }

    func testSSEDelegateQueueDrainTimesOutWhenAddOperationBlocks() {
        let queue = BlockingAddOperationQueue(delaySeconds: 0.25)
        let start = Date()

        let drained = SSEStreamRelay.drainOperationQueue(queue, timeoutSeconds: 0.01)

        XCTAssertFalse(drained)
        XCTAssertLessThan(Date().timeIntervalSince(start), 0.2)
    }

    func testNonStreamingTaskWaitReturnsOnShutdownWithoutFullTimeout() {
        let server = ProxyServer(port: 0)
        let semaphore = DispatchSemaphore(value: 0)
        let session = URLSession(configuration: .ephemeral)
        defer { session.invalidateAndCancel() }
        let task = session.dataTask(with: URL(string: "https://example.test/messages")!)
        let start = Date()

        let result = server.waitForNonStreamingTaskCompletion(
            semaphore: semaphore,
            task: task,
            totalTimeoutSeconds: proxyNonStreamTotalTimeoutSeconds,
            pollMilliseconds: 1
        )

        XCTAssertEqual(result, .shutdown)
        XCTAssertLessThan(Date().timeIntervalSince(start), 1.0)
    }

    func testURLSessionConfigurationUsesProxyTimeoutCeilings() {
        // WO-401: Darwin URLSession's default 60s timeout must not preempt proxy ceilings.
        let configuration = ProxyServer.makeSessionConfiguration(forwardProxy: nil)

        XCTAssertEqual(configuration.timeoutIntervalForRequest, proxyNonStreamTotalTimeoutSeconds)
        XCTAssertGreaterThanOrEqual(
            configuration.timeoutIntervalForResource,
            proxyNonStreamTotalTimeoutSeconds
        )
        XCTAssertGreaterThanOrEqual(
            configuration.timeoutIntervalForResource,
            Double(curlStreamMaxTimeSeconds)
        )
    }
    #endif

    // MARK: - CurlHTTPClient TLS args (regression: existing behavior preserved)

    func testTLSArgsInsecureWins() {
        let args = CurlHTTPClient.tlsArgs(caCertPath: "/some/cert.pem", insecure: true)
        XCTAssertEqual(args, ["-k"])
    }

    func testTLSArgsCACertPath() {
        let args = CurlHTTPClient.tlsArgs(caCertPath: "/certs/bundle.pem", insecure: false)
        XCTAssertEqual(args, ["--cacert", "/certs/bundle.pem"])
    }

    func testTLSArgsDefaultIsEmpty() {
        let args = CurlHTTPClient.tlsArgs(caCertPath: nil, insecure: false)
        XCTAssertTrue(args.isEmpty)
    }

    #if canImport(Darwin)
    func testSSEStreamRelayConnectionFailureStartsWithHTTP502() {
        FailingStreamURLProtocol.reset()
        var sockets = [Int32](repeating: 0, count: 2)
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &sockets), 0)
        defer {
            close(sockets[0])
            close(sockets[1])
        }

        let relay = SSEStreamRelay(
            clientSocket: sockets[1],
            sendFlags: 0,
            redactionMode: .perSSEEvent,
            config: PastewatchConfig.defaultConfig,
            severity: .high,
            idleTimeoutSeconds: 5,
            maxSessionSeconds: 1
        )
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [FailingStreamURLProtocol.self]
        let delegateQueue = OperationQueue()
        delegateQueue.maxConcurrentOperationCount = 1
        let session = URLSession(configuration: configuration, delegate: relay, delegateQueue: delegateQueue)
        defer { session.invalidateAndCancel() }

        let finished = expectation(description: "relay returns after connection failure")
        let request = URLRequest(url: URL(string: "https://example.test/stream")!)
        DispatchQueue.global().async {
            relay.execute(request: request, session: session)
            finished.fulfill()
        }

        wait(for: [finished], timeout: 2)
        let response = readSocketString(from: sockets[0])
        XCTAssertTrue(response.hasPrefix("HTTP/1.1 502 Bad Gateway"), response)
        XCTAssertFalse(response.hasPrefix("[PASTEWATCH-STREAM-DROP]"), response)
    }

    func testSSEStreamRelayHardCeilingAfterHeadersSendsHTTP504() {
        HangingStreamURLProtocol.reset()
        var sockets = [Int32](repeating: 0, count: 2)
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &sockets), 0)
        defer {
            close(sockets[0])
            close(sockets[1])
        }

        let relay = SSEStreamRelay(
            clientSocket: sockets[1],
            sendFlags: 0,
            redactionMode: .perSSEEvent,
            config: PastewatchConfig.defaultConfig,
            severity: .high,
            idleTimeoutSeconds: 5,
            maxSessionSeconds: 0.05
        )
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [HangingStreamURLProtocol.self]
        let delegateQueue = OperationQueue()
        delegateQueue.maxConcurrentOperationCount = 1
        let session = URLSession(configuration: configuration, delegate: relay, delegateQueue: delegateQueue)
        defer { session.invalidateAndCancel() }

        let finished = expectation(description: "relay returns after hard ceiling")
        let request = URLRequest(url: URL(string: "https://example.test/stream")!)
        DispatchQueue.global().async {
            relay.execute(request: request, session: session)
            finished.fulfill()
        }

        wait(for: [finished], timeout: 2)
        XCTAssertTrue(HangingStreamURLProtocol.waitForStop(timeout: 1))
        let response = readSocketString(from: sockets[0])
        XCTAssertTrue(response.hasPrefix("HTTP/1.1 504 Gateway Timeout"), response)
        XCTAssertTrue(response.contains(#""error": "Gateway Timeout""#), response)
    }

    func testSSEStreamRelayIdleTimeoutAfterHeadersSendsHTTP504() {
        HangingStreamURLProtocol.reset()
        var sockets = [Int32](repeating: 0, count: 2)
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &sockets), 0)
        defer {
            close(sockets[0])
            close(sockets[1])
        }

        let relay = SSEStreamRelay(
            clientSocket: sockets[1],
            sendFlags: 0,
            redactionMode: .perSSEEvent,
            config: PastewatchConfig.defaultConfig,
            severity: .medium,
            idleTimeoutSeconds: 0.05,
            maxSessionSeconds: 1
        )
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [HangingStreamURLProtocol.self]
        let delegateQueue = OperationQueue()
        delegateQueue.maxConcurrentOperationCount = 1
        let session = URLSession(configuration: configuration, delegate: relay, delegateQueue: delegateQueue)
        defer { session.invalidateAndCancel() }

        let finished = expectation(description: "relay returns after post-header idle timeout")
        let request = URLRequest(url: URL(string: "https://example.test/stream")!)
        DispatchQueue.global().async {
            relay.execute(request: request, session: session)
            finished.fulfill()
        }

        wait(for: [finished], timeout: 2)
        let response = readSocketString(from: sockets[0])
        XCTAssertTrue(response.hasPrefix("HTTP/1.1 504 Gateway Timeout"), response)
        XCTAssertTrue(response.contains(#""error": "Gateway Timeout""#), response)
    }

    func testSSEStreamRelayIdleTimeoutStatsSnapshotIsConsistent() {
        // WO-400: timer-driven return reads stream stats through the relay snapshot lock.
        StatsThenHangStreamURLProtocol.reset()
        var sockets = [Int32](repeating: 0, count: 2)
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &sockets), 0)
        defer {
            close(sockets[0])
            close(sockets[1])
        }

        let relay = SSEStreamRelay(
            clientSocket: sockets[1],
            sendFlags: 0,
            redactionMode: .perSSEEvent,
            config: PastewatchConfig.defaultConfig,
            severity: .medium,
            idleTimeoutSeconds: 0.05,
            maxSessionSeconds: 1
        )
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [StatsThenHangStreamURLProtocol.self]
        let delegateQueue = OperationQueue()
        delegateQueue.maxConcurrentOperationCount = 2
        let session = URLSession(configuration: configuration, delegate: relay, delegateQueue: delegateQueue)
        defer { session.invalidateAndCancel() }

        let finished = expectation(description: "relay returns after idle timeout with stats")
        let request = URLRequest(url: URL(string: "https://example.test/stream")!)
        DispatchQueue.global().async {
            relay.execute(request: request, session: session)
            finished.fulfill()
        }

        wait(for: [finished], timeout: 2)
        let stats = relay.snapshotStreamStats()
        XCTAssertEqual(stats.redactionCount, 2)
        XCTAssertEqual(stats.redactionTypes, ["Google API Key", "Google API Key"])
        XCTAssertEqual(stats.advisoryCount, 1)
        XCTAssertEqual(stats.advisoryTypes, ["IP"])
    }

    func testSSEStreamRelayOverflowKeepsIdleTimerArmed() {
        OverflowThenHangStreamURLProtocol.reset()
        var sockets = [Int32](repeating: 0, count: 2)
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &sockets), 0)
        defer {
            close(sockets[0])
            close(sockets[1])
        }

        DispatchQueue.global().async {
            var buffer = [UInt8](repeating: 0, count: 65536)
            while recv(sockets[0], &buffer, buffer.count, 0) > 0 {}
        }

        var config = PastewatchConfig.defaultConfig
        config.enabledTypes = []

        let relay = SSEStreamRelay(
            clientSocket: sockets[1],
            sendFlags: 0,
            redactionMode: .perSSEEvent,
            config: config,
            severity: .high,
            idleTimeoutSeconds: 0.05,
            maxSessionSeconds: 10
        )
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [OverflowThenHangStreamURLProtocol.self]
        let delegateQueue = OperationQueue()
        delegateQueue.maxConcurrentOperationCount = 1
        let session = URLSession(configuration: configuration, delegate: relay, delegateQueue: delegateQueue)
        defer { session.invalidateAndCancel() }

        let finished = expectation(description: "relay returns after overflow idle timeout")
        let request = URLRequest(url: URL(string: "https://example.test/stream")!)
        DispatchQueue.global().async {
            relay.execute(request: request, session: session)
            finished.fulfill()
        }

        XCTAssertTrue(OverflowThenHangStreamURLProtocol.waitForStop(timeout: 2))
        shutdown(sockets[0], SHUT_RDWR)
        wait(for: [finished], timeout: 2)
    }

    func testSSEStreamRelayRawStreamInjectsAlertBeforeSplitDone() {
        SplitDoneStreamURLProtocol.reset()
        var sockets = [Int32](repeating: 0, count: 2)
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &sockets), 0)
        defer {
            close(sockets[0])
            close(sockets[1])
        }

        let relay = SSEStreamRelay(
            clientSocket: sockets[1],
            sendFlags: 0,
            redactionMode: .rawStream,
            config: PastewatchConfig.defaultConfig,
            severity: .high,
            idleTimeoutSeconds: 5,
            maxSessionSeconds: 1
        )
        var capturedAdvisoryCount = -1
        relay.buildAlertBeforeDone = { _, _, advisoryCount, _ in
            // WO-389: the `[DONE]` sentinel must not be scanned into advisory counts.
            capturedAdvisoryCount = advisoryCount
            return Data("event: pastewatch_advisory\ndata: {}\n\n".utf8)
        }
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [SplitDoneStreamURLProtocol.self]
        let delegateQueue = OperationQueue()
        delegateQueue.maxConcurrentOperationCount = 1
        let session = URLSession(configuration: configuration, delegate: relay, delegateQueue: delegateQueue)
        defer { session.invalidateAndCancel() }

        let finished = expectation(description: "relay returns after split done")
        let request = URLRequest(url: URL(string: "https://example.test/stream")!)
        DispatchQueue.global().async {
            relay.execute(request: request, session: session)
            finished.fulfill()
        }

        wait(for: [finished], timeout: 2)
        let response = readSocketString(from: sockets[0])
        guard let advisoryRange = response.range(of: "event: pastewatch_advisory"),
              let doneRange = response.range(of: "data: [DONE]") else {
            XCTFail(response)
            return
        }
        XCTAssertLessThan(advisoryRange.lowerBound, doneRange.lowerBound)
        XCTAssertTrue(response.contains("data: one\n\n"))
        XCTAssertEqual(capturedAdvisoryCount, 0)
    }

    func testSSEStreamRelayRawStreamEOFWithoutDoneAppendsAdvisory() {
        // WO-398: truncated raw_stream responses still surface the final advisory event.
        let credential = "AIza" + String(repeating: "M", count: 35)
        NoDoneStreamURLProtocol.reset(payload: Data("data: \(credential)\n\n".utf8))
        var sockets = [Int32](repeating: 0, count: 2)
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &sockets), 0)
        defer {
            close(sockets[0])
            close(sockets[1])
        }

        let relay = SSEStreamRelay(
            clientSocket: sockets[1],
            sendFlags: 0,
            redactionMode: .rawStream,
            config: PastewatchConfig.defaultConfig,
            severity: .high,
            idleTimeoutSeconds: 5,
            maxSessionSeconds: 1
        )
        relay.buildAlertBeforeDone = { streamCount, _, advisoryCount, _ in
            guard streamCount > 0 || advisoryCount > 0 else { return nil }
            return Data("event: pastewatch_advisory\ndata: eof\n\n".utf8)
        }
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [NoDoneStreamURLProtocol.self]
        let delegateQueue = OperationQueue()
        delegateQueue.maxConcurrentOperationCount = 1
        let session = URLSession(configuration: configuration, delegate: relay, delegateQueue: delegateQueue)
        defer { session.invalidateAndCancel() }

        let finished = expectation(description: "relay returns after raw stream EOF without done")
        let request = URLRequest(url: URL(string: "https://example.test/stream")!)
        DispatchQueue.global().async {
            relay.execute(request: request, session: session)
            finished.fulfill()
        }

        wait(for: [finished], timeout: 2)
        let response = readSocketDrainString(from: sockets[0])
        guard let redactionRange = response.range(of: "<GOOGLE_API_KEY_1>"),
              let advisoryRange = response.range(of: "event: pastewatch_advisory") else {
            XCTFail(response)
            return
        }
        XCTAssertLessThan(redactionRange.lowerBound, advisoryRange.lowerBound)
    }

    func testSSEStreamRelayRawStreamEOFWithoutMatchesDoesNotAppendAdvisory() {
        // WO-398: no in-band advisory when the truncated stream had no findings.
        NoDoneStreamURLProtocol.reset(payload: Data("data: hello\n\n".utf8))
        var sockets = [Int32](repeating: 0, count: 2)
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &sockets), 0)
        defer {
            close(sockets[0])
            close(sockets[1])
        }

        let relay = SSEStreamRelay(
            clientSocket: sockets[1],
            sendFlags: 0,
            redactionMode: .rawStream,
            config: PastewatchConfig.defaultConfig,
            severity: .high,
            idleTimeoutSeconds: 5,
            maxSessionSeconds: 1
        )
        relay.buildAlertBeforeDone = { _, _, _, _ in
            Data("event: pastewatch_advisory\ndata: should-not-send\n\n".utf8)
        }
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [NoDoneStreamURLProtocol.self]
        let delegateQueue = OperationQueue()
        delegateQueue.maxConcurrentOperationCount = 1
        let session = URLSession(configuration: configuration, delegate: relay, delegateQueue: delegateQueue)
        defer { session.invalidateAndCancel() }

        let finished = expectation(description: "relay returns after raw stream EOF without findings")
        let request = URLRequest(url: URL(string: "https://example.test/stream")!)
        DispatchQueue.global().async {
            relay.execute(request: request, session: session)
            finished.fulfill()
        }

        wait(for: [finished], timeout: 2)
        let response = readSocketDrainString(from: sockets[0])
        XCTAssertTrue(response.contains("data: hello\n\n"), response)
        XCTAssertFalse(response.contains("pastewatch_advisory"), response)
    }

    func testSSEStreamRelayClientDisconnectBeforeFirstDataReturnsBounded() {
        // WO-372: EPIPE on the first header/data write cancels the active task promptly.
        let previousHandler = signal(SIGPIPE, SIG_IGN)
        defer { _ = signal(SIGPIPE, previousHandler) }

        let credential = "AIza" + String(repeating: "N", count: 35)
        FirstDataGateStreamURLProtocol.reset(payload: Data("data: \(credential)\n\n".utf8))
        var sockets = [Int32](repeating: 0, count: 2)
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &sockets), 0)
        defer { close(sockets[1]) }

        let relay = SSEStreamRelay(
            clientSocket: sockets[1],
            sendFlags: 0,
            redactionMode: .perSSEEvent,
            config: PastewatchConfig.defaultConfig,
            severity: .high,
            idleTimeoutSeconds: 5,
            maxSessionSeconds: 1
        )
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [FirstDataGateStreamURLProtocol.self]
        let delegateQueue = OperationQueue()
        delegateQueue.maxConcurrentOperationCount = 1
        let session = URLSession(configuration: configuration, delegate: relay, delegateQueue: delegateQueue)
        defer { session.invalidateAndCancel() }

        let finished = expectation(description: "relay returns after first data EPIPE")
        let request = URLRequest(url: URL(string: "https://example.test/stream")!)
        DispatchQueue.global().async {
            relay.execute(request: request, session: session)
            finished.fulfill()
        }

        XCTAssertTrue(FirstDataGateStreamURLProtocol.waitForHead(timeout: 2))
        close(sockets[0])
        FirstDataGateStreamURLProtocol.allowBody()

        XCTAssertTrue(FirstDataGateStreamURLProtocol.waitForStop(timeout: 2))
        wait(for: [finished], timeout: 2)
        XCTAssertEqual(relay.streamRedactionCount, 0)
        XCTAssertEqual(relay.streamAdvisoryCount, 0)
    }

    func testSSEStreamRelayClientDisconnectDuringStreamSkipsUndeliveredAdvisoryStats() {
        // WO-372: advisory-only bytes after EPIPE are not counted as delivered.
        let previousHandler = signal(SIGPIPE, SIG_IGN)
        defer { _ = signal(SIGPIPE, previousHandler) }

        AdvisoryAfterCloseStreamURLProtocol.reset()
        var sockets = [Int32](repeating: 0, count: 2)
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &sockets), 0)
        defer { close(sockets[1]) }

        let relay = SSEStreamRelay(
            clientSocket: sockets[1],
            sendFlags: 0,
            redactionMode: .perSSEEvent,
            config: PastewatchConfig.defaultConfig,
            severity: .high,
            idleTimeoutSeconds: 5,
            maxSessionSeconds: 1
        )
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [AdvisoryAfterCloseStreamURLProtocol.self]
        let delegateQueue = OperationQueue()
        delegateQueue.maxConcurrentOperationCount = 1
        let session = URLSession(configuration: configuration, delegate: relay, delegateQueue: delegateQueue)
        defer { session.invalidateAndCancel() }

        let finished = expectation(description: "relay returns after active stream EPIPE")
        let request = URLRequest(url: URL(string: "https://example.test/stream")!)
        DispatchQueue.global().async {
            relay.execute(request: request, session: session)
            finished.fulfill()
        }

        XCTAssertTrue(AdvisoryAfterCloseStreamURLProtocol.waitForFirstChunk(timeout: 2))
        var firstResponse = readSocketString(from: sockets[0])
        if !firstResponse.contains("<GOOGLE_API_KEY_1>") {
            firstResponse += readSocketString(from: sockets[0])
        }
        XCTAssertTrue(firstResponse.contains("<GOOGLE_API_KEY_1>"), firstResponse)
        close(sockets[0])
        AdvisoryAfterCloseStreamURLProtocol.allowSecondChunk()

        XCTAssertTrue(AdvisoryAfterCloseStreamURLProtocol.waitForStop(timeout: 2))
        wait(for: [finished], timeout: 2)
        XCTAssertEqual(relay.streamRedactionCount, 1)
        XCTAssertEqual(relay.streamAdvisoryCount, 0)
    }

    func testSSEStreamRelayRawStreamNoAlertSkipsUndeliveredAdvisoryStats() {
        // WO-381: critical detections are attempt-scoped; advisories require delivery.
        let previousHandler = signal(SIGPIPE, SIG_IGN)
        defer { _ = signal(SIGPIPE, previousHandler) }
        AdvisoryAfterCloseStreamURLProtocol.reset()
        var sockets = [Int32](repeating: 0, count: 2)
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &sockets), 0)
        defer { close(sockets[1]) }
        let relay = SSEStreamRelay(
            clientSocket: sockets[1], sendFlags: 0, redactionMode: .rawStream,
            config: PastewatchConfig.defaultConfig, severity: .high,
            idleTimeoutSeconds: 5, maxSessionSeconds: 1
        )
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [AdvisoryAfterCloseStreamURLProtocol.self]
        let session = URLSession(configuration: configuration, delegate: relay, delegateQueue: OperationQueue())
        defer { session.invalidateAndCancel() }
        let finished = expectation(description: "raw no-alert relay returns after EPIPE")
        DispatchQueue.global().async {
            relay.execute(request: URLRequest(url: URL(string: "https://example.test/stream")!), session: session)
            finished.fulfill()
        }

        XCTAssertTrue(AdvisoryAfterCloseStreamURLProtocol.waitForFirstChunk(timeout: 2))
        _ = readSocketString(from: sockets[0])
        close(sockets[0])
        AdvisoryAfterCloseStreamURLProtocol.allowSecondChunk()
        wait(for: [finished], timeout: 2)

        XCTAssertEqual(relay.streamRedactionCount, 1)
        XCTAssertEqual(relay.streamAdvisoryCount, 0)
    }

    func testSSEStreamRelayRawStreamWithAlertSkipsUndeliveredAdvisoryStats() {
        // WO-382: a failed batch send cannot commit its staged advisory counts.
        let previousHandler = signal(SIGPIPE, SIG_IGN)
        defer { _ = signal(SIGPIPE, previousHandler) }
        AdvisoryAfterCloseStreamURLProtocol.reset()
        var sockets = [Int32](repeating: 0, count: 2)
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &sockets), 0)
        defer { close(sockets[1]) }
        let relay = SSEStreamRelay(
            clientSocket: sockets[1], sendFlags: 0, redactionMode: .rawStream,
            config: PastewatchConfig.defaultConfig, severity: .high,
            idleTimeoutSeconds: 5, maxSessionSeconds: 1
        )
        relay.buildAlertBeforeDone = { _, _, advisoryCount, _ in
            advisoryCount > 0 ? Data("event: pastewatch_advisory\ndata: alert\n\n".utf8) : nil
        }
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [AdvisoryAfterCloseStreamURLProtocol.self]
        let session = URLSession(configuration: configuration, delegate: relay, delegateQueue: OperationQueue())
        defer { session.invalidateAndCancel() }
        let finished = expectation(description: "raw alert relay returns after EPIPE")
        DispatchQueue.global().async {
            relay.execute(request: URLRequest(url: URL(string: "https://example.test/stream")!), session: session)
            finished.fulfill()
        }

        XCTAssertTrue(AdvisoryAfterCloseStreamURLProtocol.waitForFirstChunk(timeout: 2))
        _ = readSocketString(from: sockets[0])
        close(sockets[0])
        AdvisoryAfterCloseStreamURLProtocol.allowSecondChunk()
        wait(for: [finished], timeout: 2)

        XCTAssertEqual(relay.streamRedactionCount, 1)
        XCTAssertEqual(relay.streamAdvisoryCount, 0)
    }

    func testSSEStreamRelayRemainderEPIPESkipsUndeliveredAdvisoryStats() {
        // WO-383: partial-frame remainder stats follow the same delivery policy.
        let previousHandler = signal(SIGPIPE, SIG_IGN)
        defer { _ = signal(SIGPIPE, previousHandler) }
        AdvisoryAfterCloseStreamURLProtocol.reset(secondPayload: Data("data: contact 10.1.2.3".utf8))
        var sockets = [Int32](repeating: 0, count: 2)
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &sockets), 0)
        defer { close(sockets[1]) }
        let relay = SSEStreamRelay(
            clientSocket: sockets[1], sendFlags: 0, redactionMode: .perSSEEvent,
            config: PastewatchConfig.defaultConfig, severity: .high,
            idleTimeoutSeconds: 5, maxSessionSeconds: 1
        )
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [AdvisoryAfterCloseStreamURLProtocol.self]
        let session = URLSession(configuration: configuration, delegate: relay, delegateQueue: OperationQueue())
        defer { session.invalidateAndCancel() }
        let finished = expectation(description: "remainder relay returns after EPIPE")
        DispatchQueue.global().async {
            relay.execute(request: URLRequest(url: URL(string: "https://example.test/stream")!), session: session)
            finished.fulfill()
        }

        XCTAssertTrue(AdvisoryAfterCloseStreamURLProtocol.waitForFirstChunk(timeout: 2))
        _ = readSocketString(from: sockets[0])
        close(sockets[0])
        AdvisoryAfterCloseStreamURLProtocol.allowSecondChunk()
        wait(for: [finished], timeout: 2)

        XCTAssertEqual(relay.streamRedactionCount, 1)
        XCTAssertEqual(relay.streamAdvisoryCount, 0)
    }

    func testSSEStreamRelayPerEventInjectsAlertOnceForDuplicateDone() {
        // WO-394: malformed duplicate terminators are forwarded without duplicate alerts.
        let credential = "AIza" + String(repeating: "U", count: 35)
        let payload = #"{"type":"content_block_delta","delta":{"type":"text_delta","text":"\#(credential)"}}"#
        NoDoneStreamURLProtocol.reset(
            payload: Data("data: \(payload)\n\ndata: [DONE]\n\ndata: [DONE]\n\n".utf8)
        )
        var sockets = [Int32](repeating: 0, count: 2)
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &sockets), 0)
        defer {
            close(sockets[0])
            close(sockets[1])
        }
        let relay = SSEStreamRelay(
            clientSocket: sockets[1], sendFlags: 0, redactionMode: .perSSEEvent,
            config: PastewatchConfig.defaultConfig, severity: .high,
            idleTimeoutSeconds: 5, maxSessionSeconds: 1
        )
        relay.buildAlertBeforeDone = { count, _, _, _ in
            count > 0 ? Data("event: pastewatch_alert\ndata: alert\n\n".utf8) : nil
        }
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [NoDoneStreamURLProtocol.self]
        let session = URLSession(configuration: configuration, delegate: relay, delegateQueue: OperationQueue())
        defer { session.invalidateAndCancel() }
        let finished = expectation(description: "duplicate done relay returns")
        DispatchQueue.global().async {
            relay.execute(request: URLRequest(url: URL(string: "https://example.test/stream")!), session: session)
            finished.fulfill()
        }

        wait(for: [finished], timeout: 2)
        let output = readSocketDrainString(from: sockets[0])
        XCTAssertEqual(output.components(separatedBy: "event: pastewatch_alert").count - 1, 1)
        XCTAssertEqual(output.components(separatedBy: "data: [DONE]").count - 1, 2)
    }

    func testSSEStreamRelayRawStreamInjectsAlertOnceForDuplicateDone() {
        // WO-380/WO-394: both relay modes share the one-shot terminal alert invariant.
        NoDoneStreamURLProtocol.reset(
            payload: Data("data: contact 10.1.2.3\n\ndata: [DONE]\n\ndata: [DONE]\n\n".utf8)
        )
        var sockets = [Int32](repeating: 0, count: 2)
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &sockets), 0)
        defer {
            close(sockets[0])
            close(sockets[1])
        }
        let relay = SSEStreamRelay(
            clientSocket: sockets[1], sendFlags: 0, redactionMode: .rawStream,
            config: PastewatchConfig.defaultConfig, severity: .medium,
            idleTimeoutSeconds: 5, maxSessionSeconds: 1
        )
        relay.buildAlertBeforeDone = { _, _, advisoryCount, _ in
            advisoryCount > 0 ? Data("event: pastewatch_advisory\ndata: alert\n\n".utf8) : nil
        }
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [NoDoneStreamURLProtocol.self]
        let session = URLSession(configuration: configuration, delegate: relay, delegateQueue: OperationQueue())
        defer { session.invalidateAndCancel() }
        let finished = expectation(description: "raw duplicate done relay returns")
        DispatchQueue.global().async {
            relay.execute(request: URLRequest(url: URL(string: "https://example.test/stream")!), session: session)
            finished.fulfill()
        }

        wait(for: [finished], timeout: 2)
        let output = readSocketDrainString(from: sockets[0])
        XCTAssertEqual(output.components(separatedBy: "event: pastewatch_advisory").count - 1, 1)
        XCTAssertEqual(output.components(separatedBy: "data: [DONE]").count - 1, 2)
    }

    func testSSEStreamRelayRawOverflowLatchesDoneBeforeDuplicate() {
        // WO-507: an oversized first chunk bypasses frame parsing but still owns DONE state.
        var parser = SSEFrameParser()
        let firstResult = parser.feed(Data((
            "data: contact 10.1.2.3\n" +
                String(repeating: "x", count: SSEFrameParser.maxFrameBytes) +
                "\ndata: [DONE]\n\n"
        ).utf8))
        XCTAssertTrue(firstResult.overflowFlushed)

        let relay = SSEStreamRelay(
            clientSocket: -1, sendFlags: 0, redactionMode: .rawStream,
            config: PastewatchConfig.defaultConfig, severity: .medium,
            idleTimeoutSeconds: 5
        )
        relay.buildAlertBeforeDone = { _, _, advisoryCount, _ in
            advisoryCount > 0 ? Data("event: pastewatch_advisory\ndata: alert\n\n".utf8) : nil
        }
        let stats = SSEStreamRelay.StreamStatsSnapshot(
            redactionCount: 0,
            redactionTypes: [],
            advisoryCount: 1,
            advisoryTypes: ["IP Address"]
        )
        let firstOutput = relay.insertingRawStreamOverflowAlertIfNeeded(
            firstResult.overflowBytes,
            stats: stats
        )
        let secondOutput = relay.insertingRawStreamOverflowAlertIfNeeded(
            Data("data: [DONE]\n\n".utf8),
            stats: stats
        )
        let output = String(data: firstOutput + secondOutput, encoding: .utf8) ?? ""

        XCTAssertEqual(output.components(separatedBy: "event: pastewatch_advisory").count - 1, 1)
        XCTAssertEqual(output.components(separatedBy: "data: [DONE]").count - 1, 2)
    }

    func testSSEStreamRelayClientDisconnectDuringDoneAlertReturnsBounded() {
        // WO-372: client EPIPE during alert+[DONE] should cancel the task without stat inflation.
        let previousHandler = signal(SIGPIPE, SIG_IGN)
        defer { _ = signal(SIGPIPE, previousHandler) }

        ControlledDoneStreamURLProtocol.reset()
        var sockets = [Int32](repeating: 0, count: 2)
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &sockets), 0)
        defer { close(sockets[1]) }

        let relay = SSEStreamRelay(
            clientSocket: sockets[1],
            sendFlags: 0,
            redactionMode: .perSSEEvent,
            config: PastewatchConfig.defaultConfig,
            severity: .high,
            idleTimeoutSeconds: 5,
            maxSessionSeconds: 1
        )
        relay.buildAlertBeforeDone = { streamCount, streamTypes, _, _ in
            guard streamCount > 0 else { return nil }
            return Data("event: pastewatch_alert\ndata: \(streamTypes.joined(separator: ","))\n\n".utf8)
        }
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [ControlledDoneStreamURLProtocol.self]
        let delegateQueue = OperationQueue()
        delegateQueue.maxConcurrentOperationCount = 1
        let session = URLSession(configuration: configuration, delegate: relay, delegateQueue: delegateQueue)
        defer { session.invalidateAndCancel() }

        let finished = expectation(description: "relay returns after client EPIPE around done alert")
        let request = URLRequest(url: URL(string: "https://example.test/stream")!)
        DispatchQueue.global().async {
            relay.execute(request: request, session: session)
            finished.fulfill()
        }

        XCTAssertTrue(ControlledDoneStreamURLProtocol.waitForFirstChunk(timeout: 2))
        var firstResponse = readSocketString(from: sockets[0])
        if !firstResponse.contains("<GOOGLE_API_KEY_1>") {
            firstResponse += readSocketString(from: sockets[0])
        }
        XCTAssertTrue(firstResponse.contains("<GOOGLE_API_KEY_1>"), firstResponse)
        close(sockets[0])
        ControlledDoneStreamURLProtocol.allowDone()

        wait(for: [finished], timeout: 2)
        XCTAssertEqual(relay.streamRedactionCount, 1)
        XCTAssertEqual(relay.streamRedactionTypes, ["Google API Key"])
    }

    private func assertNoDataAvailable(
        on socket: Int32,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        let originalFlags = fcntl(socket, F_GETFL, 0)
        XCTAssertGreaterThanOrEqual(originalFlags, 0, file: file, line: line)
        XCTAssertEqual(fcntl(socket, F_SETFL, originalFlags | O_NONBLOCK), 0, file: file, line: line)
        defer { _ = fcntl(socket, F_SETFL, originalFlags) }

        var byte: UInt8 = 0
        let readCount = recv(socket, &byte, 1, 0)
        XCTAssertEqual(readCount, -1, file: file, line: line)
        XCTAssertTrue(errno == EAGAIN || errno == EWOULDBLOCK, file: file, line: line)
    }

    private func readSocketString(
        from socket: Int32,
        file: StaticString = #filePath,
        line: UInt = #line
    ) -> String {
        var timeout = timeval(tv_sec: 1, tv_usec: 0)
        XCTAssertEqual(
            setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size)),
            0,
            file: file,
            line: line
        )
        var buffer = [UInt8](repeating: 0, count: 4096)
        let count = recv(socket, &buffer, buffer.count, 0)
        XCTAssertGreaterThan(count, 0, file: file, line: line)
        guard count > 0 else { return "" }
        return String(bytes: buffer[..<count], encoding: .utf8) ?? ""
    }

    private func readSocketDrainString(
        from socket: Int32,
        file: StaticString = #filePath,
        line: UInt = #line
    ) -> String {
        var timeout = timeval(tv_sec: 0, tv_usec: 100_000)
        XCTAssertEqual(
            setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size)),
            0,
            file: file,
            line: line
        )
        var output = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while true {
            let count = recv(socket, &buffer, buffer.count, 0)
            guard count > 0 else { break }
            output.append(contentsOf: buffer[..<count])
        }
        return String(data: output, encoding: .utf8) ?? ""
    }
    #endif
}

#if canImport(Darwin)
private final class BlockingAddOperationQueue: OperationQueue, @unchecked Sendable {
    private let delaySeconds: TimeInterval

    init(delaySeconds: TimeInterval) {
        self.delaySeconds = delaySeconds
        super.init()
    }

    override func addOperation(_ op: Operation) {
        Thread.sleep(forTimeInterval: delaySeconds)
        super.addOperation(op)
    }
}

private class FailingStreamURLProtocol: URLProtocol {
    static func reset() {}

    override class func canInit(with request: URLRequest) -> Bool {
        true
    }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest {
        request
    }

    override func startLoading() {
        client?.urlProtocol(self, didFailWithError: URLError(.cannotConnectToHost))
    }

    override func stopLoading() {}
}

private class HangingStreamURLProtocol: URLProtocol {
    private static let lock = NSLock()
    private static var stopSemaphore = DispatchSemaphore(value: 0)

    static func reset() {
        lock.lock()
        stopSemaphore = DispatchSemaphore(value: 0)
        lock.unlock()
    }

    static func waitForStop(timeout: TimeInterval) -> Bool {
        stopSemaphore.wait(timeout: .now() + timeout) == .success
    }

    override class func canInit(with request: URLRequest) -> Bool {
        true
    }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest {
        request
    }

    override func startLoading() {
        guard let url = request.url,
              let response = HTTPURLResponse(
                url: url,
                statusCode: 200,
                httpVersion: "HTTP/1.1",
                headerFields: ["Content-Type": "text/event-stream"]
              ) else {
            return
        }
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
    }

    override func stopLoading() {
        Self.stopSemaphore.signal()
    }
}

private class StatsThenHangStreamURLProtocol: URLProtocol {
    static func reset() {}

    override class func canInit(with request: URLRequest) -> Bool {
        true
    }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest {
        request
    }

    override func startLoading() {
        guard let url = request.url,
              let response = HTTPURLResponse(
                url: url,
                statusCode: 200,
                httpVersion: "HTTP/1.1",
                headerFields: ["Content-Type": "text/event-stream"]
              ) else {
            return
        }
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        let firstCredential = "AIza" + String(repeating: "O", count: 35)
        let secondCredential = "AIza" + String(repeating: "P", count: 35)
        let first = #"{"type":"content_block_delta","delta":{"type":"text_delta","text":"\#(firstCredential)"}}"#
        let second = #"{"type":"content_block_delta","delta":{"type":"text_delta","text":"\#(secondCredential)"}}"#
        let advisory = #"{"type":"content_block_delta","delta":{"type":"text_delta","text":"host 10.1.2.3"}}"#
        client?.urlProtocol(self, didLoad: Data("data: \(first)\n\n".utf8))
        client?.urlProtocol(self, didLoad: Data("data: \(second)\n\n".utf8))
        client?.urlProtocol(self, didLoad: Data("data: \(advisory)\n\n".utf8))
    }

    override func stopLoading() {}
}

private class OverflowThenHangStreamURLProtocol: URLProtocol {
    private static let lock = NSLock()
    private static var stopSemaphore = DispatchSemaphore(value: 0)

    static func reset() {
        lock.lock()
        stopSemaphore = DispatchSemaphore(value: 0)
        lock.unlock()
    }

    static func waitForStop(timeout: TimeInterval) -> Bool {
        stopSemaphore.wait(timeout: .now() + timeout) == .success
    }

    override class func canInit(with request: URLRequest) -> Bool {
        true
    }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest {
        request
    }

    override func startLoading() {
        guard let url = request.url,
              let response = HTTPURLResponse(
                url: url,
                statusCode: 200,
                httpVersion: "HTTP/1.1",
                headerFields: ["Content-Type": "text/event-stream"]
              ) else {
            return
        }
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: Data(repeating: 0x61, count: SSEFrameParser.maxFrameBytes + 1))
    }

    override func stopLoading() {
        Self.stopSemaphore.signal()
    }
}

private class ControlledDoneStreamURLProtocol: URLProtocol {
    private static let lock = NSLock()
    private static var firstChunkSemaphore = DispatchSemaphore(value: 0)
    private static var allowDoneSemaphore = DispatchSemaphore(value: 0)

    static func reset() {
        lock.lock()
        firstChunkSemaphore = DispatchSemaphore(value: 0)
        allowDoneSemaphore = DispatchSemaphore(value: 0)
        lock.unlock()
    }

    static func waitForFirstChunk(timeout: TimeInterval) -> Bool {
        firstChunkSemaphore.wait(timeout: .now() + timeout) == .success
    }

    static func allowDone() {
        allowDoneSemaphore.signal()
    }

    override class func canInit(with request: URLRequest) -> Bool {
        true
    }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest {
        request
    }

    override func startLoading() {
        guard let url = request.url,
              let response = HTTPURLResponse(
                url: url,
                statusCode: 200,
                httpVersion: "HTTP/1.1",
                headerFields: ["Content-Type": "text/event-stream"]
              ) else {
            return
        }
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        let credential = "AIza" + String(repeating: "Q", count: 35)
        let payload = #"{"type":"content_block_delta","delta":{"type":"text_delta","text":"\#(credential)"}}"#
        client?.urlProtocol(self, didLoad: Data("data: \(payload)\n\n".utf8))
        Self.firstChunkSemaphore.signal()
        _ = Self.allowDoneSemaphore.wait(timeout: .now() + 1)
        client?.urlProtocol(self, didLoad: Data("data: [DONE]\n\n".utf8))
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {
        Self.allowDoneSemaphore.signal()
    }
}

private class SplitDoneStreamURLProtocol: URLProtocol {
    static func reset() {}

    override class func canInit(with request: URLRequest) -> Bool {
        true
    }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest {
        request
    }

    override func startLoading() {
        guard let url = request.url,
              let response = HTTPURLResponse(
                url: url,
                statusCode: 200,
                httpVersion: "HTTP/1.1",
                headerFields: ["Content-Type": "text/event-stream"]
              ) else {
            return
        }
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: Data("data: one\n\ndata: [DO".utf8))
        client?.urlProtocol(self, didLoad: Data("NE]\n\n".utf8))
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}

private class NoDoneStreamURLProtocol: URLProtocol {
    private static let lock = NSLock()
    private static var payload = Data()

    static func reset(payload: Data) {
        lock.lock()
        self.payload = payload
        lock.unlock()
    }

    override class func canInit(with request: URLRequest) -> Bool {
        true
    }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest {
        request
    }

    override func startLoading() {
        guard let url = request.url,
              let response = HTTPURLResponse(
                url: url,
                statusCode: 200,
                httpVersion: "HTTP/1.1",
                headerFields: ["Content-Type": "text/event-stream"]
              ) else {
            return
        }
        Self.lock.lock()
        let payload = Self.payload
        Self.lock.unlock()
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: payload)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}

private class FirstDataGateStreamURLProtocol: URLProtocol {
    private static let lock = NSLock()
    private static var headSemaphore = DispatchSemaphore(value: 0)
    private static var allowBodySemaphore = DispatchSemaphore(value: 0)
    private static var stopSemaphore = DispatchSemaphore(value: 0)
    private static var payload = Data()

    static func reset(payload: Data) {
        lock.lock()
        headSemaphore = DispatchSemaphore(value: 0)
        allowBodySemaphore = DispatchSemaphore(value: 0)
        stopSemaphore = DispatchSemaphore(value: 0)
        self.payload = payload
        lock.unlock()
    }

    static func waitForHead(timeout: TimeInterval) -> Bool {
        headSemaphore.wait(timeout: .now() + timeout) == .success
    }

    static func allowBody() {
        allowBodySemaphore.signal()
    }

    static func waitForStop(timeout: TimeInterval) -> Bool {
        stopSemaphore.wait(timeout: .now() + timeout) == .success
    }

    override class func canInit(with request: URLRequest) -> Bool {
        true
    }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest {
        request
    }

    override func startLoading() {
        guard let url = request.url,
              let response = HTTPURLResponse(
                url: url,
                statusCode: 200,
                httpVersion: "HTTP/1.1",
                headerFields: ["Content-Type": "text/event-stream"]
              ) else {
            return
        }
        Self.lock.lock()
        let payload = Self.payload
        Self.lock.unlock()
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        Self.headSemaphore.signal()
        _ = Self.allowBodySemaphore.wait(timeout: .now() + 1)
        client?.urlProtocol(self, didLoad: payload)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {
        Self.allowBodySemaphore.signal()
        Self.stopSemaphore.signal()
    }
}

private class AdvisoryAfterCloseStreamURLProtocol: URLProtocol {
    private static let lock = NSLock()
    private static var firstChunkSemaphore = DispatchSemaphore(value: 0)
    private static var allowSecondSemaphore = DispatchSemaphore(value: 0)
    private static var stopSemaphore = DispatchSemaphore(value: 0)
    private static var secondPayload = Data()

    static func reset(secondPayload: Data? = nil) {
        lock.lock()
        firstChunkSemaphore = DispatchSemaphore(value: 0)
        allowSecondSemaphore = DispatchSemaphore(value: 0)
        stopSemaphore = DispatchSemaphore(value: 0)
        self.secondPayload = secondPayload ?? defaultSecondPayload()
        lock.unlock()
    }

    private static func defaultSecondPayload() -> Data {
        let second = #"{"type":"content_block_delta","delta":{"type":"text_delta","text":"10.1.2.3"}}"#
        return Data("data: \(second)\n\n".utf8)
    }

    static func waitForFirstChunk(timeout: TimeInterval) -> Bool {
        firstChunkSemaphore.wait(timeout: .now() + timeout) == .success
    }

    static func allowSecondChunk() {
        allowSecondSemaphore.signal()
    }

    static func waitForStop(timeout: TimeInterval) -> Bool {
        stopSemaphore.wait(timeout: .now() + timeout) == .success
    }

    override class func canInit(with request: URLRequest) -> Bool {
        true
    }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest {
        request
    }

    override func startLoading() {
        guard let url = request.url,
              let response = HTTPURLResponse(
                url: url,
                statusCode: 200,
                httpVersion: "HTTP/1.1",
                headerFields: ["Content-Type": "text/event-stream"]
              ) else {
            return
        }
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        let credential = "AIza" + String(repeating: "R", count: 35)
        let first = #"{"type":"content_block_delta","delta":{"type":"text_delta","text":"\#(credential)"}}"#
        client?.urlProtocol(self, didLoad: Data("data: \(first)\n\n".utf8))
        Self.firstChunkSemaphore.signal()
        _ = Self.allowSecondSemaphore.wait(timeout: .now() + 1)
        Self.lock.lock()
        let secondPayload = Self.secondPayload
        Self.lock.unlock()
        client?.urlProtocol(self, didLoad: secondPayload)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {
        Self.allowSecondSemaphore.signal()
        Self.stopSemaphore.signal()
    }
}
#endif

#if canImport(Darwin)
private let timeoutTestSocketStreamType = SOCK_STREAM
private let timeoutTestSendFlags: Int32 = 0
#else
private let timeoutTestSocketStreamType = Int32(SOCK_STREAM.rawValue)
private let timeoutTestSendFlags = Int32(MSG_NOSIGNAL)
#endif
