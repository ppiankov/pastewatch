import XCTest
@testable import PastewatchCore

#if canImport(Darwin)
import Darwin
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

    func testSSEStreamRelayHardCeilingCancelsHangingTaskWithoutWritingHeaders() {
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
        assertNoDataAvailable(on: sockets[0])
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
            severity: .high,
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
        relay.buildAlertBeforeDone = { _, _, _, _ in
            Data("event: pastewatch_advisory\ndata: {}\n\n".utf8)
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
#endif
