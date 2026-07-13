import XCTest
@testable import PastewatchCore

#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

/// WO-319/WO-322: real TCP proxy harness tests for admission and forwarding behavior.
final class ProxyRealServerTests: XCTestCase {

    func testRealProxyRoundTripsBufferedResponse() throws {
        let upstream = try StubHTTPServer { _ in
            StubHTTPResponse(
                status: 200,
                headers: ["Content-Type": "application/json"],
                body: Data(#"{"ok":true}"#.utf8)
            )
        }
        try upstream.start()
        defer { upstream.stop() }

        let proxyPort = try TCPTestSocket.reserveLoopbackPort()
        let proxy = ProxyServer(
            port: proxyPort,
            upstream: URL(string: "http://127.0.0.1:\(upstream.port)")!
        )
        let runningProxy = RunningProxy(server: proxy)
        try runningProxy.start()
        defer { runningProxy.stop() }

        let response = try TCPTestSocket.roundTrip(
            port: proxyPort,
            request: TCPTestSocket.postRequest(path: "/v1/messages"),
            timeoutSeconds: 10
        )

        let admission = proxy.connectionAdmissionStats
        let diagnostic = TCPTestSocket.describeResponse(response) +
            " proxy_processed=\(proxy.stats.requestsProcessed)" +
            " proxy_rejected=\(admission.rejected)" +
            " upstream_requests=\(upstream.requestCount)"
        XCTAssertTrue(response.contains("HTTP/1.1 200 OK"), diagnostic)
        XCTAssertTrue(response.contains(#"{"ok":true}"#), diagnostic)
    }

    // WO-408/WO-411: an OpenAI-shaped body is refused with 415 and never reaches upstream.
    func testUnsupportedBodyShapeRefusedBeforeUpstream() throws {
        let upstream = try StubHTTPServer { _ in
            StubHTTPResponse(status: 200, headers: [:], body: Data(#"{"ok":true}"#.utf8))
        }
        try upstream.start()
        defer { upstream.stop() }

        let proxyPort = try TCPTestSocket.reserveLoopbackPort()
        let proxy = ProxyServer(port: proxyPort, upstream: URL(string: "http://127.0.0.1:\(upstream.port)")!)
        let runningProxy = RunningProxy(server: proxy)
        try runningProxy.start()
        defer { runningProxy.stop() }

        let openAIBody = #"{"model":"gpt-4","messages":[{"role":"user","content":"x"}]}"#
        let response = try TCPTestSocket.roundTrip(
            port: proxyPort,
            request: TCPTestSocket.postRequest(path: "/v1/chat/completions", body: openAIBody),
            timeoutSeconds: 10
        )
        let diagnostic = TCPTestSocket.describeResponse(response) + " upstream_requests=\(upstream.requestCount)"
        XCTAssertTrue(response.contains("HTTP/1.1 415"), diagnostic)
        XCTAssertEqual(upstream.requestCount, 0, "foreign body must not reach upstream; \(diagnostic)")
    }

    // WO-412: unsupported JSON POST bodies without messages arrays are also refused.
    func testUnsupportedJSONPostWithoutMessagesRefusedBeforeUpstream() throws {
        let upstream = try StubHTTPServer { _ in
            StubHTTPResponse(status: 200, headers: [:], body: Data(#"{"ok":true}"#.utf8))
        }
        try upstream.start()
        defer { upstream.stop() }

        let proxyPort = try TCPTestSocket.reserveLoopbackPort()
        let proxy = ProxyServer(port: proxyPort, upstream: URL(string: "http://127.0.0.1:\(upstream.port)")!)
        let runningProxy = RunningProxy(server: proxy)
        try runningProxy.start()
        defer { runningProxy.stop() }

        let response = try TCPTestSocket.roundTrip(
            port: proxyPort,
            request: TCPTestSocket.postRequest(path: "/v1/responses", body: #"{"input":"hello"}"#),
            timeoutSeconds: 10
        )
        let diagnostic = TCPTestSocket.describeResponse(response) + " upstream_requests=\(upstream.requestCount)"
        XCTAssertTrue(response.contains("HTTP/1.1 415"), diagnostic)
        XCTAssertEqual(upstream.requestCount, 0, "unsupported body must not reach upstream; \(diagnostic)")
    }

    // WO-413: quiet mode suppresses stderr, not durable audit evidence.
    func testUnsupportedBodyShapeRefusalWritesAuditLogWhenQuiet() throws {
        let upstream = try StubHTTPServer { _ in
            StubHTTPResponse(status: 200, headers: [:], body: Data(#"{"ok":true}"#.utf8))
        }
        try upstream.start()
        defer { upstream.stop() }

        let auditPath = FileManager.default.temporaryDirectory
            .appendingPathComponent("pastewatch-refused-shape-\(UUID().uuidString).log")
        defer { try? FileManager.default.removeItem(at: auditPath) }

        let proxyPort = try TCPTestSocket.reserveLoopbackPort()
        let proxy = ProxyServer(
            port: proxyPort,
            upstream: URL(string: "http://127.0.0.1:\(upstream.port)")!,
            auditLogPath: auditPath.path,
            quietLog: true
        )
        let runningProxy = RunningProxy(server: proxy)
        try runningProxy.start()
        var proxyStopped = false
        defer {
            if !proxyStopped {
                runningProxy.stop()
            }
        }

        let response = try TCPTestSocket.roundTrip(
            port: proxyPort,
            request: TCPTestSocket.postRequest(path: "/v1/responses", body: #"{"input":"hello"}"#),
            timeoutSeconds: 10
        )
        runningProxy.stop()
        proxyStopped = true

        let diagnostic = TCPTestSocket.describeResponse(response) + " upstream_requests=\(upstream.requestCount)"
        XCTAssertTrue(response.contains("HTTP/1.1 415"), diagnostic)
        XCTAssertEqual(upstream.requestCount, 0, "unsupported body must not reach upstream; \(diagnostic)")

        let audit = try String(contentsOf: auditPath, encoding: .utf8)
        XCTAssertTrue(audit.contains("PROXY REFUSED unsupported upstream body shape"), audit)
        XCTAssertTrue(audit.contains("/v1/responses"), audit)
        XCTAssertTrue(audit.contains("unsupported JSON POST body"), audit)
    }

    // WO-408: an Anthropic-shaped count-tokens body is forwarded, not falsely refused.
    func testAnthropicCountTokensNotRefused() throws {
        let upstream = try StubHTTPServer { _ in
            StubHTTPResponse(status: 200, headers: [:], body: Data(#"{"input_tokens":3}"#.utf8))
        }
        try upstream.start()
        defer { upstream.stop() }

        let proxyPort = try TCPTestSocket.reserveLoopbackPort()
        let proxy = ProxyServer(port: proxyPort, upstream: URL(string: "http://127.0.0.1:\(upstream.port)")!)
        let runningProxy = RunningProxy(server: proxy)
        try runningProxy.start()
        defer { runningProxy.stop() }

        let body = #"{"model":"claude-3","messages":[{"role":"user","content":"count me"}]}"#
        let response = try TCPTestSocket.roundTrip(
            port: proxyPort,
            request: TCPTestSocket.postRequest(path: "/v1/messages/count_tokens", body: body),
            timeoutSeconds: 10
        )
        let diagnostic = TCPTestSocket.describeResponse(response) + " upstream_requests=\(upstream.requestCount)"
        XCTAssertFalse(response.contains("HTTP/1.1 415"), "count_tokens wrongly refused; \(diagnostic)")
        XCTAssertEqual(upstream.requestCount, 1, "count_tokens must be forwarded; \(diagnostic)")
    }

    func testAdmissionCapRejectsFifthConcurrentConnection() throws {
        let upstreamEntered = DispatchSemaphore(value: 0)
        let upstreamRelease = DispatchSemaphore(value: 0)
        let upstream = try StubHTTPServer { _ in
            upstreamEntered.signal()
            _ = upstreamRelease.wait(timeout: .now() + 5)
            return StubHTTPResponse(
                status: 200,
                headers: ["Content-Type": "application/json"],
                body: Data(#"{"held":true}"#.utf8)
            )
        }
        try upstream.start()
        defer { upstream.stop() }

        let proxyPort = try TCPTestSocket.reserveLoopbackPort()
        let proxy = ProxyServer(
            port: proxyPort,
            upstream: URL(string: "http://127.0.0.1:\(upstream.port)")!
        )
        let runningProxy = RunningProxy(server: proxy)
        try runningProxy.start()
        defer { runningProxy.stop() }

        let group = DispatchGroup()
        let responseLock = NSLock()
        var heldResponses = Array(repeating: "", count: proxyMaxActiveConnections)
        for index in 0..<proxyMaxActiveConnections {
            group.enter()
            runDetached {
                let response = (try? TCPTestSocket.roundTrip(
                    port: proxyPort,
                    request: TCPTestSocket.postRequest(path: "/v1/messages"),
                    timeoutSeconds: 5
                )) ?? ""
                responseLock.lock()
                heldResponses[index] = response
                responseLock.unlock()
                group.leave()
            }
        }

        for _ in 0..<proxyMaxActiveConnections {
            XCTAssertEqual(upstreamEntered.wait(timeout: .now() + 3), .success)
        }
        eventually(timeout: 3) {
            proxy.connectionAdmissionStats.active == proxyMaxActiveConnections
        }

        let rejected = try TCPTestSocket.roundTrip(
            port: proxyPort,
            request: TCPTestSocket.postRequest(path: "/v1/messages"),
            timeoutSeconds: 3
        )
        XCTAssertTrue(rejected.contains("HTTP/1.1 503 Service Unavailable"))
        XCTAssertTrue(rejected.contains(#""error": "Proxy admission timeout""#))
        XCTAssertGreaterThanOrEqual(proxy.connectionAdmissionStats.rejected, 1)

        for _ in 0..<proxyMaxActiveConnections {
            upstreamRelease.signal()
        }
        XCTAssertEqual(group.wait(timeout: .now() + 5), .success)
        XCTAssertTrue(heldResponses.allSatisfy { $0.contains("HTTP/1.1 200 OK") })
    }

    func testAdmitConnectionIncrementsActiveBeforeReturning() throws {
        let proxyPort = try TCPTestSocket.reserveLoopbackPort()
        let proxy = ProxyServer(port: proxyPort)
        let runningProxy = RunningProxy(server: proxy)
        try runningProxy.start()
        defer { runningProxy.stop() }

        for expectedActive in 1...proxyMaxActiveConnections {
            XCTAssertTrue(proxy.admitConnectionForTesting())
            XCTAssertEqual(proxy.connectionAdmissionStats.active, expectedActive)
        }

        for expectedActive in stride(from: proxyMaxActiveConnections - 1, through: 0, by: -1) {
            proxy.finishAdmittedConnectionForTesting()
            XCTAssertEqual(proxy.connectionAdmissionStats.active, expectedActive)
        }
    }

    func testAdmitConnectionAfterStopSendsHTTP503ToAcceptedSocket() throws {
        let proxyPort = try TCPTestSocket.reserveLoopbackPort()
        let proxy = ProxyServer(port: proxyPort)
        let runningProxy = RunningProxy(server: proxy)
        try runningProxy.start()
        defer { runningProxy.stop() }

        let sockets = try TCPTestSocket.socketPair()
        defer { close(sockets.client) }
        defer { close(sockets.server) }

        proxy.stopAdmissionForTesting()

        XCTAssertFalse(proxy.admitConnectionForTesting(sockets.server))
        let response = try TCPTestSocket.readHTTPMessage(from: sockets.client, timeoutSeconds: 2)
        let text = String(data: response, encoding: .utf8) ?? ""

        XCTAssertTrue(text.contains("HTTP/1.1 503 Service Unavailable"), TCPTestSocket.describeResponse(text))
        XCTAssertTrue(text.contains(#""error": "Service Unavailable""#), TCPTestSocket.describeResponse(text))
    }

    func testQueuedAdmissionAfterStopSendsHTTP503WhenSlotOpens() throws {
        let proxyPort = try TCPTestSocket.reserveLoopbackPort()
        let proxy = ProxyServer(port: proxyPort)
        let runningProxy = RunningProxy(server: proxy)
        try runningProxy.start()
        defer { runningProxy.stop() }

        var heldSlots = 0
        for _ in 0..<proxyMaxActiveConnections {
            XCTAssertTrue(proxy.admitConnectionForTesting())
            heldSlots += 1
        }
        defer {
            for _ in 0..<heldSlots {
                proxy.finishAdmittedConnectionForTesting()
            }
        }

        let sockets = try TCPTestSocket.socketPair()
        defer { close(sockets.client) }
        let finished = DispatchSemaphore(value: 0)
        let admittedLock = NSLock()
        var admitted: Bool?
        runDetached {
            let result = proxy.admitConnectionForTesting(sockets.server)
            admittedLock.lock()
            admitted = result
            admittedLock.unlock()
            close(sockets.server)
            finished.signal()
        }
        eventually(timeout: 1) {
            proxy.connectionAdmissionStats.queued == 1
        }

        proxy.stopAdmissionForTesting()
        proxy.finishAdmittedConnectionForTesting()
        heldSlots -= 1

        XCTAssertEqual(finished.wait(timeout: .now() + 2), .success)
        admittedLock.lock()
        let admittedResult = admitted
        admittedLock.unlock()
        XCTAssertEqual(admittedResult, false)
        let response = try TCPTestSocket.readHTTPMessage(from: sockets.client, timeoutSeconds: 2)
        let text = String(data: response, encoding: .utf8) ?? ""

        XCTAssertTrue(text.contains("HTTP/1.1 503 Service Unavailable"), TCPTestSocket.describeResponse(text))
        XCTAssertTrue(text.contains(#""error": "Service Unavailable""#), TCPTestSocket.describeResponse(text))
    }

    func testQueuedAdmissionAfterStopSendsHTTP503WhenQueueTimeoutExpires() throws {
        let proxyPort = try TCPTestSocket.reserveLoopbackPort()
        let proxy = ProxyServer(port: proxyPort)
        let runningProxy = RunningProxy(server: proxy)
        try runningProxy.start()
        defer { runningProxy.stop() }

        var heldSlots = 0
        for _ in 0..<proxyMaxActiveConnections {
            XCTAssertTrue(proxy.admitConnectionForTesting())
            heldSlots += 1
        }
        defer {
            for _ in 0..<heldSlots {
                proxy.finishAdmittedConnectionForTesting()
            }
        }

        let sockets = try TCPTestSocket.socketPair()
        defer { close(sockets.client) }
        let finished = DispatchSemaphore(value: 0)
        let admittedLock = NSLock()
        var admitted: Bool?
        runDetached {
            let result = proxy.admitConnectionForTesting(sockets.server)
            admittedLock.lock()
            admitted = result
            admittedLock.unlock()
            close(sockets.server)
            finished.signal()
        }
        eventually(timeout: 1) {
            proxy.connectionAdmissionStats.queued == 1
        }

        proxy.stopAdmissionForTesting()

        XCTAssertEqual(finished.wait(timeout: .now() + 2), .success)
        admittedLock.lock()
        let admittedResult = admitted
        admittedLock.unlock()
        XCTAssertEqual(admittedResult, false)
        let response = try TCPTestSocket.readHTTPMessage(from: sockets.client, timeoutSeconds: 2)
        let text = String(data: response, encoding: .utf8) ?? ""

        XCTAssertTrue(text.contains("HTTP/1.1 503 Service Unavailable"), TCPTestSocket.describeResponse(text))
        XCTAssertTrue(text.contains(#""error": "Service Unavailable""#), TCPTestSocket.describeResponse(text))
    }

    private func eventually(
        timeout: TimeInterval,
        file: StaticString = #filePath,
        line: UInt = #line,
        condition: () -> Bool
    ) {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if condition() { return }
            Thread.sleep(forTimeInterval: 0.01)
        }
        XCTFail("condition not satisfied before timeout", file: file, line: line)
    }
}

private final class RunningProxy {
    private let server: ProxyServer
    private let started = DispatchSemaphore(value: 0)
    private let stopped = DispatchSemaphore(value: 0)
    private var startError: Error?

    init(server: ProxyServer) {
        self.server = server
    }

    func start() throws {
        runDetached {
            do {
                try self.server.start {
                    self.started.signal()
                }
            } catch {
                self.startError = error
                self.started.signal()
            }
            self.stopped.signal()
        }
        guard started.wait(timeout: .now() + 3) == .success else {
            throw ProxyHarnessError.timeout("proxy did not start")
        }
        if let startError { throw startError }
    }

    func stop() {
        server.stop()
        _ = stopped.wait(timeout: .now() + 3)
    }
}

private struct StubHTTPResponse {
    let status: Int
    let headers: [String: String]
    let body: Data
}

private final class StubHTTPServer {
    typealias Handler = (Data) -> StubHTTPResponse

    private let handler: Handler
    private let lock = NSLock()
    private var listenSocket: Int32 = -1
    private var isRunning = false
    private var handledRequests = 0

    private(set) var port: UInt16 = 0
    var requestCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return handledRequests
    }

    init(handler: @escaping Handler) throws {
        self.handler = handler
    }

    func start() throws {
        listenSocket = try TCPTestSocket.listenOnLoopback(port: 0)
        port = try TCPTestSocket.boundPort(for: listenSocket)
        isRunning = true
        let acceptSocket = listenSocket
        runDetached {
            self.acceptLoop(listenSocket: acceptSocket)
        }
    }

    func stop() {
        lock.lock()
        isRunning = false
        let fd = listenSocket
        let portToWake = port
        listenSocket = -1
        lock.unlock()
        if fd >= 0 {
            TCPTestSocket.wakeLoopbackListener(port: portToWake)
            close(fd)
        }
    }

    private func acceptLoop(listenSocket: Int32) {
        // WO-262: mirror ProxyServer.start(); stop() owns the mutable property,
        // while the accept loop uses an immutable fd captured at listener startup.
        while running {
            var addr = sockaddr_in()
            var len = socklen_t(MemoryLayout<sockaddr_in>.size)
            let client = withUnsafeMutablePointer(to: &addr) { ptr in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                    accept(listenSocket, sockPtr, &len)
                }
            }
            guard client >= 0 else { continue }
            guard running else {
                close(client)
                break
            }
            runDetached {
                self.handle(client)
            }
        }
    }

    private var running: Bool {
        lock.lock()
        defer { lock.unlock() }
        return isRunning
    }

    private func handle(_ client: Int32) {
        defer { close(client) }
        guard let request = try? TCPTestSocket.readHTTPMessage(from: client, timeoutSeconds: 5) else {
            return
        }
        lock.lock()
        handledRequests += 1
        lock.unlock()
        let response = handler(request)
        var head = "HTTP/1.1 \(response.status) \(CurlHTTPClient.httpReasonPhrase(for: response.status))\r\n"
        for (key, value) in response.headers {
            head += "\(key): \(value)\r\n"
        }
        head += "Content-Length: \(response.body.count)\r\nConnection: close\r\n\r\n"
        var data = Data(head.utf8)
        data.append(response.body)
        try? TCPTestSocket.writeAll(data, to: client)
    }
}

private enum TCPTestSocket {
    static func postRequest(path: String, body: String = "{}") -> String {
        let bodyData = Data(body.utf8)
        return """
        POST \(path) HTTP/1.1\r
        Host: 127.0.0.1\r
        Content-Type: application/json\r
        Content-Length: \(bodyData.count)\r
        \r
        \(body)
        """
    }

    static func reserveLoopbackPort() throws -> UInt16 {
        let fd = try listenOnLoopback(port: 0)
        defer { close(fd) }
        return try boundPort(for: fd)
    }

    static func listenOnLoopback(port: UInt16) throws -> Int32 {
        let fd = socket(AF_INET, testSocketStreamType, 0)
        guard fd >= 0 else { throw ProxyHarnessError.systemError("socket") }
        var reuse: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size))

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        let bindResult = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                bind(fd, sockPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bindResult == 0 else {
            close(fd)
            throw ProxyHarnessError.systemError("bind")
        }
        guard listen(fd, 128) == 0 else {
            close(fd)
            throw ProxyHarnessError.systemError("listen")
        }
        return fd
    }

    static func boundPort(for fd: Int32) throws -> UInt16 {
        var addr = sockaddr_in()
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        let result = withUnsafeMutablePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                getsockname(fd, sockPtr, &len)
            }
        }
        guard result == 0 else { throw ProxyHarnessError.systemError("getsockname") }
        return UInt16(bigEndian: addr.sin_port)
    }

    static func wakeLoopbackListener(port: UInt16) {
        // WO-330: mirror ProxyServer.stop() so Linux CI does not leak blocked
        // accept-loop threads between real-socket harness tests.
        let fd = socket(AF_INET, testSocketStreamType, 0)
        guard fd >= 0 else { return }
        defer { close(fd) }
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        _ = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                connect(fd, sockPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
    }

    static func socketPair() throws -> (client: Int32, server: Int32) {
        var sockets = [Int32](repeating: 0, count: 2)
        let result = socketpair(AF_UNIX, testSocketStreamType, 0, &sockets)
        guard result == 0 else { throw ProxyHarnessError.systemError("socketpair") }
        return (sockets[0], sockets[1])
    }

    static func roundTrip(port: UInt16, request: String, timeoutSeconds: Int = 3) throws -> String {
        let fd = socket(AF_INET, testSocketStreamType, 0)
        guard fd >= 0 else { throw ProxyHarnessError.systemError("socket") }
        defer { close(fd) }
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        let connected = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                connect(fd, sockPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard connected == 0 else { throw ProxyHarnessError.systemError("connect") }
        try writeAll(Data(request.utf8), to: fd)
        let data = try readToEOF(from: fd, timeoutSeconds: timeoutSeconds)
        return String(data: data, encoding: .utf8) ?? ""
    }

    static func describeResponse(_ response: String) -> String {
        // WO-319: Linux XCTest logs multiline assertion messages poorly; keep
        // real-socket harness failures as a single escaped line with length.
        let escaped = response
            .replacingOccurrences(of: "\r", with: "\\r")
            .replacingOccurrences(of: "\n", with: "\\n")
        return "response_bytes=\(response.utf8.count) response=\(escaped)"
    }

    static func readHTTPMessage(from fd: Int32, timeoutSeconds: Int) throws -> Data {
        setReceiveTimeout(on: fd, seconds: timeoutSeconds)
        let deadline = Date().addingTimeInterval(TimeInterval(timeoutSeconds))
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while true {
            let n = recv(fd, &buffer, buffer.count, 0)
            if n < 0 {
                if errno == EINTR { continue }
                if errno == EAGAIN || errno == EWOULDBLOCK {
                    // WO-319: a recv timeout is not EOF; keep the harness deadline explicit.
                    guard Date() < deadline else {
                        throw ProxyHarnessError.timeout("timed out reading HTTP message")
                    }
                    Thread.sleep(forTimeInterval: 0.01)
                    continue
                }
                // WO-319: reset after bytes is an EOF-equivalent for the socket harness.
                if errno == ECONNRESET && !data.isEmpty { break }
                throw ProxyHarnessError.systemError("recv")
            }
            guard n > 0 else { break }
            data.append(contentsOf: buffer[0..<n])
            if let headerEnd = data.range(of: Data("\r\n\r\n".utf8))?.upperBound {
                let header = String(data: data[..<headerEnd], encoding: .utf8) ?? ""
                let length = header
                    .components(separatedBy: "\r\n")
                    .compactMap { line -> Int? in
                        guard line.lowercased().hasPrefix("content-length:") else { return nil }
                        return Int(line.split(separator: ":", maxSplits: 1)[1].trimmingCharacters(in: .whitespaces))
                    }
                    .first ?? 0
                if data.count >= headerEnd + length { break }
            }
        }
        return data
    }

    static func readToEOF(from fd: Int32, timeoutSeconds: Int) throws -> Data {
        setReceiveTimeout(on: fd, seconds: timeoutSeconds)
        let deadline = Date().addingTimeInterval(TimeInterval(timeoutSeconds))
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while true {
            let n = recv(fd, &buffer, buffer.count, 0)
            if n > 0 {
                data.append(contentsOf: buffer[0..<n])
                continue
            }
            if n == 0 { break }
            if errno == EINTR { continue }
            if errno == EAGAIN || errno == EWOULDBLOCK {
                // WO-319: Linux CI can report EAGAIN before proxy bytes arrive.
                guard Date() < deadline else {
                    throw ProxyHarnessError.timeout("timed out reading response")
                }
                Thread.sleep(forTimeInterval: 0.01)
                continue
            }
            // WO-319: reset after a response body is still a completed round trip.
            if errno == ECONNRESET && !data.isEmpty { break }
            throw ProxyHarnessError.systemError("recv")
        }
        return data
    }

    static func writeAll(_ data: Data, to fd: Int32) throws {
        try data.withUnsafeBytes { rawBuffer in
            guard let base = rawBuffer.baseAddress else { return }
            var offset = 0
            while offset < data.count {
                let written = send(fd, base.advanced(by: offset), data.count - offset, 0)
                guard written > 0 else { throw ProxyHarnessError.systemError("send") }
                offset += written
            }
        }
    }

    private static func setReceiveTimeout(on fd: Int32, seconds: Int) {
        var timeout = timeval(tv_sec: seconds, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
    }
}

private func runDetached(_ work: @escaping () -> Void) {
    // WO-319: use real threads for blocking sockets so Linux CI does not rely on
    // DispatchQueue.global() overcommit behavior while clients wait for EOF.
    Thread.detachNewThread(work)
}

private enum ProxyHarnessError: Error, CustomStringConvertible {
    case posix(String, Int32)
    case timeout(String)

    static func systemError(_ op: String) -> ProxyHarnessError {
        .posix(op, errno)
    }

    var description: String {
        switch self {
        case .posix(let op, let code):
            return "\(op) failed with errno \(code)"
        case .timeout(let message):
            return message
        }
    }
}

#if canImport(Darwin)
private let testSocketStreamType = SOCK_STREAM
#else
private let testSocketStreamType = Int32(SOCK_STREAM.rawValue)
#endif
