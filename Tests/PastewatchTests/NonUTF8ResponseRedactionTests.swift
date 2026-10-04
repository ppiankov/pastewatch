import Foundation
import XCTest
@testable import PastewatchCore
#if canImport(Darwin)
import Darwin
#else
import Glibc
import FoundationNetworking
#endif

// WO-641@v2: binary response tests distinguish exact replacement from transport refusal.
final class NonUTF8ResponseRedactionTests: XCTestCase {
    // WO-641@v2: a multibyte value is replaced at its detected occurrence without rewriting binary bytes.
    func testLocatableMultibyteSecretPreservesSurroundingBytes() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            let value = ["binary", "\u{00E9}", "value"].joined()
            let config = fixtureConfig(value)
            for prefix in [Data([0xFF]), Data([0xF0, 0x90, 0x80]), Data("\u{1F4A1}".utf8) + Data([0xC0, 0xAF])] {
                let body = prefix + Data("before \(value) after".utf8)
                for result in [
                    CurlHTTPClient.redactNonUTF8ResponseBody(body, config: config, severity: .high),
                    CurlHTTPClient.redactBufferedResponseBody(body, config: config, severity: .high),
                    redactRawStreamBytes(body, config: config, severity: .high)
                ] {
                    XCTAssertEqual(result.count, 1)
                    XCTAssertTrue(result.data == prefix + Data("before <CREDENTIAL_1> after".utf8))
                    XCTAssertNil(result.data.range(of: Data(value.utf8)))
                }
            }
        }
    }

    // WO-641@v2: a repaired scalar cannot be located by stealing an earlier equal standalone value.
    func testUnlocatableSecretCannotUseAnEarlierDecoy() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            let value = ["binary", "\u{FFFD}", "value"].joined()
            let config = fixtureConfig(value, anchored: true)
            let body = Data("\(value)\ndata: binary".utf8) + Data([0xFF]) + Data("value\n\n".utf8)
            for result in [
                CurlHTTPClient.redactNonUTF8ResponseBody(body, config: config, severity: .high),
                redactRawStreamBytes(body, config: config, severity: .high)
            ] {
                XCTAssertEqual(result.count, 0)
                XCTAssertTrue(result.data.isEmpty)
            }
        }
    }

    // WO-641@v2: a later unlocatable match discards earlier attempted replacements without counting them.
    func testRefusalDoesNotCountPartialReplacements() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            let value = ["binary", "\u{FFFD}", "value"].joined()
            let body = Data(value.utf8) + Data(" binary".utf8) + Data([0xFF]) + Data("value".utf8)
            let result = CurlHTTPClient.redactNonUTF8ResponseBody(body, config: fixtureConfig(value), severity: .high)
            XCTAssertTrue(result.data.isEmpty)
            XCTAssertEqual(result.count, 0)
        }
    }

    // WO-641@v2: both raw-stream variants suppress refused EOF windows and their trailing bytes.
    func testCurlRawStreamRefusesBinaryWindows() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            let value = ["binary", "\u{FFFD}", "value"].joined()
            for alert: CurlHTTPClient.StreamAlertBuilder? in [nil, { _, _, _, _ in Data("notice".utf8) }] {
                let sockets = try socketPair()
                defer { close(sockets.0); close(sockets.1) }
                let pipe = Pipe()
                let body = Data("binary".utf8) + Data([0xFF]) + Data("value\n\nlater".utf8)
                try pipe.fileHandleForWriting.write(contentsOf: body)
                try pipe.fileHandleForWriting.close()
                let result = CurlHTTPClient.relayBodyChunks(
                    from: pipe,
                    ctx: .init(clientSocket: sockets.1, sendFlags: socketFlags, redactionMode: .rawStream,
                               config: fixtureConfig(value), severity: .high),
                    alertBeforeDone: alert
                )
                shutdown(sockets.1, Int32(SHUT_WR))
                XCTAssertTrue(try readToEOF(sockets.0).isEmpty)
                XCTAssertEqual(result.redactionCount, 0)
            }
        }
    }

    // WO-641@v2: a buffered refusal reuses the HTTP error writer and records no successful redaction.
    func testBufferedProxyRefusesUnlocatableSecretWithClassOnly502() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { directory in
            let value = ["binary", "\u{FFFD}", "value"].joined()
            let body = Data("binary".utf8) + Data([0xFF]) + Data("value".utf8)
            let listener = try listenSocket()
            defer { close(listener.fd) }
            let upstreamDone = DispatchSemaphore(value: 0)
            Thread.detachNewThread {
                defer { upstreamDone.signal() }
                let client = accept(listener.fd, nil, nil)
                guard client >= 0 else { return }
                defer { close(client) }
                var bytes = [UInt8](repeating: 0, count: 4096)
                _ = recv(client, &bytes, bytes.count, 0)
                let head = "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: \(body.count)\r\nConnection: close\r\n\r\n"
                _ = sendAll(Data(head.utf8) + body, to: client, flags: self.socketFlags)
            }
            let reserved = try listenSocket()
            close(reserved.fd)
            let audit = directory.appendingPathComponent("audit.log")
            let proxy = ProxyServer(
                port: reserved.port, upstream: URL(string: "http://127.0.0.1:\(listener.port)")!,
                config: fixtureConfig(value), auditLogPath: audit.path, injectAlert: false, quietLog: true
            )
            let ready = DispatchSemaphore(value: 0)
            let stopped = DispatchSemaphore(value: 0)
            Thread.detachNewThread {
                defer { stopped.signal() }
                try? proxy.start { ready.signal() }
            }
            defer { proxy.stop(); _ = stopped.wait(timeout: .now() + 5) }
            XCTAssertEqual(ready.wait(timeout: .now() + 5), .success)
            let client = try connectSocket(port: reserved.port)
            defer { close(client) }
            let request = "GET /v1/messages HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
            XCTAssertTrue(sendAll(Data(request.utf8), to: client, flags: socketFlags))
            let response = try readToEOF(client)
            XCTAssertTrue(response.starts(with: Data("HTTP/1.1 502".utf8)))
            XCTAssertNil(response.range(of: body))
            XCTAssertNil(response.range(of: Data(value.utf8)))
            let split = try XCTUnwrap(response.range(of: Data("\r\n\r\n".utf8)))
            let json = try JSONSerialization.jsonObject(with: Data(response[split.upperBound...])) as? [String: Any]
            XCTAssertNotNil(json?["error"])
            XCTAssertTrue(String(data: response, encoding: .utf8)?.contains("Binary fixture") == true)
            XCTAssertEqual(proxy.stats.secretsRedacted, 0)
            proxy.stop()
            XCTAssertEqual(upstreamDone.wait(timeout: .now() + 5), .success)
            let log = try Data(contentsOf: audit)
            XCTAssertNil(log.range(of: Data(value.utf8)))
            XCTAssertTrue(String(data: log, encoding: .utf8)?.contains("REDACTION FAILED 1") == true)
        }
    }

    // WO-641@v2: the curl relay sends earlier frames, but neither the refused frame nor later bytes.
    func testCurlSSEStreamStopsBeforeRefusedFrame() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            let value = ["binary", "\u{FFFD}", "value"].joined()
            let first = Data("data: first\n\n".utf8)
            let bad = Data("data: binary".utf8) + Data([0xFF]) + Data("value\n\n".utf8)
            let later = Data("data: later\n\n".utf8)
            let sockets = try socketPair()
            defer { close(sockets.0); close(sockets.1) }
            let pipe = Pipe()
            try pipe.fileHandleForWriting.write(contentsOf: first + bad + later)
            try pipe.fileHandleForWriting.close()
            let result = CurlHTTPClient.relayBodyChunks(
                from: pipe,
                ctx: .init(clientSocket: sockets.1, sendFlags: socketFlags, redactionMode: .perSSEEvent,
                           config: fixtureConfig(value), severity: .high)
            )
            shutdown(sockets.1, Int32(SHUT_WR))
            XCTAssertTrue(try readToEOF(sockets.0) == first)
            XCTAssertEqual(result.redactionCount, 0)
        }
    }

    #if canImport(Darwin)
    // WO-641@v2: URLSession callbacks after refusal and EOF cannot release buffered secret bytes.
    func testDarwinStreamsStopBeforeRefusedFrame() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            let value = ["binary", "\u{FFFD}", "value"].joined()
            for mode: StreamingRedactionMode in [.rawStream, .perSSEEvent] {
                let sockets = try socketPair()
                defer { close(sockets.0); close(sockets.1) }
                let relay = SSEStreamRelay(clientSocket: sockets.1, sendFlags: 0, redactionMode: mode,
                                           config: fixtureConfig(value), severity: .high, idleTimeoutSeconds: 60)
                let session = URLSession(configuration: .ephemeral)
                defer { session.invalidateAndCancel() }
                let task = session.dataTask(with: URL(string: "http://127.0.0.1/")!)
                let first = Data("data: first\n\n".utf8)
                let bad = Data("data: binary".utf8) + Data([0xFF]) + Data("value\n\n".utf8)
                relay.urlSession(session, dataTask: task, didReceive: first)
                relay.urlSession(session, dataTask: task, didReceive: bad)
                relay.urlSession(session, dataTask: task, didReceive: Data("data: later\n\n".utf8))
                relay.urlSession(session, task: task, didCompleteWithError: nil)
                shutdown(sockets.1, Int32(SHUT_WR))
                let response = try readToEOF(sockets.0)
                XCTAssertNotNil(response.range(of: first))
                XCTAssertNil(response.range(of: bad))
                XCTAssertNil(response.range(of: Data("data: later".utf8)))
                XCTAssertEqual(relay.snapshotStreamStats().redactionCount, 0)
            }
        }
    }
    #endif

    // WO-641@v2: isolate the exact binary grammar from every ambient configuration.
    private func fixtureConfig(_ value: String, anchored: Bool = false) -> PastewatchConfig {
        var config = PastewatchConfig.defaultConfig
        config.customRules = [.init(name: "Binary fixture", pattern: (anchored ? "(?<=data: )" : "") +
                                   NSRegularExpression.escapedPattern(for: value), severity: "critical")]
        return config
    }

    // WO-641@v2: sockets use the existing signal-safe send policy on each platform.
    private var socketFlags: Int32 {
        #if canImport(Darwin)
        return 0
        #else
        return Int32(MSG_NOSIGNAL)
        #endif
    }

    // WO-641@v2: socket construction is portable and does not bind a predetermined port.
    private func streamSocket() throws -> Int32 {
        #if canImport(Darwin)
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        #else
        let fd = socket(AF_INET, Int32(SOCK_STREAM.rawValue), 0)
        #endif
        // WO-641@v2: preserve the socket syscall's actual failure code.
        guard fd >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        return fd
    }

    // WO-641@v2: the refusal test owns its loopback listener for the entire upstream exchange.
    private func listenSocket() throws -> (fd: Int32, port: UInt16) {
        let fd = try streamSocket()
        var address = sockaddr_in()
        address.sin_family = sa_family_t(AF_INET)
        address.sin_addr.s_addr = inet_addr("127.0.0.1")
        let result = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Foundation.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        // WO-641@v2: capture the bind/listen failure before closing the descriptor.
        guard result == 0, listen(fd, 2) == 0 else {
            let error = POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            close(fd)
            throw error
        }
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        let bound = withUnsafeMutablePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &length) }
        }
        // WO-641@v2: cleanup must not replace getsockname's failure code.
        guard bound == 0 else {
            let error = POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            close(fd)
            throw error
        }
        return (fd, UInt16(bigEndian: address.sin_port))
    }

    // WO-641@v2: client connect errors fail the test rather than silently skipping the transport.
    private func connectSocket(port: UInt16) throws -> Int32 {
        let fd = try streamSocket()
        var address = sockaddr_in()
        address.sin_family = sa_family_t(AF_INET)
        address.sin_addr.s_addr = inet_addr("127.0.0.1")
        address.sin_port = port.bigEndian
        let result = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        // WO-641@v2: retain connect's errno before releasing its failed socket.
        guard result == 0 else {
            let error = POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            close(fd)
            throw error
        }
        return fd
    }

    // WO-641@v2: a socket pair tests the production relay without an external server.
    private func socketPair() throws -> (Int32, Int32) {
        var fds = [Int32](repeating: 0, count: 2)
        #if canImport(Darwin)
        let result = socketpair(AF_UNIX, SOCK_STREAM, 0, &fds)
        #else
        let result = socketpair(AF_UNIX, Int32(SOCK_STREAM.rawValue), 0, &fds)
        #endif
        // WO-641@v2: report the actual socketpair failure on either platform.
        guard result == 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        return (fds[0], fds[1])
    }

    // WO-641@v2: only EOF counts as successful stream termination; timeouts fail deterministically.
    private func readToEOF(_ fd: Int32) throws -> Data {
        var timeout = timeval(tv_sec: 5, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        var result = Data()
        var bytes = [UInt8](repeating: 0, count: 4096)
        while true {
            let count = recv(fd, &bytes, bytes.count, 0)
            if count == 0 { return result }
            // WO-641@v2: child-process signals can interrupt recv without terminating the stream.
            if count < 0 {
                if errno == EINTR { continue }
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
            result.append(contentsOf: bytes.prefix(count))
        }
    }
}
