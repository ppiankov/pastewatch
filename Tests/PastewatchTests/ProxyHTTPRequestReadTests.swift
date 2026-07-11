import XCTest
@testable import PastewatchCore

#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

final class ProxyHTTPRequestReadTests: XCTestCase {

    func testSendAllReturnsFalseWhenPeerClosed() {
        #if canImport(Darwin)
        let previousHandler = signal(SIGPIPE, SIG_IGN)
        defer { _ = signal(SIGPIPE, previousHandler) }
        #endif

        var sockets = [Int32](repeating: 0, count: 2)
        XCTAssertEqual(socketpair(AF_UNIX, socketStreamType, 0, &sockets), 0)
        close(sockets[0])
        defer { close(sockets[1]) }

        XCTAssertFalse(sendAll(Data("hello".utf8), to: sockets[1], flags: testSendFlags))
    }

    func testSendAllDeliversLargePayloadAcrossMultipleWrites() {
        let payload = Data(repeating: 0x61, count: 256 * 1024)
        var sockets = [Int32](repeating: 0, count: 2)
        XCTAssertEqual(socketpair(AF_UNIX, socketStreamType, 0, &sockets), 0)
        defer {
            close(sockets[0])
            close(sockets[1])
        }

        let lock = NSLock()
        var received = Data()
        let finished = expectation(description: "reader drains large sendAll payload")
        DispatchQueue.global().async {
            var buffer = [UInt8](repeating: 0, count: 4096)
            while true {
                let count = recv(sockets[0], &buffer, buffer.count, 0)
                guard count > 0 else { break }
                lock.lock()
                received.append(contentsOf: buffer[..<count])
                let complete = received.count >= payload.count
                lock.unlock()
                if complete { break }
            }
            finished.fulfill()
        }

        XCTAssertTrue(sendAll(payload, to: sockets[1], flags: testSendFlags))
        wait(for: [finished], timeout: 2)
        lock.lock()
        let receivedCopy = received
        lock.unlock()
        XCTAssertEqual(receivedCopy, payload)
    }

    func testSendAllReturnsTrueForEmptyDataWithoutCallingSend() {
        var calls = 0

        let result = sendAll(Data(), to: -1, flags: 0) { _, _, _, _ in
            calls += 1
            return -1
        }

        XCTAssertTrue(result)
        XCTAssertEqual(calls, 0)
    }

    func testSendAllRetriesEINTRAndCompletesPartialWrites() {
        let payload = Data("abcdef".utf8)
        var calls = 0
        var delivered = Data()

        let result = sendAll(payload, to: -1, flags: 0) { _, pointer, remaining, _ in
            calls += 1
            if calls == 1 {
                errno = EINTR
                return -1
            }
            let count = min(2, remaining)
            delivered.append(Data(bytes: pointer, count: count))
            return count
        }

        XCTAssertTrue(result)
        XCTAssertEqual(delivered, payload)
        XCTAssertEqual(calls, 4)
    }

    func testCurlBodyUploadArgsUseDataBinaryFileUpload() {
        let args = CurlHTTPClient.bodyUploadArgs(forTempFile: "/tmp/pw-body")

        XCTAssertEqual(args, ["--data-binary", "@/tmp/pw-body"])
        XCTAssertFalse(args.contains("-d"))
    }

    func testCurlTemporaryBodyPathsArePerCallUnique() {
        let paths = Set((0..<100).map { _ in CurlHTTPClient.temporaryBodyPath() })

        XCTAssertEqual(paths.count, 100)
        XCTAssertTrue(paths.allSatisfy {
            $0.hasPrefix("/tmp/pw-proxy-\(ProcessInfo.processInfo.processIdentifier)-")
        })
    }

    func testCurlTemporaryBodyFileIsOwnerOnly() throws {
        let path = try XCTUnwrap(CurlHTTPClient.writeTemporaryBodyFile(Data("secret body".utf8)))
        defer { try? FileManager.default.removeItem(atPath: path) }
        var info = stat()

        XCTAssertEqual(stat(path, &info), 0)
        XCTAssertEqual(Int(info.st_mode & 0o777), 0o600)
    }

    func testCurlNonUTF8ResponseBodyRedactsASCIICredentialBytePreserving() {
        let credential = "password=s3cr3t-hunter2"
        var body = Data([0xFF, 0xFE])
        body.append(Data("prefix \(credential) suffix".utf8))
        body.append(0x00)

        let redaction = CurlHTTPClient.redactNonUTF8ResponseBody(
            body,
            config: PastewatchConfig.defaultConfig,
            severity: .high
        )

        XCTAssertEqual(redaction.count, 1)
        XCTAssertEqual(redaction.types, ["Credential"])
        XCTAssertEqual(redaction.data.prefix(2), Data([0xFF, 0xFE]))
        XCTAssertEqual(redaction.data.last, 0x00)
        XCTAssertNil(redaction.data.range(of: Data(credential.utf8)))
        XCTAssertNotNil(redaction.data.range(of: Data("<CREDENTIAL_1>".utf8)))
    }

    func testCurlNonUTF8ResponseBodyWithoutCredentialIsByteIdentical() {
        let body = Data([0xFF, 0xFE, 0x00, 0x41])

        let redaction = CurlHTTPClient.redactNonUTF8ResponseBody(
            body,
            config: PastewatchConfig.defaultConfig,
            severity: .high
        )

        XCTAssertEqual(redaction.count, 0)
        XCTAssertEqual(redaction.data, body)
    }

    func testCurlNonStreamingOutputParserPreservesNonUTF8Body() {
        var output = Data([0xFF, 0xFE, 0x00])
        output.append(Data("\n__HTTP_STATUS__200".utf8))

        let parsed = CurlHTTPClient.parseNonStreamingOutput(output)

        XCTAssertEqual(parsed?.statusCode, 200)
        XCTAssertEqual(parsed?.body, Data([0xFF, 0xFE, 0x00]))
    }

    func testCurlNonStreamingOutputParserUsesLastStatusMarker() {
        var output = Data("body\n__HTTP_STATUS__inside".utf8)
        output.append(Data("\n__HTTP_STATUS__429".utf8))

        let parsed = CurlHTTPClient.parseNonStreamingOutput(output)

        XCTAssertEqual(parsed?.statusCode, 429)
        XCTAssertEqual(parsed?.body, Data("body\n__HTTP_STATUS__inside".utf8))
    }

    func testCurlNonStreamingOutputParserRequiresFinalStatusTrailer() {
        var output = Data("body\n__HTTP_STATUS__201 still body".utf8)
        output.append(Data("\n__HTTP_STATUS__200".utf8))

        let parsed = CurlHTTPClient.parseNonStreamingOutput(output)

        XCTAssertEqual(parsed?.statusCode, 200)
        XCTAssertEqual(parsed?.body, Data("body\n__HTTP_STATUS__201 still body".utf8))
    }

    func testCurlNonStreamingOutputParserRejectsNonFinalMarker() {
        let output = Data("body\n__HTTP_STATUS__200 trailing".utf8)

        XCTAssertNil(CurlHTTPClient.parseNonStreamingOutput(output))
    }

    func testCurlResponseHeaderReaderPreservesBufferedInterimBlocks() {
        var fds = [Int32](repeating: 0, count: 2)
        XCTAssertEqual(pipe(&fds), 0)
        defer { close(fds[0]) }

        let headers = Data(
            "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n".utf8
        )
        writePipeData(headers, to: fds[1], file: #filePath, line: #line)
        close(fds[1])

        var buffered = Data()
        let first = CurlHTTPClient.readResponseHeaderBlock(from: fds[0], buffered: &buffered)
        let second = CurlHTTPClient.readResponseHeaderBlock(from: fds[0], buffered: &buffered)

        XCTAssertEqual(String(data: first ?? Data(), encoding: .utf8), "HTTP/1.1 100 Continue\r\n\r\n")
        XCTAssertEqual(
            String(data: second ?? Data(), encoding: .utf8),
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n"
        )
        XCTAssertTrue(buffered.isEmpty)
    }

    func testCurlResponseHeaderReaderRejectsEOFWithPartialHeaders() {
        var fds = [Int32](repeating: 0, count: 2)
        XCTAssertEqual(pipe(&fds), 0)
        defer { close(fds[0]) }

        let partial = Data("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n".utf8)
        writePipeData(partial, to: fds[1], file: #filePath, line: #line)
        close(fds[1])

        var buffered = Data()
        let block = CurlHTTPClient.readResponseHeaderBlock(from: fds[0], buffered: &buffered)

        XCTAssertNil(block)
        XCTAssertTrue(buffered.isEmpty)
    }

    func testCurlResponseHeaderReaderLeavesBodyBytesBufferedAfterCompleteHeaders() {
        var fds = [Int32](repeating: 0, count: 2)
        XCTAssertEqual(pipe(&fds), 0)
        defer { close(fds[0]) }

        let response = Data("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\nbody".utf8)
        writePipeData(response, to: fds[1], file: #filePath, line: #line)
        close(fds[1])

        var buffered = Data()
        let block = CurlHTTPClient.readResponseHeaderBlock(from: fds[0], buffered: &buffered)

        XCTAssertEqual(
            String(data: block ?? Data(), encoding: .utf8),
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n"
        )
        XCTAssertEqual(buffered, Data("body".utf8))
    }

    func testNegativeContentLengthIsMalformed() {
        let body = Data(#"{"messages":[{"content":"password=s3cr3t-hunter2"}]}"#.utf8)
        let result = readRequest(
            header: "POST /v1/messages HTTP/1.1\r\nHost: example.test\r\nContent-Length: -1\r\n\r\n",
            body: body
        )

        assertMalformed(result)
    }

    func testDuplicateMalformedContentLengthDoesNotOverwriteFirstValidValue() {
        let result = readRequest(
            header: "POST /v1/messages HTTP/1.1\r\n" +
                "Host: example.test\r\n" +
                "Content-Length: 5\r\n" +
                "Content-Length: abc\r\n\r\n",
            body: Data("hello".utf8)
        )

        let request = assertSuccess(result)
        XCTAssertEqual(request.body, "hello")
        XCTAssertEqual(request.bodyData, Data("hello".utf8))
    }

    func testDuplicateDifferentContentLengthUsesFirstValidValue() {
        let result = readRequest(
            header: "POST /v1/messages HTTP/1.1\r\n" +
                "Host: example.test\r\n" +
                "Content-Length: 4\r\n" +
                "Content-Length: 100\r\n\r\n",
            body: Data("test".utf8)
        )

        let request = assertSuccess(result)
        XCTAssertEqual(request.bodyData.count, 4)
        XCTAssertEqual(request.body, "test")
    }

    func testNonUTF8BodyIsPreservedAsRawBytes() {
        let body = Data([0xFF, 0xFE, 0x00])
        let result = readRequest(
            header: "POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: 3\r\n\r\n",
            body: body
        )

        let request = assertSuccess(result)
        XCTAssertNil(request.body)
        XCTAssertEqual(request.bodyData, body)
    }

    func testGetWithoutContentLengthCompletesWithEmptyBody() {
        let result = readRequest(header: "GET /health HTTP/1.1\r\nHost: example.test\r\n\r\n")

        let request = assertSuccess(result)
        XCTAssertEqual(request.method, "GET")
        XCTAssertTrue(request.bodyData.isEmpty)
    }

    func testOptionsWithoutContentLengthCompletesWithEmptyBody() {
        let result = readRequest(header: "OPTIONS /v1/messages HTTP/1.1\r\nHost: example.test\r\n\r\n")

        let request = assertSuccess(result)
        XCTAssertEqual(request.method, "OPTIONS")
        XCTAssertTrue(request.bodyData.isEmpty)
    }

    func testChunkedPostWithoutContentLengthIsMalformed() {
        let result = readRequest(
            header: "POST /v1/messages HTTP/1.1\r\n" +
                "Host: example.test\r\n" +
                "Transfer-Encoding: chunked\r\n\r\n",
            body: Data("0\r\n\r\n".utf8)
        )

        assertMalformed(result)
    }

    func testPostWithoutContentLengthIsMalformed() {
        let result = readRequest(
            header: "POST /v1/messages HTTP/1.1\r\nHost: example.test\r\n\r\n",
            body: Data(#"{"messages":[]}"#.utf8)
        )

        assertMalformed(result)
    }

    func testContentLengthZeroCompletesWithEmptyBody() {
        let result = readRequest(
            header: "POST /v1/messages HTTP/1.1\r\nHost: example.test\r\nContent-Length: 0\r\n\r\n"
        )

        let request = assertSuccess(result)
        XCTAssertTrue(request.bodyData.isEmpty)
    }

    func testContentLengthReadsExpectedByteCount() {
        let body = Data(repeating: 0x61, count: 1_024)
        let result = readRequest(
            header: "POST /v1/messages HTTP/1.1\r\nHost: example.test\r\nContent-Length: 1024\r\n\r\n",
            body: body
        )

        let request = assertSuccess(result)
        XCTAssertEqual(request.bodyData.count, 1_024)
        XCTAssertEqual(request.bodyData, body)
    }

    func testContentLengthReadsLargeBodyAcrossRecvChunks() {
        let body = Data(repeating: 0x61, count: 500 * 1024)
        let result = readRequestWithAsyncWriter(
            header: "POST /v1/messages HTTP/1.1\r\nHost: example.test\r\nContent-Length: \(body.count)\r\n\r\n",
            body: body
        )

        let request = assertSuccess(result)
        XCTAssertEqual(request.bodyData.count, body.count)
        XCTAssertEqual(request.bodyData, body)
    }

    func testLFOnlyPostHeadersReadBodyWithoutTimeout() {
        let result = readRequest(
            header: "POST /v1/messages HTTP/1.1\nHost: example.test\nContent-Length: 5\n\n",
            body: Data("hello".utf8)
        )

        let request = assertSuccess(result)
        XCTAssertEqual(request.method, "POST")
        XCTAssertEqual(request.body, "hello")
        XCTAssertEqual(request.bodyData, Data("hello".utf8))
    }

    func testLFOnlyGetWithoutContentLengthCompletesWithEmptyBody() {
        let result = readRequest(header: "GET /health HTTP/1.1\nHost: example.test\n\n")

        let request = assertSuccess(result)
        XCTAssertEqual(request.method, "GET")
        XCTAssertTrue(request.bodyData.isEmpty)
    }

    func testCRLFTerminatorWinsOverEarlierBareLFPair() {
        let result = readRequest(
            header: "POST /v1/messages HTTP/1.1\r\n" +
                "Host: example.test\r\n" +
                "X-Debug: first\n\nstill-header\r\n" +
                "Content-Length: 5\r\n\r\n",
            body: Data("hello".utf8)
        )

        let request = assertSuccess(result)
        XCTAssertEqual(request.body, "hello")
        XCTAssertEqual(request.bodyData, Data("hello".utf8))
    }

    func testCRLFTerminatorWinsWhenBareLFPairArrivesBeforeFinalCRLF() {
        let padding = String(repeating: "a", count: proxyHTTPRequestReadBufferBytes + 100)
        let result = readRequestWithAsyncWriter(
            header: "POST /v1/messages HTTP/1.1\r\n" +
                "Host: example.test\r\n" +
                "X-Debug: first\n\nstill-header\r\n" +
                "X-Pad: \(padding)\r\n" +
                "Content-Length: 5\r\n\r\n",
            body: Data("hello".utf8)
        )

        let request = assertSuccess(result)
        XCTAssertEqual(request.body, "hello")
        XCTAssertEqual(request.bodyData, Data("hello".utf8))
    }

    private func readRequest(
        header: String,
        body: Data = Data(),
        file: StaticString = #filePath,
        line: UInt = #line
    ) -> ProxyServer.ReadResult {
        var sockets = [Int32](repeating: 0, count: 2)
        XCTAssertEqual(socketpair(AF_UNIX, socketStreamType, 0, &sockets), 0, file: file, line: line)
        defer {
            close(sockets[0])
            close(sockets[1])
        }

        setReceiveTimeout(on: sockets[1], file: file, line: line)

        var data = Data(header.utf8)
        data.append(body)
        writeAll(data, to: sockets[0], file: file, line: line)

        let server = ProxyServer(port: 0)
        return server.readHTTPRequest(from: sockets[1])
    }

    private func readRequestWithAsyncWriter(
        header: String,
        body: Data,
        file: StaticString = #filePath,
        line: UInt = #line
    ) -> ProxyServer.ReadResult {
        var sockets = [Int32](repeating: 0, count: 2)
        XCTAssertEqual(socketpair(AF_UNIX, socketStreamType, 0, &sockets), 0, file: file, line: line)
        defer {
            close(sockets[0])
            close(sockets[1])
        }

        setReceiveTimeout(on: sockets[1], file: file, line: line)

        var data = Data(header.utf8)
        data.append(body)
        let writeFinished = expectation(description: "large request written")
        DispatchQueue.global().async {
            self.writeAll(data, to: sockets[0], file: file, line: line)
            writeFinished.fulfill()
        }

        let server = ProxyServer(port: 0)
        let result = server.readHTTPRequest(from: sockets[1])
        wait(for: [writeFinished], timeout: 5)
        return result
    }

    private func assertSuccess(
        _ result: ProxyServer.ReadResult,
        file: StaticString = #filePath,
        line: UInt = #line
    ) -> ProxyServer.HTTPRequest {
        guard case .success(let request) = result else {
            XCTFail("expected success, got \(result)", file: file, line: line)
            return ProxyServer.HTTPRequest(method: "", path: "", headers: [], body: nil, bodyData: Data())
        }
        return request
    }

    private func assertMalformed(
        _ result: ProxyServer.ReadResult,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        guard case .malformedRequest = result else {
            XCTFail("expected malformedRequest, got \(result)", file: file, line: line)
            return
        }
    }

    private func setReceiveTimeout(on socket: Int32, file: StaticString, line: UInt) {
        var timeout = timeval(tv_sec: 1, tv_usec: 0)
        let result = setsockopt(
            socket, SOL_SOCKET, SO_RCVTIMEO,
            &timeout, socklen_t(MemoryLayout<timeval>.size)
        )
        XCTAssertEqual(result, 0, file: file, line: line)
    }

    private func writeAll(_ data: Data, to socket: Int32, file: StaticString, line: UInt) {
        data.withUnsafeBytes { rawBuffer in
            guard let base = rawBuffer.baseAddress else { return }
            var offset = 0
            while offset < data.count {
                let sent = send(socket, base.advanced(by: offset), data.count - offset, 0)
                guard sent > 0 else {
                    XCTFail("send failed with errno \(errno)", file: file, line: line)
                    return
                }
                offset += sent
            }
        }
    }

    private func writePipeData(_ data: Data, to fd: Int32, file: StaticString, line: UInt) {
        data.withUnsafeBytes { rawBuffer in
            guard let base = rawBuffer.baseAddress else { return }
            var offset = 0
            while offset < data.count {
                let written = Foundation.write(fd, base.advanced(by: offset), data.count - offset)
                guard written > 0 else {
                    XCTFail("write failed with errno \(errno)", file: file, line: line)
                    return
                }
                offset += written
            }
        }
    }
}

#if canImport(Darwin)
private let socketStreamType = SOCK_STREAM
private let testSendFlags: Int32 = 0
#else
private let socketStreamType = Int32(SOCK_STREAM.rawValue)
private let testSendFlags: Int32 = Int32(MSG_NOSIGNAL)
#endif
