import XCTest
@testable import PastewatchCore

#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

final class ProxyHTTPRequestReadTests: XCTestCase {

    func testCurlBodyUploadArgsUseDataBinaryFileUpload() {
        let args = CurlHTTPClient.bodyUploadArgs(forTempFile: "/tmp/pw-body")

        XCTAssertEqual(args, ["--data-binary", "@/tmp/pw-body"])
        XCTAssertFalse(args.contains("-d"))
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
}

#if canImport(Darwin)
private let socketStreamType = SOCK_STREAM
#else
private let socketStreamType = Int32(SOCK_STREAM.rawValue)
#endif
