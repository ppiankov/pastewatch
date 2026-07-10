import XCTest
@testable import PastewatchCore

/// WO-146: Verifies incremental SSE relay, chunked upstream, and non-streaming path preservation.
final class ProxyStreamingTests: XCTestCase {

    // MARK: - isStreamingRequest

    func testIsStreamingRequestTrueWhenStreamTrue() {
        let server = ProxyServer(port: 0)
        let body = #"{"model":"claude-3-5-sonnet-20241022","stream":true,"messages":[]}"#
        XCTAssertTrue(server.isStreamingRequest(body))
    }

    func testIsStreamingRequestFalseWhenStreamFalse() {
        let server = ProxyServer(port: 0)
        let body = #"{"model":"claude-3-5-sonnet-20241022","stream":false,"messages":[]}"#
        XCTAssertFalse(server.isStreamingRequest(body))
    }

    func testIsStreamingRequestFalseWhenNoStreamKey() {
        let server = ProxyServer(port: 0)
        let body = #"{"model":"claude-3-5-sonnet-20241022","messages":[]}"#
        XCTAssertFalse(server.isStreamingRequest(body))
    }

    func testIsStreamingRequestFalseForInvalidJSON() {
        let server = ProxyServer(port: 0)
        XCTAssertFalse(server.isStreamingRequest("not json"))
    }

    // MARK: - resolveUpstreamURL (regression: existing behavior preserved)

    func testResolveUpstreamURLPreservesBasePath() {
        let server = ProxyServer(port: 0, upstream: URL(string: "https://gateway.example.com/v1/llm-gateway")!)
        let url = server.resolveUpstreamURL(requestTarget: "/v1/messages")
        XCTAssertEqual(url.path, "/v1/llm-gateway/v1/messages")
    }

    func testResolveUpstreamURLNoDoublingWhenAlreadyPrefixed() {
        let server = ProxyServer(port: 0, upstream: URL(string: "https://api.anthropic.com/v1")!)
        let url = server.resolveUpstreamURL(requestTarget: "/v1/messages")
        XCTAssertEqual(url.path, "/v1/messages")
    }

    // MARK: - streaming response framing

    func testStreamingHeadersUseCloseDelimitedFraming() {
        let headers = CurlHTTPClient.buildStreamingResponseHeaders(
            status: 200,
            upstreamHeaders: [
                "Content-Type": "text/event-stream",
                "Content-Length": "999",
                "Cache-Control": "no-cache"
            ]
        )

        XCTAssertTrue(headers.hasPrefix("HTTP/1.1 200 OK\r\n"))
        XCTAssertTrue(headers.contains("Content-Type: text/event-stream\r\n"))
        XCTAssertTrue(headers.contains("Cache-Control: no-cache\r\n"))
        XCTAssertTrue(headers.contains("Connection: close\r\n\r\n"))
        XCTAssertFalse(headers.lowercased().contains("transfer-encoding: chunked"))
        XCTAssertFalse(headers.lowercased().contains("content-length:"))
    }

    func testForwardHeadersForceIdentityAcceptEncoding() {
        let server = ProxyServer(
            port: 0,
            upstream: URL(string: "https://api.anthropic.com/v1")!
        )

        let headers = server.buildForwardHeaders(
            from: [
                ("Host", "127.0.0.1"),
                ("Accept-Encoding", "gzip, br"),
                ("Content-Length", "999"),
                ("Anthropic-Version", "2023-06-01")
            ],
            bodyLength: 42
        )
        let lowerNames = headers.map { $0.0.lowercased() }

        XCTAssertEqual(headers.filter { $0.0.lowercased() == "accept-encoding" }.map { $0.1 }, ["identity"])
        XCTAssertEqual(headers.filter { $0.0.lowercased() == "host" }.map { $0.1 }, ["api.anthropic.com"])
        XCTAssertEqual(headers.filter { $0.0.lowercased() == "content-length" }.map { $0.1 }, ["42"])
        XCTAssertTrue(headers.contains { $0.0 == "Anthropic-Version" && $0.1 == "2023-06-01" })
        XCTAssertEqual(lowerNames.filter { $0 == "accept-encoding" }.count, 1)
    }
}
