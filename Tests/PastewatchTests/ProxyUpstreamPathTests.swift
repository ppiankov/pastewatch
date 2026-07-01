import XCTest
@testable import PastewatchCore

/// WO-142: the proxy must preserve a non-root upstream base path (e.g. a gateway
/// pass-through like /v1/llm-gateway) when joining the agent's absolute request
/// target, instead of letting URL(string:relativeTo:) drop the base path.
final class ProxyUpstreamPathTests: XCTestCase {

    private func server(upstream: String) -> ProxyServer {
        ProxyServer(port: 0, upstream: URL(string: upstream)!)
    }

    func testRootUpstreamUnchanged() {
        let s = server(upstream: "https://api.anthropic.com")
        let url = s.resolveUpstreamURL(requestTarget: "/v1/messages")
        XCTAssertEqual(url.absoluteString, "https://api.anthropic.com/v1/messages")
    }

    func testBasePathPreserved() {
        let s = server(upstream: "https://gateway.example.com/v1/llm-gateway")
        let url = s.resolveUpstreamURL(requestTarget: "/v1/messages")
        XCTAssertEqual(url.absoluteString, "https://gateway.example.com/v1/llm-gateway/v1/messages")
    }

    func testBasePathTrailingSlashNoDoubleSlash() {
        let s = server(upstream: "https://gateway.example.com/v1/llm-gateway/")
        let url = s.resolveUpstreamURL(requestTarget: "/v1/messages")
        XCTAssertEqual(url.absoluteString, "https://gateway.example.com/v1/llm-gateway/v1/messages")
    }

    func testRequestPathAlreadyContainsBaseNotDoubled() {
        let s = server(upstream: "https://gateway.example.com/v1/llm-gateway")
        let url = s.resolveUpstreamURL(requestTarget: "/v1/llm-gateway/v1/messages")
        XCTAssertEqual(url.absoluteString, "https://gateway.example.com/v1/llm-gateway/v1/messages")
    }

    func testQueryStringPreserved() {
        let s = server(upstream: "https://gateway.example.com/v1/llm-gateway")
        let url = s.resolveUpstreamURL(requestTarget: "/v1/messages?beta=true")
        XCTAssertEqual(url.absoluteString, "https://gateway.example.com/v1/llm-gateway/v1/messages?beta=true")
    }

    func testRootUpstreamWithQuery() {
        let s = server(upstream: "https://api.anthropic.com")
        let url = s.resolveUpstreamURL(requestTarget: "/v1/messages?beta=true")
        XCTAssertEqual(url.absoluteString, "https://api.anthropic.com/v1/messages?beta=true")
    }

    func testUpstreamWithPortAndBasePath() {
        let s = server(upstream: "https://gateway.example.com:8443/api")
        let url = s.resolveUpstreamURL(requestTarget: "/v1/messages")
        XCTAssertEqual(url.absoluteString, "https://gateway.example.com:8443/api/v1/messages")
    }
}
