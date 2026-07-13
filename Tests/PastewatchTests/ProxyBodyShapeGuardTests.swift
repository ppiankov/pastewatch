import XCTest
@testable import PastewatchCore

/// WO-408: the proxy fails closed on unsupported upstream body shapes. It scans and
/// redacts Anthropic-shaped (/v1/messages) bodies; any other POST body — notably OpenAI
/// /v1/chat/completions — must be refused rather than forwarded UNSCANNED (a silent
/// no-op that makes users believe traffic was redacted when it was not). These tests
/// exercise the pure predicate directly, without a socket.
final class ProxyBodyShapeGuardTests: XCTestCase {

    private func server() -> ProxyServer {
        ProxyServer(port: 0, upstream: URL(string: "https://api.anthropic.com")!)
    }

    private func verdict(_ method: String, _ path: String, _ body: String) -> ProxyServer.BodyShapeVerdict {
        server().upstreamBodyShapeVerdict(method: method, path: path, bodyData: Data(body.utf8))
    }

    // MARK: - Anthropic shapes are allowed

    func testAnthropicToolResultBodyAllowed() {
        let body = """
        {"model":"claude-3","messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"x","content":"secret here"}]}]}
        """
        XCTAssertEqual(verdict("POST", "/v1/messages", body), .allow)
    }

    func testAnthropicAllTextBodyAllowed() {
        // Zero tool_results is a legitimate Anthropic request — must not be refused.
        let body = """
        {"model":"claude-3","messages":[{"role":"assistant","content":[{"type":"text","text":"hi"}]}]}
        """
        XCTAssertEqual(verdict("POST", "/v1/messages", body), .allow)
    }

    func testAnthropicStringContentAllowed() {
        let body = """
        {"model":"claude-3","messages":[{"role":"user","content":"just a string"}]}
        """
        XCTAssertEqual(verdict("POST", "/v1/messages", body), .allow)
    }

    func testMessagesEndpointWithoutMessagesArrayAllowed() {
        // Some Anthropic endpoints (e.g. count_tokens variants) may omit a messages array.
        let body = """
        {"model":"claude-3","system":"be terse"}
        """
        XCTAssertEqual(verdict("POST", "/v1/messages", body), .allow)
    }

    // MARK: - Foreign shapes are refused

    func testOpenAIChatCompletionsRefusedLayerA() {
        // /v1/chat/completions carries a messages array plus OpenAI-only tool_calls.
        let body = """
        {"model":"gpt-4","messages":[{"role":"assistant","content":"","tool_calls":[{"id":"c1","type":"function"}]}]}
        """
        guard case .refuse = verdict("POST", "/v1/chat/completions", body) else {
            return XCTFail("expected refuse for OpenAI chat/completions body")
        }
    }

    func testSimpleOpenAIChatCompletionsRefusedLayerA() {
        // WO-411: a simple OpenAI chat body has the same role/string-content surface
        // as a tiny Anthropic body; the unsupported path is the fail-closed signal.
        let body = """
        {"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}
        """
        guard case .refuse = verdict("POST", "/v1/chat/completions", body) else {
            return XCTFail("expected refuse for simple OpenAI chat/completions body")
        }
    }

    func testUnsupportedJSONPostWithoutMessagesRefused() {
        // WO-412: unsupported JSON POSTs without a messages array are still unredactable.
        let body = """
        {"model":"gpt-4.1","input":"hello"}
        """
        guard case .refuse = verdict("POST", "/v1/responses", body) else {
            return XCTFail("expected refuse for unsupported JSON POST body")
        }
    }

    func testForeignGenerateContentBodyWithoutMessagesRefused() {
        // WO-412: non-Anthropic JSON shapes must fail closed even when they do not look
        // like OpenAI chat/completions.
        let body = """
        {"contents":[{"parts":[{"text":"hello"}]}]}
        """
        guard case .refuse = verdict("POST", "/v1beta/models/gemini:generateContent", body) else {
            return XCTFail("expected refuse for foreign JSON POST body")
        }
    }

    func testOpenAIShapeOnMessagesEndpointRefusedLayerB() {
        // A foreign body pointed at the Anthropic endpoint is still refused.
        let body = """
        {"model":"gpt-4","messages":[{"role":"user","content":"hi","function_call":{"name":"f"}}]}
        """
        guard case .refuse = verdict("POST", "/v1/messages", body) else {
            return XCTFail("expected refuse for OpenAI shape on /v1/messages")
        }
    }

    // MARK: - Legitimate non-message traffic is NOT broken

    func testTokensCountAnthropicBodyAllowed() {
        // The Anthropic count-tokens body carries a top-level messages array in Anthropic
        // shape; it must pass, not be refused as a foreign chat body (false-refusal guard).
        let body = """
        {"model":"claude-3","messages":[{"role":"user","content":"count me"}]}
        """
        XCTAssertEqual(verdict("POST", "/v1/messages/count_tokens", body), .allow)
    }

    func testGatewayPrefixedMessagesPathAllowed() {
        // WO-419: a gateway-fronted upstream (WO-142) embeds a base path in the request
        // target. An Anthropic-shaped body at /v1/llm-gateway/v1/messages must be allowed,
        // not refused by an over-strict exact path match.
        let body = """
        {"model":"claude-3","messages":[{"role":"user","content":"hi"}]}
        """
        XCTAssertEqual(verdict("POST", "/v1/llm-gateway/v1/messages", body), .allow)
        XCTAssertEqual(verdict("POST", "/anthropic/v1/messages?beta=true", body), .allow)
    }

    func testGatewayPrefixedCountTokensAllowed() {
        // WO-419: the count_tokens endpoint through a gateway prefix must also pass.
        let body = """
        {"model":"claude-3","messages":[{"role":"user","content":"count me"}]}
        """
        XCTAssertEqual(verdict("POST", "/v1/llm-gateway/v1/messages/count_tokens", body), .allow)
    }

    func testNonJSONBodyAllowed() {
        XCTAssertEqual(verdict("POST", "/v1/anything", "not json at all"), .allow)
    }

    func testEmptyBodyAllowed() {
        XCTAssertEqual(verdict("POST", "/v1/messages", ""), .allow)
    }

    func testGetRequestAllowed() {
        XCTAssertEqual(verdict("GET", "/v1/models", ""), .allow)
    }

    func testOptionsRequestAllowed() {
        XCTAssertEqual(verdict("OPTIONS", "/v1/messages", ""), .allow)
    }

    // MARK: - isAnthropicMessagesShape direct

    func testShapeRejectsToolCalls() {
        let json: [String: Any] = ["messages": [["role": "assistant", "tool_calls": [["id": "x"]]]]]
        XCTAssertFalse(server().isAnthropicMessagesShape(json))
    }

    func testShapeRejectsMissingRole() {
        let json: [String: Any] = ["messages": [["content": "hi"]]]
        XCTAssertFalse(server().isAnthropicMessagesShape(json))
    }

    func testShapeAcceptsUnknownFutureKeys() {
        // Permissive on unknown keys — Anthropic adds fields over time.
        let json: [String: Any] = [
            "messages": [["role": "user", "content": "hi", "some_future_field": 1]]
        ]
        XCTAssertTrue(server().isAnthropicMessagesShape(json))
    }
}
