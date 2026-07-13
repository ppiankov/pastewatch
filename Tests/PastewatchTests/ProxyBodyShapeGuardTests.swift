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

    private func verdict(_ method: String, _ path: String, bodyData: Data) -> ProxyServer.BodyShapeVerdict {
        server().upstreamBodyShapeVerdict(method: method, path: path, bodyData: bodyData)
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

    func testContentNullAllowed() {
        // WO-427: JSON null maps to NSNull and is equivalent to absent content.
        let body = """
        {"model":"claude-3","messages":[{"role":"assistant","content":null}]}
        """
        XCTAssertEqual(verdict("POST", "/v1/messages", body), .allow)
    }

    func testMixedNullAndStringContentAllowed() {
        let body = """
        {"model":"claude-3","messages":[{"role":"assistant","content":null},{"role":"user","content":"continue"}]}
        """
        XCTAssertEqual(verdict("POST", "/v1/messages", body), .allow)
    }

    func testCountTokensEndpointWithoutMessagesArrayAllowed() {
        // Some Anthropic count_tokens variants may omit a messages array.
        let body = """
        {"model":"claude-3","system":"be terse"}
        """
        XCTAssertEqual(verdict("POST", "/v1/messages/count_tokens", body), .allow)
    }

    // MARK: - Foreign shapes are refused

    func testOpenAIChatCompletionsRefusedLayerA() {
        // /v1/chat/completions carries a messages array plus OpenAI-only tool_calls.
        let body = """
        {"model":"gpt-4","messages":[{"role":"assistant","content":"","tool_calls":[{"id":"c1","type":"function"}]}]}
        """
        XCTAssertEqual(
            verdict("POST", "/v1/chat/completions", body),
            .refuse("unsupported JSON POST body on /v1/chat/completions")
        )
    }

    func testSimpleOpenAIChatCompletionsRefusedLayerA() {
        // WO-411: a simple OpenAI chat body has the same role/string-content surface
        // as a tiny Anthropic body; the unsupported path is the fail-closed signal.
        let body = """
        {"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}
        """
        XCTAssertEqual(
            verdict("POST", "/v1/chat/completions", body),
            .refuse("unsupported JSON POST body on /v1/chat/completions")
        )
    }

    func testUnsupportedJSONPostWithoutMessagesRefused() {
        // WO-412: unsupported JSON POSTs without a messages array are still unredactable.
        let body = """
        {"model":"gpt-4.1","input":"hello"}
        """
        XCTAssertEqual(verdict("POST", "/v1/responses", body), .refuse("unsupported JSON POST body on /v1/responses"))
    }

    func testForeignGenerateContentBodyWithoutMessagesRefused() {
        // WO-412: non-Anthropic JSON shapes must fail closed even when they do not look
        // like OpenAI chat/completions.
        let body = """
        {"contents":[{"parts":[{"text":"hello"}]}]}
        """
        XCTAssertEqual(
            verdict("POST", "/v1beta/models/gemini:generateContent", body),
            .refuse("unsupported JSON POST body on /v1beta/models/gemini:generateContent")
        )
    }

    func testOpenAIShapeOnMessagesEndpointRefusedLayerB() {
        // A foreign body pointed at the Anthropic endpoint is still refused.
        let body = """
        {"model":"gpt-4","messages":[{"role":"user","content":"hi","function_call":{"name":"f"}}]}
        """
        XCTAssertEqual(
            verdict("POST", "/v1/messages", body),
            .refuse("non-Anthropic messages schema on /v1/messages")
        )
    }

    func testPlainOpenAIShapeOnMessagesEndpointRefusedLayerB() {
        // WO-422: model markers keep plain OpenAI bodies from passing as tiny
        // Anthropic requests when a gateway misroutes them to /v1/messages.
        let body = """
        {"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}
        """
        XCTAssertEqual(
            verdict("POST", "/v1/messages", body),
            .refuse("non-Anthropic messages schema on /v1/messages")
        )
    }

    func testOFamilyModelDashPrefixesRefusedLayerB() {
        // WO-428: future OpenAI o-family dash-prefixed models must fail closed.
        for model in ["o1-mini", "o2-mini", "o3-mini", "o4-mini", "o5-mini", "o6-mini"] {
            let body = """
            {"model":"\(model)","messages":[{"role":"user","content":"hello"}]}
            """
            XCTAssertEqual(
                verdict("POST", "/v1/messages", body),
                .refuse("non-Anthropic messages schema on /v1/messages"),
                "expected \(model) to be refused"
            )
        }
    }

    func testOFamilyBareLookalikeDoesNotMatchForeignPrefix() {
        // WO-428: avoid the old broad "o1*" match; unknown future fields stay permissive.
        let body = """
        {"model":"o1fast","messages":[{"role":"user","content":"hello"}]}
        """
        XCTAssertEqual(verdict("POST", "/v1/messages", body), .allow)
    }

    func testTopLevelJSONArrayRefusedOnUnsupportedPath() {
        // WO-422: JSON arrays are parseable JSON bodies, not opaque non-JSON bytes.
        let body = """
        [{"role":"user","content":"hello"}]
        """
        XCTAssertEqual(
            verdict("POST", "/v1/chat/completions", body),
            .refuse("unsupported JSON POST body on /v1/chat/completions")
        )
    }

    func testTopLevelJSONArrayRefusedOnMessagesPath() {
        let body = """
        [{"role":"user","content":"hello"}]
        """
        XCTAssertEqual(
            verdict("POST", "/v1/messages", body),
            .refuse("malformed Anthropic JSON body on /v1/messages")
        )
    }

    func testNonUTF8ForeignPathRefused() {
        let data = Data([0xff, 0xfe, 0xfd])
        XCTAssertEqual(
            verdict("POST", "/v1/chat/completions", bodyData: data),
            .refuse("unsupported non-JSON POST body on /v1/chat/completions")
        )
    }

    func testNonUTF8MessagesPathRefused() {
        let data = Data([0xff, 0xfe, 0xfd])
        XCTAssertEqual(
            verdict("POST", "/v1/messages", bodyData: data),
            .refuse("malformed Anthropic JSON body on /v1/messages")
        )
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

    func testNonJSONBodyOnMessagesPathRefused() {
        XCTAssertEqual(
            verdict("POST", "/v1/messages", "not json at all"),
            .refuse("malformed Anthropic JSON body on /v1/messages")
        )
    }

    func testNonJSONBodyOnUnsupportedPathRefused() {
        XCTAssertEqual(
            verdict("POST", "/v1/anything", "not json at all"),
            .refuse("unsupported non-JSON POST body on /v1/anything")
        )
    }

    func testEmptyMessagesBodyRefused() {
        XCTAssertEqual(
            verdict("POST", "/v1/messages", ""),
            .refuse("malformed Anthropic JSON body on /v1/messages")
        )
    }

    func testGetRequestAllowed() {
        XCTAssertEqual(verdict("GET", "/v1/models", ""), .allow)
    }

    func testOptionsRequestAllowed() {
        XCTAssertEqual(verdict("OPTIONS", "/v1/messages", ""), .allow)
    }

    // MARK: - Supported path predicate direct

    func testSupportedAnthropicPathPredicate() {
        let proxy = server()
        let allowed = [
            "/v1/messages",
            "/v1/messages?beta=true",
            "/v1/messages/count_tokens",
            "/v1/llm-gateway/v1/messages",
            "/anthropic/v1/messages?beta=true",
            "/v1/llm-gateway/v1/messages/count_tokens",
        ]
        let refused = [
            "/v1/chat/completions",
            "/v1/responses",
            "/v1/messages_extra",
            "/v1/messages/extra",
            "/v1beta/models/gemini:generateContent",
        ]

        for path in allowed {
            XCTAssertTrue(proxy.isSupportedAnthropicPostPath(path), "expected supported path: \(path)")
        }
        for path in refused {
            XCTAssertFalse(proxy.isSupportedAnthropicPostPath(path), "expected unsupported path: \(path)")
        }
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

    func testShapeRejectsContentBlockWithoutType() {
        let json: [String: Any] = ["messages": [["role": "user", "content": [["text": "hi"]]]]]
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
