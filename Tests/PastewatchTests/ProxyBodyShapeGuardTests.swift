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

    private func modelAdvisory(_ path: String, _ body: String) -> Bool {
        server().modelIdentityAdvisoryNeeded(method: "POST", path: path, bodyData: Data(body.utf8))
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

    func testOpenAIOnlyNullFieldsAllowed() {
        // WO-431: JSON null does not make the OpenAI-only keys a foreign-shape signal.
        let body = """
        {"model":"claude-3","messages":[{"role":"user","content":"hi","tool_calls":null,"function_call":null}]}
        """
        XCTAssertEqual(verdict("POST", "/v1/messages", body), .allow)
    }

    func testCountTokensEndpointWithoutMessagesArrayRefused() {
        // WO-437: official Count Tokens requests require messages; arbitrary
        // messages-free objects cannot be positively identified or scanned.
        let body = """
        {"model":"claude-3","system":"be terse"}
        """
        XCTAssertEqual(
            verdict("POST", "/v1/messages/count_tokens", body),
            .refuse("malformed Anthropic count_tokens body")
        )
    }

    func testMessageBatchesEndpointAllowed() {
        // WO-432: Message Batches wrap normal Messages params under requests[].params.
        let body = """
        {"requests":[{"custom_id":"r1","params":{"model":"claude-3","messages":[{"role":"user","content":"hi"}]}}]}
        """
        XCTAssertEqual(verdict("POST", "/v1/messages/batches", body), .allow)
        XCTAssertEqual(verdict("POST", "/gateway/v1/messages/batches?beta=true", body), .allow)
    }

    func testTrailingSlashSupportedAnthropicPathsAllowed() {
        let messagesBody = """
        {"model":"claude-3","messages":[{"role":"user","content":"hi"}]}
        """
        let countTokensBody = """
        {"model":"claude-3","system":"be terse","messages":[{"role":"user","content":"count"}]}
        """
        let batchesBody = """
        {"requests":[{"custom_id":"r1","params":{"model":"claude-3","messages":[{"role":"user","content":"hi"}]}}]}
        """

        XCTAssertEqual(verdict("POST", "/v1/messages/", messagesBody), .allow)
        XCTAssertEqual(verdict("POST", "/gateway/v1/messages/", messagesBody), .allow)
        XCTAssertEqual(verdict("POST", "/v1/messages/count_tokens/", countTokensBody), .allow)
        XCTAssertEqual(verdict("POST", "/v1/messages/batches/", batchesBody), .allow)
    }

    func testNonstandardModelNamesAreAllowedAndAdvisoryOnly() {
        // WO-430: vendor identity cannot refuse a valid Anthropic wire shape.
        for model in [
            "company-gateway-claude-alias", "qwen-max", "deepseek-chat",
            "o7-preview", "command-r", "kimi-k2", "gpt-4", "o1-mini",
        ] {
            let body = """
            {"model":"\(model)","messages":[{"role":"user","content":"hi"}]}
            """
            XCTAssertEqual(verdict("POST", "/v1/messages", body), .allow, model)
            XCTAssertTrue(modelAdvisory("/v1/messages", body), model)
        }
    }

    func testRecognizedAnthropicModelDoesNotRaiseModelAdvisory() {
        let body = """
        {"model":"claude-3","messages":[{"role":"user","content":"hi"}]}
        """
        XCTAssertEqual(verdict("POST", "/v1/messages", body), .allow)
        XCTAssertFalse(modelAdvisory("/v1/messages", body))
    }

    func testNonstandardModelWithToolResultDoesNotRaiseModelAdvisory() {
        let body = """
        {"model":"qwen-max","messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"x","content":"safe"}]}]}
        """
        XCTAssertEqual(verdict("POST", "/v1/messages", body), .allow)
        XCTAssertFalse(modelAdvisory("/v1/messages", body))
    }

    // MARK: - Foreign shapes are refused

    func testOpenAIChatCompletionsRefusedLayerA() {
        // /v1/chat/completions carries a messages array plus OpenAI-only tool_calls.
        let body = """
        {"model":"gpt-4","messages":[{"role":"assistant","content":"","tool_calls":[{"id":"c1","type":"function"}]}]}
        """
        XCTAssertEqual(
            verdict("POST", "/v1/chat/completions", body),
            .refuse("unsupported JSON POST body")
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
            .refuse("unsupported JSON POST body")
        )
    }

    func testUnsupportedJSONPostWithoutMessagesRefused() {
        // WO-412: unsupported JSON POSTs without a messages array are still unredactable.
        let body = """
        {"model":"gpt-4.1","input":"hello"}
        """
        XCTAssertEqual(verdict("POST", "/v1/responses", body), .refuse("unsupported JSON POST body"))
    }

    func testForeignGenerateContentBodyWithoutMessagesRefused() {
        // WO-412: non-Anthropic JSON shapes must fail closed even when they do not look
        // like OpenAI chat/completions.
        let body = """
        {"contents":[{"parts":[{"text":"hello"}]}]}
        """
        XCTAssertEqual(
            verdict("POST", "/v1beta/models/gemini:generateContent", body),
            .refuse("unsupported JSON POST body")
        )
    }

    func testOpenAIShapeOnMessagesEndpointRefusedLayerB() {
        // A foreign body pointed at the Anthropic endpoint is still refused.
        let body = """
        {"model":"gpt-4","messages":[{"role":"user","content":"hi","function_call":{"name":"f"}}]}
        """
        XCTAssertEqual(
            verdict("POST", "/v1/messages", body),
            .refuse("non-Anthropic messages schema")
        )
    }

    func testMessageBatchWithNonstandardModelIsAllowedAndAdvisoryOnly() {
        let body = """
        {"requests":[{"custom_id":"r1","params":{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}}]}
        """
        XCTAssertEqual(verdict("POST", "/v1/messages/batches", body), .allow)
        XCTAssertTrue(modelAdvisory("/v1/messages/batches", body))
    }

    // WO-446: a tool_result suppresses model telemetry only for its own batch payload.
    func testMixedBatchStillAdvisesForUnscannedNonstandardModel() {
        let body = """
        {"requests":[
          {"custom_id":"scanned","params":{"model":"qwen-max","messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1","content":"safe"}]}]}},
          {"custom_id":"unscanned","params":{"model":"deepseek-chat","messages":[{"role":"user","content":"hello"}]}}
        ]}
        """
        XCTAssertTrue(modelAdvisory("/v1/messages/batches", body))
    }

    // WO-446: batches need no model advisory when every nonstandard payload was scanned.
    func testAllToolResultBatchSuppressesModelAdvisory() {
        let body = """
        {"requests":[
          {"custom_id":"r1","params":{"model":"qwen-max","messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1","content":"safe"}]}]}},
          {"custom_id":"r2","params":{"model":"deepseek-chat","messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_2","content":"safe"}]}]}}
        ]}
        """
        XCTAssertFalse(modelAdvisory("/v1/messages/batches", body))
    }

    // WO-446: recognized models never create advisory telemetry in a batch.
    func testRecognizedModelBatchNeedsNoModelAdvisory() {
        let body = """
        {"requests":[
          {"custom_id":"r1","params":{"model":"claude-3","messages":[{"role":"user","content":"hello"}]}},
          {"custom_id":"r2","params":{"model":"anthropic.gateway-alias","messages":[{"role":"user","content":"hello"}]}}
        ]}
        """
        XCTAssertFalse(modelAdvisory("/v1/messages/batches", body))
    }

    func testMalformedMessageBatchRefused() {
        let body = """
        {"requests":[{"custom_id":"r1","params":{"model":"claude-3","input":"hi"}}]}
        """
        XCTAssertEqual(
            verdict("POST", "/v1/messages/batches", body),
            .refuse("malformed Anthropic batch body")
        )
    }

    func testBatchResultsPathUnsupported() {
        let body = """
        {"requests":[]}
        """
        XCTAssertEqual(
            verdict("POST", "/v1/messages/batches/results", body),
            .refuse("unsupported JSON POST body")
        )
    }

    func testPlainOpenAIModelOnMessagesEndpointIsAdvisoryOnly() {
        // WO-430: a model marker is not a wire-shape discriminator.
        let body = """
        {"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}
        """
        XCTAssertEqual(verdict("POST", "/v1/messages", body), .allow)
        XCTAssertTrue(modelAdvisory("/v1/messages", body))
    }

    func testOFamilyModelDashPrefixesAreAdvisoryOnly() {
        // WO-430 supersedes WO-428's refusal posture: model identity cannot block traffic.
        for model in ["o1-mini", "o2-mini", "o3-mini", "o4-mini", "o5-mini", "o6-mini"] {
            let body = """
            {"model":"\(model)","messages":[{"role":"user","content":"hello"}]}
            """
            XCTAssertEqual(verdict("POST", "/v1/messages", body), .allow, model)
            XCTAssertTrue(modelAdvisory("/v1/messages", body), model)
        }
    }

    func testOFamilyBareLookalikeRemainsAllowedButAdvisory() {
        // WO-430: unknown model names stay permissive regardless of prefix classification.
        let body = """
        {"model":"o1fast","messages":[{"role":"user","content":"hello"}]}
        """
        XCTAssertEqual(verdict("POST", "/v1/messages", body), .allow)
        XCTAssertTrue(modelAdvisory("/v1/messages", body))
    }

    func testTopLevelJSONArrayRefusedOnUnsupportedPath() {
        // WO-422: JSON arrays are parseable JSON bodies, not opaque non-JSON bytes.
        let body = """
        [{"role":"user","content":"hello"}]
        """
        XCTAssertEqual(
            verdict("POST", "/v1/chat/completions", body),
            .refuse("unsupported JSON POST body")
        )
    }

    func testTopLevelJSONArrayRefusedOnMessagesPath() {
        let body = """
        [{"role":"user","content":"hello"}]
        """
        XCTAssertEqual(
            verdict("POST", "/v1/messages", body),
            .refuse("malformed Anthropic JSON body")
        )
    }

    func testNonUTF8ForeignPathRefused() {
        let data = Data([0xff, 0xfe, 0xfd])
        XCTAssertEqual(
            verdict("POST", "/v1/chat/completions", bodyData: data),
            .refuse("unsupported non-JSON POST body")
        )
    }

    func testNonUTF8MessagesPathRefused() {
        let data = Data([0xff, 0xfe, 0xfd])
        XCTAssertEqual(
            verdict("POST", "/v1/messages", bodyData: data),
            .refuse("malformed Anthropic JSON body")
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
            .refuse("malformed Anthropic JSON body")
        )
    }

    func testNonJSONBodyOnUnsupportedPathRefused() {
        XCTAssertEqual(
            verdict("POST", "/v1/anything", "not json at all"),
            .refuse("unsupported non-JSON POST body")
        )
    }

    func testEmptyMessagesBodyAllowed() {
        XCTAssertEqual(verdict("POST", "/v1/messages", ""), .allow)
    }

    func testEmptyUnsupportedPostBodyAllowed() {
        XCTAssertEqual(verdict("POST", "/v1/anything", ""), .allow)
    }

    func testGetRequestAllowed() {
        XCTAssertEqual(verdict("GET", "/v1/models", ""), .allow)
    }

    func testOptionsRequestAllowed() {
        XCTAssertEqual(verdict("OPTIONS", "/v1/messages", ""), .allow)
    }

    func testNonCanonicalOrUnsupportedMethodsWithBodiesAreRefused() {
        // WO-422: method admission and body scanning use the same exact POST predicate.
        let body = #"{"model":"claude-3","messages":[{"role":"user","content":"password=hidden"}]}"#
        for method in ["post", "Post", "PUT", "PATCH", "GET", "DELETE", "PROPFIND"] {
            XCTAssertEqual(
                verdict(method, "/v1/messages", body),
                .refuse("unsupported request method with body"),
                method
            )
        }
    }

    // MARK: - Supported path predicate direct

    func testSupportedAnthropicPathPredicate() {
        let proxy = server()
        let allowed = [
            "/v1/messages",
            "/v1/messages?beta=true",
            "/v1/messages/count_tokens",
            "/v1/messages/batches",
            "/v1/messages/",
            "/v1/messages/count_tokens/",
            "/v1/messages/batches/",
            "/v1/llm-gateway/v1/messages",
            "/anthropic/v1/messages?beta=true",
            "/v1/llm-gateway/v1/messages/count_tokens",
            "/v1/llm-gateway/v1/messages/batches?beta=true",
        ]
        let refused = [
            "/v1/chat/completions",
            "/v1/responses",
            "/v1/messages_extra",
            "/v1/messages/extra",
            "/v1/messages/batches/results",
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

    func testShapeAcceptsNullOpenAIOnlyFields() {
        let json: [String: Any] = [
            "messages": [["role": "assistant", "tool_calls": NSNull(), "function_call": NSNull()]]
        ]
        XCTAssertTrue(server().isAnthropicMessagesShape(json))
    }

    func testBatchShapeAcceptsNestedMessagesParams() {
        let json: [String: Any] = [
            "requests": [
                [
                    "custom_id": "r1",
                    "params": [
                        "model": "claude-3",
                        "messages": [["role": "user", "content": "hi"]],
                    ],
                ],
            ],
        ]
        XCTAssertTrue(server().isAnthropicBatchShape(json))
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
