import XCTest
@testable import PastewatchCore

final class ProxyAlertTests: XCTestCase {

    private var server: ProxyServer!

    override func setUp() {
        super.setUp()
        server = ProxyServer(port: 0, injectAlert: true)
    }

    // MARK: - buildAlertBlock

    func testAlertBlockFormat() {
        let block = server.buildAlertBlock(redactionCount: 2, types: ["AWS Key", "Credential"])
        XCTAssertEqual(block["type"] as? String, "text")
        let text = block["text"] as? String ?? ""
        XCTAssertTrue(text.hasPrefix("[PASTEWATCH]"))
        XCTAssertTrue(text.contains("2 secret(s) redacted"))
        XCTAssertTrue(text.contains("AWS Key"))
        XCTAssertTrue(text.contains("Credential"))
        // WO-521: the model must distinguish expected one-way markers from real corruption.
        XCTAssertTrue(text.contains("<TYPE_n>"))
        XCTAssertTrue(text.contains("one-way"))
        XCTAssertTrue(text.contains("not corruption"))
        XCTAssertTrue(text.contains("malformed"))
    }

    func testAlertBlockDeduplicatesTypes() {
        let block = server.buildAlertBlock(
            redactionCount: 3,
            types: ["AWS Key", "AWS Key", "Credential"]
        )
        let text = block["text"] as? String ?? ""
        XCTAssertTrue(text.contains("AWS Key, Credential"))
        XCTAssertTrue(text.contains("3 secret(s) redacted"))
    }

    func testAlertBlockSingleType() {
        let block = server.buildAlertBlock(redactionCount: 1, types: ["Workledger Key"])
        let text = block["text"] as? String ?? ""
        XCTAssertTrue(text.contains("1 secret(s) redacted"))
        XCTAssertTrue(text.contains("Workledger Key"))
    }

    func testAlertSSEDataUsesSingleEventFrameFormat() throws {
        let data = try XCTUnwrap(server.buildAlertSSEData(redactionCount: 1, types: ["Credential"]))
        let frame = String(data: data, encoding: .utf8) ?? ""

        XCTAssertTrue(frame.hasPrefix("event: pastewatch_alert\ndata: "))
        XCTAssertTrue(frame.hasSuffix("\n\n"))
        XCTAssertTrue(frame.contains(#""type":"text""#))
        XCTAssertTrue(frame.contains("[PASTEWATCH]"))
    }

    // MARK: - injectAlertIntoResponse

    func testInjectAlertIntoValidResponse() throws {
        let response: [String: Any] = [
            "id": "msg_123",
            "type": "message",
            "role": "assistant",
            "content": [["type": "text", "text": "Hello world"]]
        ]
        let data = try JSONSerialization.data(withJSONObject: response)

        let result = server.injectAlertIntoResponse(data, redactionCount: 1, types: ["Credential"])
        let json = try JSONSerialization.jsonObject(with: result) as? [String: Any]
        let content = json?["content"] as? [[String: Any]]

        XCTAssertEqual(content?.count, 2, "Should have alert + original text block")
        let alertText = content?[0]["text"] as? String ?? ""
        XCTAssertTrue(alertText.hasPrefix("[PASTEWATCH]"))
        XCTAssertEqual(content?[1]["text"] as? String, "Hello world")
    }

    func testInjectAlertPreservesResponseFields() throws {
        let response: [String: Any] = [
            "id": "msg_456",
            "type": "message",
            "role": "assistant",
            "model": "claude-opus-4-6",
            "content": [["type": "text", "text": "test"]]
        ]
        let data = try JSONSerialization.data(withJSONObject: response)

        let result = server.injectAlertIntoResponse(data, redactionCount: 1, types: ["AWS Key"])
        let json = try JSONSerialization.jsonObject(with: result) as? [String: Any]

        XCTAssertEqual(json?["id"] as? String, "msg_456")
        XCTAssertEqual(json?["model"] as? String, "claude-opus-4-6")
        XCTAssertEqual(json?["role"] as? String, "assistant")
    }

    func testPassthroughOnErrorResponse() throws {
        let errorResponse: [String: Any] = [
            "type": "error",
            "error": ["type": "overloaded_error", "message": "Overloaded"]
        ]
        let data = try JSONSerialization.data(withJSONObject: errorResponse)

        let result = server.injectAlertIntoResponse(data, redactionCount: 1, types: ["Credential"])
        let json = try JSONSerialization.jsonObject(with: result) as? [String: Any]
        XCTAssertEqual(json?["type"] as? String, "error")
        XCTAssertNil(json?["content"], "Error response should not have content injected")
    }

    func testPassthroughOnNonJSON() {
        let htmlData = Data("<html>Bad Gateway</html>".utf8)

        let result = server.injectAlertIntoResponse(htmlData, redactionCount: 1, types: ["Credential"])
        XCTAssertEqual(result, htmlData, "Non-JSON should pass through unchanged")
    }

    func testBufferedAlertInjectionOnlyRunsForJSONResponses() {
        XCTAssertTrue(server.shouldInjectAlertIntoBufferedResponse(
            headers: ["Content-Type": "application/json"]
        ))
        XCTAssertTrue(server.shouldInjectAlertIntoBufferedResponse(
            headers: ["content-type": "application/json; charset=utf-8"]
        ))
        XCTAssertFalse(server.shouldInjectAlertIntoBufferedResponse(
            headers: ["Content-Type": "text/event-stream"]
        ))
        XCTAssertFalse(server.shouldInjectAlertIntoBufferedResponse(headers: [:]))
    }

    func testBufferedSSEAlertInjectionUsesCommentFallback() throws {
        let comment = try XCTUnwrap(server.buildAlertSSECommentData(
            redactionCount: 1,
            types: ["Credential"]
        ))
        let text = String(data: comment, encoding: .utf8) ?? ""

        XCTAssertTrue(server.shouldInjectAlertIntoBufferedSSEResponse(
            headers: ["Content-Type": "text/event-stream; charset=utf-8"]
        ))
        XCTAssertTrue(text.hasPrefix(": [PASTEWATCH]"))
        XCTAssertTrue(text.hasSuffix("\n\n"))
        XCTAssertTrue(text.contains("1 secret(s) redacted"))
    }

    func testAlertInjectionSkippedAuditLineForNonJSONBufferedResponse() throws {
        let path = NSTemporaryDirectory() + "pastewatch-alert-skip-\(UUID().uuidString).log"
        defer { try? FileManager.default.removeItem(atPath: path) }
        let auditServer = ProxyServer(port: 0, auditLogPath: path)

        auditServer.logAlertInjectionSkipped(path: "/v1/messages", contentType: "text/event-stream")
        auditServer.drainAuditLogForTesting()

        let log = try String(contentsOfFile: path)
        XCTAssertTrue(log.contains("PROXY ALERT SKIPPED"))
        XCTAssertTrue(log.contains("/v1/messages"))
        XCTAssertTrue(log.contains("text/event-stream"))
    }

    func testAlertInjectedAsSSECommentAuditLine() throws {
        let path = NSTemporaryDirectory() + "pastewatch-alert-sse-\(UUID().uuidString).log"
        defer { try? FileManager.default.removeItem(atPath: path) }
        let auditServer = ProxyServer(port: 0, auditLogPath: path)

        auditServer.logAlertInjectedAsSSEComment(path: "/v1/messages")
        auditServer.drainAuditLogForTesting()

        let log = try String(contentsOfFile: path)
        XCTAssertTrue(log.contains("PROXY ALERT INJECTED"))
        XCTAssertTrue(log.contains("sse-comment"))
        XCTAssertTrue(log.contains("/v1/messages"))
    }

    // WO-486: audit paths are bounded single-line path components, never raw request targets.
    func testAuditSafePathDropsQueryControlsAndBoundsLength() {
        let queryValue = "synthetic-query-value"
        let controlled = "/v1/messages\n\r\u{001B}\u{0000}\u{0085}?secret=\(queryValue)"
        let sanitized = server.auditSafePath(controlled)

        XCTAssertEqual(sanitized, "/v1/messages_____")
        XCTAssertFalse(sanitized.contains(queryValue))
        XCTAssertFalse(sanitized.unicodeScalars.contains { scalar in
            scalar.value <= 0x1f || (0x7f...0x9f).contains(scalar.value)
        })

        let bounded = server.auditSafePath("/" + String(repeating: "a", count: 700))
        XCTAssertEqual(bounded.count, 515)
        XCTAssertTrue(bounded.hasSuffix("..."))
    }

    func testAdvisorySSEDataUsesDistinctEventFrame() throws {
        let data = try XCTUnwrap(server.buildAdvisorySSEData(advisoryCount: 1, types: ["Email"]))
        let frame = String(data: data, encoding: .utf8) ?? ""

        XCTAssertTrue(frame.hasPrefix("event: pastewatch_advisory\ndata: "))
        XCTAssertTrue(frame.hasSuffix("\n\n"))
        XCTAssertTrue(frame.contains("possible secret"))
        XCTAssertTrue(frame.contains("Email"))
        XCTAssertTrue(frame.contains("custom rule"))
    }

    func testPassthroughOnEmptyContentArray() throws {
        let response: [String: Any] = [
            "id": "msg_789",
            "type": "message",
            "role": "assistant",
            "content": [] as [[String: Any]]
        ]
        let data = try JSONSerialization.data(withJSONObject: response)

        let result = server.injectAlertIntoResponse(data, redactionCount: 1, types: ["JWT"])
        let json = try JSONSerialization.jsonObject(with: result) as? [String: Any]
        let content = json?["content"] as? [[String: Any]]

        XCTAssertEqual(content?.count, 1, "Should have just the alert block")
        let alertText = content?[0]["text"] as? String ?? ""
        XCTAssertTrue(alertText.hasPrefix("[PASTEWATCH]"))
    }

    // MARK: - Flag behavior

    func testNoInjectionWhenFlagOff() throws {
        let serverNoAlert = ProxyServer(port: 0, injectAlert: false)
        XCTAssertFalse(serverNoAlert.injectAlert)
    }

    func testUTF8ToolResultBodyHonorsCustomRules() {
        var config = PastewatchConfig.defaultConfig
        config.customRules = [
            CustomRuleConfig(name: "ACME Proxy Token", pattern: #"ACME-PROXY-[A-Z]+"#, severity: "high")
        ]
        let customServer = ProxyServer(port: 0, config: config, severity: .high)
        let body = """
        {"messages":[{"role":"user","content":[{"type":"tool_result","content":"token ACME-PROXY-ALPHA"}]}]}
        """

        let result = customServer.scanAndRedactBody(body)

        XCTAssertEqual(result.redacted, 1)
        XCTAssertEqual(result.redactedTypes, ["ACME Proxy Token"])
        XCTAssertFalse(result.body.contains("ACME-PROXY-ALPHA"))
        XCTAssertTrue(result.body.contains("<CREDENTIAL_1>"), result.body)
    }

    func testAssistantOnlyToolUseRecursesIntoExplicitlyAuthorizedInput() throws {
        // WO-463/WO-467: tool_use.input is CONTRACT context, so only explicit
        // operator authorization may mutate a deeply nested value.
        var config = PastewatchConfig.defaultConfig
        config.customRules = [
            CustomRuleConfig(
                name: "Approved nested token",
                pattern: #"ACME-NESTED-[A-Z]+"#,
                severity: "high"
            )
        ]
        let customServer = ProxyServer(port: 0, config: config, severity: .high)
        let value = "ACME-NESTED-ALPHA"
        let body = """
        {"messages":[{"role":"assistant","content":[{"type":"tool_use","id":"toolu_1","name":"lookup","input":{"outer":[{"inner":"\(value)"}]}}]}]}
        """

        let result = customServer.scanAndRedactBody(body)

        XCTAssertEqual(result.redacted, 1)
        XCTAssertFalse(result.body.contains(value))
        let json = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(result.body.utf8)) as? [String: Any]
        )
        let messages = try XCTUnwrap(json["messages"] as? [[String: Any]])
        let content = try XCTUnwrap(messages[0]["content"] as? [[String: Any]])
        let input = try XCTUnwrap(content[0]["input"] as? [String: Any])
        let outer = try XCTUnwrap(input["outer"] as? [[String: Any]])
        XCTAssertEqual(outer[0]["inner"] as? String, "<CREDENTIAL_1>")
    }

    func testToolSchemaEnumPreservesBuiltInAndMutatesCustomRule() throws {
        // WO-468: schema enums are recursively scanned as CONTRACT material.
        // WO-529: Enable dbConnectionString for DSN detection.
        var config = PastewatchConfig.defaultConfig
        if !config.enabledTypes.contains(SensitiveDataType.dbConnectionString.rawValue) {
            config.enabledTypes.append(SensitiveDataType.dbConnectionString.rawValue)
        }
        config.customRules = [
            CustomRuleConfig(
                name: "Approved schema token",
                pattern: #"ACME-SCHEMA-[A-Z]+"#,
                severity: "high"
            )
        ]
        let customServer = ProxyServer(port: 0, config: config, severity: .low)
        let dsn = "postgres" + "://user:example@localhost/db"
        let approved = "ACME-SCHEMA-ALPHA"
        let body = """
        {"tools":[{"name":"lookup","input_schema":{"type":"string","enum":["\(dsn)","\(approved)","safe"]}}],"messages":[]}
        """

        let result = customServer.scanAndRedactBody(body)

        XCTAssertEqual(result.redacted, 1)
        XCTAssertEqual(result.advisoryCount, 1)
        let json = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(result.body.utf8)) as? [String: Any]
        )
        let tools = try XCTUnwrap(json["tools"] as? [[String: Any]])
        let schema = try XCTUnwrap(tools[0]["input_schema"] as? [String: Any])
        let values = try XCTUnwrap(schema["enum"] as? [String])
        XCTAssertEqual(values[0], dsn)
        XCTAssertEqual(values[1], "<CREDENTIAL_1>")
        XCTAssertEqual(values[2], "safe")
    }

    func testBodyRedactionAuditIsDeferredForStreamingRequests() {
        XCTAssertFalse(server.shouldLogBodyRedactionBeforeForwarding(
            redactionCount: 1,
            requestWantsStream: true
        ))
    }

    func testBodyRedactionAuditIsNotDeferredInBufferMode() {
        var config = PastewatchConfig.defaultConfig
        config.responseStreamingRedactionMode = .buffer
        let bufferModeServer = ProxyServer(port: 0, config: config)

        XCTAssertTrue(bufferModeServer.shouldLogBodyRedactionBeforeForwarding(
            redactionCount: 1,
            requestWantsStream: true
        ))
    }

    func testForwardedBodyRedactionStillCountsAsForwardedRedaction() {
        let forwardedServer = ProxyServer(port: 0)

        forwardedServer.recordInitialRequestStats(redactionCount: 2)

        XCTAssertEqual(forwardedServer.stats.requestsProcessed, 1)
        XCTAssertEqual(forwardedServer.stats.requestsRedacted, 1)
        XCTAssertEqual(forwardedServer.stats.secretsRedacted, 2)
    }

    func testDeferredStreamingBodyRedactionDoesNotCountUntilAccepted() {
        let streamingServer = ProxyServer(port: 0)

        streamingServer.recordInitialRequestStats(
            redactionCount: 1,
            countForwardedRedaction: false
        )

        XCTAssertEqual(streamingServer.stats.requestsProcessed, 1)
        XCTAssertEqual(streamingServer.stats.requestsRedacted, 0)
        XCTAssertEqual(streamingServer.stats.secretsRedacted, 0)

        streamingServer.recordForwardedBodyRedactionStats(redactionCount: 1)

        XCTAssertEqual(streamingServer.stats.requestsRedacted, 1)
        XCTAssertEqual(streamingServer.stats.secretsRedacted, 1)
    }

    func testRejectedStreamingBodyRedactionLogsAuditAndStats() throws {
        let path = NSTemporaryDirectory() + "pastewatch-stream-reject-\(UUID().uuidString).log"
        defer { try? FileManager.default.removeItem(atPath: path) }
        let streamingServer = ProxyServer(port: 0, auditLogPath: path)

        streamingServer.recordInitialRequestStats(
            redactionCount: 1,
            countForwardedRedaction: false
        )
        streamingServer.recordRejectedStreamingBodyRedactionIfNeeded(
            path: "/v1/messages",
            redactionCount: 1,
            redactedTypes: ["Credential"]
        )
        streamingServer.drainAuditLogForTesting()

        XCTAssertEqual(streamingServer.stats.requestsProcessed, 1)
        XCTAssertEqual(streamingServer.stats.requestsRedacted, 1)
        XCTAssertEqual(streamingServer.stats.secretsRedacted, 1)
        let log = try String(contentsOfFile: path)
        XCTAssertTrue(log.contains("PROXY REDACTED 1 secret(s) in /v1/messages"))
        XCTAssertTrue(log.contains("Credential x1"))
    }

    func testStreamingAdvisoryOnlyStatsLogAuditAndStats() throws {
        let path = NSTemporaryDirectory() + "pastewatch-stream-advisory-\(UUID().uuidString).log"
        defer { try? FileManager.default.removeItem(atPath: path) }
        let streamingServer = ProxyServer(port: 0, auditLogPath: path)

        streamingServer.recordInitialRequestStats(
            redactionCount: 0
        )
        streamingServer.recordStreamingAuditStats(ProxyServer.StreamingAuditStats(
            path: "/v1/messages",
            bodyCount: 0,
            bodyTypes: [],
            streamCount: 0,
            streamTypes: [],
            advisoryCount: 1,
            advisoryTypes: ["Email"]
        ))
        streamingServer.drainAuditLogForTesting()

        XCTAssertEqual(streamingServer.stats.requestsProcessed, 1)
        XCTAssertEqual(streamingServer.stats.requestsRedacted, 0)
        XCTAssertEqual(streamingServer.stats.secretsRedacted, 0)
        XCTAssertEqual(streamingServer.stats.advisoryMatches, 1)
        let log = try String(contentsOfFile: path)
        XCTAssertTrue(log.contains("PROXY ADVISORY 1 possible secret match(es) in /v1/messages"))
        XCTAssertTrue(log.contains("Email x1"))
    }

    func testBodyAdvisoryOnlyStatsLogAuditAndStats() throws {
        let path = NSTemporaryDirectory() + "pastewatch-body-advisory-\(UUID().uuidString).log"
        defer { try? FileManager.default.removeItem(atPath: path) }
        let advisoryServer = ProxyServer(port: 0, auditLogPath: path)

        advisoryServer.recordBodyAdvisoryStats(path: "/v1/messages", count: 1, types: ["Email"])
        advisoryServer.drainAuditLogForTesting()

        XCTAssertEqual(advisoryServer.stats.advisoryMatches, 1)
        let log = try String(contentsOfFile: path)
        XCTAssertTrue(log.contains("PROXY ADVISORY 1 possible secret match(es) in /v1/messages"))
        XCTAssertTrue(log.contains("Email x1"))
    }

    func testAdvisoryDedupSeparatesRequestAndStreamSources() throws {
        let path = NSTemporaryDirectory() + "pastewatch-advisory-source-dedup-\(UUID().uuidString).log"
        defer { try? FileManager.default.removeItem(atPath: path) }
        let advisoryServer = ProxyServer(port: 0, auditLogPath: path)

        advisoryServer.recordBodyAdvisoryStats(path: "/v1/messages", count: 1, types: ["Email"])
        advisoryServer.recordStreamingAuditStats(ProxyServer.StreamingAuditStats(
            path: "/v1/messages",
            bodyCount: 0,
            bodyTypes: [],
            streamCount: 0,
            streamTypes: [],
            advisoryCount: 1,
            advisoryTypes: ["Email"]
        ))
        advisoryServer.drainAuditLogForTesting()

        XCTAssertEqual(advisoryServer.stats.advisoryMatches, 2)
        let log = try String(contentsOfFile: path)
        XCTAssertEqual(log.components(separatedBy: "PROXY ADVISORY").count - 1, 2)
    }

    func testStreamingRedactionAndAdvisoryStatsLogSeparateAuditLines() throws {
        let path = NSTemporaryDirectory() + "pastewatch-stream-mixed-\(UUID().uuidString).log"
        defer { try? FileManager.default.removeItem(atPath: path) }
        let streamingServer = ProxyServer(port: 0, auditLogPath: path)

        streamingServer.recordInitialRequestStats(
            redactionCount: 0,
            countForwardedRedaction: false
        )
        streamingServer.recordStreamingAuditStats(ProxyServer.StreamingAuditStats(
            path: "/v1/messages",
            bodyCount: 0,
            bodyTypes: [],
            streamCount: 1,
            streamTypes: ["Credential"],
            advisoryCount: 1,
            advisoryTypes: ["Email"]
        ))
        streamingServer.drainAuditLogForTesting()

        XCTAssertEqual(streamingServer.stats.requestsProcessed, 1)
        XCTAssertEqual(streamingServer.stats.requestsRedacted, 1)
        XCTAssertEqual(streamingServer.stats.secretsRedacted, 1)
        XCTAssertEqual(streamingServer.stats.advisoryMatches, 1)
        let log = try String(contentsOfFile: path)
        XCTAssertTrue(log.contains("PROXY REDACTED 1 secret(s) in /v1/messages"))
        XCTAssertTrue(log.contains("Credential x1"))
        XCTAssertTrue(log.contains("PROXY ADVISORY 1 possible secret match(es) in /v1/messages"))
        XCTAssertTrue(log.contains("Email x1"))
    }

    func testAdvisoryDedupDoesNotResetRedactionDedup() throws {
        let path = NSTemporaryDirectory() + "pastewatch-stream-dedup-\(UUID().uuidString).log"
        defer { try? FileManager.default.removeItem(atPath: path) }
        let streamingServer = ProxyServer(port: 0, auditLogPath: path)
        let summary = ProxyServer.StreamingAuditStats(
            path: "/v1/messages",
            bodyCount: 0,
            bodyTypes: [],
            streamCount: 1,
            streamTypes: ["Credential"],
            advisoryCount: 1,
            advisoryTypes: ["Email"]
        )

        streamingServer.recordStreamingAuditStats(summary)
        streamingServer.recordStreamingAuditStats(summary)
        streamingServer.drainAuditLogForTesting()

        let log = try String(contentsOfFile: path)
        XCTAssertEqual(log.components(separatedBy: "PROXY REDACTED").count - 1, 1)
        XCTAssertEqual(log.components(separatedBy: "PROXY ADVISORY").count - 1, 1)
    }

    func testAdvisoryDedupKeepsDistinctPaths() throws {
        let path = NSTemporaryDirectory() + "pastewatch-stream-dedup-path-\(UUID().uuidString).log"
        defer { try? FileManager.default.removeItem(atPath: path) }
        let streamingServer = ProxyServer(port: 0, auditLogPath: path)

        for requestPath in ["/v1/messages", "/v1/other"] {
            streamingServer.recordStreamingAuditStats(ProxyServer.StreamingAuditStats(
                path: requestPath,
                bodyCount: 0,
                bodyTypes: [],
                streamCount: 1,
                streamTypes: ["Credential"],
                advisoryCount: 1,
                advisoryTypes: ["Email"]
            ))
        }
        streamingServer.drainAuditLogForTesting()

        let log = try String(contentsOfFile: path)
        XCTAssertEqual(log.components(separatedBy: "PROXY REDACTED").count - 1, 2)
        XCTAssertEqual(log.components(separatedBy: "PROXY ADVISORY").count - 1, 2)
        XCTAssertTrue(log.contains("/v1/messages"))
        XCTAssertTrue(log.contains("/v1/other"))
    }

    func testBufferedResponseRedactionStatsDoNotDoubleCountRequest() {
        let responseOnlyServer = ProxyServer(port: 0)
        responseOnlyServer.recordInitialRequestStats(redactionCount: 0)
        responseOnlyServer.recordBufferedResponseRedactionStats(requestRedactionCount: 0, responseRedactionCount: 1)

        XCTAssertEqual(responseOnlyServer.stats.requestsProcessed, 1)
        XCTAssertEqual(responseOnlyServer.stats.requestsRedacted, 1)
        XCTAssertEqual(responseOnlyServer.stats.secretsRedacted, 1)

        let requestAndResponseServer = ProxyServer(port: 0)
        requestAndResponseServer.recordInitialRequestStats(redactionCount: 1)
        requestAndResponseServer.recordBufferedResponseRedactionStats(requestRedactionCount: 1, responseRedactionCount: 1)

        XCTAssertEqual(requestAndResponseServer.stats.requestsProcessed, 1)
        XCTAssertEqual(requestAndResponseServer.stats.requestsRedacted, 1)
        XCTAssertEqual(requestAndResponseServer.stats.secretsRedacted, 2)
    }

    func testRequestAndBufferedResponseRedactionAuditDoNotDedupEachOther() throws {
        let path = NSTemporaryDirectory() + "pastewatch-buffered-response-dedup-\(UUID().uuidString).log"
        defer { try? FileManager.default.removeItem(atPath: path) }
        let auditServer = ProxyServer(port: 0, auditLogPath: path)

        auditServer.recordRejectedStreamingBodyRedactionIfNeeded(
            path: "/v1/messages",
            redactionCount: 1,
            redactedTypes: ["Credential"]
        )
        auditServer.recordBufferedResponseRedactionAuditForTesting(
            path: "/v1/messages",
            count: 1,
            types: ["Credential"]
        )
        auditServer.recordRejectedStreamingBodyRedactionIfNeeded(
            path: "/v1/messages",
            redactionCount: 1,
            redactedTypes: ["Credential"]
        )
        auditServer.recordBufferedResponseRedactionAuditForTesting(
            path: "/v1/messages",
            count: 1,
            types: ["Credential"]
        )
        auditServer.drainAuditLogForTesting()

        let log = try String(contentsOfFile: path)
        XCTAssertEqual(log.components(separatedBy: "PROXY REDACTED").count - 1, 2)
        XCTAssertTrue(log.contains("PROXY REDACTED 1 secret(s) in /v1/messages"))
        XCTAssertTrue(log.contains("PROXY REDACTED 1 secret(s) in response /v1/messages"))
    }

    // WO-512: audit and stats distinguish tool argument mutation from ordinary stream text.
    func testToolCallStreamingMutationHasDistinctAuditSignal() throws {
        let path = NSTemporaryDirectory() + "pastewatch-tool-call-audit-\(UUID().uuidString).log"
        defer { try? FileManager.default.removeItem(atPath: path) }
        let auditServer = ProxyServer(port: 0, auditLogPath: path)

        auditServer.recordStreamingAuditStats(.init(
            path: "/v1/messages",
            bodyCount: 0,
            bodyTypes: [],
            streamCount: 1,
            streamTypes: ["Tool argument: Google API Key"],
            advisoryCount: 0,
            advisoryTypes: [],
            toolCallCount: 1
        ))
        auditServer.drainAuditLogForTesting()

        let log = try String(contentsOfFile: path)
        XCTAssertEqual(auditServer.stats.toolCallPayloadMutations, 1)
        XCTAssertTrue(log.contains("PROXY TOOL ARGUMENT REDACTED 1 secret(s) in /v1/messages"), log)
        XCTAssertTrue(log.contains("Tool argument: Google API Key"), log)
    }

    func testStreamingStatsDeferralPolicyHonorsPlatformAndMode() {
        var bufferConfig = PastewatchConfig.defaultConfig
        bufferConfig.responseStreamingRedactionMode = .buffer
        let bufferServer = ProxyServer(port: 0, config: bufferConfig)
        let streamServer = ProxyServer(port: 0)

        XCTAssertFalse(bufferServer.shouldDeferForwardedRedactionStats(requestWantsStream: true))
        XCTAssertFalse(streamServer.shouldDeferForwardedRedactionStats(requestWantsStream: false))
        #if canImport(Darwin)
        XCTAssertTrue(streamServer.shouldDeferForwardedRedactionStats(requestWantsStream: true))
        #else
        XCTAssertFalse(streamServer.shouldDeferForwardedRedactionStats(requestWantsStream: true))
        #endif
    }

    func testBufferModeWarningIgnoresQuietFlag() {
        var config = PastewatchConfig.defaultConfig
        config.responseStreamingRedactionMode = .buffer

        let warning = "WARNING: responseStreamingRedactionMode=buffer does not scan buffered response bodies\n"

        XCTAssertEqual(ProxyServer.bufferModeWarning(config: config, quiet: false), warning)
        XCTAssertEqual(ProxyServer.bufferModeWarning(config: config, quiet: true), warning)
        XCTAssertNil(ProxyServer.bufferModeWarning(config: PastewatchConfig.defaultConfig, quiet: false))
    }

    func testAuditTimestampIncludesFractionalSeconds() {
        let first = server.formatAuditTimestamp(Date(timeIntervalSince1970: 1_704_067_200.123))
        let second = server.formatAuditTimestamp(Date(timeIntervalSince1970: 1_704_067_200.124))

        XCTAssertTrue(first.contains(".123"))
        XCTAssertTrue(first.hasSuffix("Z"))
        XCTAssertNotEqual(first, second)
    }

    // WO-395: shared formatter access remains well-formed under concurrent first use.
    func testAuditTimestampFormattingIsSerializedAcrossHandlers() {
        let server = ProxyServer(port: 0)
        let lock = NSLock()
        var timestamps: [String] = []

        DispatchQueue.concurrentPerform(iterations: 200) { offset in
            let timestamp = server.formatAuditTimestamp(Date(timeIntervalSince1970: Double(offset)))
            lock.lock()
            timestamps.append(timestamp)
            lock.unlock()
        }

        XCTAssertEqual(timestamps.count, 200)
        XCTAssertTrue(timestamps.allSatisfy { $0.contains("T") && $0.contains(".") && $0.hasSuffix("Z") })
    }

    // WO-503: scan plaintext/future block payloads without corrupting encoded media.
    func testUnhandledDocumentTextPayloadIsRedacted() {
        let key = "AKIA" + "QWERTYUIOPASDFGH"
        let body = """
        {"messages":[{"role":"user","content":[{"type":"document","source":{"type":"text","media_type":"text/plain","data":"\(key)"}}]}]}
        """

        let result = server.scanAndRedactBody(body)

        XCTAssertEqual(result.redacted, 1)
        XCTAssertFalse(result.body.contains(key))
    }

    func testUnknownContentBlockPayloadIsRedacted() {
        let key = "AKIA" + "QWERTYUIOPASDFGH"
        let body = """
        {"messages":[{"role":"user","content":[{"type":"custom_x","payload":{"nested":"\(key)"}}]}]}
        """

        let result = server.scanAndRedactBody(body)

        XCTAssertEqual(result.redacted, 1)
        XCTAssertFalse(result.body.contains(key))
    }

    func testUnknownContentBlockWithTextStillScansNestedPayload() {
        let key = "AKIA" + "QWERTYUIOPASDFGH"
        let body = """
        {"messages":[{"role":"user","content":[{"type":"custom_x","text":"safe","payload":{"nested":"\(key)"}}]}]}
        """

        let result = server.scanAndRedactBody(body)

        XCTAssertEqual(result.redacted, 1)
        XCTAssertFalse(result.body.contains(key))
        XCTAssertTrue(result.body.contains("safe"))
    }

    func testBase64PayloadAndStructuralDiscriminatorsArePreserved() throws {
        var config = PastewatchConfig.defaultConfig
        config.customRules = [
            CustomRuleConfig(
                name: "Structural words",
                pattern: #"^(image|base64|image/png)$"#,
                severity: "critical"
            )
        ]
        let structuralServer = ProxyServer(port: 0, config: config, severity: .low)
        let encodedData = "AKIA" + "QWERTYUIOPASDFGH"
        let body = """
        {"messages":[{"role":"user","content":[{"type":"image","source":{"type":"base64","media_type":"image/png","data":"\(encodedData)"}}]}]}
        """

        let result = structuralServer.scanAndRedactBody(body)
        let json = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(result.body.utf8)) as? [String: Any]
        )
        let messages = try XCTUnwrap(json["messages"] as? [[String: Any]])
        let content = try XCTUnwrap(messages[0]["content"] as? [[String: Any]])
        let source = try XCTUnwrap(content[0]["source"] as? [String: Any])

        XCTAssertEqual(result.redacted, 0)
        XCTAssertEqual(result.advisoryCount, 0)
        XCTAssertEqual(content[0]["type"] as? String, "image")
        XCTAssertEqual(source["type"] as? String, "base64")
        XCTAssertEqual(source["media_type"] as? String, "image/png")
        XCTAssertEqual(source["data"] as? String, encodedData)
    }

    // WO-460: known Anthropic blocks expose only their documented text-bearing fields.
    func testDocumentAndSearchResultTraversalPreservesProtocolMetadata() throws {
        let documentKey = "AKIA" + "ZXCVBNMASDFGHJKL"
        let nestedDocumentKey = "AIza" + String(repeating: "D", count: 35)
        let searchKey = "AIza" + String(repeating: "S", count: 35)
        let toolResultKey = "AIza" + String(repeating: "T", count: 35)
        let metadataKey = "AIza" + String(repeating: "M", count: 35)
        let request: [String: Any] = [
            "messages": [[
                "role": "user",
                "content": [
                    [
                        "type": "document",
                        "source": ["type": "text", "media_type": "text/plain", "data": documentKey],
                    ],
                    [
                        "type": "document",
                        "source": [
                            "type": "content",
                            "content": [["type": "text", "text": nestedDocumentKey]],
                        ],
                    ],
                    [
                        "type": "document",
                        "source": ["type": "url", "url": "https://example.test/\(metadataKey)"],
                    ],
                    [
                        "type": "search_result",
                        "source": "https://search.test/\(metadataKey)",
                        "title": metadataKey,
                        "content": [[
                            "type": "text",
                            "text": searchKey,
                            "citations": [["type": "web_search_result_location", "url": metadataKey]],
                        ]],
                    ],
                    ["type": "redacted_thinking", "data": metadataKey],
                    [
                        "type": "tool_result",
                        "tool_use_id": "toolu_1",
                        "content": [[
                            "type": "document",
                            "source": ["type": "text", "media_type": "text/plain", "data": toolResultKey],
                        ]],
                    ],
                ],
            ]],
        ]
        let body = String(data: try JSONSerialization.data(withJSONObject: request), encoding: .utf8)!

        let result = server.scanAndRedactBody(body)
        let output = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(result.body.utf8)) as? [String: Any]
        )
        let messages = try XCTUnwrap(output["messages"] as? [[String: Any]])
        let blocks = try XCTUnwrap(messages[0]["content"] as? [[String: Any]])

        XCTAssertEqual(result.redacted, 4)
        XCTAssertFalse(result.body.contains(documentKey))
        XCTAssertFalse(result.body.contains(nestedDocumentKey))
        XCTAssertFalse(result.body.contains(searchKey))
        XCTAssertFalse(result.body.contains(toolResultKey))
        XCTAssertEqual((blocks[2]["source"] as? [String: Any])?["url"] as? String,
                       "https://example.test/\(metadataKey)")
        XCTAssertEqual(blocks[3]["source"] as? String, "https://search.test/\(metadataKey)")
        XCTAssertEqual(blocks[3]["title"] as? String, metadataKey)
        XCTAssertEqual(blocks[4]["data"] as? String, metadataKey)
    }

    // WO-459@v2: null siblings cannot suppress scanning of valid tool-result blocks.
    func testMixedNullToolResultContentStillRedactsTextBlock() throws {
        let credential = "AIza" + String(repeating: "N", count: 35)
        let request: [String: Any] = [
            "messages": [[
                "role": "user",
                "content": [[
                    "type": "tool_result",
                    "tool_use_id": "toolu_1",
                    "content": [NSNull(), ["type": "text", "text": credential]],
                ]],
            ]],
        ]
        let body = String(data: try JSONSerialization.data(withJSONObject: request), encoding: .utf8)!

        let result = server.scanAndRedactBody(body)
        let output = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(result.body.utf8)) as? [String: Any]
        )
        let messages = try XCTUnwrap(output["messages"] as? [[String: Any]])
        let blocks = try XCTUnwrap(messages[0]["content"] as? [[String: Any]])
        let toolContent = try XCTUnwrap(blocks[0]["content"] as? [Any])
        let textBlock = try XCTUnwrap(toolContent[1] as? [String: Any])

        XCTAssertTrue(toolContent[0] is NSNull)
        XCTAssertEqual(result.redacted, 1)
        XCTAssertFalse(result.body.contains(credential))
        XCTAssertTrue((textBlock["text"] as? String)?.hasPrefix("<GOOGLE_API_KEY_") == true)
    }

    // WO-506: opaque execution payloads remain replayable while plaintext stderr is scanned.
    func testEncryptedCodeExecutionTraversalPreservesOpaqueFields() throws {
        let encryptedOutput = "AIza" + String(repeating: "E", count: 35)
        let fileID = "AIza" + String(repeating: "F", count: 35)
        let toolUseID = "AIza" + String(repeating: "T", count: 35)
        let stderrSecret = "AIza" + String(repeating: "S", count: 35)
        let request: [String: Any] = [
            "messages": [[
                "role": "assistant",
                "content": [[
                    "type": "code_execution_tool_result",
                    "tool_use_id": toolUseID,
                    "content": [
                        "type": "encrypted_code_execution_result",
                        "encrypted_stdout": encryptedOutput,
                        "content": [["type": "code_execution_output", "file_id": fileID]],
                        "return_code": 1,
                        "stderr": stderrSecret,
                    ],
                ]],
            ]],
        ]
        let body = String(data: try JSONSerialization.data(withJSONObject: request), encoding: .utf8)!

        let result = server.scanAndRedactBody(body)
        let output = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(result.body.utf8)) as? [String: Any]
        )
        let messages = try XCTUnwrap(output["messages"] as? [[String: Any]])
        let blocks = try XCTUnwrap(messages[0]["content"] as? [[String: Any]])
        let encrypted = try XCTUnwrap(blocks[0]["content"] as? [String: Any])
        let files = try XCTUnwrap(encrypted["content"] as? [[String: Any]])

        XCTAssertEqual(result.redacted, 1)
        XCTAssertEqual(blocks[0]["tool_use_id"] as? String, toolUseID)
        XCTAssertEqual(encrypted["encrypted_stdout"] as? String, encryptedOutput)
        XCTAssertEqual(files[0]["file_id"] as? String, fileID)
        XCTAssertEqual(encrypted["return_code"] as? Int, 1)
        XCTAssertNotEqual(encrypted["stderr"] as? String, stderrSecret)
        XCTAssertTrue((encrypted["stderr"] as? String)?.hasPrefix("<GOOGLE_API_KEY_") == true)
    }
}
