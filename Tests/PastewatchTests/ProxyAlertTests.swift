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

    func testAdvisorySSEDataUsesDistinctEventFrame() throws {
        let data = try XCTUnwrap(server.buildAdvisorySSEData(advisoryCount: 1, types: ["Email"]))
        let frame = String(data: data, encoding: .utf8) ?? ""

        XCTAssertTrue(frame.hasPrefix("event: pastewatch_advisory\ndata: "))
        XCTAssertTrue(frame.hasSuffix("\n\n"))
        XCTAssertTrue(frame.contains("possible secret"))
        XCTAssertTrue(frame.contains("Email"))
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

    func testNonUTF8RequestBodyStillScansLossyTextForAudit() {
        var body = Data([0xFF, 0xFE, 0x00])
        body.append(Data("password=s3cr3t-hunter2".utf8))

        let result = server.scanNonUTF8BodyForRedactions(body)

        XCTAssertEqual(result.redacted, 1)
        XCTAssertEqual(result.redactedTypes, ["Credential"])
        XCTAssertTrue(result.shouldBlockForwarding)
    }

    func testNonUTF8RequestBodyWithoutSecretDoesNotBlockForwarding() {
        let body = Data([0xFF, 0xFE, 0x00, 0x41])

        let result = server.scanNonUTF8BodyForRedactions(body)

        XCTAssertEqual(result.redacted, 0)
        XCTAssertEqual(result.redactedTypes, [])
        XCTAssertFalse(result.shouldBlockForwarding)
    }

    func testBodyRedactionAuditIsDeferredForStreamingRequests() {
        XCTAssertFalse(server.shouldLogBodyRedactionBeforeForwarding(
            redactionCount: 1,
            requestWantsStream: true,
            shouldBlockNonUTF8Forwarding: false
        ))
    }

    func testBodyRedactionAuditIsNotDeferredWhenMalformedBodyBlocksForwarding() {
        XCTAssertTrue(server.shouldLogBodyRedactionBeforeForwarding(
            redactionCount: 1,
            requestWantsStream: true,
            shouldBlockNonUTF8Forwarding: true
        ))
    }

    func testBodyRedactionAuditIsNotDeferredInBufferMode() {
        var config = PastewatchConfig.defaultConfig
        config.responseStreamingRedactionMode = .buffer
        let bufferModeServer = ProxyServer(port: 0, config: config)

        XCTAssertTrue(bufferModeServer.shouldLogBodyRedactionBeforeForwarding(
            redactionCount: 1,
            requestWantsStream: true,
            shouldBlockNonUTF8Forwarding: false
        ))
    }

    func testBlockedNonUTF8RedactionDoesNotCountAsForwardedRedaction() {
        let blockedServer = ProxyServer(port: 0)

        blockedServer.recordInitialRequestStats(redactionCount: 1, shouldBlockNonUTF8Forwarding: true)

        XCTAssertEqual(blockedServer.stats.requestsProcessed, 1)
        XCTAssertEqual(blockedServer.stats.requestsRedacted, 0)
        XCTAssertEqual(blockedServer.stats.secretsRedacted, 0)
    }

    func testForwardedBodyRedactionStillCountsAsForwardedRedaction() {
        let forwardedServer = ProxyServer(port: 0)

        forwardedServer.recordInitialRequestStats(redactionCount: 2, shouldBlockNonUTF8Forwarding: false)

        XCTAssertEqual(forwardedServer.stats.requestsProcessed, 1)
        XCTAssertEqual(forwardedServer.stats.requestsRedacted, 1)
        XCTAssertEqual(forwardedServer.stats.secretsRedacted, 2)
    }

    func testDeferredStreamingBodyRedactionDoesNotCountUntilAccepted() {
        let streamingServer = ProxyServer(port: 0)

        streamingServer.recordInitialRequestStats(
            redactionCount: 1,
            shouldBlockNonUTF8Forwarding: false,
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
            shouldBlockNonUTF8Forwarding: false,
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
            redactionCount: 0,
            shouldBlockNonUTF8Forwarding: false
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

    func testStreamingRedactionAndAdvisoryStatsLogSeparateAuditLines() throws {
        let path = NSTemporaryDirectory() + "pastewatch-stream-mixed-\(UUID().uuidString).log"
        defer { try? FileManager.default.removeItem(atPath: path) }
        let streamingServer = ProxyServer(port: 0, auditLogPath: path)

        streamingServer.recordInitialRequestStats(
            redactionCount: 0,
            shouldBlockNonUTF8Forwarding: false,
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
        responseOnlyServer.recordInitialRequestStats(redactionCount: 0, shouldBlockNonUTF8Forwarding: false)
        responseOnlyServer.recordBufferedResponseRedactionStats(requestRedactionCount: 0, responseRedactionCount: 1)

        XCTAssertEqual(responseOnlyServer.stats.requestsProcessed, 1)
        XCTAssertEqual(responseOnlyServer.stats.requestsRedacted, 1)
        XCTAssertEqual(responseOnlyServer.stats.secretsRedacted, 1)

        let requestAndResponseServer = ProxyServer(port: 0)
        requestAndResponseServer.recordInitialRequestStats(redactionCount: 1, shouldBlockNonUTF8Forwarding: false)
        requestAndResponseServer.recordBufferedResponseRedactionStats(requestRedactionCount: 1, responseRedactionCount: 1)

        XCTAssertEqual(requestAndResponseServer.stats.requestsProcessed, 1)
        XCTAssertEqual(requestAndResponseServer.stats.requestsRedacted, 1)
        XCTAssertEqual(requestAndResponseServer.stats.secretsRedacted, 2)
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
}
