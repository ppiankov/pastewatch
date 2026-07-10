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
}
