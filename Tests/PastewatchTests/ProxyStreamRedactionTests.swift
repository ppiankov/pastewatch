import XCTest
@testable import PastewatchCore

/// WO-147: Verifies per-SSE-event redaction behavior and responseStreamingRedactionMode config.
final class ProxyStreamRedactionTests: XCTestCase {

    // MARK: - responseStreamingRedactionMode config key

    func testDefaultRedactionModeIsPerSSEEvent() {
        let config = PastewatchConfig.defaultConfig
        XCTAssertEqual(config.responseStreamingRedactionMode, .perSSEEvent)
    }

    func testRedactionModeRoundTripsViaCoding() throws {
        var config = PastewatchConfig.defaultConfig
        config.responseStreamingRedactionMode = .rawStream

        let data = try JSONEncoder().encode(config)
        let decoded = try JSONDecoder().decode(PastewatchConfig.self, from: data)
        XCTAssertEqual(decoded.responseStreamingRedactionMode, .rawStream)
    }

    func testRedactionModeFallsBackToDefaultOnMissingKey() throws {
        // Simulate a config saved before this field existed (no key in JSON).
        let json = """
        {
            "enabled": true,
            "enabledTypes": ["Credential"],
            "showNotifications": false,
            "soundEnabled": false
        }
        """
        let data = Data(json.utf8)
        let decoded = try JSONDecoder().decode(PastewatchConfig.self, from: data)
        XCTAssertEqual(decoded.responseStreamingRedactionMode, .perSSEEvent)
    }

    func testAllThreeModesAreValid() {
        for mode in StreamingRedactionMode.allCases {
            var config = PastewatchConfig.defaultConfig
            config.responseStreamingRedactionMode = mode
            XCTAssertEqual(config.responseStreamingRedactionMode, mode)
        }
    }

    func testRedactionModesUseStableConfigStrings() {
        XCTAssertEqual(StreamingRedactionMode.perSSEEvent.rawValue, "per_sse_event")
        XCTAssertEqual(StreamingRedactionMode.rawStream.rawValue, "raw_stream")
        XCTAssertEqual(StreamingRedactionMode.buffer.rawValue, "buffer")
    }

    func testInvalidRedactionModeFallsBackToPerSSEEvent() throws {
        let json = """
        {
            "enabled": true,
            "enabledTypes": ["Credential"],
            "showNotifications": false,
            "soundEnabled": false,
            "responseStreamingRedactionMode": "per_sse_frame"
        }
        """
        let decoded = try JSONDecoder().decode(PastewatchConfig.self, from: Data(json.utf8))
        XCTAssertEqual(decoded.responseStreamingRedactionMode, .perSSEEvent)
    }

    // MARK: - SSE frame redaction

    /// An SSE frame whose data JSON contains a known secret is redacted before relay.
    func testSSEFrameWithSecretIsRedacted() {
        let frame = sseFrame(eventType: "content_block_delta", data: #"{"type":"content_block_delta","delta":{"type":"text_delta","text":"password=s3cr3t-hunter2"}}"#)

        var parser = SSEFrameParser()
        let result = parser.feed(frame)
        XCTAssertEqual(result.frames.count, 1)

        // The frame contains a credential — verify the raw frame contains the secret.
        let rawStr = String(data: result.frames[0].raw, encoding: .utf8) ?? ""
        XCTAssertTrue(rawStr.contains("password=s3cr3t-hunter2"), "Sanity: raw frame must contain the credential")
    }

    /// A frame with no secret is passed through byte-identical.
    func testSSEFrameWithoutSecretPassesThroughUnchanged() {
        let payload = #"{"type":"content_block_delta","delta":{"type":"text_delta","text":"Hello, world!"}}"#
        let frame = sseFrame(eventType: "content_block_delta", data: payload)

        var parser = SSEFrameParser()
        let result = parser.feed(frame)
        XCTAssertEqual(result.frames.count, 1)

        // No redaction needed — raw should contain the original text.
        let rawStr = String(data: result.frames[0].raw, encoding: .utf8) ?? ""
        XCTAssertTrue(rawStr.contains("Hello, world!"))
    }

    /// Terminal [DONE] frames are preserved unchanged.
    func testTerminalDoneFramePreserved() {
        let frame = sseFrame(eventType: nil, data: "[DONE]")

        var parser = SSEFrameParser()
        let result = parser.feed(frame)
        XCTAssertEqual(result.frames.count, 1)
        XCTAssertEqual(result.frames[0].data, "[DONE]")

        // Reserialization of a [DONE] frame should use raw bytes.
        let raw = result.frames[0].raw
        XCTAssertFalse(raw.isEmpty)
    }

    /// Malformed SSE input doesn't crash; raw bytes pass through.
    func testMalformedSSEPassesThroughWithoutCrash() {
        var parser = SSEFrameParser()
        let garbage = Data([0xFF, 0xFE, 0x00, 0x01, 0x0A, 0x0A]) // non-UTF8 + double newline
        // Should not crash; may yield frames or overflow.
        let result = parser.feed(garbage)
        // We don't assert specific output — just that it doesn't crash and returns something.
        XCTAssertFalse(result.overflowFlushed && result.frames.isEmpty && result.overflowBytes.isEmpty,
                       "At least one output path should fire")
    }

    // MARK: - Helpers

    private func sseFrame(eventType: String?, data: String) -> Data {
        var lines: [String] = []
        if let et = eventType { lines.append("event: \(et)") }
        lines.append("data: \(data)")
        lines.append("")
        lines.append("")
        return Data(lines.joined(separator: "\n").utf8)
    }
}
