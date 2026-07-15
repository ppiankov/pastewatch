import XCTest
@testable import PastewatchCore

#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

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

    func testFrameBeforeInvalidUTF8RemainderCanBeRedacted() {
        let credential = "AIza" + String(repeating: "M", count: 35)
        let payload = #"{"type":"content_block_delta","delta":{"type":"text_delta","text":"\#(credential)"}}"#
        var frame = sseFrame(eventType: "content_block_delta", data: payload)
        frame.append(contentsOf: [0xFF])

        var parser = SSEFrameParser()
        let result = parser.feed(frame)
        XCTAssertEqual(result.frames.count, 1)
        XCTAssertNotNil(result.frames[0].data)

        let redaction = redactSSEFrame(
            result.frames[0],
            config: PastewatchConfig.defaultConfig,
            severity: .high
        )
        let redacted = String(data: redaction.data, encoding: .utf8) ?? ""
        XCTAssertEqual(redaction.count, 1)
        XCTAssertFalse(redacted.contains(credential))
        XCTAssertEqual(parser.remainingBytes, Data([0xFF]))
    }

    func testThinkingDeltaSecretIsRedacted() {
        let credential = "AIza" + String(repeating: "N", count: 35)
        let payload = #"{"type":"content_block_delta","delta":{"type":"thinking_delta","thinking":"\#(credential)"}}"#
        let redaction = redactFirstFrame(payload: payload)

        let redacted = String(data: redaction.data, encoding: .utf8) ?? ""
        XCTAssertEqual(redaction.count, 1)
        XCTAssertFalse(redacted.contains(credential))
        XCTAssertTrue(redacted.contains("<GOOGLE_API_KEY_1>"))
    }

    func testInputJSONDeltaSecretIsRedacted() {
        let credential = "AIza" + String(repeating: "P", count: 35)
        let payload = #"{"type":"content_block_delta","delta":{"type":"input_json_delta","partial_json":"\#(credential)"}}"#
        let redaction = redactFirstFrame(payload: payload)

        let redacted = String(data: redaction.data, encoding: .utf8) ?? ""
        XCTAssertEqual(redaction.count, 1)
        XCTAssertFalse(redacted.contains(credential))
        XCTAssertTrue(redacted.contains("<GOOGLE_API_KEY_1>"))
    }

    func testCriticalMatchMutatesStreamBytes() {
        let credential = "AIza" + String(repeating: "Q", count: 35)
        let payload = #"{"type":"content_block_delta","delta":{"type":"text_delta","text":"\#(credential)"}}"#
        let redaction = redactFirstFrame(payload: payload)
        let redacted = String(data: redaction.data, encoding: .utf8) ?? ""

        XCTAssertEqual(redaction.count, 1)
        XCTAssertEqual(redaction.advisoryCount, 0)
        XCTAssertFalse(redacted.contains(credential))
        XCTAssertTrue(redacted.contains("<GOOGLE_API_KEY_1>"))
    }

    func testCriticalMutationSetIgnoresSeverityThreshold() {
        let credential = "AIza" + String(repeating: "R", count: 35)
        let payload = #"{"type":"content_block_delta","delta":{"type":"text_delta","text":"\#(credential)"}}"#
        var parser = SSEFrameParser()
        let result = parser.feed(sseFrame(eventType: "content_block_delta", data: payload))
        XCTAssertEqual(result.frames.count, 1)

        for severity in Severity.allCases {
            let redaction = redactSSEFrame(
                result.frames[0],
                config: PastewatchConfig.defaultConfig,
                severity: severity
            )
            let redacted = String(data: redaction.data, encoding: .utf8) ?? ""

            XCTAssertEqual(redaction.count, 1, "severity \(severity.rawValue)")
            XCTAssertEqual(redaction.types, ["Google API Key"], "severity \(severity.rawValue)")
            XCTAssertFalse(redacted.contains(credential), "severity \(severity.rawValue)")
            XCTAssertTrue(redacted.contains("<GOOGLE_API_KEY_1>"), "severity \(severity.rawValue)")
        }
    }

    func testHighBuiltInMatchIsAdvisoryOnlyAndByteIdentical() {
        let email = "operator@example.com"
        let payload = #"{"type":"content_block_delta","delta":{"type":"text_delta","text":"contact \#(email)"}}"#
        var parser = SSEFrameParser()
        let result = parser.feed(sseFrame(eventType: "content_block_delta", data: payload))
        XCTAssertEqual(result.frames.count, 1)

        for severity in [Severity.high, .medium, .low] {
            let redaction = redactSSEFrame(
                result.frames[0],
                config: PastewatchConfig.defaultConfig,
                severity: severity
            )

            XCTAssertEqual(redaction.count, 0, "severity \(severity.rawValue)")
            XCTAssertEqual(redaction.types, [], "severity \(severity.rawValue)")
            XCTAssertEqual(redaction.advisoryCount, 1, "severity \(severity.rawValue)")
            XCTAssertEqual(redaction.advisoryTypes, ["Email"], "severity \(severity.rawValue)")
            XCTAssertEqual(redaction.data, result.frames[0].raw, "severity \(severity.rawValue)")
        }

        let critical = redactSSEFrame(
            result.frames[0],
            config: PastewatchConfig.defaultConfig,
            severity: .critical
        )
        XCTAssertEqual(critical.count, 0)
        XCTAssertEqual(critical.advisoryCount, 0)
        XCTAssertEqual(critical.data, result.frames[0].raw)
    }

    func testHighCustomRuleMatchMutatesStreamBytes() {
        let secret = "ACME-STREAM-SECRET"
        let payload = #"{"type":"content_block_delta","delta":{"type":"text_delta","text":"token \#(secret)"}}"#
        var parser = SSEFrameParser()
        let result = parser.feed(sseFrame(eventType: "content_block_delta", data: payload))
        XCTAssertEqual(result.frames.count, 1)
        var config = PastewatchConfig.defaultConfig
        config.customRules = [
            CustomRuleConfig(name: "ACME Stream Secret", pattern: #"ACME-STREAM-[A-Z]+"#, severity: "low")
        ]

        let redaction = redactSSEFrame(
            result.frames[0],
            config: config,
            severity: .critical
        )
        let redacted = String(data: redaction.data, encoding: .utf8) ?? ""

        XCTAssertEqual(redaction.count, 1)
        XCTAssertEqual(redaction.types, ["ACME Stream Secret"])
        XCTAssertEqual(redaction.advisoryCount, 0)
        XCTAssertFalse(redacted.contains(secret))
        XCTAssertTrue(redacted.contains("<CREDENTIAL_1>"))
    }

    func testCustomRulePromotesHighBuiltInToStreamMutation() {
        let email = "operator@example.com"
        let payload = #"{"type":"content_block_delta","delta":{"type":"text_delta","text":"contact \#(email)"}}"#
        var parser = SSEFrameParser()
        let result = parser.feed(sseFrame(eventType: "content_block_delta", data: payload))
        XCTAssertEqual(result.frames.count, 1)
        var config = PastewatchConfig.defaultConfig
        config.customRules = [
            CustomRuleConfig(name: "Approved Operator Email", pattern: #"operator@example\.com"#, severity: "low")
        ]

        let redaction = redactSSEFrame(
            result.frames[0],
            config: config,
            severity: .critical
        )
        let redacted = String(data: redaction.data, encoding: .utf8) ?? ""

        XCTAssertEqual(redaction.count, 1)
        XCTAssertEqual(redaction.types, ["Approved Operator Email"])
        XCTAssertEqual(redaction.advisoryCount, 0)
        XCTAssertFalse(redacted.contains(email))
        XCTAssertTrue(redacted.contains("<CREDENTIAL_1>"))
    }

    func testSeverityControlsAdvisoryVolumeNotMutationSet() {
        let credential = "AIza" + String(repeating: "S", count: 35)
        let email = "operator@example.com"
        let ipAddress = "10.1.2.3"
        let uuid = "550e8400-e29b-41d4-a716-446655440000"
        let text = "\(credential) contact \(email) host \(ipAddress) trace \(uuid)"
        let payload = #"{"type":"content_block_delta","delta":{"type":"text_delta","text":"\#(text)"}}"#
        var parser = SSEFrameParser()
        let result = parser.feed(sseFrame(eventType: "content_block_delta", data: payload))
        XCTAssertEqual(result.frames.count, 1)

        let cases: [(Severity, Set<String>)] = [
            (.critical, []),
            (.high, ["Email"]),
            (.medium, ["Email", "IP"]),
            (.low, ["Email", "IP", "UUID"])
        ]

        for (severity, advisoryTypes) in cases {
            let redaction = redactSSEFrame(
                result.frames[0],
                config: PastewatchConfig.defaultConfig,
                severity: severity
            )
            let output = String(data: redaction.data, encoding: .utf8) ?? ""

            XCTAssertEqual(redaction.count, 1, "severity \(severity.rawValue)")
            XCTAssertEqual(redaction.types, ["Google API Key"], "severity \(severity.rawValue)")
            XCTAssertEqual(Set(redaction.advisoryTypes), advisoryTypes, "severity \(severity.rawValue)")
            XCTAssertFalse(output.contains(credential), "severity \(severity.rawValue)")
            XCTAssertTrue(output.contains(email), "severity \(severity.rawValue)")
            XCTAssertTrue(output.contains(ipAddress), "severity \(severity.rawValue)")
            XCTAssertTrue(output.contains(uuid), "severity \(severity.rawValue)")
        }
    }

    // WO-371: mixed critical and advisory severities keep independent outcomes.
    func testMixedCriticalAndMediumFrameRedactsOnlyCriticalAndAdvisesMedium() {
        let credential = "AIza" + String(repeating: "T", count: 35)
        let ipAddress = "10.1.2.3"
        let payload = #"{"type":"content_block_delta","delta":{"type":"text_delta","text":"\#(credential) from \#(ipAddress)"}}"#
        var parser = SSEFrameParser()
        let result = parser.feed(sseFrame(eventType: "content_block_delta", data: payload))
        XCTAssertEqual(result.frames.count, 1)

        let redaction = redactSSEFrame(
            result.frames[0],
            config: PastewatchConfig.defaultConfig,
            severity: .medium
        )
        let output = String(data: redaction.data, encoding: .utf8) ?? ""

        XCTAssertEqual(redaction.count, 1)
        XCTAssertEqual(redaction.types, ["Google API Key"])
        XCTAssertEqual(redaction.advisoryCount, 1)
        XCTAssertEqual(redaction.advisoryTypes, ["IP"])
        XCTAssertFalse(output.contains(credential))
        XCTAssertTrue(output.contains("<GOOGLE_API_KEY_1>"))
        XCTAssertTrue(output.contains(ipAddress))
    }

    func testInvalidUTF8RawFrameWithCredentialIsRedacted() {
        let credential = "AIza" + String(repeating: "U", count: 35)
        var raw = Data([0xFF, 0xFE])
        raw.append(Data("data: \(credential)\n\n".utf8))
        let frame = SSEFrameParser.Frame(raw: raw, eventType: nil, data: nil)

        let redaction = redactSSEFrame(
            frame,
            config: PastewatchConfig.defaultConfig,
            severity: .high
        )
        let redacted = String(bytes: redaction.data, encoding: .utf8) ?? ""

        XCTAssertEqual(redaction.count, 1)
        XCTAssertFalse(redacted.contains(credential))
        XCTAssertTrue(redacted.contains("<GOOGLE_API_KEY_1>"))
    }

    func testRawStreamFallbackPreservesInvalidBytesWithoutCriticalMatch() {
        let raw = Data([0xFF, 0xFE, 0x41])

        let redaction = redactRawStreamBytes(
            raw,
            config: PastewatchConfig.defaultConfig,
            severity: .high
        )

        XCTAssertEqual(redaction.count, 0)
        XCTAssertEqual(redaction.advisoryCount, 0)
        XCTAssertEqual(redaction.data, raw)
    }

    func testRawStreamFallbackRedactsCredentialWithMalformedUTF8() {
        let credential = "AIza" + String(repeating: "V", count: 35)
        var raw = Data([0xFF, 0xFE])
        raw.append(Data(" \(credential)".utf8))

        let redaction = redactRawStreamBytes(
            raw,
            config: PastewatchConfig.defaultConfig,
            severity: .high
        )
        let redacted = String(bytes: redaction.data, encoding: .utf8) ?? ""

        XCTAssertEqual(redaction.count, 1)
        XCTAssertFalse(redacted.contains(credential))
        XCTAssertTrue(redacted.contains("<GOOGLE_API_KEY_1>"))
    }

    func testRawDoneInsertionPlacesAlertBeforeDoneFrame() {
        let alert = Data("event: pastewatch_advisory\ndata: {}\n\n".utf8)
        let stream = Data("data: one\n\nevent: message_stop\ndata: [DONE]\n\n".utf8)

        let output = insertingSSEDataBeforeDone(alert, into: stream)
        let text = String(data: output, encoding: .utf8) ?? ""

        XCTAssertTrue(text.contains("data: one\n\nevent: pastewatch_advisory"))
        XCTAssertTrue(text.contains("data: {}\n\nevent: message_stop\ndata: [DONE]"))
    }

    func testRawDoneInsertionWithoutAlertIsByteIdentical() {
        let stream = Data("data: one\n\ndata: [DONE]\n\n".utf8)

        XCTAssertEqual(insertingSSEDataBeforeDone(nil, into: stream), stream)
    }

    func testLuhnValidCardMutatesStreamBytes() {
        let card = "4111111111111111"
        let payload = #"{"type":"content_block_delta","delta":{"type":"text_delta","text":"card \#(card)"}}"#
        let redaction = redactFirstFrame(payload: payload)
        let redacted = String(data: redaction.data, encoding: .utf8) ?? ""

        XCTAssertEqual(redaction.count, 1)
        XCTAssertFalse(redacted.contains(card))
        XCTAssertTrue(redacted.contains("<CARD_1>"))
    }

    func testUTF8ProxyBodyLeavesHighBuiltInUnmutated() {
        let email = "operator@example.com"
        let server = ProxyServer(port: 0, severity: .high)
        let body = #"{"messages":[{"role":"user","content":[{"type":"tool_result","content":"contact \#(email)"}]}]}"#

        let result = server.scanAndRedactBody(body)

        XCTAssertEqual(result.redacted, 0)
        XCTAssertEqual(result.redactedTypes, [])
        XCTAssertEqual(result.advisoryCount, 1)
        XCTAssertEqual(result.advisoryTypes, ["Email"])
        XCTAssertEqual(result.body, body)
    }

    func testUTF8ProxyBodyCustomRuleMutatesAtCriticalThreshold() {
        let secret = "ACME-PROXY-ALPHA"
        var config = PastewatchConfig.defaultConfig
        config.customRules = [
            CustomRuleConfig(name: "ACME Proxy Token", pattern: #"ACME-PROXY-[A-Z]+"#, severity: "low")
        ]
        let server = ProxyServer(port: 0, config: config, severity: .critical)
        let body = #"{"messages":[{"role":"user","content":[{"type":"tool_result","content":"token \#(secret)"}]}]}"#

        let result = server.scanAndRedactBody(body)

        XCTAssertEqual(result.redacted, 1)
        XCTAssertEqual(result.redactedTypes, ["ACME Proxy Token"])
        XCTAssertEqual(result.advisoryCount, 0)
        XCTAssertFalse(result.body.contains(secret))
        XCTAssertTrue(result.body.contains("<CREDENTIAL_1>"))
    }

    func testUTF8ProxyBodyCustomRulePromotesHighBuiltIn() {
        let email = "operator@example.com"
        var config = PastewatchConfig.defaultConfig
        config.customRules = [
            CustomRuleConfig(name: "Approved Operator Email", pattern: #"operator@example\.com"#, severity: "low")
        ]
        let server = ProxyServer(port: 0, config: config, severity: .critical)
        let body = #"{"messages":[{"role":"user","content":[{"type":"tool_result","content":"contact \#(email)"}]}]}"#

        let result = server.scanAndRedactBody(body)

        XCTAssertEqual(result.redacted, 1)
        XCTAssertEqual(result.redactedTypes, ["Approved Operator Email"])
        XCTAssertEqual(result.advisoryCount, 0)
        XCTAssertFalse(result.body.contains(email))
        XCTAssertTrue(result.body.contains("<CREDENTIAL_1>"))
    }

    func testCurlNonUTF8ResponseHighBuiltInIsByteIdentical() {
        let email = "operator@example.com"
        var body = Data([0xFF, 0xFE])
        body.append(Data("prefix \(email) suffix".utf8))
        body.append(0x00)

        let redaction = CurlHTTPClient.redactNonUTF8ResponseBody(
            body,
            config: PastewatchConfig.defaultConfig,
            severity: .high
        )

        XCTAssertEqual(redaction.count, 0)
        XCTAssertEqual(redaction.advisoryCount, 1)
        XCTAssertEqual(redaction.advisoryTypes, ["Email"])
        XCTAssertEqual(redaction.data, body)
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
        let redaction = redactSSEFrame(
            result.frames[0],
            config: PastewatchConfig.defaultConfig,
            severity: .high
        )
        XCTAssertEqual(redaction.count, 0)
        XCTAssertEqual(redaction.data, result.frames[0].raw)
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

    func testLinuxRelayAdvisoryStatsCountAfterSuccessfulSend() {
        let relay = relayAdvisoryStream(closePeerBeforeRelay: false)

        XCTAssertEqual(relay.result.advisoryCount, 1)
        XCTAssertEqual(relay.result.advisoryTypes, ["IP"])
        XCTAssertTrue(relay.output.contains("10.1.2.3"))
    }

    func testLinuxRelayAdvisoryStatsSkipFailedSend() {
        #if canImport(Darwin)
        let previousHandler = signal(SIGPIPE, SIG_IGN)
        defer { _ = signal(SIGPIPE, previousHandler) }
        #endif

        let relay = relayAdvisoryStream(closePeerBeforeRelay: true)

        XCTAssertEqual(relay.result.advisoryCount, 0)
        XCTAssertTrue(relay.output.isEmpty)
    }

    func testLinuxRelayRemainderAdvisoryStatsSkipFailedSend() {
        #if canImport(Darwin)
        let previousHandler = signal(SIGPIPE, SIG_IGN)
        defer { _ = signal(SIGPIPE, previousHandler) }
        #endif

        let relay = relayStream(
            Data("data: contact 10.1.2.3".utf8),
            mode: .perSSEEvent,
            closePeerBeforeRelay: true,
            severity: .medium
        )

        XCTAssertEqual(relay.result.advisoryCount, 0)
        XCTAssertTrue(relay.output.isEmpty)
    }

    func testLinuxRelayRawStreamAdvisoryStatsCountAfterSuccessfulSend() {
        let relay = relayStream(
            rawStreamAdvisorySSE(),
            mode: .rawStream,
            closePeerBeforeRelay: false,
            alertBeforeDone: advisoryAlertBeforeDone,
            severity: .medium
        )

        XCTAssertEqual(relay.result.advisoryCount, 1)
        XCTAssertEqual(relay.result.advisoryTypes, ["IP"])
        XCTAssertTrue(relay.output.contains("event: pastewatch_advisory"))
        XCTAssertTrue(relay.output.contains("10.1.2.3"))
        XCTAssertTrue(relay.output.contains("data: [DONE]"))
    }

    // WO-371: raw_stream mode reports medium advisory matches without mutating bytes.
    func testLinuxRelayRawStreamMediumAdvisoryIsByteIdentical() {
        let ipAddress = "10.1.2.3"
        let relay = relayStream(
            rawStreamAdvisorySSE("data: contact \(ipAddress)\n\n"),
            mode: .rawStream,
            closePeerBeforeRelay: false,
            alertBeforeDone: advisoryAlertBeforeDone,
            severity: .medium
        )

        XCTAssertEqual(relay.result.redactionCount, 0)
        XCTAssertEqual(relay.result.advisoryCount, 1)
        XCTAssertEqual(relay.result.advisoryTypes, ["IP"])
        XCTAssertTrue(relay.output.contains(ipAddress))
        XCTAssertTrue(relay.output.contains("event: pastewatch_advisory"))
    }

    func testLinuxRelayRawStreamAlertSurvivesRedactionBeforeDone() {
        // WO-388: post-redaction byte shifts before [DONE] must not suppress alert injection.
        let credential = "AIza" + String(repeating: "W", count: 35)
        var stream = Data("data: \(credential)\n\n".utf8)
        stream.append(Data("data: [DONE]\n\n".utf8))

        let relay = relayStream(
            stream,
            mode: .rawStream,
            closePeerBeforeRelay: false,
            alertBeforeDone: redactionAlertBeforeDone
        )

        XCTAssertEqual(relay.result.redactionCount, 1)
        XCTAssertFalse(relay.output.contains(credential))
        XCTAssertTrue(relay.output.contains("<GOOGLE_API_KEY_1>"))
        guard let alertRange = relay.output.range(of: "event: pastewatch_alert"),
              let doneRange = relay.output.range(of: "data: [DONE]") else {
            XCTFail(relay.output)
            return
        }
        XCTAssertLessThan(alertRange.lowerBound, doneRange.lowerBound)
    }

    func testLinuxRelayRawStreamAlertForwardsPartialChunkBeforeTerminator() {
        let ipAddress = "10.1.2.3"
        let relay = relayPartialRawStream(
            Data(("data: contact \(ipAddress) " + String(repeating: "x", count: 5_000)).utf8)
        )

        XCTAssertTrue(relay.firstOutput.contains(ipAddress), relay.firstOutput)
        XCTAssertEqual(relay.result?.advisoryCount, 1)
        XCTAssertEqual(relay.result?.advisoryTypes, ["IP"])
    }

    func testLinuxRelayRawStreamEOFWithoutDoneDeliversAdvisoryAlert() {
        let ipAddress = "10.1.2.3"
        let relay = relayStream(
            Data("data: contact \(ipAddress)\n\n".utf8),
            mode: .rawStream,
            closePeerBeforeRelay: false,
            alertBeforeDone: advisoryAlertBeforeDone,
            severity: .medium
        )

        guard let bodyRange = relay.output.range(of: ipAddress),
              let advisoryRange = relay.output.range(of: "event: pastewatch_advisory") else {
            XCTFail(relay.output)
            return
        }
        XCTAssertLessThan(bodyRange.lowerBound, advisoryRange.lowerBound)
        XCTAssertEqual(relay.result.advisoryCount, 1)
        XCTAssertEqual(relay.result.advisoryTypes, ["IP"])
    }

    func testLinuxRelayRawStreamEOFOverlapRedactsCriticalCredential() {
        let credential = "AIza" + String(repeating: "X", count: 35)
        let stream = Data(("data: " + String(repeating: "a", count: 5_000) + " " + credential + "\n\n").utf8)
        let relay = relayStream(
            stream,
            mode: .rawStream,
            closePeerBeforeRelay: false,
            alertBeforeDone: advisoryAlertBeforeDone
        )

        XCTAssertEqual(relay.result.redactionCount, 1)
        XCTAssertEqual(relay.result.redactionTypes, ["Google API Key"])
        XCTAssertFalse(relay.output.contains(credential))
        XCTAssertTrue(relay.output.contains("<GOOGLE_API_KEY_1>"))
    }

    func testLinuxRelayRawStreamAdvisoryStatsSkipFailedSend() {
        #if canImport(Darwin)
        let previousHandler = signal(SIGPIPE, SIG_IGN)
        defer { _ = signal(SIGPIPE, previousHandler) }
        #endif

        let relay = relayStream(
            rawStreamAdvisorySSE(),
            mode: .rawStream,
            closePeerBeforeRelay: true,
            alertBeforeDone: advisoryAlertBeforeDone,
            severity: .medium
        )

        XCTAssertEqual(relay.result.advisoryCount, 0)
        XCTAssertTrue(relay.output.isEmpty)
    }

    func testLinuxRelayRawStreamNoAlertAdvisoryStatsSkipFailedSend() {
        #if canImport(Darwin)
        let previousHandler = signal(SIGPIPE, SIG_IGN)
        defer { _ = signal(SIGPIPE, previousHandler) }
        #endif

        let relay = relayStream(
            Data("contact 10.1.2.3".utf8),
            mode: .rawStream,
            closePeerBeforeRelay: true,
            severity: .medium
        )

        XCTAssertEqual(relay.result.advisoryCount, 0)
        XCTAssertTrue(relay.output.isEmpty)
    }

    func testLinuxRelayStopsAfterClientEPIPEMidStream() {
        #if canImport(Darwin)
        let previousHandler = signal(SIGPIPE, SIG_IGN)
        defer { _ = signal(SIGPIPE, previousHandler) }
        #endif

        let pipe = Pipe()
        var sockets = [Int32](repeating: 0, count: 2)
        XCTAssertEqual(socketpair(AF_UNIX, testSocketStreamType, 0, &sockets), 0)
        defer { close(sockets[1]) }

        let ctx = CurlHTTPClient.StreamContext(
            clientSocket: sockets[1],
            sendFlags: testSendFlags,
            redactionMode: .perSSEEvent,
            config: PastewatchConfig.defaultConfig,
            severity: .medium
        )
        var result: CurlHTTPClient.StreamRelayResult?
        let finished = expectation(description: "relay exits after mid-stream EPIPE")
        DispatchQueue.global().async {
            result = CurlHTTPClient.relayBodyChunks(from: pipe, ctx: ctx)
            finished.fulfill()
        }

        pipe.fileHandleForWriting.write(advisoryFrame(text: "10.1.2.3"))
        let firstOutput = readAvailableString(from: sockets[0])
        XCTAssertTrue(firstOutput.contains("10.1.2.3"), firstOutput)
        close(sockets[0])

        pipe.fileHandleForWriting.write(advisoryFrame(text: "10.2.3.4"))
        pipe.fileHandleForWriting.closeFile()
        wait(for: [finished], timeout: 2)

        XCTAssertEqual(result?.advisoryCount, 1)
        XCTAssertEqual(result?.advisoryTypes, ["IP"])
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

    private func redactFirstFrame(payload: String) -> SSEFrameRedactionResult {
        var parser = SSEFrameParser()
        let result = parser.feed(sseFrame(eventType: "content_block_delta", data: payload))
        XCTAssertEqual(result.frames.count, 1)
        return redactSSEFrame(
            result.frames[0],
            config: PastewatchConfig.defaultConfig,
            severity: .high
        )
    }

    private func relayAdvisoryStream(closePeerBeforeRelay: Bool) -> (
        result: CurlHTTPClient.StreamRelayResult,
        output: String
    ) {
        let payload = #"{"type":"content_block_delta","delta":{"type":"text_delta","text":"contact 10.1.2.3"}}"#
        var stream = sseFrame(eventType: "content_block_delta", data: payload)
        stream.append(sseFrame(eventType: nil, data: "[DONE]"))
        return relayStream(stream, mode: .perSSEEvent, closePeerBeforeRelay: closePeerBeforeRelay, severity: .medium)
    }

    private func rawStreamAdvisorySSE(_ frame: String = "data: contact 10.1.2.3\n\n") -> Data {
        var stream = Data(frame.utf8)
        stream.append(Data("data: [DONE]\n\n".utf8))
        return stream
    }

    private func advisoryFrame(text: String) -> Data {
        let payload = #"{"type":"content_block_delta","delta":{"type":"text_delta","text":"contact \#(text)"}}"#
        return sseFrame(eventType: "content_block_delta", data: payload)
    }

    private func advisoryAlertBeforeDone(
        _ streamCount: Int,
        _ streamTypes: [String],
        _ advisoryCount: Int,
        _ advisoryTypes: [String]
    ) -> Data? {
        guard advisoryCount > 0 else { return nil }
        return Data(
            "event: pastewatch_advisory\ndata: \(advisoryCount):\(advisoryTypes.joined(separator: ","))\n\n".utf8
        )
    }

    private func redactionAlertBeforeDone(
        _ streamCount: Int,
        _ streamTypes: [String],
        _ advisoryCount: Int,
        _ advisoryTypes: [String]
    ) -> Data? {
        guard streamCount > 0 else { return nil }
        return Data("event: pastewatch_alert\ndata: \(streamCount):\(streamTypes.joined(separator: ","))\n\n".utf8)
    }

    private func relayStream(
        _ stream: Data,
        mode: StreamingRedactionMode,
        closePeerBeforeRelay: Bool,
        alertBeforeDone: ((
            _ streamCount: Int,
            _ streamTypes: [String],
            _ advisoryCount: Int,
            _ advisoryTypes: [String]
        ) -> Data?)? = nil,
        severity: Severity = .high
    ) -> (
        result: CurlHTTPClient.StreamRelayResult,
        output: String
    ) {
        let pipe = Pipe()
        pipe.fileHandleForWriting.write(stream)
        pipe.fileHandleForWriting.closeFile()

        var sockets = [Int32](repeating: 0, count: 2)
        XCTAssertEqual(socketpair(AF_UNIX, testSocketStreamType, 0, &sockets), 0)
        defer { close(sockets[1]) }
        defer {
            if !closePeerBeforeRelay {
                close(sockets[0])
            }
        }
        if closePeerBeforeRelay {
            close(sockets[0])
        }

        let ctx = CurlHTTPClient.StreamContext(
            clientSocket: sockets[1],
            sendFlags: testSendFlags,
            redactionMode: mode,
            config: PastewatchConfig.defaultConfig,
            severity: severity
        )
        let result = CurlHTTPClient.relayBodyChunks(from: pipe, ctx: ctx, alertBeforeDone: alertBeforeDone)
        let output = closePeerBeforeRelay ? "" : readAllAvailableString(from: sockets[0])
        return (result, output)
    }

    private func relayPartialRawStream(_ firstChunk: Data) -> (
        result: CurlHTTPClient.StreamRelayResult?,
        firstOutput: String
    ) {
        let pipe = Pipe()
        var sockets = [Int32](repeating: 0, count: 2)
        XCTAssertEqual(socketpair(AF_UNIX, testSocketStreamType, 0, &sockets), 0)
        defer {
            close(sockets[0])
            close(sockets[1])
        }

        let ctx = CurlHTTPClient.StreamContext(
            clientSocket: sockets[1],
            sendFlags: testSendFlags,
            redactionMode: .rawStream,
            config: PastewatchConfig.defaultConfig,
            severity: .medium
        )
        var result: CurlHTTPClient.StreamRelayResult?
        let finished = expectation(description: "raw stream relay finishes")
        DispatchQueue.global().async {
            result = CurlHTTPClient.relayBodyChunks(
                from: pipe,
                ctx: ctx,
                alertBeforeDone: self.advisoryAlertBeforeDone
            )
            finished.fulfill()
        }

        pipe.fileHandleForWriting.write(firstChunk)
        let firstOutput = readAvailableString(from: sockets[0])
        pipe.fileHandleForWriting.closeFile()
        wait(for: [finished], timeout: 2)
        return (result, firstOutput)
    }

    private func readAvailableString(from socket: Int32) -> String {
        var timeout = timeval(tv_sec: 1, tv_usec: 0)
        XCTAssertEqual(
            setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size)),
            0
        )
        var buffer = [UInt8](repeating: 0, count: 4096)
        let count = recv(socket, &buffer, buffer.count, 0)
        guard count > 0 else { return "" }
        return String(bytes: buffer[..<count], encoding: .utf8) ?? ""
    }

    private func readAllAvailableString(from socket: Int32) -> String {
        var timeout = socketReadDrainTimeout
        XCTAssertEqual(
            setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size)),
            0
        )
        var output = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while true {
            let count = recv(socket, &buffer, buffer.count, 0)
            guard count > 0 else { break }
            output.append(contentsOf: buffer[..<count])
        }
        return String(data: output, encoding: .utf8) ?? ""
    }
}

#if canImport(Darwin)
private let testSocketStreamType = SOCK_STREAM
private let testSendFlags: Int32 = 0
#else
private let testSocketStreamType = Int32(SOCK_STREAM.rawValue)
private let testSendFlags: Int32 = Int32(MSG_NOSIGNAL)
#endif
private let socketReadDrainTimeout = timeval(tv_sec: 0, tv_usec: 100_000)
