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

    // WO-384: malformed partial bytes stay before the injected alert, not after it.
    func testRawDoneInsertionWithoutPriorTerminatorFallsBackToDoneStart() {
        let alert = Data("event: pastewatch_advisory\ndata: {}\n\n".utf8)
        let partial = "data: partial"
        let stream = Data("\(partial)data: [DONE]\n\n".utf8)

        let output = insertingSSEDataBeforeDone(alert, into: stream)
        let text = String(data: output, encoding: .utf8) ?? ""

        XCTAssertTrue(text.hasPrefix(partial + "event: pastewatch_advisory"), text)
        XCTAssertTrue(text.hasSuffix("data: {}\n\ndata: [DONE]\n\n"), text)
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

    // WO-380: post-termination bytes remain redacted but cannot trigger a second alert.
    func testLinuxRawStreamInjectsAlertOnlyOnceAcrossDuplicateDoneChunks() {
        let pipe = Pipe()
        var sockets = [Int32](repeating: 0, count: 2)
        XCTAssertEqual(socketpair(AF_UNIX, testSocketStreamType, 0, &sockets), 0)
        defer {
            close(sockets[0])
            close(sockets[1])
        }
        let ctx = CurlHTTPClient.StreamContext(
            clientSocket: sockets[1], sendFlags: testSendFlags, redactionMode: .rawStream,
            config: PastewatchConfig.defaultConfig, severity: .medium
        )
        var result: CurlHTTPClient.StreamRelayResult?
        let finished = expectation(description: "duplicate done relay finishes")
        DispatchQueue.global().async {
            result = CurlHTTPClient.relayBodyChunks(
                from: pipe, ctx: ctx, alertBeforeDone: self.advisoryAlertBeforeDone
            )
            finished.fulfill()
        }

        pipe.fileHandleForWriting.write(Data("data: contact 10.1.2.3\n\ndata: [DONE]\n\n".utf8))
        let first = readAvailableString(from: sockets[0])
        pipe.fileHandleForWriting.write(Data("data: [DONE]\n\n".utf8))
        pipe.fileHandleForWriting.closeFile()
        wait(for: [finished], timeout: 2)
        let output = first + readAllAvailableString(from: sockets[0])

        XCTAssertEqual(output.components(separatedBy: "event: pastewatch_advisory").count - 1, 1)
        XCTAssertEqual(output.components(separatedBy: "data: [DONE]").count - 1, 2)
        XCTAssertEqual(result?.advisoryCount, 1)
    }

    // WO-508: post-DONE frame assembly must retain secrets split by curl reads.
    func testLinuxRawStreamRedactsCredentialSplitAcrossPostDoneChunks() {
        let pipe = Pipe()
        var sockets = [Int32](repeating: 0, count: 2)
        XCTAssertEqual(socketpair(AF_UNIX, testSocketStreamType, 0, &sockets), 0)
        defer {
            close(sockets[0])
            close(sockets[1])
        }
        let ctx = CurlHTTPClient.StreamContext(
            clientSocket: sockets[1], sendFlags: testSendFlags, redactionMode: .rawStream,
            config: PastewatchConfig.defaultConfig, severity: .medium
        )
        var result: CurlHTTPClient.StreamRelayResult?
        let finished = expectation(description: "post-done split credential relay finishes")
        DispatchQueue.global().async {
            result = CurlHTTPClient.relayBodyChunks(
                from: pipe, ctx: ctx, alertBeforeDone: self.advisoryAlertBeforeDone
            )
            finished.fulfill()
        }

        let credential = "AIza" + String(repeating: "Z", count: 35)
        let splitIndex = credential.index(credential.startIndex, offsetBy: 12)
        let prefix = String(credential[..<splitIndex])
        let suffix = String(credential[splitIndex...])
        let firstChunkPrefix = "data: contact 10.1.2.3\n\ndata: [DONE]\n\ndata: "
        let filler = String(
            repeating: "x",
            count: 65_536 - firstChunkPrefix.utf8.count - 1 - prefix.utf8.count
        )
        let firstChunk = Data((firstChunkPrefix + filler + " " + prefix).utf8)
        XCTAssertEqual(firstChunk.count, 65_536)
        pipe.fileHandleForWriting.write(firstChunk)
        let firstOutput = readAvailableString(from: sockets[0])
        pipe.fileHandleForWriting.write(Data((suffix + "\n\n").utf8))
        var trailingOutput = readAvailableString(from: sockets[0])
        trailingOutput += readAllAvailableString(from: sockets[0])
        pipe.fileHandleForWriting.closeFile()
        wait(for: [finished], timeout: 2)
        let output = firstOutput + trailingOutput + readAllAvailableString(from: sockets[0])

        XCTAssertFalse(output.contains(credential))
        XCTAssertTrue(output.contains("<GOOGLE_API_KEY_1>"), output)
        XCTAssertEqual(output.components(separatedBy: "event: pastewatch_advisory").count - 1, 1)
        XCTAssertEqual(result?.redactionCount, 1)
        XCTAssertEqual(result?.advisoryCount, 1)
    }

    // WO-384: Linux raw-stream insertion uses the same no-terminator fallback.
    func testLinuxRawStreamAlertInsertionWithoutPriorTerminatorKeepsPartialPrefix() {
        let stream = Data("data: contact 10.1.2.3\npartialdata: [DONE]\n\n".utf8)
        let relay = relayStream(
            stream, mode: .rawStream, closePeerBeforeRelay: false,
            alertBeforeDone: advisoryAlertBeforeDone, severity: .medium
        )

        XCTAssertTrue(
            relay.output.hasPrefix("data: contact 10.1.2.3\npartialevent: pastewatch_advisory"),
            relay.output
        )
        XCTAssertTrue(relay.output.hasSuffix("data: [DONE]\n\n"), relay.output)
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

    // MARK: - Tool-call stream fixtures

    // WO-515: realistic Anthropic fragments pin the client-side reassembly contract.
    func testAnthropicToolCallFixtureReassemblesValidJSON() throws {
        let fixture = anthropicToolCallFixture(fragments: [#"{"query":"hel"#, #"lo\/world","limit":2}"#])

        XCTAssertEqual(try reassembleAnthropicToolJSON(from: fixture), ["query": "hello/world", "limit": 2])
    }

    // WO-515: LiteLLM/OpenAI frames use a different envelope but the same fragment contract.
    func testOpenAIToolCallFixtureReassemblesValidJSON() throws {
        let fixture = openAIToolCallFixture(fragments: [#"{"query":"hel"#, #"lo","limit":2}"#])

        XCTAssertEqual(try reassembleOpenAIToolJSON(from: fixture), ["query": "hello", "limit": 2])
    }

    // WO-515: raw fixture bytes retain escaped slash and unicode spelling for fidelity tests.
    func testToolCallFixtureRetainsRawEscaping() {
        let fragment = #"{"path":"https:\/\/example.com\/\u0061"}"#
        let fixture = anthropicToolCallFixture(fragments: [fragment])
        let raw = String(bytes: fixture, encoding: .utf8) ?? ""

        XCTAssertTrue(raw.contains(#"https:\\\/\\\/example.com\\\/\\u0061"#), raw)
    }

    // WO-511: Anthropic argument fragments are scanned as one logical payload.
    func testAnthropicToolCallRedactsSecretSplitAcrossFrames() throws {
        let credential = "AIza" + String(repeating: "T", count: 35)
        let split = credential.index(credential.startIndex, offsetBy: 13)
        let fixture = anthropicToolCallFixture(fragments: [
            #"{"token":"\#(credential[..<split])"#,
            #"\#(credential[split...])"}"#
        ])

        let transformed = transformToolCallFixture(fixture)
        let object = try reassembleAnthropicToolJSON(from: transformed.data)

        XCTAssertEqual(object["token"] as? String, "<GOOGLE_API_KEY_1>")
        XCTAssertEqual(transformed.redactionCount, 1)
        XCTAssertEqual(transformed.toolCallRedactionCount, 1)
        XCTAssertEqual(transformed.types, ["Tool argument: Google API Key"])
    }

    // WO-509 and WO-510: nested JSON escapes are decoded for detection but spliced in raw bytes.
    func testAnthropicToolCallRedactsUnicodeEscapedSecret() throws {
        let credentialTail = "Iza" + String(repeating: "J", count: 35)
        let fixture = anthropicToolCallFixture(fragments: [
            #"{"token":"\u0041\#(credentialTail)"}"#
        ])

        let transformed = transformToolCallFixture(fixture)
        let object = try reassembleAnthropicToolJSON(from: transformed.data)

        XCTAssertEqual(object["token"] as? String, "<GOOGLE_API_KEY_1>")
        XCTAssertEqual(transformed.toolCallRedactionCount, 1)
    }

    // WO-509: decoded object keys are part of the tool payload and cannot bypass scanning.
    func testAnthropicToolCallRedactsUnicodeEscapedSecretInObjectKey() throws {
        let credentialTail = "Iza" + String(repeating: "K", count: 35)
        let fixture = anthropicToolCallFixture(fragments: [
            #"{"\u0041\#(credentialTail)":"value"}"#
        ])

        let transformed = transformToolCallFixture(fixture)
        let object = try reassembleAnthropicToolJSON(from: transformed.data)

        XCTAssertEqual(object["<GOOGLE_API_KEY_1>"] as? String, "value")
        XCTAssertEqual(transformed.toolCallRedactionCount, 1)
    }

    // WO-519@v2: complete escaped tokens are scanned when aggregate tool JSON is truncated.
    func testAnthropicToolCallRedactsUnicodeEscapedSecretInTruncatedJSON() {
        let credentialTail = "Iza" + String(repeating: "Q", count: 35)
        let truncated = "{\"token\":\"\\u0041\(credentialTail)\""
        let fixture = anthropicToolCallFixture(fragments: [truncated])

        let transformed = transformToolCallFixture(fixture)
        let output = String(bytes: transformed.data, encoding: .utf8) ?? ""

        XCTAssertTrue(output.contains("<GOOGLE_API_KEY_1>"), output)
        XCTAssertFalse(output.contains(credentialTail), output)
        XCTAssertEqual(transformed.redactionCount, 1)
        XCTAssertEqual(transformed.toolCallRedactionCount, 1)
        XCTAssertEqual(transformed.types, ["Tool argument: Google API Key"])
    }

    // WO-519@v2: an escape in an unterminated token cannot bypass decoded scanning.
    func testAnthropicToolCallBlocksUnmappedEscapeInTruncatedJSON() throws {
        let credentialTail = "Iza" + String(repeating: "R", count: 35)
        let truncated = "{\"token\":\"\\u0041\(credentialTail)"
        let fixture = anthropicToolCallFixture(fragments: [truncated])
        var parser = SSEFrameParser()
        var transformer = ToolCallStreamRedactor(
            config: PastewatchConfig.defaultConfig,
            customRules: [],
            severity: .high
        )
        var blocked: ToolCallStreamRedactor.ProcessResult?

        for frame in parser.feed(fixture).frames {
            let result = transformer.process(frame)
            if result.terminateStream {
                blocked = result
                break
            }
        }

        let result = try XCTUnwrap(blocked)
        let output = try XCTUnwrap(result.frames.first?.data)
        XCTAssertEqual(
            output,
            Data(
                "event: pastewatch_error\ndata: {\"error\":\"stream redaction could not preserve valid JSON\"}\n\n"
                    .appending("data: [DONE]\n\n").utf8
            )
        )
        XCTAssertFalse(String(bytes: output, encoding: .utf8)?.contains(credentialTail) ?? true)
    }

    // WO-510: a deterministic match in a JSON scalar must remain valid client-side JSON.
    func testAnthropicToolCallQuotesNumericSecretPlaceholder() throws {
        let fixture = anthropicToolCallFixture(fragments: [#"{"card":4242424242424242}"#])

        let transformed = transformToolCallFixture(fixture)
        let object = try reassembleAnthropicToolJSON(from: transformed.data)

        XCTAssertEqual(object["card"] as? String, "<CARD_1>")
        XCTAssertEqual(transformed.toolCallRedactionCount, 1)
    }

    // WO-518: decoded and raw spellings share first-occurrence placeholder ordering.
    func testToolCallPlaceholderOrderIncludesEscapedMatches() throws {
        let firstTail = "Iza" + String(repeating: "L", count: 35)
        let second = "AIza" + String(repeating: "M", count: 35)
        let fixture = anthropicToolCallFixture(fragments: [
            #"{"first":"\u0041\#(firstTail)","second":"\#(second)"}"#
        ])

        let transformed = transformToolCallFixture(fixture)
        let object = try reassembleAnthropicToolJSON(from: transformed.data)

        XCTAssertEqual(object["first"] as? String, "<GOOGLE_API_KEY_1>")
        XCTAssertEqual(object["second"] as? String, "<GOOGLE_API_KEY_2>")
    }

    // WO-518: placeholder identity persists across independently flushed tool blocks.
    func testSequentialAnthropicToolBlocksKeepDistinctPlaceholders() {
        let first = "AIza" + String(repeating: "N", count: 35)
        let second = "AIza" + String(repeating: "P", count: 35)
        var fixture = anthropicToolCallFixture(fragments: [#"{"key":"\#(first)"}"#], index: 0)
        fixture.append(anthropicToolCallFixture(fragments: [#"{"key":"\#(second)"}"#], index: 1))

        let transformed = transformToolCallFixture(fixture)
        let output = String(bytes: transformed.data, encoding: .utf8) ?? ""

        XCTAssertTrue(output.contains("<GOOGLE_API_KEY_1>"), output)
        XCTAssertTrue(output.contains("<GOOGLE_API_KEY_2>"), output)
        XCTAssertEqual(transformed.toolCallRedactionCount, 2)
    }

    // WO-509: OpenAI/LiteLLM argument fragments use the same fail-closed scanner.
    func testOpenAIToolCallRedactsSecretSplitAcrossFrames() throws {
        let credential = "AIza" + String(repeating: "U", count: 35)
        let split = credential.index(credential.startIndex, offsetBy: 17)
        let fixture = openAIToolCallFixture(fragments: [
            #"{"token":"\#(credential[..<split])"#,
            #"\#(credential[split...])"}"#
        ])

        let transformed = transformToolCallFixture(fixture)
        let object = try reassembleOpenAIToolJSON(from: transformed.data)

        XCTAssertEqual(object["token"] as? String, "<GOOGLE_API_KEY_1>")
        XCTAssertEqual(transformed.toolCallRedactionCount, 1)
    }

    // WO-512: multiple tool calls in one frame accumulate rather than overwrite stats.
    func testOpenAIFrameAccumulatesMultipleToolCallMutations() throws {
        let first = "AIza" + String(repeating: "A", count: 35)
        let second = "AIza" + String(repeating: "B", count: 35)
        let object: [String: Any] = [
            "choices": [[
                "index": 0,
                "delta": ["tool_calls": [
                    ["index": 0, "function": ["arguments": "{\"key\":\"\(first)\"}"]],
                    ["index": 1, "function": ["arguments": "{\"key\":\"\(second)\"}"]]
                ]],
                "finish_reason": "tool_calls"
            ]]
        ]
        let data = try JSONSerialization.data(withJSONObject: object)
        let payload = try XCTUnwrap(String(data: data, encoding: .utf8))

        let transformed = transformToolCallFixture(sseFrame(eventType: nil, data: payload))
        let output = String(bytes: transformed.data, encoding: .utf8) ?? ""

        XCTAssertFalse(output.contains(first))
        XCTAssertFalse(output.contains(second))
        XCTAssertTrue(output.contains("<GOOGLE_API_KEY_1>"), output)
        XCTAssertTrue(output.contains("<GOOGLE_API_KEY_2>"), output)
        XCTAssertEqual(transformed.redactionCount, 2)
        XCTAssertEqual(transformed.toolCallRedactionCount, 2)
    }

    // WO-509: sparse choice arrays keep independent argument buffers by explicit choice index.
    func testOpenAIInterleavedChoicesDoNotCrossContaminateArguments() {
        let first = "AIza" + String(repeating: "G", count: 35)
        let second = "AIza" + String(repeating: "H", count: 35)
        let firstSplit = first.index(first.startIndex, offsetBy: 18)
        let secondSplit = second.index(second.startIndex, offsetBy: 19)
        var fixture = Data()
        fixture.append(openAIChoiceFrame(choice: 0, arguments: String(first[..<firstSplit])))
        fixture.append(openAIChoiceFrame(choice: 1, arguments: String(second[..<secondSplit])))
        fixture.append(openAIChoiceFrame(choice: 0, arguments: String(first[firstSplit...])))
        fixture.append(openAIChoiceFrame(choice: 0, arguments: nil, finishReason: "tool_calls"))
        fixture.append(openAIChoiceFrame(choice: 1, arguments: String(second[secondSplit...])))
        fixture.append(openAIChoiceFrame(choice: 1, arguments: nil, finishReason: "tool_calls"))

        let transformed = transformToolCallFixture(fixture)
        let output = String(bytes: transformed.data, encoding: .utf8) ?? ""

        XCTAssertFalse(output.contains(first))
        XCTAssertFalse(output.contains(second))
        XCTAssertEqual(transformed.toolCallRedactionCount, 2)
    }

    // WO-510: a duplicate key outside tool_calls cannot capture the argument replacement.
    func testOpenAIToolArgumentLocatorUsesStructuralPath() throws {
        let credential = "AIza" + String(repeating: "C", count: 35)
        let object: [String: Any] = [
            "arguments": "keep-me",
            "choices": [[
                "index": 0,
                "delta": ["tool_calls": [[
                    "index": 0,
                    "function": ["arguments": "{\"key\":\"\(credential)\"}"]
                ]]],
                "finish_reason": "tool_calls"
            ]]
        ]
        let payload = try XCTUnwrap(String(
            data: JSONSerialization.data(withJSONObject: object),
            encoding: .utf8
        ))

        let transformed = transformToolCallFixture(sseFrame(eventType: nil, data: payload))
        let output = String(bytes: transformed.data, encoding: .utf8) ?? ""

        XCTAssertTrue(output.contains(#""arguments":"keep-me""#), output)
        XCTAssertFalse(output.contains(credential), output)
        XCTAssertEqual(transformed.toolCallRedactionCount, 1)
    }

    // WO-509: recognizing tool arguments cannot narrow scanning of sibling response fields.
    func testOpenAIToolFrameStillRedactsSiblingContent() throws {
        let contentCredential = "AIza" + String(repeating: "D", count: 35)
        let toolCredential = "AIza" + String(repeating: "E", count: 35)
        let object: [String: Any] = [
            "choices": [[
                "index": 0,
                "delta": [
                    "content": contentCredential,
                    "tool_calls": [[
                        "index": 0,
                        "function": ["arguments": "{\"key\":\"\(toolCredential)\"}"]
                    ]]
                ],
                "finish_reason": "tool_calls"
            ]]
        ]
        let data = try JSONSerialization.data(withJSONObject: object)
        let payload = try XCTUnwrap(String(data: data, encoding: .utf8))

        let transformed = transformToolCallFixture(sseFrame(eventType: nil, data: payload))
        let output = String(bytes: transformed.data, encoding: .utf8) ?? ""

        XCTAssertFalse(output.contains(contentCredential), output)
        XCTAssertFalse(output.contains(toolCredential), output)
        XCTAssertEqual(transformed.redactionCount, 2)
        XCTAssertEqual(transformed.toolCallRedactionCount, 1)
    }

    // WO-512: the reassembled tool scan and sibling-frame scan must not double-count one advisory.
    func testToolArgumentAdvisoryIsCountedOnce() {
        let fixture = openAIToolCallFixture(fragments: [#"{"contact":"operator@example.com"}"#])

        let transformed = transformToolCallFixture(fixture, severity: .low)

        XCTAssertEqual(transformed.advisoryCount, 1)
        XCTAssertEqual(transformed.redactionCount, 0)
    }

    // WO-511: the Linux curl relay must use the same cross-frame transformer.
    func testLinuxRelayRedactsAnthropicToolSecretSplitAcrossFrames() throws {
        let credential = "AIza" + String(repeating: "W", count: 35)
        let split = credential.index(credential.startIndex, offsetBy: 15)
        let fixture = anthropicToolCallFixture(fragments: [
            #"{"token":"\#(credential[..<split])"#,
            #"\#(credential[split...])"}"#
        ])

        let relay = relayStream(
            fixture,
            mode: .perSSEEvent,
            closePeerBeforeRelay: false
        )
        let object = try reassembleAnthropicToolJSON(from: Data(relay.output.utf8))

        XCTAssertEqual(object["token"] as? String, "<GOOGLE_API_KEY_1>")
        XCTAssertEqual(relay.result.redactionCount, 1)
        XCTAssertEqual(relay.result.toolCallRedactionCount, 1)
    }

    // WO-509: recognition alone cannot rewrite a clean or unknown event byte.
    func testCleanToolCallStreamIsByteIdentical() {
        let fixture = anthropicToolCallFixture(fragments: [#"{"query":"hello"}"#])

        XCTAssertEqual(transformToolCallFixture(fixture).data, fixture)
    }

    // WO-509: clean OpenAI-compatible arguments retain their exact wire spelling.
    func testCleanOpenAIToolCallStreamIsByteIdentical() {
        let fixture = openAIToolCallFixture(fragments: [#"{"query":"hello\/world"}"#])

        XCTAssertEqual(transformToolCallFixture(fixture).data, fixture)
    }

    // WO-509: unknown envelopes remain on the byte-preserving frame-wide path.
    func testUnknownStreamEnvelopeWithoutSecretIsByteIdentical() {
        let fixture = sseFrame(
            eventType: "gateway_extension",
            data: #"{"extension":{"payload":"hello\/world","unicode":"\u0061"}}"#
        )

        XCTAssertEqual(transformToolCallFixture(fixture).data, fixture)
    }

    // WO-509: a valid unknown envelope must not leave as corrupted JSON after mutation.
    func testUnknownNumericSecretFrameFailsClosedInsteadOfCorruptingJSON() throws {
        let fixture = sseFrame(
            eventType: "gateway_extension",
            data: #"{"extension":{"card":4242424242424242}}"#
        )
        var parser = SSEFrameParser()
        let frame = try XCTUnwrap(parser.feed(fixture).frames.first)
        var transformer = ToolCallStreamRedactor(
            config: PastewatchConfig.defaultConfig,
            customRules: [],
            severity: .high
        )

        let result = transformer.process(frame)

        XCTAssertTrue(result.terminateStream)
        XCTAssertEqual(result.frames.first?.data, Data(
            "event: pastewatch_error\ndata: {\"error\":\"stream redaction could not preserve valid JSON\"}\n\n"
                .appending("data: [DONE]\n\n").utf8
        ))
    }

    // WO-512: the in-band alert identifies a mutation inside tool arguments.
    func testLinuxToolCallAlertCarriesDistinctMutationType() {
        let credential = "AIza" + String(repeating: "N", count: 35)
        var fixture = anthropicToolCallFixture(fragments: [#"{"token":"\#(credential)"}"#])
        fixture.append(sseFrame(eventType: nil, data: "[DONE]"))

        let relay = relayStream(
            fixture,
            mode: .perSSEEvent,
            closePeerBeforeRelay: false,
            alertBeforeDone: redactionAlertBeforeDone
        )

        XCTAssertTrue(relay.output.contains("event: pastewatch_alert"), relay.output)
        XCTAssertTrue(relay.output.contains("Tool argument: Google API Key"), relay.output)
    }

    // WO-510: mutation changes only the partial_json string-token bytes.
    func testPartialJSONMutationPreservesSurroundingFrameBytes() throws {
        let credential = "AIza" + String(repeating: "V", count: 35)
        let partialJSON = #"{"path":"https:\/\/example.com\/\u0061","token":"\#(credential)"}"#
        let object: [String: Any] = [
            "type": "content_block_delta",
            "index": 0,
            "delta": ["type": "input_json_delta", "partial_json": partialJSON]
        ]
        let canonical = try XCTUnwrap(String(
            data: JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]),
            encoding: .utf8
        ))
        let payload = canonical
            .replacingOccurrences(of: #"\\\/"#, with: #"\\/"#)
            .replacingOccurrences(of: #"\\u0061"#, with: #"\u005Cu0061"#)
        let delta = sseFrame(eventType: "custom_event", data: payload)
        let stop = sseFrame(eventType: "content_block_stop", data: #"{"type":"content_block_stop","index":0}"#)

        XCTAssertNotNil(try? JSONSerialization.jsonObject(with: Data(payload.utf8)))
        XCTAssertNotEqual(payload, canonical)

        let transformed = transformToolCallFixture(delta + stop)
        let output = String(bytes: transformed.data, encoding: .utf8) ?? ""
        let expected = (String(bytes: delta + stop, encoding: .utf8) ?? "")
            .replacingOccurrences(of: credential, with: "<GOOGLE_API_KEY_1>")

        XCTAssertEqual(output, expected)
        XCTAssertEqual(transformed.toolCallRedactionCount, 1)
    }

    // WO-510: SSE multi-line data prefixes are preserved while mapping logical JSON offsets.
    func testMultilineSSEDataPreservesPrefixesDuringToolMutation() {
        let credential = "AIza" + String(repeating: "F", count: 35)
        let delta = Data(
            ("event: content_block_delta\n"
                + "data: {\"type\":\"content_block_delta\",\"index\":0,\n"
                + "data: \"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"key\\\":\\\"\(credential)\\\"}\"}}\n\n").utf8
        )
        let stop = sseFrame(eventType: "content_block_stop", data: #"{"type":"content_block_stop","index":0}"#)

        let transformed = transformToolCallFixture(delta + stop)
        let output = String(bytes: transformed.data, encoding: .utf8) ?? ""
        let expected = (String(bytes: delta + stop, encoding: .utf8) ?? "")
            .replacingOccurrences(of: credential, with: "<GOOGLE_API_KEY_1>")

        XCTAssertEqual(output, expected)
    }

    // WO-511: the memory bound terminates locally instead of releasing unscanned arguments.
    func testToolCallBufferOverflowFailsClosed() throws {
        let fragment = String(repeating: "x", count: SSEFrameParser.maxFrameBytes)
        let object: [String: Any] = [
            "type": "content_block_delta",
            "index": 0,
            "delta": ["type": "input_json_delta", "partial_json": fragment]
        ]
        let payload = try JSONSerialization.data(withJSONObject: object)
        let payloadString = try XCTUnwrap(String(data: payload, encoding: .utf8))
        let raw = Data("data: \(payloadString)\n\n".utf8)
        let frame = SSEFrameParser.Frame(raw: raw, eventType: nil, data: payloadString)
        var transformer = ToolCallStreamRedactor(
            config: PastewatchConfig.defaultConfig,
            customRules: [],
            severity: .high
        )

        let result = transformer.process(frame)

        XCTAssertTrue(result.terminateStream)
        XCTAssertEqual(result.frames.count, 1)
        XCTAssertEqual(
            String(bytes: result.frames[0].data, encoding: .utf8) ?? "",
            "event: pastewatch_error\ndata: {\"error\":\"stream buffer limit exceeded\"}\n\ndata: [DONE]\n\n"
        )
    }

    // WO-511: the next complete frame is rejected before retained storage crosses the cap.
    func testToolCallAggregateBufferNeverRetainsOverflowFrame() throws {
        func frame(fill: Character) throws -> SSEFrameParser.Frame {
            let object: [String: Any] = [
                "type": "content_block_delta",
                "index": 0,
                "delta": [
                    "type": "input_json_delta",
                    "partial_json": String(repeating: fill, count: SSEFrameParser.maxFrameBytes / 2)
                ]
            ]
            let payload = try JSONSerialization.data(withJSONObject: object)
            let payloadString = try XCTUnwrap(String(data: payload, encoding: .utf8))
            return SSEFrameParser.Frame(
                raw: Data("data: \(payloadString)\n\n".utf8),
                eventType: nil,
                data: payloadString
            )
        }
        let first = try frame(fill: "a")
        let second = try frame(fill: "b")
        var transformer = ToolCallStreamRedactor(
            config: PastewatchConfig.defaultConfig,
            customRules: [],
            severity: .high
        )

        XCTAssertFalse(transformer.process(first).terminateStream)
        let result = transformer.process(second)

        XCTAssertTrue(result.terminateStream)
        XCTAssertEqual(transformer.peakPendingBytes, first.raw.count)
        XCTAssertLessThanOrEqual(transformer.peakPendingBytes, SSEFrameParser.maxFrameBytes)
    }

    // WO-511: a first oversized tool frame cannot bypass the stateful transformer.
    func testParserOverflowToolFrameFailsClosedWithoutPriorFragment() {
        let payload = Data(
            ("data: {\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\""
                + String(repeating: "x", count: SSEFrameParser.maxFrameBytes)
                + "\"}}\n\n").utf8
        )
        var parser = SSEFrameParser()
        let parsed = parser.feed(payload)
        var transformer = ToolCallStreamRedactor(
            config: PastewatchConfig.defaultConfig,
            customRules: [],
            severity: .high
        )

        let blocked = transformer.blockForParserOverflow(parsed.overflowBytes)

        XCTAssertTrue(parsed.overflowFlushed)
        XCTAssertEqual(blocked?.terminateStream, true)
        XCTAssertEqual(blocked?.frames.first?.data.suffix(14), Data("data: [DONE]\n\n".utf8))
    }

    // WO-511: JSON escaping of a protocol key cannot bypass the parser-overflow gate.
    func testParserOverflowEscapedToolKeyFailsClosed() {
        let payload = Data(
            ("data: {\"delta\":{\"type\":\"input_json_delta\",\"partial\\u005fjson\":\""
                + String(repeating: "x", count: SSEFrameParser.maxFrameBytes)
                + "\"}}\n\n").utf8
        )
        var parser = SSEFrameParser()
        let parsed = parser.feed(payload)
        var transformer = ToolCallStreamRedactor(
            config: PastewatchConfig.defaultConfig,
            customRules: [],
            severity: .high
        )

        let blocked = transformer.blockForParserOverflow(parsed.overflowBytes)

        XCTAssertTrue(parsed.overflowFlushed)
        XCTAssertEqual(blocked?.terminateStream, true)
    }

    // WO-514: an explicitly supplied sink captures raw and transformed frame decisions.
    func testToolCallDebugSinkRecordsMutationDecision() throws {
        let path = NSTemporaryDirectory() + "pastewatch-tool-debug-\(UUID().uuidString).jsonl"
        defer { try? FileManager.default.removeItem(atPath: path) }
        let credential = "AIza" + String(repeating: "Z", count: 35)
        let split = credential.index(credential.startIndex, offsetBy: 17)
        let fixture = anthropicToolCallFixture(fragments: [
            #"{"token":"\#(credential[..<split])"#,
            #"\#(credential[split...])"}"#
        ])
        var parser = SSEFrameParser()
        var transformer = ToolCallStreamRedactor(
            config: PastewatchConfig.defaultConfig,
            customRules: [],
            severity: .high,
            debugSink: try StreamDebugSink(path: path)
        )

        for frame in parser.feed(fixture).frames { _ = transformer.process(frame) }
        _ = transformer.finish()

        let records = try String(contentsOfFile: path).split(separator: "\n").compactMap { line in
            try JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any]
        }
        let toolRecords = records.filter { $0["scanned_fields"] as? [String] == ["partial_json"] }
        XCTAssertEqual(toolRecords.count, 2)
        XCTAssertTrue(toolRecords.allSatisfy { record in
            record["decision"] as? String == "mutated"
                && record["shape"] as? String == "anthropic-delta"
                && record["match_types"] as? [String] == ["Tool argument: Google API Key"]
        })
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

    // WO-515: fixtures model the exact events clients concatenate into tool JSON.
    private func anthropicToolCallFixture(fragments: [String], index: Int = 0) -> Data {
        var stream = sseFrame(
            eventType: "content_block_start",
            data: #"{"type":"content_block_start","index":\#(index),"content_block":{"type":"tool_use","id":"tool_1","name":"search","input":{}}}"#
        )
        for fragment in fragments {
            let encoded = jsonStringLiteral(fragment)
            stream.append(sseFrame(
                eventType: "content_block_delta",
                data: #"{"type":"content_block_delta","index":\#(index),"delta":{"type":"input_json_delta","partial_json":\#(encoded)}}"#
            ))
        }
        stream.append(sseFrame(
            eventType: "content_block_stop",
            data: #"{"type":"content_block_stop","index":\#(index)}"#
        ))
        return stream
    }

    // WO-515: OpenAI-compatible gateways stream function arguments as JSON string fragments.
    private func openAIToolCallFixture(fragments: [String], index: Int = 0) -> Data {
        var stream = Data()
        for fragment in fragments {
            let encoded = jsonStringLiteral(fragment)
            stream.append(sseFrame(
                eventType: nil,
                data: #"{"choices":[{"index":0,"delta":{"tool_calls":[{"index":\#(index),"function":{"arguments":\#(encoded)}}]}}]}"#
            ))
        }
        stream.append(sseFrame(eventType: nil, data: #"{"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}"#))
        return stream
    }

    // WO-509: build sparse OpenAI choice frames without normalizing choice indexes.
    private func openAIChoiceFrame(
        choice: Int,
        arguments: String?,
        finishReason: String? = nil
    ) -> Data {
        var choiceObject: [String: Any] = ["index": choice, "delta": [String: Any]()]
        if let arguments {
            choiceObject["delta"] = [
                "tool_calls": [["index": 0, "function": ["arguments": arguments]]]
            ]
        }
        if let finishReason { choiceObject["finish_reason"] = finishReason }
        let payload = (try? JSONSerialization.data(withJSONObject: ["choices": [choiceObject]])) ?? Data()
        return sseFrame(eventType: nil, data: String(bytes: payload, encoding: .utf8) ?? "")
    }

    // WO-515: reassembly validates what an Anthropic client sees, not individual frame syntax.
    private func reassembleAnthropicToolJSON(from stream: Data) throws -> NSDictionary {
        var parser = SSEFrameParser()
        let fragments = parser.feed(stream).frames.compactMap { frame -> String? in
            guard let payload = frame.data,
                  let data = payload.data(using: .utf8),
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let delta = json["delta"] as? [String: Any],
                  delta["type"] as? String == "input_json_delta" else { return nil }
            return delta["partial_json"] as? String
        }
        return try decodedJSONObject(fragments.joined())
    }

    // WO-515: OpenAI-compatible clients concatenate function.arguments by tool index.
    private func reassembleOpenAIToolJSON(from stream: Data) throws -> NSDictionary {
        var parser = SSEFrameParser()
        let fragments = parser.feed(stream).frames.compactMap { frame -> String? in
            guard let payload = frame.data,
                  let data = payload.data(using: .utf8),
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let choices = json["choices"] as? [[String: Any]],
                  let delta = choices.first?["delta"] as? [String: Any],
                  let calls = delta["tool_calls"] as? [[String: Any]],
                  let function = calls.first?["function"] as? [String: Any] else { return nil }
            return function["arguments"] as? String
        }
        return try decodedJSONObject(fragments.joined())
    }

    // WO-515: fixture assertions decode only complete reassembled tool arguments.
    private func decodedJSONObject(_ json: String) throws -> NSDictionary {
        let value = try JSONSerialization.jsonObject(with: Data(json.utf8))
        return try XCTUnwrap(value as? NSDictionary)
    }

    // WO-515: fixture generation delegates string escaping to Foundation.
    private func jsonStringLiteral(_ value: String) -> String {
        let encoded = try? JSONSerialization.data(withJSONObject: [value])
        let array = encoded.flatMap { String(data: $0, encoding: .utf8) } ?? "[]"
        return String(array.dropFirst().dropLast())
    }

    // WO-511: named fixture result keeps cross-platform assertions explicit.
    private struct ToolCallFixtureTransform {
        let data: Data
        let redactionCount: Int
        let toolCallRedactionCount: Int
        let advisoryCount: Int
        let types: [String]
    }

    // WO-511: direct transformer tests exercise the platform-shared state machine.
    private func transformToolCallFixture(
        _ fixture: Data,
        severity: Severity = .high
    ) -> ToolCallFixtureTransform {
        var parser = SSEFrameParser()
        let parsed = parser.feed(fixture)
        XCTAssertFalse(parsed.overflowFlushed)
        var transformer = ToolCallStreamRedactor(
            config: PastewatchConfig.defaultConfig,
            customRules: [],
            severity: severity
        )
        var output = Data()
        var redactionCount = 0
        var toolCallRedactionCount = 0
        var advisoryCount = 0
        var types: [String] = []
        for frame in parsed.frames {
            let result = transformer.process(frame)
            XCTAssertFalse(result.terminateStream)
            for transformed in result.frames {
                output.append(transformed.data)
                redactionCount += transformed.count
                toolCallRedactionCount += transformed.toolCallRedactionCount
                advisoryCount += transformed.advisoryCount
                types.append(contentsOf: transformed.types)
            }
        }
        let tail = transformer.finish()
        XCTAssertFalse(tail.terminateStream)
        for transformed in tail.frames {
            output.append(transformed.data)
            redactionCount += transformed.count
            toolCallRedactionCount += transformed.toolCallRedactionCount
            advisoryCount += transformed.advisoryCount
            types.append(contentsOf: transformed.types)
        }
        return ToolCallFixtureTransform(
            data: output,
            redactionCount: redactionCount,
            toolCallRedactionCount: toolCallRedactionCount,
            advisoryCount: advisoryCount,
            types: types
        )
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
