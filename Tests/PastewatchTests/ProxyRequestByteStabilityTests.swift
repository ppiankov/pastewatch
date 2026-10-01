import XCTest
@testable import PastewatchCore

// WO-631: compare transport bytes without ever printing a fixture credential on failure.
final class ProxyRequestByteStabilityTests: XCTestCase {
    private let placeholder = "<GOOGLE_API_KEY_1>"
    private var credential: String { "AI" + "za" + String(repeating: "J", count: 35) }

    // WO-631: pure request tests need neither a listener nor an external upstream.
    private func makeProxy() -> ProxyServer {
        ProxyServer(port: 0, upstream: URL(string: "http://127.0.0.1:1")!, quietLog: true)
    }

    // WO-631: F1 rebuilding dictionaries must not vary the encoded cached prefix.
    func testRepeatedRedactionHasOneEncoding() {
        let proxy = makeProxy()
        let body = requestBody(value: credential)
        var outputs = Set<Data>()
        for _ in 0..<50 {
            let result = proxy.scanAndRedactBody(body)
            XCTAssertFalse(result.serializationFailed)
            XCTAssertEqual(result.redacted, 7)
            XCTAssertEqual(result.advisoryCount, 0)
            outputs.insert(Data(result.body.utf8))
        }
        XCTAssertEqual(outputs.count, 1, "Identical input must have exactly one wire encoding")
    }

    // WO-631: F2 exact expected bytes pin ordering, whitespace, numeric spelling and untouched escapes.
    func testOnlyChangedStringTokensDifferFromInput() {
        let body = requestBody(value: credential)
        let expected = Data(requestBody(value: placeholder).utf8)
        for _ in 0..<5 {
            let result = makeProxy().scanAndRedactBody(body)
            XCTAssertFalse(result.serializationFailed)
            XCTAssertTrue(Data(result.body.utf8) == expected, "Bytes outside replacement tokens changed")
        }
    }

    // WO-631: F3 retain every request surface's redaction and accounting through the unchanged walk.
    func testStructuredSecretCoverageAndCountsArePreserved() throws {
        let result = makeProxy().scanAndRedactBody(requestBody(value: credential))
        XCTAssertEqual(result.redacted, 7)
        XCTAssertEqual(result.redactedTypes.count, 7)
        XCTAssertEqual(Set(result.redactedTypes).count, 1)
        XCTAssertEqual(result.advisoryCount, 0)
        XCTAssertTrue(result.advisoryTypes.isEmpty)
        XCTAssertNil(result.blockingAdvisory)
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(result.body.utf8)) as? [String: Any])
        let tools = try XCTUnwrap(object["tools"] as? [[String: Any]])
        let schema = try XCTUnwrap(tools[0]["input_schema"] as? [String: Any])
        let properties = try XCTUnwrap(schema["properties"] as? [String: [String: Any]])
        let examples = try XCTUnwrap(tools[0]["input_examples"] as? [[String: Any]])
        let system = try XCTUnwrap(object["system"] as? [[String: Any]])
        let messages = try XCTUnwrap(object["messages"] as? [[String: Any]])
        let assistant = try XCTUnwrap(messages[0]["content"] as? [[String: Any]])
        let input = try XCTUnwrap(assistant[0]["input"] as? [String: Any])
        let user = try XCTUnwrap(messages[1]["content"] as? [[String: Any]])
        let values = [tools[0]["description"], properties["z_last"]?["description"], examples[0]["z_last"],
                      system[0]["text"], input["z_last"], user[0]["content"], user[1]["text"]]
        XCTAssertTrue(values.allSatisfy { $0 as? String == placeholder }, "A request surface missed redaction")
        XCTAssertTrue(Data(result.body.utf8) == Data(requestBody(value: placeholder).utf8))
    }

    // WO-631: F4 byte positions survive escaped keys, Unicode, controls and literal UTF-8.
    func testJSONSpecialCharactersAndEscapedSecretStillRoundTrip() throws {
        let value = "quote \" backslash \\ slash / tab\t newline\n control\u{0001} \u{00E9} \u{1F680} " + credential
        let encoded = try JSONSerialization.data(withJSONObject: value, options: [.fragmentsAllowed])
        let literal = try XCTUnwrap(String(data: encoded, encoding: .utf8))
        let escaped = literal.replacingOccurrences(of: credential, with: #"\u0041"# + credential.dropFirst())
        let prefix = #"{ "model":"claude-3", "messages":[{"role":"user", "\u0063ontent" : "#
        let suffix = #"}], "unchanged":"keep\/\u0061", "number":1.00 }"#
        for wireLiteral in [literal, escaped] {
            let result = makeProxy().scanAndRedactBody(prefix + wireLiteral + suffix)
            XCTAssertFalse(result.serializationFailed)
            XCTAssertEqual(result.redacted, 1)
            XCTAssertTrue(result.body.hasPrefix(prefix))
            XCTAssertTrue(result.body.hasSuffix(suffix))
            let object = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(result.body.utf8)) as? [String: Any])
            let messages = try XCTUnwrap(object["messages"] as? [[String: Any]])
            let expected = value.replacingOccurrences(of: credential, with: placeholder)
            XCTAssertTrue(messages[0]["content"] as? String == expected, "Escaped value did not round-trip")
        }
    }

    // WO-631: same-valued metadata and property names must not be globally replaced.
    func testUnscannedEqualValuesAndKeysStayVerbatim() {
        let prefix = "{\"metadata\":{\"\(credential)\":\"\(credential)\"},\"messages\":[{\"role\":\"user\",\"content\":\""
        let suffix = "\"}]}"
        let result = makeProxy().scanAndRedactBody(prefix + credential + suffix)
        XCTAssertEqual(result.redacted, 1)
        XCTAssertFalse(result.serializationFailed)
        XCTAssertTrue(Data(result.body.utf8) == Data((prefix + placeholder + suffix).utf8))
    }

    // WO-631: batch params must preserve independent JSON paths and exact outer framing.
    func testBatchRequestBytesAreStable() {
        let prefix = "{ \"requests\" : [ {\"custom_id\":\"r1\", \"params\" : "
        let middle = "}, {\"custom_id\":\"r2\", \"params\" : "
        let suffix = "} ] }\n"
        let body = prefix + requestBody(value: credential) + middle + requestBody(value: credential) + suffix
        let expected = prefix + requestBody(value: placeholder) + middle + requestBody(value: placeholder) + suffix
        let result = makeProxy().scanAndRedactBody(body)
        XCTAssertFalse(result.serializationFailed)
        XCTAssertEqual(result.redacted, 14)
        XCTAssertTrue(Data(result.body.utf8) == Data(expected.utf8))
    }

    // WO-631: the unchanged branch must not invoke output assembly at all.
    func testZeroRedactionsPreserveOriginalBytesWithoutSerialization() {
        let proxy = makeProxy()
        proxy.requestBodySerializer = { _, _ in
            XCTFail("An unchanged request reached the splicer")
            throw CocoaError(.fileWriteUnknown)
        }
        let body = requestBody(value: "ordinary text")
        let result = proxy.scanAndRedactBody(body)
        XCTAssertEqual(result.redacted, 0)
        XCTAssertFalse(result.serializationFailed)
        XCTAssertTrue(Data(result.body.utf8) == Data(body.utf8))
    }

    // WO-631: F5 a real splice error must preserve scan evidence and set the forwarding veto.
    func testForcedSpliceFailurePreservesScanEvidence() {
        let proxy = makeProxy()
        let splice = proxy.requestBodySerializer
        proxy.requestBodySerializer = { _, object in try splice(Data("{".utf8), object) }
        let result = proxy.scanAndRedactBody(requestBody(value: credential))
        XCTAssertTrue(result.serializationFailed)
        XCTAssertEqual(result.redacted, 7)
        XCTAssertEqual(result.redactedTypes.count, 7)
        XCTAssertEqual(result.advisoryCount, 0)
    }

    // WO-631: byte-preserving output conversion must not repair malformed UTF-8 into a forwarded body.
    func testInvalidUTF8OutputFailsClosed() {
        let proxy = makeProxy()
        proxy.requestBodySerializer = { _, _ in Data([0xFF]) }
        let result = proxy.scanAndRedactBody(requestBody(value: credential))
        XCTAssertTrue(result.serializationFailed)
        XCTAssertEqual(result.redacted, 7)
    }

    // WO-631: Foundation may collapse duplicate keys; refusing avoids ambiguous token ownership.
    func testDuplicateDecodedKeysFailClosed() {
        for secondKey in ["content", #"\u0063ontent"#] {
            let body = "{\"messages\":[{\"role\":\"user\",\"content\":\"\(credential)\",\"\(secondKey)\":\"\(credential)\"}]}"
            let result = makeProxy().scanAndRedactBody(body)
            XCTAssertGreaterThan(result.redacted, 0)
            XCTAssertTrue(result.serializationFailed)
        }
    }

    // WO-631: preserve BOM and JSON whitespace when Foundation accepts this UTF-8 input.
    func testUTF8BOMAndTrailingWhitespaceArePreserved() {
        let prefix = "\u{FEFF}\r\n\t"
        let suffix = " \r\n\t"
        let body = prefix + requestBody(value: credential) + suffix
        let result = makeProxy().scanAndRedactBody(body)
        XCTAssertEqual(result.redacted, 7)
        XCTAssertFalse(result.serializationFailed)
        XCTAssertTrue(Data(result.body.utf8) == Data((prefix + requestBody(value: placeholder) + suffix).utf8))
    }

    // WO-631: deliberately noncanonical layout exposes object order and numeric/escape normalization.
    private func requestBody(value: String) -> String {
        let template = #"""
          {
            "model" : "claude-3",
            "metadata" : {"escaped":"keep\/\u0061", "decimal":1.00, "exponent":1e+2, "zero":-0.0,
              "integer":9007199254740993, "true":true, "false":false, "null":null, "empty":{}, "array":[]},
            "tools" : [{
              "name":"fetch", "description":"@@VALUE@@",
              "input_schema":{
                "type":"object", "properties":{
                  "z_last":{"description":"@@VALUE@@", "type":"string"},
                  "a_first":{"type":"string"}, "middle":{"type":"number"}
                }, "required":["z_last"]
              },
              "input_examples":[{"z_last":"@@VALUE@@", "a_first":"unchanged"}],
              "cache_control":{"type":"ephemeral"}
            }],
            "system":[{"type":"text", "text":"@@VALUE@@", "cache_control":{"type":"ephemeral"}}],
            "messages":[
              {"role":"assistant", "content":[{"type":"tool_use", "id":"toolu_1", "name":"fetch",
                "input":{"z_last":"@@VALUE@@", "a_first":"unchanged", "middle":1e+2}}]},
              {"role":"user", "content":[
                {"type":"tool_result", "tool_use_id":"toolu_1", "content":"@@VALUE@@"},
                {"type":"text", "text":"@@VALUE@@"}
              ]}
            ]
          }
        """#
        return template.replacingOccurrences(of: "@@VALUE@@", with: value)
    }
}
