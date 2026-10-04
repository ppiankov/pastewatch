import XCTest
@testable import PastewatchCore

// WO-630@v2: an unappliable authorized span must not produce file content or store mappings.
final class MCPReadFailClosedTests: XCTestCase {
    // WO-630@v2: inject a stale authorized span into the same responder the MCP read handler uses.
    func testUnappliableReadReturnsMCPErrorWithoutFileContent() throws {
        let value = ["AK", "IA", "ZXCVBN", "M12345", "QWER"].joined()
        let content = "benign\n" + value
        let match = DetectedMatch(type: .awsKey, value: value, range: try XCTUnwrap(content.range(of: "benign")), line: 2)
        let decision = MCPReadDecision(authorized: [match], reportedAdvisories: [])
        let (response, entries) = decision.response(request: (id: .int(1), filePath: "fixture.txt"), content: content, store: RedactionStore(), encode: { _, _ in
            XCTFail("an unappliable read must not reach payload encoding")
            return "{}"
        }, onFailure: { text in
            JSONRPCResponse(jsonrpc: "2.0", id: .int(1), result: .object([
                "isError": .bool(true), "content": .array([.object(["type": .string("text"), "text": .string(text)])])
            ]), error: nil)
        })
        guard case .object(let result) = response.result else { return XCTFail("MCP tool error required") }
        XCTAssertEqual(result["isError"], .bool(true))
        XCTAssertTrue(entries.isEmpty)
        let text = try XCTUnwrap(String(data: JSONEncoder().encode(response), encoding: .utf8))
        XCTAssertTrue(text.contains("AWS Key at line 2"))
        XCTAssertFalse(text.contains(value))
        XCTAssertFalse(text.contains("benign"))
        XCTAssertFalse(text.contains("redactions"))
    }

    // WO-630@v2: reject stale value/range metadata instead of redacting unrelated bytes.
    func testReadRefusesMismatchedAuthorizedRangeBeforeStoreMutation() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            let value = ["AK", "IA", "ZXCVBN", "M12345", "QWER"].joined()
            let content = "benign\n" + value
            let range = try XCTUnwrap(content.range(of: "benign"))
            let match = DetectedMatch(type: .awsKey, value: value, range: range, line: 2)
            let decision = MCPReadDecision(authorized: [match], reportedAdvisories: [])
            let store = RedactionStore()
            XCTAssertThrowsError(try decision.redact(content: content, store: store, filePath: "fixture.txt")) { error in
                XCTAssertTrue(error.localizedDescription.contains("AWS Key"))
                XCTAssertTrue(error.localizedDescription.contains("line 2"))
                XCTAssertFalse(error.localizedDescription.contains(value))
                XCTAssertFalse(error.localizedDescription.contains(content))
            }
            XCTAssertFalse(store.hasMappings(for: "fixture.txt"))
        }
    }

    // WO-630@v2: validate the entire batch before any mapping can be installed.
    func testOutOfBoundsAndOverlappingSpansRefuseWithoutPartialMappings() throws {
        let value = ["AK", "IA", "ZXCVBN", "M12345", "QWER"].joined()
        let content = value + "\nbenign"
        let goodRange = try XCTUnwrap(content.range(of: value))
        let good = DetectedMatch(type: .awsKey, value: value, range: goodRange)
        let foreign = String(repeating: "x", count: content.utf8.count + 100)
        let badRange = foreign.index(foreign.startIndex, offsetBy: 50)..<foreign.endIndex
        let invalid = DetectedMatch(type: .awsKey, value: value, range: badRange, line: 2)
        for batch in [[good, invalid], [good, good]] {
            let store = RedactionStore()
            let decision = MCPReadDecision(authorized: batch, reportedAdvisories: [])
            XCTAssertThrowsError(try decision.redact(content: content, store: store, filePath: "fixture.txt"))
            XCTAssertFalse(store.hasMappings(for: "fixture.txt"))
        }
    }

    // WO-630@v2: JSON encoding errors disclose classes and lines, not partial or secret-bearing payloads.
    func testEncodingFailureContainsOnlyFindingMetadata() throws {
        let value = ["AK", "IA", "ZXCVBN", "M12345", "QWER"].joined()
        let match = DetectedMatch(type: .awsKey, value: value, range: value.startIndex..<value.endIndex, line: 7)
        let decision = MCPReadDecision(authorized: [match], reportedAdvisories: [])
        XCTAssertThrowsError(try decision.encodePayload(.object([
            "content": .string(value), "invalid": .number(.infinity)
        ]))) { error in
            XCTAssertTrue(error.localizedDescription.contains("AWS Key at line 7"))
            XCTAssertFalse(error.localizedDescription.contains(value))
        }
    }

    // WO-630@v2: every authorization category replaces its target bytes and restores exactly.
    func testAuthorizedFixtureCategoriesReplaceAndRestoreExactBytes() throws {
        let password = ["Q7m", "N4r", "Z9T", "2xV", "6k"].joined()
        let connection = ["post", "gres", "://", "app:", password, "@db:5432/prod"].joined()
        let aws = ["AK", "IA", "ZXCVBN", "M12345", "QWER"].joined()
        let vault = ["hvs", ".", "CAESI", String(repeating: "aB9qZ2", count: 6)].joined()
        let stripe = ["cs_", "live_", String(repeating: "Ab9Cd2Ef", count: 4)].joined()
        let custom = ["Opaque", "Fixture", "9Q7m"].joined()
        var config = TestConfigHelper.configWithAmbiguousAdvisories([.dbConnectionString])
        config.customRules = [.init(name: "Opaque fixture", pattern: custom)]
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            for (content, target) in [(aws, aws), (vault, vault), (stripe, stripe), (custom, custom), (connection, password)] {
                let matches = DetectionRules.scan(content, config: config, customRules: CustomRule.compileValid(config.customRules))
                let decision = MCPReadDecision.evaluate(matches: matches, content: content, config: config,
                                                        minimumSeverity: .high, filePath: "fixture.txt")
                XCTAssertEqual(decision.authorized.count, 1)
                let store = RedactionStore()
                let (redacted, entries) = try decision.redact(content: content, store: store, filePath: "fixture.txt")
                XCTAssertEqual(entries.count, decision.authorized.count)
                XCTAssertFalse(redacted.contains(target))
                XCTAssertTrue(store.resolve(content: redacted, filePath: "fixture.txt").content == content)
            }
            let known = DetectedMatch(type: .credential, value: password, range: password.startIndex..<password.endIndex,
                                      mutationAuthorizationSources: [.exactKnownSecret])
            let decision = MCPReadDecision(authorized: [known], reportedAdvisories: [])
            let store = RedactionStore()
            let (redacted, entries) = try decision.redact(content: password, store: store, filePath: "known.txt")
            XCTAssertEqual(entries.count, 1)
            XCTAssertFalse(redacted.contains(password))
            XCTAssertTrue(store.resolve(content: redacted, filePath: "known.txt").content == password)
        }
    }

    // WO-630@v2: advisory-only database shapes remain visible without being called clean.
    func testAmbiguousMatchRemainsAdvisoryOnly() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            let content = ["post", "gres", "://", "db:5432/prod"].joined()
            let config = TestConfigHelper.configWithAmbiguousAdvisories([.dbConnectionString])
            let decision = MCPReadDecision.evaluate(matches: DetectionRules.scan(content, config: config),
                                                    content: content, config: config,
                                                    minimumSeverity: .high, filePath: "fixture.md")
            XCTAssertTrue(decision.authorized.isEmpty)
            XCTAssertEqual(decision.reportedAdvisories.count, 1)
            let (redacted, entries) = try decision.redact(content: content, store: RedactionStore(), filePath: "fixture.md")
            XCTAssertTrue(redacted == content)
            XCTAssertTrue(entries.isEmpty)
        }
    }
}
