import XCTest
@testable import PastewatchCore

final class ObfuscatorTests: XCTestCase {
    // WO-529@v3: Config with ambiguous types enabled for obfuscator tests.
    let config: PastewatchConfig = {
        var config = PastewatchConfig.defaultConfig
        let types: [SensitiveDataType] = [.email, .ipAddress, .uuid, .genericApiKey]
        for type in types where !config.enabledTypes.contains(type.rawValue) {
            config.enabledTypes.append(type.rawValue)
        }
        config.obfuscate = [
            ObfuscateEntry(type: "email", pattern: "@example.com"),
            ObfuscateEntry(type: "email", pattern: "@test.com"),
            ObfuscateEntry(type: "email", pattern: "@company.com"),
            ObfuscateEntry(type: "email", pattern: "@b.com"),
            ObfuscateEntry(type: "email", pattern: "@d.com")
        ]
        return config
    }()

    func testObfuscatesSingleEmail() {
        let content = "Contact john@example.com for help"
        let matches = DetectionRules.scan(content, config: config)
        let result = Obfuscator.obfuscate(content, matches: matches)

        XCTAssertEqual(result, "Contact <EMAIL_1> for help")
    }

    func testObfuscatesMultipleEmailsInOrder() {
        let content = "Send to alice@test.com and bob@test.com"
        let matches = DetectionRules.scan(content, config: config)
        let result = Obfuscator.obfuscate(content, matches: matches)

        XCTAssertEqual(result, "Send to <EMAIL_1> and <EMAIL_2>")
    }

    func testObfuscatesMixedTypes() {
        let content = "Email: user@company.com, IP: 10.0.0.1"
        let matches = DetectionRules.scan(content, config: config)
        let result = Obfuscator.obfuscate(content, matches: matches)

        XCTAssertTrue(result.contains("<EMAIL_1>"))
        XCTAssertTrue(result.contains("<IP_1>"))
        XCTAssertFalse(result.contains("user@company.com"))
        XCTAssertFalse(result.contains("10.0.0.1"))
    }

    func testReturnsOriginalWhenNoMatches() {
        let content = "Just a normal message"
        let matches: [DetectedMatch] = []
        let result = Obfuscator.obfuscate(content, matches: matches)

        XCTAssertEqual(result, content)
    }

    func testPreservesNonSensitiveContent() {
        let content = "Please send report to admin@company.com by Monday"
        let matches = DetectionRules.scan(content, config: config)
        let result = Obfuscator.obfuscate(content, matches: matches)

        XCTAssertTrue(result.contains("Please send report to"))
        XCTAssertTrue(result.contains("by Monday"))
        XCTAssertTrue(result.contains("<EMAIL_1>"))
    }

    func testHandlesAdjacentMatches() {
        let content = "a@b.com c@d.com"
        let matches = DetectionRules.scan(content, config: config)
        let result = Obfuscator.obfuscate(content, matches: matches)

        XCTAssertEqual(result, "<EMAIL_1> <EMAIL_2>")
    }

    func testHandlesUUID() {
        let content = "ID: 550e8400-e29b-41d4-a716-446655440000"
        let matches = DetectionRules.scan(content, config: config)
        let result = Obfuscator.obfuscate(content, matches: matches)

        XCTAssertEqual(result, "ID: <UUID_1>")
    }

    func testHandlesAPIKey() {
        // Test generic token_ prefix pattern (avoids GitHub secret scanning)
        let content = "mytoken: token_abcdefghijklmnopqrstuvwxyz"
        let matches = DetectionRules.scan(content, config: config)
        let result = Obfuscator.obfuscate(content, matches: matches)

        XCTAssertTrue(result.contains("<API_KEY_1>"))
        XCTAssertFalse(result.contains("token_abc"))
    }

    // WO-478: advisory diagnostics must never be interpreted as replacement ranges.
    func testLeavesMalformedPrivateKeyAdvisoryUnchanged() {
        let content = "-----BEGIN PRIVATE " + "KEY-----\nmalformed"
        let matches = DetectionRules.scan(content, config: config)

        XCTAssertEqual(matches.map(\.advisory), [.malformedPrivateKey])
        XCTAssertEqual(Obfuscator.obfuscate(content, matches: matches), content)
    }

    // WO-645@v1: pin mixed-type numbering and advisory bytes before consolidating replacement.
    func testMixedRewriteGoldenBytesBeforeResolverExtraction() throws {
        let first = ["AK", "IA", "ZXCVBN", "M12345", "QWER"].joined()
        let second = ["AK", "IA", "QWERTY", "U56789", "ZXCV"].joined()
        let identifier = ["123e4567", "e89b", "12d3", "a456", "426614174000"].joined(separator: "-")
        let content = "\u{1F600} first " + first + " then " + identifier + " next " + second + " advisory public"
        let rows: [(SensitiveDataType, String)] = [(.awsKey, first), (.uuid, identifier), (.awsKey, second)]
        var matches = try rows.map { type, value in
            DetectedMatch(type: type, value: value, range: try XCTUnwrap(content.range(of: value)), line: 1)
        }
        matches.append(DetectedMatch(type: .credential, value: "public", range: try XCTUnwrap(content.range(of: "public")),
                                     line: 1, advisory: .documentationPolicy))
        let expected = "\u{1F600} first <AWS_KEY_1> then <UUID_1> next <AWS_KEY_2> advisory public"
        let actual = Obfuscator.obfuscate(content, matches: Array(matches.reversed()))
        XCTAssertTrue(actual.utf8.elementsEqual(expected.utf8))
    }

    // WO-645@v1: resolver targeting cannot change numbering by original match position.
    func testReplacementResolverPreservesOriginalPositionNumbering() throws {
        let content = "first [alpha] next [beta]"
        let matches = try ["[beta]", "[alpha]"].map { value in
            DetectedMatch(type: .uuid, value: value, range: try XCTUnwrap(content.range(of: value)), line: 1)
        }
        var calls = 0
        let actual = Obfuscator.obfuscate(content, matches: matches, replacementRange: { match in
            calls += 1
            return content.index(after: match.range.lowerBound)..<content.index(before: match.range.upperBound)
        })
        XCTAssertTrue(actual == "first [<UUID_1>] next [<UUID_2>]")
        XCTAssertEqual(calls, 2)
    }

    // WO-645@v1: advisory filtering must precede the resolver, even for direct callers.
    func testAdvisoryNeverReachesReplacementResolver() throws {
        let content = "public"
        let match = DetectedMatch(type: .credential, value: content, range: content.startIndex..<content.endIndex,
                                  line: 1, advisory: .documentationPolicy)
        var calls = 0
        let result = Obfuscator.obfuscate(content, matches: [match], replacementRange: { match in
            calls += 1
            return match.range
        })
        XCTAssertTrue(result.utf8.elementsEqual(content.utf8))
        XCTAssertEqual(calls, 0)
    }

    // WO-557@v2: Foundation and generated-shell regexes recognize the same marker.
    func testMCPPlaceholderRegexFormsMatchTheSameMarker() throws {
        let marker = Obfuscator.makeMCPPlaceholder(type: .awsKey, number: 12)
        let foundation = try NSRegularExpression(pattern: Obfuscator.mcpPlaceholderPattern)
        XCTAssertNotNil(
            foundation.firstMatch(
                in: marker,
                range: NSRange(marker.startIndex..., in: marker)
            )
        )
        XCTAssertTrue(marker.range(of: Obfuscator.mcpPlaceholderPOSIXERE, options: .regularExpression) != nil)
    }
}
