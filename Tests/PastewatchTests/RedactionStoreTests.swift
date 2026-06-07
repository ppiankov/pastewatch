import XCTest
@testable import PastewatchCore

final class RedactionStoreTests: XCTestCase {

    func testRedactReplacesSensitiveValues() {
        let store = RedactionStore()
        let text = "key=user@example.com"
        let matches = DetectionRules.scan(text, config: .defaultConfig)
        XCTAssertFalse(matches.isEmpty)

        let (redacted, entries) = store.redact(content: text, matches: matches, filePath: "/tmp/test.txt")
        XCTAssertFalse(redacted.contains("user@example.com"))
        XCTAssertTrue(redacted.contains("__PW_EMAIL_1__"))
        XCTAssertEqual(entries.count, matches.count)
        XCTAssertEqual(entries[0].placeholder, "__PW_EMAIL_1__")
        XCTAssertEqual(entries[0].type, "Email")
    }

    func testResolveRestoresOriginalValues() {
        let store = RedactionStore()
        let text = "contact: user@example.com"
        let matches = DetectionRules.scan(text, config: .defaultConfig)
        let (redacted, _) = store.redact(content: text, matches: matches, filePath: "/tmp/test.txt")

        let result = store.resolve(content: redacted, filePath: "/tmp/test.txt")
        XCTAssertEqual(result.content, text)
        XCTAssertEqual(result.resolved, 1)
        XCTAssertEqual(result.unresolved, 0)
    }

    // WO-132: round-trip must be byte-faithful even when astral-plane characters
    // (emoji / surrogate pairs) precede a redacted value. The resolve path used
    // Character offsets against a UTF-16 NSRange, so positions after a 2-unit
    // emoji drifted and corrupted the surrounding bytes.
    func testRoundTripPreservesContentWithMultibytePrefix() {
        let secret = "sk-abc123DEF456ghi789JKL012mno345PQR"
        let cases = [
            "// 🔑 key=\"\(secret)\"}",
            "café=\"\(secret)\"}",
            "密码=\"\(secret)\"},",
            "k=\"\(secret)\"🔒",
            "// 🎉 header\napi=\"\(secret)\"\ntail",
        ]
        for text in cases {
            let store = RedactionStore()
            let matches = DetectionRules.scan(text, config: .defaultConfig)
            XCTAssertFalse(matches.isEmpty, "no match for: \(text)")
            let (redacted, _) = store.redact(content: text, matches: matches, filePath: "/tmp/rt.txt")
            let result = store.resolve(content: redacted, filePath: "/tmp/rt.txt")
            XCTAssertEqual(result.content, text, "round-trip corrupted: \(text)")
            XCTAssertEqual(result.unresolved, 0, "unresolved placeholder for: \(text)")
        }
    }

    func testRoundTripPreservesTwoSecretsAcrossEmoji() {
        let text = "a=\"sk-abc123DEF456ghi789JKL012mno345PQR\" 🚀 "
            + "b=\"sk-zzz999YYY888xxx777WWW666vvv555UUU\""
        let store = RedactionStore()
        let matches = DetectionRules.scan(text, config: .defaultConfig)
        let (redacted, _) = store.redact(content: text, matches: matches, filePath: "/tmp/rt2.txt")
        let result = store.resolve(content: redacted, filePath: "/tmp/rt2.txt")
        XCTAssertEqual(result.content, text)
        XCTAssertEqual(result.unresolved, 0)
    }

    func testIdempotentReRead() {
        let store = RedactionStore()
        let text = "email: user@example.com"
        let matches = DetectionRules.scan(text, config: .defaultConfig)

        let (redacted1, entries1) = store.redact(content: text, matches: matches, filePath: "/tmp/test.txt")
        let (redacted2, entries2) = store.redact(content: text, matches: matches, filePath: "/tmp/test.txt")

        XCTAssertEqual(redacted1, redacted2)
        XCTAssertEqual(entries1.count, entries2.count)
        XCTAssertEqual(entries1[0].placeholder, entries2[0].placeholder)
    }

    func testUnresolvedPlaceholders() {
        let store = RedactionStore()
        let content = "value: __PW_FAKE_PLACEHOLDER_1__"

        let result = store.resolveAll(content: content)
        XCTAssertEqual(result.resolved, 0)
        XCTAssertEqual(result.unresolved, 1)
        XCTAssertEqual(result.unresolvedPlaceholders, ["__PW_FAKE_PLACEHOLDER_1__"])
        XCTAssertEqual(result.content, content)
    }

    func testClearRemovesAllMappings() {
        let store = RedactionStore()
        let text = "email: user@example.com"
        let matches = DetectionRules.scan(text, config: .defaultConfig)
        let (redacted, _) = store.redact(content: text, matches: matches, filePath: "/tmp/test.txt")

        store.clear()

        XCTAssertFalse(store.hasMappings(for: "/tmp/test.txt"))
        let result = store.resolve(content: redacted, filePath: "/tmp/test.txt")
        XCTAssertEqual(result.resolved, 0)
    }

    func testCrossFileResolve() {
        let store = RedactionStore()

        let text1 = "email: admin@corp.com"
        let matches1 = DetectionRules.scan(text1, config: .defaultConfig)
        store.redact(content: text1, matches: matches1, filePath: "/tmp/a.txt")

        let text2 = "contact: dev@corp.com"
        let matches2 = DetectionRules.scan(text2, config: .defaultConfig)
        store.redact(content: text2, matches: matches2, filePath: "/tmp/b.txt")

        // Global counters: admin@corp.com → EMAIL_1, dev@corp.com → EMAIL_2
        let mixed = "users: __PW_EMAIL_1__ and __PW_EMAIL_2__"
        let result = store.resolveAll(content: mixed)
        XCTAssertEqual(result.resolved, 2)
        XCTAssertTrue(result.content.contains("admin@corp.com"))
        XCTAssertTrue(result.content.contains("dev@corp.com"))
    }

    func testCrossFileConsistency() {
        let store = RedactionStore()
        let email = "shared@corp.com"

        let text1 = "from: \(email)"
        let matches1 = DetectionRules.scan(text1, config: .defaultConfig)
        let (redacted1, entries1) = store.redact(content: text1, matches: matches1, filePath: "/tmp/a.txt")

        let text2 = "to: \(email)"
        let matches2 = DetectionRules.scan(text2, config: .defaultConfig)
        let (redacted2, entries2) = store.redact(content: text2, matches: matches2, filePath: "/tmp/b.txt")

        // Same value across files → same placeholder
        XCTAssertEqual(entries1[0].placeholder, entries2[0].placeholder)
        XCTAssertTrue(redacted1.contains("__PW_EMAIL_1__"))
        XCTAssertTrue(redacted2.contains("__PW_EMAIL_1__"))
    }

    func testNoMatchesReturnsOriginal() {
        let store = RedactionStore()
        let text = "nothing sensitive here"
        let matches = DetectionRules.scan(text, config: .defaultConfig)
        XCTAssertTrue(matches.isEmpty)

        let (redacted, entries) = store.redact(content: text, matches: matches, filePath: "/tmp/test.txt")
        XCTAssertEqual(redacted, text)
        XCTAssertTrue(entries.isEmpty)
        XCTAssertFalse(store.hasMappings(for: "/tmp/test.txt"))
    }

    func testMultipleTypesInSameFile() {
        let store = RedactionStore()
        let text = "email: user@example.com ip: 192.168.1.100"
        let matches = DetectionRules.scan(text, config: .defaultConfig)
        XCTAssertTrue(matches.count >= 2)

        let (redacted, entries) = store.redact(content: text, matches: matches, filePath: "/tmp/test.txt")
        XCTAssertFalse(redacted.contains("user@example.com"))
        XCTAssertFalse(redacted.contains("192.168.1.100"))
        XCTAssertTrue(entries.count >= 2)

        let result = store.resolve(content: redacted, filePath: "/tmp/test.txt")
        XCTAssertEqual(result.content, text)
        XCTAssertTrue(result.resolved >= 2)
    }

    // MARK: - Custom prefix placeholder tests

    func testCustomPrefixRedact() {
        let store = RedactionStore(placeholderPrefix: "REDACTED_")
        let text = "key=user@example.com"
        let matches = DetectionRules.scan(text, config: .defaultConfig)

        let (redacted, entries) = store.redact(content: text, matches: matches, filePath: "/tmp/test.txt")
        XCTAssertFalse(redacted.contains("user@example.com"))
        XCTAssertTrue(redacted.contains("REDACTED_001"))
        XCTAssertEqual(entries[0].placeholder, "REDACTED_001")
    }

    func testCustomPrefixResolve() {
        let store = RedactionStore(placeholderPrefix: "REDACTED_")
        let text = "contact: user@example.com"
        let matches = DetectionRules.scan(text, config: .defaultConfig)
        let (redacted, _) = store.redact(content: text, matches: matches, filePath: "/tmp/test.txt")

        let result = store.resolve(content: redacted, filePath: "/tmp/test.txt")
        XCTAssertEqual(result.content, text)
        XCTAssertEqual(result.resolved, 1)
        XCTAssertEqual(result.unresolved, 0)
    }

    func testCustomPrefixSequentialNumbering() {
        let store = RedactionStore(placeholderPrefix: "SAFE_VALUE_")
        let text = "email: user@example.com ip: 192.168.1.100"
        let matches = DetectionRules.scan(text, config: .defaultConfig)

        let (redacted, entries) = store.redact(content: text, matches: matches, filePath: "/tmp/test.txt")
        XCTAssertTrue(redacted.contains("SAFE_VALUE_001"))
        XCTAssertTrue(redacted.contains("SAFE_VALUE_002"))
        XCTAssertEqual(entries.count, matches.count)

        let result = store.resolve(content: redacted, filePath: "/tmp/test.txt")
        XCTAssertEqual(result.content, text)
    }

    func testCustomPrefixCrossFileConsistency() {
        let store = RedactionStore(placeholderPrefix: "TOKEN_")
        let email = "shared@corp.com"

        let text1 = "from: \(email)"
        let matches1 = DetectionRules.scan(text1, config: .defaultConfig)
        let (_, entries1) = store.redact(content: text1, matches: matches1, filePath: "/tmp/a.txt")

        let text2 = "to: \(email)"
        let matches2 = DetectionRules.scan(text2, config: .defaultConfig)
        let (_, entries2) = store.redact(content: text2, matches: matches2, filePath: "/tmp/b.txt")

        // Same value across files → same placeholder
        XCTAssertEqual(entries1[0].placeholder, entries2[0].placeholder)
        XCTAssertEqual(entries1[0].placeholder, "TOKEN_001")
    }

    func testCustomPrefixClear() {
        let store = RedactionStore(placeholderPrefix: "PH_")
        let text = "email: user@example.com"
        let matches = DetectionRules.scan(text, config: .defaultConfig)
        store.redact(content: text, matches: matches, filePath: "/tmp/test.txt")

        store.clear()
        XCTAssertFalse(store.hasMappings(for: "/tmp/test.txt"))
    }

    func testCustomPrefixCrossFileResolve() {
        let store = RedactionStore(placeholderPrefix: "SECRET_")

        let text1 = "email: admin@corp.com"
        let matches1 = DetectionRules.scan(text1, config: .defaultConfig)
        store.redact(content: text1, matches: matches1, filePath: "/tmp/a.txt")

        let text2 = "contact: dev@corp.com"
        let matches2 = DetectionRules.scan(text2, config: .defaultConfig)
        store.redact(content: text2, matches: matches2, filePath: "/tmp/b.txt")

        let mixed = "users: SECRET_001 and SECRET_002"
        let result = store.resolveAll(content: mixed)
        XCTAssertEqual(result.resolved, 2)
        XCTAssertTrue(result.content.contains("admin@corp.com"))
        XCTAssertTrue(result.content.contains("dev@corp.com"))
    }

    func testDefaultStoreIgnoresCustomPrefixPlaceholders() {
        let store = RedactionStore()
        let content = "value: REDACTED_001"
        let result = store.resolveAll(content: content)
        // Default store should not match custom prefix patterns
        XCTAssertEqual(result.resolved, 0)
        XCTAssertEqual(result.content, content)
    }
}
