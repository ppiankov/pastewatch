import XCTest
@testable import Pastewatch

final class ObfuscatorTests: XCTestCase {
    let config = PastewatchConfig.defaultConfig

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
}
