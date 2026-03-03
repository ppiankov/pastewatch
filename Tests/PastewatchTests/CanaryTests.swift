import XCTest
@testable import PastewatchCore

final class CanaryTests: XCTestCase {

    // MARK: - Generate

    func testGenerateProducesAllTypes() {
        let manifest = CanaryGenerator.generate()
        XCTAssertEqual(manifest.canaries.count, 7)

        let types = Set(manifest.canaries.map { $0.type })
        XCTAssertTrue(types.contains("AWS Key"))
        XCTAssertTrue(types.contains("GitHub Token"))
        XCTAssertTrue(types.contains("OpenAI Key"))
        XCTAssertTrue(types.contains("Anthropic Key"))
        XCTAssertTrue(types.contains("DB Connection"))
        XCTAssertTrue(types.contains("Stripe Key"))
        XCTAssertTrue(types.contains("API Key"))
    }

    func testGenerateAWSKeyFormat() {
        let token = CanaryGenerator.generateAWSKey(prefix: "test")
        XCTAssertTrue(token.value.hasPrefix("AKIA"))
        XCTAssertEqual(token.value.count, 20)
        // After AKIA, all chars must be [0-9A-Z]
        let suffix = String(token.value.dropFirst(4))
        XCTAssertTrue(suffix.allSatisfy { $0.isUppercase || $0.isNumber })
    }

    func testGenerateGitHubTokenFormat() {
        let token = CanaryGenerator.generateGitHubToken(prefix: "test")
        XCTAssertTrue(token.value.hasPrefix("ghp_"))
        XCTAssertEqual(token.value.count, 40)
    }

    func testGenerateOpenAIKeyFormat() {
        let token = CanaryGenerator.generateOpenAIKey(prefix: "test")
        XCTAssertTrue(token.value.hasPrefix("sk-proj-"))
        XCTAssertGreaterThanOrEqual(token.value.count, 28)
    }

    func testGenerateAnthropicKeyFormat() {
        let token = CanaryGenerator.generateAnthropicKey(prefix: "test")
        XCTAssertTrue(token.value.hasPrefix("sk-ant-api03-"))
        XCTAssertGreaterThanOrEqual(token.value.count, 33)
    }

    func testGenerateDBURLFormat() {
        let token = CanaryGenerator.generateDBURL(prefix: "myapp")
        XCTAssertTrue(token.value.hasPrefix("postgres://"))
        XCTAssertTrue(token.value.contains("myapp_user"))
        XCTAssertTrue(token.value.contains("myapp_db"))
        XCTAssertTrue(token.value.contains("canary.internal:5432"))
    }

    func testGenerateStripeKeyFormat() {
        let token = CanaryGenerator.generateStripeKey(prefix: "test")
        XCTAssertTrue(token.value.hasPrefix("sk_test_"))
        XCTAssertGreaterThanOrEqual(token.value.count, 32)
    }

    func testGenerateGenericAPIKeyFormat() {
        let token = CanaryGenerator.generateGenericAPIKey(prefix: "test")
        XCTAssertTrue(token.value.hasPrefix("token_"))
        XCTAssertGreaterThanOrEqual(token.value.count, 26)
    }

    // MARK: - Prefix

    func testPrefixEmbedded() {
        let manifest = CanaryGenerator.generate(prefix: "myproject")
        let aws = manifest.canaries.first { $0.type == "AWS Key" }
        XCTAssertTrue(aws?.value.contains("MYPROJECT") == true)

        let gh = manifest.canaries.first { $0.type == "GitHub Token" }
        XCTAssertTrue(gh?.value.contains("myproject") == true)

        let db = manifest.canaries.first { $0.type == "DB Connection" }
        XCTAssertTrue(db?.value.contains("myproject") == true)
    }

    func testDefaultPrefix() {
        let manifest = CanaryGenerator.generate()
        XCTAssertEqual(manifest.prefix, "canary")
        let aws = manifest.canaries.first { $0.type == "AWS Key" }
        XCTAssertTrue(aws?.value.contains("CANARY") == true)
    }

    // MARK: - Verify

    func testVerifyAllDetected() {
        let manifest = CanaryGenerator.generate()
        let results = CanaryGenerator.verify(manifest: manifest)

        XCTAssertEqual(results.count, 7)
        for result in results {
            XCTAssertTrue(result.detected, "\(result.type) not detected")
            XCTAssertNotNil(result.detectedAs, "\(result.type) detectedAs is nil")
        }
    }

    func testVerifyDetectionTypes() {
        let manifest = CanaryGenerator.generate()
        let results = CanaryGenerator.verify(manifest: manifest)

        let aws = results.first { $0.type == "AWS Key" }
        XCTAssertEqual(aws?.detectedAs, "AWS Key")

        let openai = results.first { $0.type == "OpenAI Key" }
        XCTAssertEqual(openai?.detectedAs, "OpenAI Key")

        let anthropic = results.first { $0.type == "Anthropic Key" }
        XCTAssertEqual(anthropic?.detectedAs, "Anthropic Key")

        let db = results.first { $0.type == "DB Connection" }
        XCTAssertEqual(db?.detectedAs, "DB Connection")
    }

    // MARK: - Check

    func testCheckFindsLeakedCanary() {
        let manifest = CanaryGenerator.generate(prefix: "leak")
        let awsValue = manifest.canaries.first { $0.type == "AWS Key" }!.value
        let logContent = "some log line: used key \(awsValue) at 10:00"

        let results = CanaryGenerator.checkLog(manifest: manifest, logContent: logContent)
        let aws = results.first { $0.type == "AWS Key" }
        XCTAssertTrue(aws?.found == true)

        // Other types should not be found
        let gh = results.first { $0.type == "GitHub Token" }
        XCTAssertFalse(gh?.found == true)
    }

    func testCheckCleanLog() {
        let manifest = CanaryGenerator.generate()
        let logContent = "normal log entry without any secrets"
        let results = CanaryGenerator.checkLog(manifest: manifest, logContent: logContent)

        for result in results {
            XCTAssertFalse(result.found, "\(result.type) found in clean log")
        }
    }

    // MARK: - Manifest Roundtrip

    func testManifestRoundtrip() throws {
        let manifest = CanaryGenerator.generate(prefix: "roundtrip")

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try encoder.encode(manifest)

        let decoded = try JSONDecoder().decode(CanaryManifest.self, from: data)
        XCTAssertEqual(decoded.prefix, "roundtrip")
        XCTAssertEqual(decoded.canaries.count, 7)
        XCTAssertEqual(decoded.generatedAt, manifest.generatedAt)

        for (original, roundtripped) in zip(manifest.canaries, decoded.canaries) {
            XCTAssertEqual(original.type, roundtripped.type)
            XCTAssertEqual(original.value, roundtripped.value)
        }
    }

    // MARK: - Uniqueness

    func testUniqueValues() {
        let manifest1 = CanaryGenerator.generate()
        let manifest2 = CanaryGenerator.generate()

        let values1 = Set(manifest1.canaries.map { $0.value })
        let values2 = Set(manifest2.canaries.map { $0.value })
        // At least some values should differ (randomness)
        XCTAssertNotEqual(values1, values2)
    }
}
