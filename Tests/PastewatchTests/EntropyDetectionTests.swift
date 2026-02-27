import XCTest
@testable import PastewatchCore

final class EntropyDetectionTests: XCTestCase {

    // MARK: - Shannon entropy function

    func testLowEntropyString() {
        // Repeated characters have low entropy
        let entropy = DetectionRules.shannonEntropy("aaaaaabbbbbbccccccdddddd")
        XCTAssertLessThan(entropy, 4.0)
    }

    func testHighEntropyString() {
        // Mixed-case alphanumeric has high entropy
        let token = ["xK9mP2qL8n", "R5vT1wY6hJ3dF0sA4cE7bG"].joined()
        let entropy = DetectionRules.shannonEntropy(token)
        XCTAssertGreaterThanOrEqual(entropy, 4.0)
    }

    func testEmptyStringEntropy() {
        XCTAssertEqual(DetectionRules.shannonEntropy(""), 0.0)
    }

    // MARK: - Detection integration

    func testDetectsHighEntropyTokenWhenEnabled() {
        var config = PastewatchConfig.defaultConfig
        config.enabledTypes.append("High Entropy")
        // Use a context that doesn't trigger credential/API key patterns
        let token = ["xK9mP2qL8n", "R5vT1wY6hJ3dF0sA4cE7bG"].joined()
        let content = "the value is \(token) here"
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertTrue(matches.contains { $0.type == .highEntropyString })
    }

    func testDoesNotDetectLowEntropyString() {
        var config = PastewatchConfig.defaultConfig
        config.enabledTypes.append("High Entropy")
        let content = "export VALUE=aaaaaabbbbbbccccccddddddeeeeee"
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertFalse(matches.contains { $0.type == .highEntropyString })
    }

    func testDoesNotDuplicatePatternMatch() {
        // AWS key already caught by pattern rule should not also be flagged as high entropy
        var config = PastewatchConfig.defaultConfig
        config.enabledTypes.append("High Entropy")
        let awsKey = ["AKIA", "IOSFODNN7EXAMPLE"].joined()
        let content = "key = \(awsKey)"
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertFalse(matches.contains { $0.type == .highEntropyString })
    }

    func testShortHighEntropyStringNotDetected() {
        var config = PastewatchConfig.defaultConfig
        config.enabledTypes.append("High Entropy")
        // Only 10 chars — below minimum length of 20
        let content = "token = xK9mP2qL8n"
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertFalse(matches.contains { $0.type == .highEntropyString })
    }

    func testPureAlphabeticNotDetected() {
        var config = PastewatchConfig.defaultConfig
        config.enabledTypes.append("High Entropy")
        // All lowercase, no character mix
        let content = "value = abcdefghijklmnopqrstuvwxyz"
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertFalse(matches.contains { $0.type == .highEntropyString })
    }

    func testPureNumericNotDetected() {
        var config = PastewatchConfig.defaultConfig
        config.enabledTypes.append("High Entropy")
        let content = "id = 98765432101234567890"
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertFalse(matches.contains { $0.type == .highEntropyString })
    }

    func testGitSHANotDetected() {
        var config = PastewatchConfig.defaultConfig
        config.enabledTypes.append("High Entropy")
        // 40-char hex string resembling a git SHA
        let content = "commit = a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertFalse(matches.contains { $0.type == .highEntropyString })
    }

    // MARK: - Config tests

    func testDisabledByDefault() {
        let config = PastewatchConfig.defaultConfig
        XCTAssertFalse(config.isTypeEnabled(.highEntropyString))
        let token = ["xK9mP2qL8n", "R5vT1wY6hJ3dF0sA4cE7bG"].joined()
        let content = "secret = \(token)"
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertFalse(matches.contains { $0.type == .highEntropyString })
    }

    func testEnabledWhenInEnabledTypes() {
        var config = PastewatchConfig.defaultConfig
        config.enabledTypes.append("High Entropy")
        XCTAssertTrue(config.isTypeEnabled(.highEntropyString))
    }

    // MARK: - Tokenizer

    func testTokenizerSplitsOnDelimiters() {
        let content = "key=\"value\" other:data"
        let tokens = DetectionRules.tokenizeForEntropy(content)
        let tokenStrings = tokens.map { $0.token }
        XCTAssertTrue(tokenStrings.contains("key"))
        XCTAssertTrue(tokenStrings.contains("value"))
        XCTAssertTrue(tokenStrings.contains("other"))
        XCTAssertTrue(tokenStrings.contains("data"))
    }
}
