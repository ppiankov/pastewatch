import XCTest
@testable import PastewatchCore

final class GuardDecisionTests: XCTestCase {
    func testKnownTestCredentialIsSuppressed() {
        let content = ["AKIA", "IOSFODNN7EXAMPLE"].joined()
        let matches = DetectionRules.scan(content, config: .defaultConfig)

        let decision = GuardDecision.evaluate(
            matches: matches,
            content: content,
            config: .defaultConfig,
            contentTrust: .trustedFile,
            minimumSeverity: .low
        )

        XCTAssertFalse(matches.isEmpty)
        XCTAssertTrue(decision.reportableMatches.isEmpty)
        XCTAssertTrue(decision.actionableMatches.isEmpty)
    }

    func testConfigAndInlineAllowlistsUseTheSameDecisionPipeline() {
        let allowed = "AKIA" + "QWERTYUIOPASDFGH"
        let inline = "AKIA" + "ZXCVBNMASDFGHJKL"
        let content = "first=\(allowed)\nsecond=\(inline) # pastewatch:allow"
        var config = PastewatchConfig.defaultConfig
        config.allowedValues = [allowed]

        let decision = GuardDecision.evaluate(
            matches: DetectionRules.scan(content, config: config),
            content: content,
            config: config,
            contentTrust: .trustedFile,
            minimumSeverity: .critical
        )

        XCTAssertTrue(decision.reportableMatches.isEmpty)
        XCTAssertTrue(decision.actionableMatches.isEmpty)
    }

    func testBelowThresholdMatchRemainsReportableButNotActionable() {
        let content = ["admin", "@", "internal-corp.com"].joined()

        let decision = GuardDecision.evaluate(
            matches: DetectionRules.scan(content, config: .defaultConfig),
            content: content,
            config: .defaultConfig,
            contentTrust: .trustedFile,
            minimumSeverity: .critical
        )

        XCTAssertEqual(decision.reportableMatches.count, 1)
        XCTAssertTrue(decision.actionableMatches.isEmpty)
    }

    func testNilThresholdMakesEveryReportableMatchActionable() {
        let content = "AKIA" + "QWERTYUIOPASDFGH"

        let decision = GuardDecision.evaluate(
            matches: DetectionRules.scan(content, config: .defaultConfig),
            content: content,
            config: .defaultConfig,
            contentTrust: .trustedFile,
            minimumSeverity: nil
        )

        XCTAssertFalse(decision.reportableMatches.isEmpty)
        XCTAssertEqual(decision.actionableMatches, decision.reportableMatches)
    }

    func testAgentControlledContentCannotSelfAuthorizeInlineAllowComment() {
        let content = "AKIA" + "QWERTYUIOPASDFGH # pastewatch:allow"

        let decision = GuardDecision.evaluate(
            matches: DetectionRules.scan(content, config: .defaultConfig),
            content: content,
            config: .defaultConfig,
            contentTrust: .agentControlled,
            minimumSeverity: .high
        )

        XCTAssertFalse(decision.reportableMatches.isEmpty)
        XCTAssertFalse(decision.actionableMatches.isEmpty)
    }
}
