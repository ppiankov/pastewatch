import XCTest
@testable import PastewatchCore

final class SeverityTests: XCTestCase {

    func testCriticalTypes() {
        let criticalTypes: [SensitiveDataType] = [
            .awsKey, .genericApiKey, .sshPrivateKey,
            .dbConnectionString, .jwtToken, .creditCard, .credential,
            .slackWebhook, .discordWebhook, .azureConnectionString, .gcpServiceAccount,
            .openaiKey, .anthropicKey, .huggingfaceToken, .groqKey,
            .npmToken, .pypiToken, .rubygemsToken,
            .gitlabToken, .telegramBotToken, .sendgridKey, .shopifyToken, .digitaloceanToken
        ]
        for type in criticalTypes {
            XCTAssertEqual(type.severity, .critical, "\(type.rawValue) should be critical")
        }
    }

    func testHighTypes() {
        XCTAssertEqual(SensitiveDataType.email.severity, .high)
        XCTAssertEqual(SensitiveDataType.phone.severity, .high)
    }

    func testMediumTypes() {
        XCTAssertEqual(SensitiveDataType.ipAddress.severity, .medium)
        XCTAssertEqual(SensitiveDataType.filePath.severity, .medium)
        XCTAssertEqual(SensitiveDataType.hostname.severity, .medium)
    }

    func testLowTypes() {
        XCTAssertEqual(SensitiveDataType.uuid.severity, .low)
    }

    func testSarifLevelMapping() {
        XCTAssertEqual(Severity.critical.sarifLevel, "error")
        XCTAssertEqual(Severity.high.sarifLevel, "error")
        XCTAssertEqual(Severity.medium.sarifLevel, "warning")
        XCTAssertEqual(Severity.low.sarifLevel, "note")
    }

    // WO-559@v2: product policies retain independent named defaults.
    func testPolicyDefaultsAreExplicitAndIndependent() {
        XCTAssertEqual(Severity.defaultGuardThreshold, .high)
        XCTAssertEqual(Severity.defaultCustomRuleSeverity, .high)
        XCTAssertEqual(Severity.defaultRemediationThreshold, .high)
    }

    // WO-558@v2: generated hooks and CLI guards share one blocked exit status.
    func testGuardBlockedExitContract() {
        XCTAssertEqual(GuardExitContract.blocked, 2)
    }
}
