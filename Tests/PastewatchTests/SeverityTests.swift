import XCTest
@testable import PastewatchCore

final class SeverityTests: XCTestCase {

    func testCriticalTypes() {
        let criticalTypes: [SensitiveDataType] = [
            .awsKey, .genericApiKey, .sshPrivateKey,
            .dbConnectionString, .jwtToken, .creditCard, .credential
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
}
