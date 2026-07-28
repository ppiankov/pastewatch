import XCTest
@testable import PastewatchCore

final class FailOnSeverityTests: XCTestCase {

    func testSeverityOrdering() {
        XCTAssertTrue(Severity.critical > Severity.high)
        XCTAssertTrue(Severity.high > Severity.medium)
        XCTAssertTrue(Severity.medium > Severity.low)
        XCTAssertFalse(Severity.low > Severity.critical)
    }

    func testSeverityComparableEquality() {
        XCTAssertTrue(Severity.critical >= Severity.critical)
        XCTAssertTrue(Severity.high >= Severity.high)
        XCTAssertFalse(Severity.low >= Severity.high)
    }

    func testSeverityInitFromString() {
        XCTAssertEqual(Severity(rawValue: "critical"), .critical)
        XCTAssertEqual(Severity(rawValue: "high"), .high)
        XCTAssertEqual(Severity(rawValue: "medium"), .medium)
        XCTAssertEqual(Severity(rawValue: "low"), .low)
        XCTAssertNil(Severity(rawValue: "extreme"))
    }

    func testThresholdFilteringLogic() {
        // Simulate: matches with only medium severity, threshold = high
        // Should NOT fail (no match meets threshold)
        let mediumTypes: [SensitiveDataType] = [.ipAddress, .hostname]
        for type in mediumTypes {
            XCTAssertTrue(type.severity < Severity.high,
                          "\(type.rawValue) should be below high threshold")
        }
    }

    func testThresholdCriticalMatchExceedsHighThreshold() {
        // AWS key is critical, threshold high → should fail
        let awsSeverity = SensitiveDataType.awsKey.severity
        XCTAssertTrue(awsSeverity >= Severity.high)
        XCTAssertTrue(awsSeverity >= Severity.critical)
    }

    // WO-580@v3: external scripts depend on these distinct stable outcomes.
    func testScanExitContractPreservesNumericBehavior() {
        XCTAssertEqual(ScanExitContract.clean, 0)
        XCTAssertEqual(ScanExitContract.operationalFailure, 2)
        XCTAssertEqual(ScanExitContract.findingsDetected, 6)
        XCTAssertEqual(GuardExitContract.blocked, 2)
    }
}
