import XCTest
@testable import PastewatchCore

final class InventoryReportTests: XCTestCase {

    // MARK: - Helpers

    private func makeMatch(
        type: SensitiveDataType, value: String,
        line: Int = 1, filePath: String? = nil
    ) -> DetectedMatch {
        DetectedMatch(
            type: type, value: value,
            range: value.startIndex..<value.endIndex,
            line: line, filePath: filePath
        )
    }

    private func makeResults() -> [FileScanResult] {
        let key = ["AKIA", "IOSFODNN7EXAMPLE"].joined()
        return [
            FileScanResult(
                filePath: "config.env",
                matches: [
                    makeMatch(type: .awsKey, value: key, line: 1, filePath: "config.env"),
                    makeMatch(type: .email, value: "admin@corp.com", line: 3, filePath: "config.env")
                ],
                content: ""
            ),
            FileScanResult(
                filePath: "app.yml",
                matches: [
                    makeMatch(type: .email, value: "dev@corp.com", line: 5, filePath: "app.yml")
                ],
                content: ""
            )
        ]
    }

    // MARK: - Tests

    func testBuildReportFromResults() {
        let report = InventoryReport.build(from: makeResults(), directory: ".")
        XCTAssertEqual(report.totalFindings, 3)
        XCTAssertEqual(report.filesAffected, 2)
        XCTAssertEqual(report.entries.count, 3) // (config.env, AWS Key), (config.env, Email), (app.yml, Email)
        XCTAssertEqual(report.version, "1")
    }

    func testSeverityBreakdown() {
        let report = InventoryReport.build(from: makeResults(), directory: ".")
        // AWS key = critical (1), email = high (2)
        XCTAssertEqual(report.severityBreakdown.critical, 1)
        XCTAssertEqual(report.severityBreakdown.high, 2)
        XCTAssertEqual(report.severityBreakdown.medium, 0)
        XCTAssertEqual(report.severityBreakdown.low, 0)
    }

    func testHotSpotsSortedAndLimited() {
        // Create 12 files with varying match counts
        var results: [FileScanResult] = []
        for i in 1...12 {
            let matches = (0..<i).map { j in
                makeMatch(type: .email, value: "u\(j)@test.com", line: j + 1, filePath: "file\(i).txt")
            }
            results.append(FileScanResult(filePath: "file\(i).txt", matches: matches, content: ""))
        }
        let report = InventoryReport.build(from: results, directory: ".")
        XCTAssertEqual(report.hotSpots.count, 10) // limited to 10
        XCTAssertEqual(report.hotSpots.first?.filePath, "file12.txt") // most findings first
        XCTAssertTrue(report.hotSpots.first!.findingCount >= report.hotSpots.last!.findingCount)
    }

    func testTypeGroupsAggregation() {
        let report = InventoryReport.build(from: makeResults(), directory: ".")
        // Email appears in 2 files, AWS Key in 1
        let emailGroup = report.typeGroups.first { $0.type == "Email" }
        XCTAssertNotNil(emailGroup)
        XCTAssertEqual(emailGroup?.count, 2)
        XCTAssertEqual(emailGroup?.files.count, 2)

        let awsGroup = report.typeGroups.first { $0.type == "AWS Key" }
        XCTAssertNotNil(awsGroup)
        XCTAssertEqual(awsGroup?.count, 1)
    }

    func testEmptyResultsProduceEmptyReport() {
        let report = InventoryReport.build(from: [], directory: ".")
        XCTAssertEqual(report.totalFindings, 0)
        XCTAssertEqual(report.filesAffected, 0)
        XCTAssertTrue(report.entries.isEmpty)
        XCTAssertTrue(report.hotSpots.isEmpty)
        XCTAssertTrue(report.typeGroups.isEmpty)
    }

    func testJSONRoundTrip() throws {
        let report = InventoryReport.build(from: makeResults(), directory: "./test")
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(report)
        let decoded = try JSONDecoder().decode(InventoryReport.self, from: data)
        XCTAssertEqual(decoded.totalFindings, report.totalFindings)
        XCTAssertEqual(decoded.filesAffected, report.filesAffected)
        XCTAssertEqual(decoded.entries.count, report.entries.count)
        XCTAssertEqual(decoded.directory, report.directory)
    }

    func testCompareDetectsAddedAndRemoved() {
        let previous = InventoryReport.build(from: makeResults(), directory: ".")

        // Current has one fewer file (app.yml removed) but a new one
        let key = ["AKIA", "IOSFODNN7EXAMPLE"].joined()
        let currentResults = [
            FileScanResult(
                filePath: "config.env",
                matches: [makeMatch(type: .awsKey, value: key, line: 1, filePath: "config.env")],
                content: ""
            ),
            FileScanResult(
                filePath: "new.json",
                matches: [makeMatch(type: .email, value: "new@corp.com", line: 2, filePath: "new.json")],
                content: ""
            )
        ]
        let current = InventoryReport.build(from: currentResults, directory: ".")

        let delta = InventoryReport.compare(current: current, previous: previous)
        // Added: (new.json, Email)
        // Removed: (config.env, Email), (app.yml, Email)
        XCTAssertEqual(delta.added.count, 1)
        XCTAssertEqual(delta.added.first?.filePath, "new.json")
        XCTAssertEqual(delta.removed.count, 2)
        XCTAssertEqual(delta.totalBefore, 3)
        XCTAssertEqual(delta.totalAfter, 2)
    }

    func testCompareIdenticalReportsEmptyDelta() {
        let results = makeResults()
        let report1 = InventoryReport.build(from: results, directory: ".")
        let report2 = InventoryReport.build(from: results, directory: ".")
        let delta = InventoryReport.compare(current: report1, previous: report2)
        XCTAssertTrue(delta.added.isEmpty)
        XCTAssertTrue(delta.removed.isEmpty)
    }
}
