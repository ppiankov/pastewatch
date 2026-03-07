import XCTest
@testable import PastewatchCore

final class PostureScannerTests: XCTestCase {

    // MARK: - Aggregate

    func testAggregateEmptyRepos() {
        let report = PostureScanner.aggregate(org: "testorg", summaries: [], totalRepos: 0)
        XCTAssertEqual(report.totalFindings, 0)
        XCTAssertEqual(report.reposScanned, 0)
        XCTAssertEqual(report.organization, "testorg")
    }

    func testAggregateSumsSeverities() {
        let summaries = [
            RepositorySummary(
                name: "repo-a", totalFindings: 3, filesAffected: 2,
                severityBreakdown: SeverityBreakdown(critical: 1, high: 1, medium: 1, low: 0),
                typeGroups: [], hotSpots: []
            ),
            RepositorySummary(
                name: "repo-b", totalFindings: 2, filesAffected: 1,
                severityBreakdown: SeverityBreakdown(critical: 0, high: 2, medium: 0, low: 0),
                typeGroups: [], hotSpots: []
            ),
        ]
        let report = PostureScanner.aggregate(org: "testorg", summaries: summaries, totalRepos: 5)
        XCTAssertEqual(report.totalFindings, 5)
        XCTAssertEqual(report.reposScanned, 2)
        XCTAssertEqual(report.totalRepos, 5)
        XCTAssertEqual(report.severityBreakdown.critical, 1)
        XCTAssertEqual(report.severityBreakdown.high, 3)
        XCTAssertEqual(report.severityBreakdown.medium, 1)
        XCTAssertEqual(report.severityBreakdown.low, 0)
    }

    func testAggregateSortsByFindings() {
        let summaries = [
            RepositorySummary(
                name: "few", totalFindings: 1, filesAffected: 1,
                severityBreakdown: SeverityBreakdown(critical: 0, high: 1, medium: 0, low: 0),
                typeGroups: [], hotSpots: []
            ),
            RepositorySummary(
                name: "many", totalFindings: 10, filesAffected: 5,
                severityBreakdown: SeverityBreakdown(critical: 5, high: 5, medium: 0, low: 0),
                typeGroups: [], hotSpots: []
            ),
        ]
        let report = PostureScanner.aggregate(org: "org", summaries: summaries, totalRepos: 2)
        XCTAssertEqual(report.repositories.first?.name, "many")
        XCTAssertEqual(report.repositories.last?.name, "few")
    }

    // MARK: - Compare

    func testCompareDetectsNewAndResolved() {
        let current = PostureReport(
            version: "1", generatedAt: "2025-01-01T00:00:00Z", organization: "org",
            totalRepos: 3, reposScanned: 3, totalFindings: 5,
            severityBreakdown: SeverityBreakdown(critical: 0, high: 5, medium: 0, low: 0),
            repositories: [
                RepositorySummary(name: "repo-a", totalFindings: 3, filesAffected: 1,
                                  severityBreakdown: SeverityBreakdown(critical: 0, high: 3, medium: 0, low: 0),
                                  typeGroups: [], hotSpots: []),
                RepositorySummary(name: "repo-c", totalFindings: 2, filesAffected: 1,
                                  severityBreakdown: SeverityBreakdown(critical: 0, high: 2, medium: 0, low: 0),
                                  typeGroups: [], hotSpots: []),
                RepositorySummary(name: "repo-b", totalFindings: 0, filesAffected: 0,
                                  severityBreakdown: SeverityBreakdown(critical: 0, high: 0, medium: 0, low: 0),
                                  typeGroups: [], hotSpots: []),
            ]
        )
        let previous = PostureReport(
            version: "1", generatedAt: "2024-12-01T00:00:00Z", organization: "org",
            totalRepos: 3, reposScanned: 3, totalFindings: 4,
            severityBreakdown: SeverityBreakdown(critical: 0, high: 4, medium: 0, low: 0),
            repositories: [
                RepositorySummary(name: "repo-a", totalFindings: 2, filesAffected: 1,
                                  severityBreakdown: SeverityBreakdown(critical: 0, high: 2, medium: 0, low: 0),
                                  typeGroups: [], hotSpots: []),
                RepositorySummary(name: "repo-b", totalFindings: 2, filesAffected: 1,
                                  severityBreakdown: SeverityBreakdown(critical: 0, high: 2, medium: 0, low: 0),
                                  typeGroups: [], hotSpots: []),
                RepositorySummary(name: "repo-c", totalFindings: 0, filesAffected: 0,
                                  severityBreakdown: SeverityBreakdown(critical: 0, high: 0, medium: 0, low: 0),
                                  typeGroups: [], hotSpots: []),
            ]
        )
        let delta = PostureScanner.compare(current: current, previous: previous)
        XCTAssertEqual(delta.newFindings, ["repo-c"])
        XCTAssertEqual(delta.resolvedFindings, ["repo-b"])
        XCTAssertEqual(delta.totalBefore, 4)
        XCTAssertEqual(delta.totalAfter, 5)
        XCTAssertTrue(delta.summary.contains("+1"))
    }

    func testCompareNoChanges() {
        let report = PostureReport(
            version: "1", generatedAt: "2025-01-01T00:00:00Z", organization: "org",
            totalRepos: 1, reposScanned: 1, totalFindings: 2,
            severityBreakdown: SeverityBreakdown(critical: 0, high: 2, medium: 0, low: 0),
            repositories: [
                RepositorySummary(name: "repo-a", totalFindings: 2, filesAffected: 1,
                                  severityBreakdown: SeverityBreakdown(critical: 0, high: 2, medium: 0, low: 0),
                                  typeGroups: [], hotSpots: []),
            ]
        )
        let delta = PostureScanner.compare(current: report, previous: report)
        XCTAssertTrue(delta.newFindings.isEmpty)
        XCTAssertTrue(delta.resolvedFindings.isEmpty)
        XCTAssertEqual(delta.totalBefore, 2)
        XCTAssertEqual(delta.totalAfter, 2)
    }

    // MARK: - Formatters

    func testFormatTextContainsOrgName() {
        let report = PostureReport(
            version: "1", generatedAt: "2025-01-01T00:00:00Z", organization: "myorg",
            totalRepos: 2, reposScanned: 2, totalFindings: 0,
            severityBreakdown: SeverityBreakdown(critical: 0, high: 0, medium: 0, low: 0),
            repositories: []
        )
        let text = PostureFormatter.formatText(report)
        XCTAssertTrue(text.contains("myorg"))
        XCTAssertTrue(text.contains("2/2"))
    }

    func testFormatJSONRoundtrip() {
        let report = PostureReport(
            version: "1", generatedAt: "2025-01-01T00:00:00Z", organization: "org",
            totalRepos: 1, reposScanned: 1, totalFindings: 3,
            severityBreakdown: SeverityBreakdown(critical: 1, high: 2, medium: 0, low: 0),
            repositories: [
                RepositorySummary(name: "repo-x", totalFindings: 3, filesAffected: 2,
                                  severityBreakdown: SeverityBreakdown(critical: 1, high: 2, medium: 0, low: 0),
                                  typeGroups: [], hotSpots: []),
            ]
        )
        let json = PostureFormatter.formatJSON(report)
        let data = json.data(using: .utf8)!
        let decoded = try! JSONDecoder().decode(PostureReport.self, from: data)
        XCTAssertEqual(decoded.totalFindings, 3)
        XCTAssertEqual(decoded.repositories.first?.name, "repo-x")
    }

    func testFormatMarkdownContainsTable() {
        let report = PostureReport(
            version: "1", generatedAt: "2025-01-01T00:00:00Z", organization: "org",
            totalRepos: 1, reposScanned: 1, totalFindings: 1,
            severityBreakdown: SeverityBreakdown(critical: 0, high: 1, medium: 0, low: 0),
            repositories: [
                RepositorySummary(name: "repo-y", totalFindings: 1, filesAffected: 1,
                                  severityBreakdown: SeverityBreakdown(critical: 0, high: 1, medium: 0, low: 0),
                                  typeGroups: [], hotSpots: []),
            ]
        )
        let md = PostureFormatter.formatMarkdown(report)
        XCTAssertTrue(md.contains("| repo-y |"))
        XCTAssertTrue(md.contains("## Posture Report"))
    }

    func testFindingsOnlyHidesCleanRepos() {
        let report = PostureReport(
            version: "1", generatedAt: "2025-01-01T00:00:00Z", organization: "org",
            totalRepos: 2, reposScanned: 2, totalFindings: 1,
            severityBreakdown: SeverityBreakdown(critical: 0, high: 1, medium: 0, low: 0),
            repositories: [
                RepositorySummary(name: "dirty", totalFindings: 1, filesAffected: 1,
                                  severityBreakdown: SeverityBreakdown(critical: 0, high: 1, medium: 0, low: 0),
                                  typeGroups: [], hotSpots: []),
                RepositorySummary(name: "clean", totalFindings: 0, filesAffected: 0,
                                  severityBreakdown: SeverityBreakdown(critical: 0, high: 0, medium: 0, low: 0),
                                  typeGroups: [], hotSpots: []),
            ]
        )
        let withClean = PostureFormatter.formatText(report, findingsOnly: false)
        XCTAssertTrue(withClean.contains("clean"))

        let withoutClean = PostureFormatter.formatText(report, findingsOnly: true)
        XCTAssertTrue(withoutClean.contains("dirty"))
        XCTAssertFalse(withoutClean.contains("Clean repositories"))
    }

    // MARK: - ScanRepo integration

    func testScanRepoOnEmptyDirectory() throws {
        let tempDir = NSTemporaryDirectory() + "posture-test-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: tempDir) }

        let config = PastewatchConfig.defaultConfig
        let summary = try PostureScanner.scanRepo(at: tempDir, name: "empty-repo", config: config)
        XCTAssertEqual(summary.name, "empty-repo")
        XCTAssertEqual(summary.totalFindings, 0)
        XCTAssertEqual(summary.filesAffected, 0)
    }

    func testScanRepoFindsSecrets() throws {
        let tempDir = NSTemporaryDirectory() + "posture-test-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: tempDir) }

        let secretFile = (tempDir as NSString).appendingPathComponent("config.py")
        let key = ["AKIA", "IOSFODNN7EXAMPLE"].joined()
        try "AWS_KEY = \"\(key)\"".write(toFile: secretFile, atomically: true, encoding: .utf8)

        let config = PastewatchConfig.defaultConfig
        let summary = try PostureScanner.scanRepo(at: tempDir, name: "leaky-repo", config: config)
        XCTAssertEqual(summary.name, "leaky-repo")
        XCTAssertGreaterThan(summary.totalFindings, 0)
        XCTAssertGreaterThan(summary.filesAffected, 0)
    }
}
