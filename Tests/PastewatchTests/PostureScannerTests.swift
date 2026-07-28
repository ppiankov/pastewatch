import ArgumentParser
import XCTest
@testable import PastewatchCLI
@testable import PastewatchCore

final class PostureScannerTests: XCTestCase {
    private enum FixtureScanError: Error {
        case failed
    }

    // MARK: - Aggregate

    // WO-553@v3: an explicitly empty enumeration is still complete.
    func testAggregateEmptyRepos() {
        let report = PostureScanner.aggregate(org: "testorg", summaries: [], totalRepos: 0)
        XCTAssertEqual(report.totalFindings, 0)
        XCTAssertEqual(report.reposScanned, 0)
        XCTAssertEqual(report.organization, "testorg")
        XCTAssertTrue(report.repoEnumerationComplete)
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

    // WO-553@v3: repository enumeration has no fixed result cap.
    func testEnumerationUsesUnboundedGitHubPagination() {
        let arguments = PostureScanner.enumerateReposArguments(org: "example")
        XCTAssertEqual(arguments.first, "api")
        XCTAssertTrue(arguments.contains("--paginate"))
        XCTAssertTrue(arguments.contains("orgs/example/repos?per_page=100"))
        XCTAssertFalse(arguments.contains("--limit"))
    }

    // WO-553@v3: documented user accounts route to the users API, while
    // organizations retain the orgs endpoint.
    func testEnumerationRoutesByGitHubOwnerType() {
        XCTAssertEqual(
            PostureScanner.repositoryOwnerTypeArguments(owner: "example"),
            ["api", "users/example", "--jq", ".type"]
        )
        XCTAssertTrue(
            PostureScanner.enumerateReposArguments(owner: "example", ownerType: .user)
                .contains("users/example/repos?per_page=100")
        )
        XCTAssertTrue(
            PostureScanner.enumerateReposArguments(owner: "example", ownerType: .organization)
                .contains("orgs/example/repos?per_page=100")
        )
    }

    // WO-553@v3: successful diagnostics stay on stderr and cannot become repo names.
    func testRunCommandKeepsSuccessfulStderrSeparate() throws {
        let output = try PostureScanner.runCommand(
            "/bin/sh",
            ["-c", "printf 'repo-one\\n'; printf 'diagnostic\\n' >&2"]
        )

        XCTAssertEqual(output, "repo-one\n")
        XCTAssertFalse(output.contains("diagnostic"))
    }

    // WO-553@v3: historical artifacts cannot claim unrecorded completeness.
    func testLegacyReportDoesNotClaimCompleteEnumeration() throws {
        let json = """
        {
          "version":"1","generatedAt":"2025-01-01T00:00:00Z","organization":"org",
          "totalRepos":1,"reposScanned":1,"totalFindings":0,
          "severityBreakdown":{"critical":0,"high":0,"medium":0,"low":0},
          "repositories":[]
        }
        """
        let report = try JSONDecoder().decode(PostureReport.self, from: Data(json.utf8))
        XCTAssertFalse(report.repoEnumerationComplete)
        XCTAssertTrue(report.repoEnumerationCapped)
        XCTAssertTrue(PostureFormatter.formatText(report).contains("enumeration incomplete"))
        XCTAssertTrue(PostureFormatter.formatMarkdown(report).contains("enumeration incomplete"))
    }

    func testFormatJSONRoundtrip() throws {
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
        let data = try XCTUnwrap(json.data(using: .utf8))
        let decoded = try JSONDecoder().decode(PostureReport.self, from: data)
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

    // WO-575@v2: skipped scans reduce completeness instead of becoming clean summaries.
    func testAggregateDisclosesSkippedRepositories() throws {
        let scanned = RepositorySummary(
            name: "scanned",
            totalFindings: 0,
            filesAffected: 0,
            severityBreakdown: SeverityBreakdown(critical: 0, high: 0, medium: 0, low: 0),
            typeGroups: [],
            hotSpots: []
        )

        let report = PostureScanner.aggregate(
            org: "example",
            summaries: [scanned],
            totalRepos: 2
        )

        XCTAssertEqual(report.reposScanned, 1)
        XCTAssertEqual(report.reposSkipped, 1)
        XCTAssertFalse(report.repoScanComplete)
        XCTAssertTrue(PostureFormatter.formatText(report).contains("Repos skipped: 1 (scan incomplete)"))
        XCTAssertTrue(PostureFormatter.formatMarkdown(report).contains("**Repos skipped:** 1 (scan incomplete)"))

        let decoded = try JSONDecoder().decode(
            PostureReport.self,
            from: try XCTUnwrap(PostureFormatter.formatJSON(report).data(using: .utf8))
        )
        XCTAssertEqual(decoded.reposSkipped, 1)
        XCTAssertFalse(decoded.repoScanComplete)
    }

    // WO-575@v2: historical JSON derives scan completeness when the new fields are absent.
    func testLegacyReportDerivesSkippedRepositoryCount() throws {
        let json = """
        {
          "version": "1",
          "generatedAt": "2025-01-01T00:00:00Z",
          "organization": "example",
          "totalRepos": 3,
          "reposScanned": 2,
          "totalFindings": 0,
          "severityBreakdown": {"critical": 0, "high": 0, "medium": 0, "low": 0},
          "repositories": []
        }
        """

        let report = try JSONDecoder().decode(
            PostureReport.self,
            from: try XCTUnwrap(json.data(using: .utf8))
        )

        XCTAssertEqual(report.reposSkipped, 1)
        XCTAssertFalse(report.repoScanComplete)
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

    // WO-575@v2: detector-configuration failures propagate instead of producing clean posture data.
    func testScanRepoPropagatesSharedPatternFailure() throws {
        let tempDir = NSTemporaryDirectory() + "posture-test-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: tempDir) }
        try "TOKEN=ordinary-value\n".write(
            toFile: (tempDir as NSString).appendingPathComponent("config.env"),
            atomically: true,
            encoding: .utf8
        )
        var config = PastewatchConfig.defaultConfig
        config.sharedPatternFiles = [
            (tempDir as NSString).appendingPathComponent("missing-patterns.json"),
        ]

        XCTAssertThrowsError(
            try PostureScanner.scanRepo(at: tempDir, name: "invalid-config", config: config)
        ) { error in
            XCTAssertTrue(error is SharedSecretPatternLoadError)
        }
    }

    // WO-591: command execution maps detector failures to exit 2 before rendering.
    func testPostureExecutionRejectsSharedPatternFailureWithoutReport() throws {
        var command = Posture()
        command.repos = ["example/repository"]
        let artifact = FileManager.default.temporaryDirectory
            .appendingPathComponent("pastewatch-posture-\(UUID().uuidString).json")
        defer { try? FileManager.default.removeItem(at: artifact) }

        XCTAssertThrowsError(
            try command.run(
                config: .defaultConfig,
                cloneRepo: { _, _, baseDir in baseDir },
                scanRepo: { _, _, _ in
                    throw SharedSecretPatternLoadError(
                        path: "fixture",
                        message: "unavailable"
                    )
                },
                emitReport: { _ in
                    try Data("partial".utf8).write(to: artifact)
                }
            )
        ) { error in
            XCTAssertEqual((error as? ExitCode)?.rawValue, 2)
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: artifact.path))
    }

    // WO-591: a later scan failure cannot emit an earlier repository as a partial report.
    func testPostureExecutionRejectsLaterScanFailureWithoutPartialReport() throws {
        var command = Posture()
        command.repos = ["example/complete", "example/failure"]
        var emitted = false

        XCTAssertThrowsError(
            try command.run(
                config: .defaultConfig,
                cloneRepo: { _, _, baseDir in baseDir },
                scanRepo: { _, name, _ in
                    if name == "failure" { throw FixtureScanError.failed }
                    return RepositorySummary(
                        name: name,
                        totalFindings: 0,
                        filesAffected: 0,
                        severityBreakdown: SeverityBreakdown(
                            critical: 0,
                            high: 0,
                            medium: 0,
                            low: 0
                        ),
                        typeGroups: [],
                        hotSpots: []
                    )
                },
                emitReport: { _ in emitted = true }
            )
        ) { error in
            XCTAssertEqual((error as? ExitCode)?.rawValue, 2)
        }
        XCTAssertFalse(emitted)
    }

    // WO-591: clone failures remain explicit incomplete evidence and still render once.
    func testPostureExecutionRendersCloneFailureAsIncompleteReport() throws {
        var command = Posture()
        command.repos = ["example/skipped", "example/complete"]
        var emittedReport: PostureReport?

        try command.run(
            config: .defaultConfig,
            cloneRepo: { _, name, baseDir in
                if name == "skipped" { throw FixtureScanError.failed }
                return baseDir
            },
            scanRepo: { _, name, _ in
                RepositorySummary(
                    name: name,
                    totalFindings: 0,
                    filesAffected: 0,
                    severityBreakdown: SeverityBreakdown(
                        critical: 0,
                        high: 0,
                        medium: 0,
                        low: 0
                    ),
                    typeGroups: [],
                    hotSpots: []
                )
            },
            emitReport: { emittedReport = $0 }
        )

        XCTAssertEqual(emittedReport?.reposScanned, 1)
        XCTAssertEqual(emittedReport?.reposSkipped, 1)
        XCTAssertEqual(emittedReport?.repoScanComplete, false)
    }
}
