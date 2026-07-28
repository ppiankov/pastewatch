import XCTest
@testable import PastewatchCore

final class StartupSweepTests: XCTestCase {
    private var tempRoots: [URL] = []

    override func tearDownWithError() throws {
        for root in tempRoots {
            try? FileManager.default.removeItem(at: root)
        }
        tempRoots.removeAll()
        try super.tearDownWithError()
    }

    func testCandidatePathExpansionUsesInjectedHomeAndCwd() throws {
        let home = try makeTempDirectory()
        let project = home.appendingPathComponent("work/project", isDirectory: true)
        let nested = project.appendingPathComponent("nested", isDirectory: true)
        try FileManager.default.createDirectory(at: nested, withIntermediateDirectories: true)
        try write("fish one", to: home.appendingPathComponent(".config/fish/conf.d/10-one.fish"))
        try write("fish two", to: home.appendingPathComponent(".config/fish/conf.d/20-two.fish"))

        let sweep = StartupSweep(homeDirectory: home, currentDirectory: nested)
        let paths = sweep.candidatePaths().map(StartupSweep.normalizedPath)

        XCTAssertTrue(paths.contains(home.appendingPathComponent(".zshrc").path))
        XCTAssertTrue(paths.contains(home.appendingPathComponent(".zshenv").path))
        XCTAssertTrue(paths.contains(home.appendingPathComponent(".zprofile").path))
        XCTAssertTrue(paths.contains(home.appendingPathComponent(".bashrc").path))
        XCTAssertTrue(paths.contains(home.appendingPathComponent(".bash_profile").path))
        XCTAssertTrue(paths.contains(home.appendingPathComponent(".profile").path))
        XCTAssertTrue(paths.contains(home.appendingPathComponent(".config/fish/config.fish").path))
        XCTAssertTrue(paths.contains(home.appendingPathComponent(".config/fish/conf.d/10-one.fish").path))
        XCTAssertTrue(paths.contains(home.appendingPathComponent(".config/fish/conf.d/20-two.fish").path))
        XCTAssertTrue(paths.contains(nested.appendingPathComponent(".envrc").path))
        XCTAssertTrue(paths.contains(project.appendingPathComponent(".envrc").path))
        XCTAssertTrue(paths.contains(home.appendingPathComponent(".envrc").path))
    }

    func testMissingFilesAreSilent() throws {
        let home = try makeTempDirectory()
        let sweep = StartupSweep(homeDirectory: home, currentDirectory: home)

        let report = sweep.run()

        XCTAssertFalse(report.hasWarningOutput)
        XCTAssertTrue(report.warnedFiles.isEmpty)
        XCTAssertTrue(report.skippedFiles.isEmpty)
        XCTAssertTrue(report.readErrors.isEmpty)
    }

    func testLargeFilesAreSkippedWithoutReadingContents() throws {
        let home = try makeTempDirectory()
        let largeContent = String(repeating: "a", count: Int(StartupSweep.maxFileSizeBytes) + 1)
        let path = home.appendingPathComponent(".zshrc")
        try write(largeContent, to: path)

        let report = StartupSweep(homeDirectory: home, currentDirectory: home).run()

        XCTAssertTrue(report.warnedFiles.isEmpty)
        XCTAssertEqual(report.skippedFiles.map(\.path), [path.path])
        XCTAssertTrue(StartupSweepWarningRenderer.render(report)?.contains("skipped") ?? false)
        XCTAssertFalse(StartupSweepWarningRenderer.render(report)?.contains(largeContent) ?? true)
    }

    func testDetectionUsesExistingEngineAndWarningOmitsValues() throws {
        let home = try makeTempDirectory()
        let credentialValue = firstDatabaseURL
        let path = home.appendingPathComponent(".zshrc")
        try write("export DATABASE_URL=\(credentialValue)\n", to: path)

        let report = StartupSweep(homeDirectory: home, currentDirectory: home).run()
        let warning = try XCTUnwrap(StartupSweepWarningRenderer.render(report))

        XCTAssertEqual(report.warnedFiles.count, 1)
        XCTAssertEqual(report.warnedFiles.first?.findingCount, 1)
        XCTAssertEqual(report.warnedFiles.first?.lineNumbers, [1])
        XCTAssertTrue(warning.contains(path.path))
        XCTAssertTrue(warning.contains("finding(s)"))
        XCTAssertFalse(warning.contains(credentialValue))
        XCTAssertFalse(warning.contains("export DATABASE_URL"))
    }

    func testCacheSuppressesUnchangedFindings() throws {
        let home = try makeTempDirectory()
        let cacheURL = home.appendingPathComponent(".cache/startup-sweep.json")
        try write("DATABASE_URL=\(firstDatabaseURL)\n", to: home.appendingPathComponent(".zshrc"))

        let firstReport = StartupSweep(homeDirectory: home, currentDirectory: home)
            .run(cache: StartupSweepCache(url: cacheURL))
        let secondReport = StartupSweep(homeDirectory: home, currentDirectory: home)
            .run(cache: StartupSweepCache(url: cacheURL))

        XCTAssertEqual(firstReport.warnedFiles.count, 1)
        XCTAssertTrue(secondReport.warnedFiles.isEmpty)
        // WO-590@v2: repeated findings are suppressed, never reclassified as clean.
        XCTAssertEqual(secondReport.suppressedFiles.count, 1)
        XCTAssertTrue(secondReport.cleanFiles.isEmpty)
    }

    // WO-590@v2: equal count/severity findings with different identities warn independently.
    func testCacheRewarnsWhenPolicyChangesWhichFindingIsReportable() throws {
        let home = try makeTempDirectory()
        let path = home.appendingPathComponent(".zshrc")
        let cacheURL = home.appendingPathComponent(".cache/startup-sweep.json")
        let firstValue = "PW-CACHE-ALPHA"
        let secondValue = "PW-CACHE-BRAVO"
        try write("\(firstValue)\n\(secondValue)\n", to: path)

        var firstConfig = PastewatchConfig.defaultConfig
        firstConfig.customRules = [
            CustomRuleConfig(name: "cache fixture", pattern: "PW-CACHE-[A-Z]+")
        ]
        firstConfig.allowedValues = [secondValue]
        let firstReport = StartupSweep(
            homeDirectory: home,
            currentDirectory: home,
            config: firstConfig
        ).run(cache: StartupSweepCache(url: cacheURL))

        var secondConfig = firstConfig
        secondConfig.allowedValues = [firstValue]
        let secondReport = StartupSweep(
            homeDirectory: home,
            currentDirectory: home,
            config: secondConfig
        ).run(cache: StartupSweepCache(url: cacheURL))

        XCTAssertEqual(firstReport.warnedFiles.first?.findingCount, 1)
        XCTAssertEqual(secondReport.warnedFiles.first?.findingCount, 1)
        let cacheText = try String(contentsOf: cacheURL, encoding: .utf8)
        XCTAssertFalse(cacheText.contains(firstValue))
        XCTAssertFalse(cacheText.contains(secondValue))
    }

    // WO-590@v2: old cache entries cannot suppress findings after identity is introduced.
    func testLegacyCacheSchemaIsInvalidated() throws {
        let home = try makeTempDirectory()
        let path = home.appendingPathComponent(".zshrc")
        let cacheURL = home.appendingPathComponent(".cache/startup-sweep.json")
        try write("DATABASE_URL=\(firstDatabaseURL)\n", to: path)
        try FileManager.default.createDirectory(
            at: cacheURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        let legacy: [String: Any] = [
            "schemaVersion": 1,
            "entries": [
                path.path: [
                    "contentHash": "legacy",
                    "findingCount": 1,
                    "severitySummary": ["critical": 1]
                ]
            ]
        ]
        try JSONSerialization.data(withJSONObject: legacy).write(to: cacheURL)

        let report = StartupSweep(homeDirectory: home, currentDirectory: home)
            .run(cache: StartupSweepCache(url: cacheURL))

        XCTAssertEqual(report.warnedFiles.count, 1)
    }

    func testCacheRewarnsOnContentHashChange() throws {
        let home = try makeTempDirectory()
        let path = home.appendingPathComponent(".zshrc")
        let cacheURL = home.appendingPathComponent(".cache/startup-sweep.json")
        try write("DATABASE_URL=\(firstDatabaseURL)\n", to: path)

        _ = StartupSweep(homeDirectory: home, currentDirectory: home)
            .run(cache: StartupSweepCache(url: cacheURL))
        try write("DATABASE_URL=\(secondDatabaseURL)\n", to: path)
        let report = StartupSweep(homeDirectory: home, currentDirectory: home)
            .run(cache: StartupSweepCache(url: cacheURL))

        XCTAssertEqual(report.warnedFiles.count, 1)
        XCTAssertEqual(report.warnedFiles.first?.findingCount, 1)
    }

    func testCacheRewarnsOnFindingCountChange() throws {
        let home = try makeTempDirectory()
        let path = home.appendingPathComponent(".zshrc")
        let cacheURL = home.appendingPathComponent(".cache/startup-sweep.json")
        try write("DATABASE_URL=\(firstDatabaseURL)\n", to: path)

        _ = StartupSweep(homeDirectory: home, currentDirectory: home)
            .run(cache: StartupSweepCache(url: cacheURL))
        try write(
            """
            DATABASE_URL=\(firstDatabaseURL)
            CACHE_URL=\(cacheDatabaseURL)
            """,
            to: path
        )
        let report = StartupSweep(homeDirectory: home, currentDirectory: home)
            .run(cache: StartupSweepCache(url: cacheURL))

        XCTAssertEqual(report.warnedFiles.count, 1)
        XCTAssertEqual(report.warnedFiles.first?.findingCount, 2)
    }

    // WO-551@v2: cached clean scans cannot hide later allowlist-aware findings.
    func testCleanCacheDoesNotHideLaterFindingsAfterHashChange() throws {
        let home = try makeTempDirectory()
        let path = home.appendingPathComponent(".zshrc")
        let cacheURL = home.appendingPathComponent(".cache/startup-sweep.json")
        try write("export PATH=/usr/bin\n", to: path)

        let cleanReport = StartupSweep(homeDirectory: home, currentDirectory: home)
            .run(cache: StartupSweepCache(url: cacheURL))
        try write("DATABASE_URL=\(firstDatabaseURL)\n", to: path)
        let dirtyReport = StartupSweep(homeDirectory: home, currentDirectory: home)
            .run(cache: StartupSweepCache(url: cacheURL))

        XCTAssertTrue(cleanReport.warnedFiles.isEmpty)
        XCTAssertEqual(dirtyReport.warnedFiles.count, 1)
    }

    // WO-551@v2: startup sweep applies the configured allowlist before reporting.
    func testConfigAllowlistSuppressesStartupFinding() throws {
        let home = try makeTempDirectory()
        let value = firstDatabaseURL
        try write("ACCESS_KEY=\(value)\n", to: home.appendingPathComponent(".zshrc"))
        var config = PastewatchConfig.defaultConfig
        config.allowedValues = [value]

        let report = StartupSweep(
            homeDirectory: home,
            currentDirectory: home,
            config: config
        ).run()

        XCTAssertTrue(report.warnedFiles.isEmpty)
    }

    // WO-578@v2: .envrc values are parsed as dotenv content before custom-rule scanning.
    func testQuotedEnvrcValueUsesFormatAwareScanning() throws {
        let home = try makeTempDirectory()
        let value = "STARTUP-CUSTOM-12345"
        try write("CUSTOM_TOKEN=\"\(value)\"\n", to: home.appendingPathComponent(".envrc"))
        var config = PastewatchConfig.defaultConfig
        config.customRules = [
            CustomRuleConfig(name: "startup fixture", pattern: "^\(value)$", severity: "high"),
        ]

        let report = StartupSweep(
            homeDirectory: home,
            currentDirectory: home,
            config: config
        ).run()

        XCTAssertEqual(report.warnedFiles.count, 1)
        XCTAssertEqual(report.warnedFiles.first?.findingCount, 1)
    }

    // WO-578@v2: trusted startup files honor explicit inline allow directives.
    func testInlineAllowSuppressesStartupFinding() throws {
        let home = try makeTempDirectory()
        let value = firstDatabaseURL
        try write(
            "DATABASE_URL=\(value) # pastewatch:allow\n",
            to: home.appendingPathComponent(".envrc")
        )

        let report = StartupSweep(homeDirectory: home, currentDirectory: home).run()

        XCTAssertTrue(report.warnedFiles.isEmpty)
        XCTAssertEqual(report.cleanFiles.count, 1)
    }

    // WO-578@v2: known test credentials follow the trusted-file guard policy.
    func testKnownTestCredentialIsNotReported() throws {
        let home = try makeTempDirectory()
        let testCredential = "AKIA" + "IOSFODNN7EXAMPLE"
        try write(
            "AWS_ACCESS_KEY_ID=\(testCredential)\n",
            to: home.appendingPathComponent(".envrc")
        )

        let report = StartupSweep(homeDirectory: home, currentDirectory: home).run()

        XCTAssertTrue(report.warnedFiles.isEmpty)
        XCTAssertEqual(report.cleanFiles.count, 1)
    }

    // WO-578@v2: malformed dotenv-shaped content falls back to raw fail-closed scanning.
    func testMalformedEnvrcStillScansRawContent() throws {
        let home = try makeTempDirectory()
        let credential = "AIza" + String(repeating: "R", count: 35)
        try write("broken \(credential)\n", to: home.appendingPathComponent(".envrc"))

        let report = StartupSweep(homeDirectory: home, currentDirectory: home).run()

        XCTAssertEqual(report.warnedFiles.count, 1)
        XCTAssertEqual(report.warnedFiles.first?.findingCount, 1)
    }

    // WO-578@v2: shared-pattern failures are reported and never persisted as clean scans.
    func testSharedPatternFailureDoesNotPopulateCleanCache() throws {
        let home = try makeTempDirectory()
        let cacheURL = home.appendingPathComponent(".cache/startup-sweep.json")
        let credential = firstDatabaseURL
        try write("DATABASE_URL=\(credential)\n", to: home.appendingPathComponent(".zshrc"))
        var config = PastewatchConfig.defaultConfig
        config.sharedPatternFiles = [home.appendingPathComponent("missing-patterns.json").path]

        let report = StartupSweep(
            homeDirectory: home,
            currentDirectory: home,
            config: config
        ).run(cache: StartupSweepCache(url: cacheURL))

        XCTAssertTrue(report.warnedFiles.isEmpty)
        XCTAssertTrue(report.cleanFiles.isEmpty)
        XCTAssertEqual(report.sharedPatternErrors.count, 1)
        XCTAssertFalse(StartupSweepWarningRenderer.render(report)?.contains(credential) ?? true)
        let cache = try JSONDecoder().decode(StartupSweepCacheState.self, from: Data(contentsOf: cacheURL))
        XCTAssertTrue(cache.entries.isEmpty)
    }

    private func makeTempDirectory() throws -> URL {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("pastewatch-startup-sweep-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        tempRoots.append(root)
        return root
    }

    private func write(_ content: String, to url: URL) throws {
        try FileManager.default.createDirectory(
            at: url.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try content.write(to: url, atomically: true, encoding: .utf8)
    }

    private var firstDatabaseURL: String {
        // WO-542: startup-sweep behavior must not depend on default-off ambiguous detectors.
        "AKIA" + "QWERTYUIOPASDFGH"
    }

    private var secondDatabaseURL: String {
        "AKIA" + "ZXCVBNMASDFGHJKL"
    }

    private var cacheDatabaseURL: String {
        "AKIA" + "MNBVCXZLKJHGFDSA"
    }
}
