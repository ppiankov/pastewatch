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
        "postgres" + "://user:pass@host:5432/db"
    }

    private var secondDatabaseURL: String {
        "postgres" + "://user:pass@host:5432/otherdb"
    }

    private var cacheDatabaseURL: String {
        "redis" + "://user:pass@host:6379/0"
    }
}
