import XCTest
@testable import PastewatchCore

final class DirectoryScannerTests: XCTestCase {
    // WO-529@v3: scanner fixtures explicitly restore their ambiguous DB detector.
    let config: PastewatchConfig = {
        var config = PastewatchConfig.defaultConfig
        if !config.enabledTypes.contains(SensitiveDataType.dbConnectionString.rawValue) {
            config.enabledTypes.append(SensitiveDataType.dbConnectionString.rawValue)
        }
        return config
    }()
    var testDir: String!

    override func setUp() {
        super.setUp()
        testDir = NSTemporaryDirectory() + "pastewatch-test-\(UUID().uuidString)"
        try? FileManager.default.createDirectory(atPath: testDir, withIntermediateDirectories: true)
    }

    override func tearDown() {
        try? FileManager.default.removeItem(atPath: testDir)
        super.tearDown()
    }

    func testScansEnvFile() throws {
        // Build test content dynamically to avoid pre-commit hook detection
        // WO-542: keep the DB fixture detector-valid without embedding a credential literal.
        let proto = ["postgres", "://user", "CRED", "@host:5432/mydb"].joined()
        let envContent = "DB_URL=\(proto)\n"
        try envContent.write(toFile: testDir + "/.env", atomically: true, encoding: .utf8)

        let results = try DirectoryScanner.scan(directory: testDir, config: config)
        XCTAssertGreaterThan(results.count, 0)
        XCTAssertEqual(results[0].filePath, ".env")
    }

    func testScansRecursively() throws {
        let subdir = testDir + "/subdir"
        try FileManager.default.createDirectory(atPath: subdir, withIntermediateDirectories: true)
        // WO-542: keep the recursive DB fixture detector-valid without a literal.
        let proto = ["postgres", "://user", "CRED", "@host:5432/mydb"].joined()
        try "db_url: \(proto)".write(toFile: subdir + "/config.yml", atomically: true, encoding: .utf8)

        let results = try DirectoryScanner.scan(directory: testDir, config: config)
        XCTAssertGreaterThan(results.count, 0)
        let paths = results.map { $0.filePath }
        XCTAssertTrue(paths.contains("subdir/config.yml"))
    }

    func testSkipsGitDirectory() throws {
        let gitDir = testDir + "/.git"
        try FileManager.default.createDirectory(atPath: gitDir, withIntermediateDirectories: true)
        try "password=secret123".write(toFile: gitDir + "/config", atomically: true, encoding: .utf8)

        // Also add a scannable file
        try "clean content".write(toFile: testDir + "/readme.txt", atomically: true, encoding: .utf8)

        let results = try DirectoryScanner.scan(directory: testDir, config: config)
        let paths = results.flatMap { $0.matches }.compactMap { $0.filePath }
        XCTAssertFalse(paths.contains { $0.contains(".git") })
    }

    func testSkipsUnsupportedExtensions() throws {
        try "password=secret".write(toFile: testDir + "/image.png", atomically: true, encoding: .utf8)
        try "password=secret".write(toFile: testDir + "/config.yml", atomically: true, encoding: .utf8)

        let results = try DirectoryScanner.scan(directory: testDir, config: config)
        let paths = results.map { $0.filePath }
        XCTAssertFalse(paths.contains("image.png"))
    }

    func testEmptyDirectory() throws {
        let results = try DirectoryScanner.scan(directory: testDir, config: config)
        XCTAssertEqual(results.count, 0)
    }

    func testNoFindingsReturnsEmpty() throws {
        try "Hello world, nothing sensitive here".write(toFile: testDir + "/clean.txt", atomically: true, encoding: .utf8)

        let results = try DirectoryScanner.scan(directory: testDir, config: config)
        XCTAssertEqual(results.count, 0)
    }

    func testFilePathsAreRelative() throws {
        // WO-542: opt in only the email fixture used for relative path reporting.
        let email = ["test", "@company.com"].joined()
        let emailConfig: PastewatchConfig = {
            var config = PastewatchConfig.defaultConfig
            if !config.enabledTypes.contains(SensitiveDataType.email.rawValue) {
                config.enabledTypes.append(SensitiveDataType.email.rawValue)
            }
            config.obfuscate = [ObfuscateEntry(type: "email", pattern: "@company.com")]
            return config
        }()
        try email.write(toFile: testDir + "/data.txt", atomically: true, encoding: .utf8)

        let results = try DirectoryScanner.scan(directory: testDir, config: emailConfig)
        XCTAssertGreaterThan(results.count, 0)
        // Should be relative, not absolute
        XCTAssertFalse(results[0].filePath.hasPrefix("/"))
    }

    // WO-549@v2: structured matches must index the source string used for mutation.
    func testStructuredMatchRangesIndexTheOriginalContent() throws {
        let value = "CredentialValueWithEntropy123456789"
        let content = #"{"apiKey":"\#(value)"}"#
        let matches = try DirectoryScanner.scanFileContentOrThrow(
            content: content,
            ext: "json",
            relativePath: "config.json",
            config: .defaultConfig
        )
        let credential = try XCTUnwrap(matches.first { $0.type == .credential })
        XCTAssertEqual(String(content[credential.range]), value)
    }

    // WO-549@v2: identical structured values must map to distinct source occurrences.
    func testStructuredDuplicateValuesReceiveDistinctSourceRanges() throws {
        let value = "CredentialValueWithEntropy123456789"
        let content = #"{"apiKey":"\#(value)","clientSecret":"\#(value)"}"#
        let matches = try DirectoryScanner.scanFileContentOrThrow(
            content: content,
            ext: "json",
            relativePath: "config.json",
            config: .defaultConfig
        ).filter { $0.type == .credential }

        XCTAssertEqual(matches.count, 2)
        XCTAssertEqual(Set(matches.map(\.range.lowerBound)).count, 2)
        XCTAssertTrue(matches.allSatisfy { String(content[$0.range]) == value })
    }

    // WO-549@v2: repeated matches inside one parsed value retain parser-local identity.
    func testStructuredValueWithRepeatedSecretReceivesDistinctSourceRanges() throws {
        let credential = "AIza" + String(repeating: "R", count: 35)
        let content = #"{"message":"\#(credential) and \#(credential)"}"#
        let matches = try DirectoryScanner.scanFileContentOrThrow(
            content: content,
            ext: "json",
            relativePath: "config.json",
            config: .defaultConfig
        ).filter { $0.type == .googleApiKey }

        XCTAssertEqual(matches.count, 2)
        XCTAssertEqual(Set(matches.map(\.range.lowerBound)).count, 2)
    }

    // WO-549@v2: configured mutation provenance survives source-range rebasing.
    func testStructuredMatchesPreserveConfiguredObfuscationProvenance() throws {
        let value = ["operator", "@", "example.com"].joined()
        let content = #"{"contact":"\#(value)"}"#
        var configured = PastewatchConfig.defaultConfig
        configured.obfuscate = [ObfuscateEntry(type: "email", pattern: "@example.com")]

        let match = try XCTUnwrap(DirectoryScanner.scanFileContentOrThrow(
            content: content,
            ext: "json",
            relativePath: "config.json",
            config: configured
        ).first)

        XCTAssertTrue(match.mutationAuthorizationSources.contains(.configuredObfuscate))
        XCTAssertEqual(match.obfuscateRuleIdentifier, "email[0]")
    }

    // WO-550@v2: malformed structured input falls back to the raw diagnostic scan.
    func testMalformedJSONStillScansRawContent() throws {
        let credential = "AIza" + String(repeating: "R", count: 35)
        let content = #"{"token":"\#(credential)""#

        let matches = try DirectoryScanner.scanFileContentOrThrow(
            content: content,
            ext: "json",
            relativePath: "broken.json",
            config: .defaultConfig
        )

        XCTAssertTrue(matches.contains { $0.value == credential })
    }

    // WO-549@v2: decoded escapes fail closed instead of mapping to unrelated bytes.
    func testEscapedStructuredCredentialFailsClosedWhenRangeCannotBeMapped() {
        let content = #"{"apiKey":"CredentialValue\nWithEntropy123456789"}"#

        XCTAssertThrowsError(try DirectoryScanner.scanFileContentOrThrow(
            content: content,
            ext: "json",
            relativePath: "escaped.json",
            config: .defaultConfig
        )) { error in
            XCTAssertTrue(error is StructuredMatchRangeError)
        }
    }

    // WO-595@v2: directory scans reject oversized members before reading them.
    func testDirectoryScanRejectsFileSizeOverLimit() throws {
        let content = String(repeating: "a", count: 32)
        try content.write(toFile: testDir + "/large.txt", atomically: true, encoding: .utf8)
        let limits = ScanInputLimits(maximumFileBytes: 16, maximumLineBytes: 64)

        XCTAssertThrowsError(
            try DirectoryScanner.scan(directory: testDir, config: config, limits: limits)
        ) { error in
            XCTAssertEqual(
                error as? ScanInputLimitError,
                .fileBytes(actual: 32, maximum: 16)
            )
        }
    }

    // WO-595@v2: directory scans reject pathological lines even below the file cap.
    func testDirectoryScanRejectsLineLengthOverLimit() throws {
        try "123456".write(toFile: testDir + "/long-line.txt", atomically: true, encoding: .utf8)
        let limits = ScanInputLimits(maximumFileBytes: 64, maximumLineBytes: 5)

        XCTAssertThrowsError(
            try DirectoryScanner.scan(directory: testDir, config: config, limits: limits)
        ) { error in
            XCTAssertEqual(
                error as? ScanInputLimitError,
                .lineBytes(line: 1, actual: 6, maximum: 5)
            )
        }
    }

    // WO-602@v2: supported malformed text cannot be omitted from directory evidence.
    func testDirectoryScanRejectsInvalidTextEncoding() throws {
        try Data([0x61, 0xFF, 0x62]).write(
            to: URL(fileURLWithPath: testDir + "/invalid.txt")
        )

        XCTAssertThrowsError(
            try DirectoryScanner.scan(directory: testDir, config: config)
        ) { error in
            XCTAssertEqual(error as? ScanInputTextError, .invalidUTF8)
        }
    }

    // WO-600@v2: output larger than a pipe buffer must be drained before waiting for git.
    func testGitIgnoredFilesDrainsLargeOutput() throws {
        try runGit(["init", "-q"])
        try "ignored-*\n".write(
            toFile: testDir + "/.gitignore",
            atomically: true,
            encoding: .utf8
        )
        let paths = (0..<10_000).map { "ignored-\($0)-\(String(repeating: "x", count: 12))" }

        let startedAt = Date()
        let ignored = DirectoryScanner.gitIgnoredFiles(in: testDir, paths: paths)

        XCTAssertEqual(ignored.count, paths.count)
        XCTAssertLessThan(Date().timeIntervalSince(startedAt), 5)
    }

    // WO-600@v2: ignore classification falls back to scanning when output exceeds the cap.
    func testGitIgnoredFilesReturnsEmptyWhenOutputExceedsLimit() throws {
        try runGit(["init", "-q"])
        try "ignored-*\n".write(
            toFile: testDir + "/.gitignore",
            atomically: true,
            encoding: .utf8
        )
        let limits = ScanInputLimits(maximumFileBytes: 32, maximumLineBytes: 64)

        let ignored = DirectoryScanner.gitIgnoredFiles(
            in: testDir,
            paths: ["ignored-\(String(repeating: "x", count: 64))"],
            limits: limits
        )

        XCTAssertTrue(ignored.isEmpty)
    }

    // WO-600@v2: build the large check-ignore fixture without shell buffering.
    private func runGit(_ arguments: [String]) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/git")
        process.arguments = ["-C", testDir] + arguments
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        process.waitUntilExit()
        XCTAssertEqual(process.terminationStatus, 0)
    }

    // MARK: - Bail (early exit)

    func testBailReturnsOneResult() throws {
        // WO-542: preserve multiple DB findings with detector-valid composed fixtures.
        let conn1 = ["postgres", "://user", "CRED", "@host1:5432/db1"].joined()
        let conn2 = ["postgres", "://user", "CRED", "@host2:5432/db2"].joined()
        try "DB_URL=\(conn1)".write(toFile: testDir + "/a.env", atomically: true, encoding: .utf8)
        try "DB_URL=\(conn2)".write(toFile: testDir + "/b.env", atomically: true, encoding: .utf8)

        let all = try DirectoryScanner.scan(directory: testDir, config: config)
        XCTAssertGreaterThan(all.count, 1, "should find multiple files without bail")

        let bailed = try DirectoryScanner.scan(directory: testDir, config: config, bail: true)
        XCTAssertEqual(bailed.count, 1, "bail should return exactly one result")
    }

    func testBailWithNoFindingsReturnsEmpty() throws {
        try "clean content".write(toFile: testDir + "/clean.txt", atomically: true, encoding: .utf8)

        // WO-542: clean scans retain the same explicit fixture policy.
        let results = try DirectoryScanner.scan(directory: testDir, config: config, bail: true)
        XCTAssertEqual(results.count, 0)
    }

    func testBailStillHasMatches() throws {
        // WO-542: preserve bail coverage with a detector-valid composed DB fixture.
        let conn = ["postgres", "://user", "CRED", "@host:5432/mydb"].joined()
        try "DB_URL=\(conn)".write(toFile: testDir + "/a.env", atomically: true, encoding: .utf8)

        let results = try DirectoryScanner.scan(directory: testDir, config: config, bail: true)
        XCTAssertEqual(results.count, 1)
        XCTAssertGreaterThan(results[0].matches.count, 0)
    }
}
