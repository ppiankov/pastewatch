import XCTest
@testable import PastewatchCore

final class DirectoryScannerTests: XCTestCase {
    let config = PastewatchConfig.defaultConfig
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
        let proto = ["postgres", "://user:pass@host:5432/mydb"].joined()
        let envContent = "DB_URL=\(proto)\n"
        try envContent.write(toFile: testDir + "/.env", atomically: true, encoding: .utf8)

        let results = try DirectoryScanner.scan(directory: testDir, config: config)
        XCTAssertGreaterThan(results.count, 0)
        XCTAssertEqual(results[0].filePath, ".env")
    }

    func testScansRecursively() throws {
        let subdir = testDir + "/subdir"
        try FileManager.default.createDirectory(atPath: subdir, withIntermediateDirectories: true)
        let proto = ["postgres", "://user:pass@host:5432/mydb"].joined()
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
        try "test@company.com".write(toFile: testDir + "/data.txt", atomically: true, encoding: .utf8)

        let results = try DirectoryScanner.scan(directory: testDir, config: config)
        XCTAssertGreaterThan(results.count, 0)
        // Should be relative, not absolute
        XCTAssertFalse(results[0].filePath.hasPrefix("/"))
    }

    // MARK: - Bail (early exit)

    func testBailReturnsOneResult() throws {
        let conn1 = ["postgres", "://user:pass@host1:5432/db1"].joined()
        let conn2 = ["postgres", "://user:pass@host2:5432/db2"].joined()
        try "DB_URL=\(conn1)".write(toFile: testDir + "/a.env", atomically: true, encoding: .utf8)
        try "DB_URL=\(conn2)".write(toFile: testDir + "/b.env", atomically: true, encoding: .utf8)

        let all = try DirectoryScanner.scan(directory: testDir, config: config)
        XCTAssertGreaterThan(all.count, 1, "should find multiple files without bail")

        let bailed = try DirectoryScanner.scan(directory: testDir, config: config, bail: true)
        XCTAssertEqual(bailed.count, 1, "bail should return exactly one result")
    }

    func testBailWithNoFindingsReturnsEmpty() throws {
        try "clean content".write(toFile: testDir + "/clean.txt", atomically: true, encoding: .utf8)

        let results = try DirectoryScanner.scan(directory: testDir, config: config, bail: true)
        XCTAssertEqual(results.count, 0)
    }

    func testBailStillHasMatches() throws {
        let conn = ["postgres", "://user:pass@host:5432/mydb"].joined()
        try "DB_URL=\(conn)".write(toFile: testDir + "/a.env", atomically: true, encoding: .utf8)

        let results = try DirectoryScanner.scan(directory: testDir, config: config, bail: true)
        XCTAssertEqual(results.count, 1)
        XCTAssertGreaterThan(results[0].matches.count, 0)
    }
}
