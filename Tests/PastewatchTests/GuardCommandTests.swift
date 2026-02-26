import XCTest
@testable import PastewatchCore

final class GuardCommandTests: XCTestCase {

    private var testDir: String!
    private let config = PastewatchConfig.defaultConfig

    override func setUp() {
        super.setUp()
        testDir = NSTemporaryDirectory() + "pastewatch-guard-test-\(UUID().uuidString)"
        try? FileManager.default.createDirectory(atPath: testDir, withIntermediateDirectories: true)
    }

    override func tearDown() {
        try? FileManager.default.removeItem(atPath: testDir)
        super.tearDown()
    }

    // MARK: - Core scanning logic (exercises CommandParser + DetectionRules together)

    func testBlocksFileWithSecrets() throws {
        let testFile = testDir + "/config.env"
        let key = ["AKIA", "IOSFODNN7EXAMPLE"].joined()
        try "AWS_KEY=\(key)".write(toFile: testFile, atomically: true, encoding: .utf8)

        let paths = CommandParser.extractFilePaths(from: "cat \(testFile)")
        XCTAssertEqual(paths.count, 1)

        let content = try String(contentsOfFile: paths[0], encoding: .utf8)
        let matches = DetectionRules.scan(content, config: config)
        let filtered = matches.filter { $0.effectiveSeverity >= .high }

        XCTAssertFalse(filtered.isEmpty, "Should find high+ severity secrets")
    }

    func testAllowsCleanFile() throws {
        let testFile = testDir + "/readme.txt"
        try "Hello world, nothing sensitive here".write(toFile: testFile, atomically: true, encoding: .utf8)

        let paths = CommandParser.extractFilePaths(from: "cat \(testFile)")
        XCTAssertEqual(paths.count, 1)

        let content = try String(contentsOfFile: paths[0], encoding: .utf8)
        let matches = DetectionRules.scan(content, config: config)
        let filtered = matches.filter { $0.effectiveSeverity >= .high }

        XCTAssertTrue(filtered.isEmpty, "Clean file should have no high+ findings")
    }

    func testAllowsNonExistentFile() {
        let paths = CommandParser.extractFilePaths(from: "cat /nonexistent/file.txt")
        XCTAssertEqual(paths.count, 1)

        // File doesn't exist → should not block (command will fail on its own)
        let exists = FileManager.default.fileExists(atPath: paths[0])
        XCTAssertFalse(exists)
    }

    func testSeverityThresholdFiltering() throws {
        let testFile = testDir + "/hosts.txt"
        // Email is high severity, IP is medium
        try "contact: admin@internal-corp.com\nserver: 10.0.1.50".write(
            toFile: testFile, atomically: true, encoding: .utf8)

        let content = try String(contentsOfFile: testFile, encoding: .utf8)
        let matches = DetectionRules.scan(content, config: config)

        let criticalOnly = matches.filter { $0.effectiveSeverity >= .critical }
        let highAndUp = matches.filter { $0.effectiveSeverity >= .high }

        // Critical threshold: nothing should match
        XCTAssertTrue(criticalOnly.isEmpty)
        // High threshold: email should match
        XCTAssertFalse(highAndUp.isEmpty)
    }

    func testNoFileCommandAllowed() {
        let paths = CommandParser.extractFilePaths(from: "echo hello world")
        XCTAssertTrue(paths.isEmpty, "Non-file command should extract no paths")
    }

    func testSedCommandExtractsFile() throws {
        let testFile = testDir + "/app.conf"
        try "password=s3cr3t_value_here123!".write(toFile: testFile, atomically: true, encoding: .utf8)

        let paths = CommandParser.extractFilePaths(from: "sed -i 's/old/new/' \(testFile)")
        XCTAssertEqual(paths.count, 1)
        XCTAssertEqual(paths[0], testFile)
    }
}
