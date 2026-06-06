import XCTest
@testable import PastewatchCore

final class GitDiffScannerTests: XCTestCase {

    // MARK: - parseDiff tests

    func testParseSingleFileSingleHunk() {
        let diff = """
        diff --git a/config.py b/config.py
        index abc1234..def5678 100644
        --- a/config.py
        +++ b/config.py
        @@ -1,3 +1,4 @@
         existing line
        +new line
         another existing
        +second new line
        """
        let files = GitDiffScanner.parseDiff(diff)
        XCTAssertEqual(files.count, 1)
        XCTAssertEqual(files[0].path, "config.py")
        XCTAssertEqual(files[0].addedLines, [2, 4])
    }

    func testParseMultiHunkFile() {
        let diff = """
        diff --git a/app.js b/app.js
        index abc..def 100644
        --- a/app.js
        +++ b/app.js
        @@ -5,3 +5,4 @@
         context
        +added at line 6
         context
        @@ -20,3 +21,4 @@
         context
        +added at line 22
         context
        """
        let files = GitDiffScanner.parseDiff(diff)
        XCTAssertEqual(files.count, 1)
        XCTAssertEqual(files[0].path, "app.js")
        XCTAssertTrue(files[0].addedLines.contains(6))
        XCTAssertTrue(files[0].addedLines.contains(22))
    }

    func testParseMultiFileDiff() {
        let diff = """
        diff --git a/file1.py b/file1.py
        index abc..def 100644
        --- a/file1.py
        +++ b/file1.py
        @@ -1,2 +1,3 @@
         line1
        +new in file1
         line2
        diff --git a/file2.js b/file2.js
        index abc..def 100644
        --- a/file2.js
        +++ b/file2.js
        @@ -1,2 +1,3 @@
         line1
        +new in file2
         line2
        """
        let files = GitDiffScanner.parseDiff(diff)
        XCTAssertEqual(files.count, 2)
        XCTAssertEqual(files[0].path, "file1.py")
        XCTAssertEqual(files[1].path, "file2.js")
        XCTAssertEqual(files[0].addedLines, [2])
        XCTAssertEqual(files[1].addedLines, [2])
    }

    func testParseNewFile() {
        let diff = """
        diff --git a/new.py b/new.py
        new file mode 100644
        index 0000000..abc1234
        --- /dev/null
        +++ b/new.py
        @@ -0,0 +1,3 @@
        +line one
        +line two
        +line three
        """
        let files = GitDiffScanner.parseDiff(diff)
        XCTAssertEqual(files.count, 1)
        XCTAssertEqual(files[0].path, "new.py")
        XCTAssertEqual(files[0].addedLines, [1, 2, 3])
    }

    func testParseBinaryFileSkipped() {
        let diff = """
        diff --git a/image.png b/image.png
        Binary files /dev/null and b/image.png differ
        diff --git a/config.py b/config.py
        index abc..def 100644
        --- a/config.py
        +++ b/config.py
        @@ -1,2 +1,3 @@
         existing
        +added line
         existing
        """
        let files = GitDiffScanner.parseDiff(diff)
        XCTAssertEqual(files.count, 1)
        XCTAssertEqual(files[0].path, "config.py")
    }

    func testParseDeletedFileSkipped() {
        // Deleted files have +++ /dev/null — should be excluded
        let diff = """
        diff --git a/old.py b/old.py
        deleted file mode 100644
        index abc1234..0000000
        --- a/old.py
        +++ /dev/null
        @@ -1,3 +0,0 @@
        -line one
        -line two
        -line three
        """
        let files = GitDiffScanner.parseDiff(diff)
        XCTAssertEqual(files.count, 0)
    }

    func testContextLinesNotInAddedLines() {
        let diff = """
        diff --git a/app.py b/app.py
        index abc..def 100644
        --- a/app.py
        +++ b/app.py
        @@ -1,4 +1,5 @@
         context line 1
         context line 2
        +added at line 3
         context line 4
         context line 5
        """
        let files = GitDiffScanner.parseDiff(diff)
        XCTAssertEqual(files.count, 1)
        XCTAssertEqual(files[0].addedLines, [3])
        // Context lines 1, 2, 4, 5 should NOT be in addedLines
        XCTAssertFalse(files[0].addedLines.contains(1))
        XCTAssertFalse(files[0].addedLines.contains(2))
        XCTAssertFalse(files[0].addedLines.contains(4))
        XCTAssertFalse(files[0].addedLines.contains(5))
    }

    func testRemovedLinesDoNotAffectNumbering() {
        let diff = """
        diff --git a/app.py b/app.py
        index abc..def 100644
        --- a/app.py
        +++ b/app.py
        @@ -1,4 +1,4 @@
         context line 1
        -old line 2
        +new line 2
         context line 3
         context line 4
        """
        let files = GitDiffScanner.parseDiff(diff)
        XCTAssertEqual(files.count, 1)
        // The + line replaces the - line, so it's at line 2 in the new file
        XCTAssertEqual(files[0].addedLines, [2])
    }

    func testEmptyDiff() {
        let files = GitDiffScanner.parseDiff("")
        XCTAssertEqual(files.count, 0)
    }

    // MARK: - Filtering tests

    func testFilterMatchesToAddedLinesOnly() {
        // Simulate: file has secrets on lines 1 and 3, but only line 3 was added
        let secret = ["sk_live_", "abc123def456ghi789jkl012"].joined()
        let content = "safe_value = 123\nexisting = true\napi_key = \"\(secret)\"\n"
        let config = PastewatchConfig.defaultConfig
        let addedLines: Set<Int> = [3]

        let allMatches = DirectoryScanner.scanFileContent(
            content: content, ext: "py",
            relativePath: "test.py", config: config
        )

        let filtered = allMatches.filter { addedLines.contains($0.line) }

        // Should find the secret on line 3
        XCTAssertGreaterThan(filtered.count, 0)
        for match in filtered {
            XCTAssertEqual(match.line, 3)
        }
    }

    func testSecretOnContextLineNotReported() {
        // Secret exists on line 1 but only line 2 was added
        let secret = ["sk_live_", "abc123def456ghi789jkl012"].joined()
        let content = "api_key = \"\(secret)\"\nnew_safe_line = true\n"
        let config = PastewatchConfig.defaultConfig
        let addedLines: Set<Int> = [2]

        let allMatches = DirectoryScanner.scanFileContent(
            content: content, ext: "py",
            relativePath: "test.py", config: config
        )

        let filtered = allMatches.filter { addedLines.contains($0.line) }

        // Secret is on line 1 (not added), so filtered should be empty
        XCTAssertEqual(filtered.count, 0)
    }

    func testSecretOnAddedLineDetected() {
        // Secret on line 2 which was added
        let dbUrl = ["postgres://", "user:pass@host:5432/mydb"].joined()
        let content = "safe = true\ndb_url = \"\(dbUrl)\"\n"
        let config = PastewatchConfig.defaultConfig
        let addedLines: Set<Int> = [2]

        let allMatches = DirectoryScanner.scanFileContent(
            content: content, ext: "py",
            relativePath: "test.py", config: config
        )

        let filtered = allMatches.filter { addedLines.contains($0.line) }

        XCTAssertGreaterThan(filtered.count, 0)
        XCTAssertTrue(filtered.allSatisfy { $0.line == 2 })
    }

    // WO-128: git diff scans must fail closed when shared patterns cannot load.
    func testScanFailsClosedForMissingSharedPatternFile() throws {
        let tempDir = try createTempGitRepo()
        defer { try? FileManager.default.removeItem(atPath: tempDir) }

        let originalDir = FileManager.default.currentDirectoryPath
        FileManager.default.changeCurrentDirectoryPath(tempDir)
        defer { FileManager.default.changeCurrentDirectoryPath(originalDir) }

        try "clean=true\n".write(toFile: tempDir + "/config.txt", atomically: true, encoding: .utf8)
        try runShell("git", args: ["-C", tempDir, "add", "config.txt"])
        try runShell("git", args: ["-C", tempDir, "commit", "--no-verify", "-m", "initial"])
        try "clean=false\n".write(toFile: tempDir + "/config.txt", atomically: true, encoding: .utf8)

        var config = PastewatchConfig.defaultConfig
        config.sharedPatternFiles = [tempDir + "/missing-shared-patterns.json"]

        XCTAssertThrowsError(try GitDiffScanner.scan(unstaged: true, config: config)) { error in
            XCTAssertTrue(error.localizedDescription.contains("sharedPatternFiles"))
            XCTAssertTrue(error.localizedDescription.contains("could not read"))
        }
    }

    private func createTempGitRepo() throws -> String {
        let tempDir = NSTemporaryDirectory() + "pw-diff-test-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: tempDir, withIntermediateDirectories: true)
        try runShell("git", args: ["-C", tempDir, "init"])
        try runShell("git", args: ["-C", tempDir, "config", "user.email", "test@test.com"])
        try runShell("git", args: ["-C", tempDir, "config", "user.name", "Test"])
        return tempDir
    }

    @discardableResult
    private func runShell(_ cmd: String, args: [String]) throws -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/\(cmd)")
        process.arguments = args
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        try process.run()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            throw NSError(domain: "shell", code: Int(process.terminationStatus))
        }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        return String(data: data, encoding: .utf8) ?? ""
    }
}
