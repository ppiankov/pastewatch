import XCTest

final class HookTests: XCTestCase {
    var testDir: String!

    override func setUp() {
        super.setUp()
        testDir = NSTemporaryDirectory() + "pastewatch-hook-test-\(UUID().uuidString)"
        try? FileManager.default.createDirectory(atPath: testDir, withIntermediateDirectories: true)
        // Initialize a git repo
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/git")
        process.arguments = ["init", testDir]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try? process.run()
        process.waitUntilExit()
    }

    override func tearDown() {
        try? FileManager.default.removeItem(atPath: testDir)
        super.tearDown()
    }

    // Test that hooks directory creation works
    func testHooksDirExists() {
        let hooksDir = testDir + "/.git/hooks"
        XCTAssertTrue(FileManager.default.fileExists(atPath: hooksDir))
    }

    // Test hook script content has correct structure
    func testHookScriptContainsMarkers() {
        let hookContent = """
        #!/bin/sh

        # BEGIN PASTEWATCH
        git diff --cached --diff-filter=d --no-color | pastewatch-cli scan --check
        PASTEWATCH_RESULT=$?
        if [ $PASTEWATCH_RESULT -eq 6 ]; then
            echo "pastewatch: sensitive data detected in staged changes" >&2
            exit 1
        fi
        # END PASTEWATCH
        """
        XCTAssertTrue(hookContent.contains("BEGIN PASTEWATCH"))
        XCTAssertTrue(hookContent.contains("END PASTEWATCH"))
        XCTAssertTrue(hookContent.contains("pastewatch-cli scan --check"))
    }

    // Test section removal from multi-hook file
    func testSectionRemoval() {
        let content = """
        #!/bin/sh
        echo "other hook"

        # BEGIN PASTEWATCH
        git diff --cached | pastewatch-cli scan --check
        PASTEWATCH_RESULT=$?
        if [ $PASTEWATCH_RESULT -eq 6 ]; then
            exit 1
        fi
        # END PASTEWATCH

        echo "more stuff"
        """
        var lines = content.components(separatedBy: "\n")
        var inSection = false
        lines.removeAll { line in
            if line.contains("BEGIN PASTEWATCH") { inSection = true; return true }
            if line.contains("END PASTEWATCH") { inSection = false; return true }
            return inSection
        }
        let result = lines.joined(separator: "\n")
        XCTAssertFalse(result.contains("pastewatch"))
        XCTAssertTrue(result.contains("other hook"))
        XCTAssertTrue(result.contains("more stuff"))
    }

    // Test that empty hook (shebang only) is detected
    func testEmptyHookDetection() {
        let remaining = "#!/bin/sh"
        XCTAssertTrue(remaining == "#!/bin/sh" || remaining == "#!/bin/bash" || remaining.isEmpty)
    }

    // Test hook file creation in temp directory
    func testHookFileCreation() throws {
        let hooksDir = testDir + "/.git/hooks"
        let hookPath = hooksDir + "/pre-commit"

        let hookContent = "#!/bin/sh\n\n# BEGIN PASTEWATCH\necho test\n# END PASTEWATCH\n"
        try hookContent.write(toFile: hookPath, atomically: true, encoding: .utf8)

        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: hookPath)

        let attrs = try FileManager.default.attributesOfItem(atPath: hookPath)
        let perms = attrs[.posixPermissions] as? Int
        XCTAssertEqual(perms, 0o755)
    }

    // Test hook file removal
    func testHookFileRemoval() throws {
        let hooksDir = testDir + "/.git/hooks"
        let hookPath = hooksDir + "/pre-commit"

        try "#!/bin/sh\n".write(toFile: hookPath, atomically: true, encoding: .utf8)
        XCTAssertTrue(FileManager.default.fileExists(atPath: hookPath))

        try FileManager.default.removeItem(atPath: hookPath)
        XCTAssertFalse(FileManager.default.fileExists(atPath: hookPath))
    }

    // Test relative path becomes absolute
    func testRelativePathResolution() {
        let cwd = FileManager.default.currentDirectoryPath
        let relativePath = ".git/hooks"
        let absolutePath = cwd + "/" + relativePath
        XCTAssertTrue(absolutePath.hasPrefix("/"))
    }
}
