import Foundation
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
        process.environment = testEnvironment()
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try? process.run()
        process.waitUntilExit()
        // Git templates may install real hooks; these tests need an empty pre-commit slot.
        try? FileManager.default.removeItem(atPath: testDir + "/.git/hooks/pre-commit")
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
    func testHookScriptContainsMarkers() throws {
        try installPastewatchHook()

        let hookContent = try String(contentsOfFile: hookPath(), encoding: .utf8)
        XCTAssertTrue(hookContent.contains("BEGIN PASTEWATCH"))
        XCTAssertTrue(hookContent.contains("END PASTEWATCH"))
        XCTAssertTrue(hookContent.contains("pastewatch-cli scan --check"))
        XCTAssertTrue(hookContent.contains("PASTEWATCH_RESULT"))
        XCTAssertTrue(hookContent.contains("scan failed with exit code"))
    }

    // WO-130: clean scans are the only generated-hook success path.
    func testGeneratedHookAllowsCleanScanExit() throws {
        let result = try runGeneratedHook(scanExitCode: 0)

        XCTAssertEqual(result.status, 0)
        XCTAssertFalse(result.stderr.contains("sensitive data detected"), result.stderr)
        XCTAssertFalse(result.stderr.contains("scan failed"), result.stderr)
    }

    // WO-130: findings still block with the existing user-facing message.
    func testGeneratedHookBlocksFindingsExit() throws {
        let result = try runGeneratedHook(scanExitCode: 6)

        XCTAssertEqual(result.status, 1)
        XCTAssertTrue(result.stderr.contains("sensitive data detected"), result.stderr)
    }

    // WO-130: sharedPatternFiles load failures return exit 2 and must block commits.
    func testGeneratedHookBlocksScanFailureExit() throws {
        let result = try runGeneratedHook(scanExitCode: 2)

        XCTAssertEqual(result.status, 1)
        XCTAssertTrue(result.stderr.contains("scan failed with exit code 2"), result.stderr)
    }

    // WO-130: any unexpected scan error must fail closed instead of committing.
    func testGeneratedHookBlocksUnexpectedScanErrorExit() throws {
        let result = try runGeneratedHook(scanExitCode: 99)

        XCTAssertEqual(result.status, 1)
        XCTAssertTrue(result.stderr.contains("scan failed with exit code 99"), result.stderr)
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

    private struct HookResult {
        let status: Int32
        let stderr: String
    }

    private func runGeneratedHook(scanExitCode: Int32) throws -> HookResult {
        try writeFakePastewatchCLI(scanExitCode: scanExitCode)
        try stageFileForHookInput()

        try installPastewatchHook()

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/sh")
        process.arguments = [hookPath()]
        process.currentDirectoryURL = URL(fileURLWithPath: testDir)
        process.environment = testEnvironment(pathPrefix: "\(testDir ?? "")/bin")

        let stderr = Pipe()
        process.standardOutput = FileHandle.nullDevice
        process.standardError = stderr

        try process.run()
        process.waitUntilExit()

        return HookResult(
            status: process.terminationStatus,
            stderr: String(data: stderr.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        )
    }

    private func installPastewatchHook() throws {
        let process = Process()
        process.executableURL = pastewatchCLIURL()
        process.arguments = ["hook", "install"]
        process.currentDirectoryURL = URL(fileURLWithPath: testDir)
        process.environment = testEnvironment()
        process.standardOutput = FileHandle.nullDevice

        let stderr = Pipe()
        process.standardError = stderr

        try process.run()
        process.waitUntilExit()

        guard process.terminationStatus == 0 else {
            let errorOutput = String(
                data: stderr.fileHandleForReading.readDataToEndOfFile(),
                encoding: .utf8
            ) ?? ""
            throw NSError(
                domain: "HookTests",
                code: Int(process.terminationStatus),
                userInfo: [NSLocalizedDescriptionKey: "hook install failed: \(errorOutput)"]
            )
        }
    }

    private func writeFakePastewatchCLI(scanExitCode: Int32) throws {
        let binDir = testDir + "/bin"
        try FileManager.default.createDirectory(atPath: binDir, withIntermediateDirectories: true)
        let cliPath = binDir + "/pastewatch-cli"
        let script = """
        #!/bin/sh
        cat >/dev/null
        if [ "$1" = "scan" ] && [ "$2" = "--check" ]; then
            exit \(scanExitCode)
        fi
        exit 64
        """
        try script.write(toFile: cliPath, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: cliPath)
    }

    private func stageFileForHookInput() throws {
        let filePath = testDir + "/staged.txt"
        try "changed\n".write(toFile: filePath, atomically: true, encoding: .utf8)
        try runGit(["add", "staged.txt"])
    }

    private func runGit(_ arguments: [String]) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/git")
        process.arguments = ["-C", testDir] + arguments
        process.environment = testEnvironment()
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice

        try process.run()
        process.waitUntilExit()

        guard process.terminationStatus == 0 else {
            throw NSError(
                domain: "HookTests",
                code: Int(process.terminationStatus),
                userInfo: [NSLocalizedDescriptionKey: "git \(arguments.joined(separator: " ")) failed"]
            )
        }
    }

    private func hookPath() -> String {
        testDir + "/.git/hooks/pre-commit"
    }

    private func pastewatchCLIURL() -> URL {
        let productsDirectory = Bundle.main.bundleURL.deletingLastPathComponent()
        let bundled = productsDirectory.appendingPathComponent("PastewatchCLI")
        if FileManager.default.fileExists(atPath: bundled.path) {
            return bundled
        }
        return URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
            .appendingPathComponent(".build/debug/PastewatchCLI")
    }

    private func testEnvironment(pathPrefix: String? = nil) -> [String: String] {
        let basePath = "/usr/bin:/bin"
        let path = pathPrefix.map { "\($0):\(basePath)" } ?? basePath
        return [
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
            "PATH": path
        ]
    }
}
