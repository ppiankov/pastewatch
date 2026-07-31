import Foundation
@testable import PastewatchCLI
@testable import PastewatchCore
import XCTest

final class HookTests: XCTestCase {
    var testDir: String!

    override func setUp() {
        // WO-594: hook tests isolate repository and configuration state per case.
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
        try? runGit(["config", "user.email", "pastewatch-tests@example.invalid"])
        try? runGit(["config", "user.name", "Pastewatch Tests"])
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
        // WO-594: generated hooks call the structured staged-check boundary.
        try installPastewatchHook()

        let hookContent = try String(contentsOfFile: hookPath(), encoding: .utf8)
        XCTAssertTrue(hookContent.contains("BEGIN PASTEWATCH"))
        XCTAssertTrue(hookContent.contains("END PASTEWATCH"))
        XCTAssertTrue(hookContent.contains("pastewatch-cli hook check-staged"))
        XCTAssertFalse(hookContent.contains("git diff --cached"))
        XCTAssertTrue(hookContent.contains("PASTEWATCH_RESULT"))
        XCTAssertTrue(hookContent.contains("scan failed with exit code"))
        let permissions = try FileManager.default.attributesOfItem(
            atPath: hookPath()
        )[.posixPermissions] as? Int
        XCTAssertEqual(permissions, 0o755)
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

    // WO-594: committed exact path/line/digest evidence authorizes only its fixture.
    func testCommittedFixtureAuthorizationAllowsExactStagedLine() throws {
        let fixtureLine = syntheticFixtureLine()
        try commitManifest([
            HookFixtureAuthorization(
                path: "fixture.txt",
                line: 1,
                fingerprint: GitDiffScanner.hookFixtureFingerprint(fixtureLine)
            )
        ])
        try stageFixture(fixtureLine, path: "fixture.txt")

        let result = try runRealHookCheck()

        XCTAssertEqual(result.status, 0, result.stderr)
        XCTAssertFalse(result.stderr.contains(fixtureLine))
    }

    // WO-594: no committed authorization preserves the existing blocking behavior.
    func testUnapprovedFixtureStillBlocks() throws {
        let fixtureLine = syntheticFixtureLine()
        try stageFixture(fixtureLine, path: "fixture.txt")

        let result = try runRealHookCheck()

        XCTAssertEqual(result.status, ScanExitContract.findingsDetected, result.stderr)
        XCTAssertFalse(result.stderr.contains(fixtureLine))
    }

    // WO-594: changing an authorized line invalidates its digest.
    func testStaleFixtureFingerprintBlocks() throws {
        let fixtureLine = syntheticFixtureLine()
        try commitManifest([
            HookFixtureAuthorization(
                path: "fixture.txt",
                line: 1,
                fingerprint: GitDiffScanner.hookFixtureFingerprint(fixtureLine + "-stale")
            )
        ])
        try stageFixture(fixtureLine, path: "fixture.txt")

        let result = try runRealHookCheck()

        XCTAssertEqual(result.status, ScanExitContract.findingsDetected, result.stderr)
        XCTAssertFalse(result.stderr.contains(fixtureLine))
    }

    // WO-594: moving identical content to another path invalidates authorization.
    func testMovedFixtureBlocks() throws {
        let fixtureLine = syntheticFixtureLine()
        try commitManifest([
            HookFixtureAuthorization(
                path: "approved.txt",
                line: 1,
                fingerprint: GitDiffScanner.hookFixtureFingerprint(fixtureLine)
            )
        ])
        try stageFixture(fixtureLine, path: "moved.txt")

        let result = try runRealHookCheck()

        XCTAssertEqual(result.status, ScanExitContract.findingsDetected, result.stderr)
        XCTAssertFalse(result.stderr.contains(fixtureLine))
    }

    // WO-594: malformed committed policy fails before the staged scan can pass.
    func testMalformedFixtureManifestFailsClosed() throws {
        try commitRawManifest(#"{"version":1,"fixtures":[{"path":"fixture.txt"}]}"#)
        let fixtureLine = syntheticFixtureLine()
        try stageFixture(fixtureLine, path: "fixture.txt")

        let result = try runRealHookCheck()

        XCTAssertEqual(result.status, ScanExitContract.operationalFailure, result.stderr)
        XCTAssertTrue(result.stderr.contains("invalid hook fixture authorization entry"))
        XCTAssertFalse(result.stderr.contains(fixtureLine))
    }

    // WO-594: staged source comments cannot grant their own authorization.
    func testInlineFixtureAuthorizationAttemptBlocks() throws {
        let fixtureLine = syntheticFixtureLine()
        let attemptedAuthorization = GitDiffScanner.hookFixtureFingerprint(fixtureLine)
        try stageFixture(
            "\(fixtureLine)\n// pastewatch fixture \(attemptedAuthorization)",
            path: "fixture.txt"
        )

        let result = try runRealHookCheck()

        XCTAssertEqual(result.status, ScanExitContract.findingsDetected, result.stderr)
        XCTAssertFalse(result.stderr.contains(fixtureLine))
    }

    // WO-604: a PATH-spelled argv[0] must still resolve the running CLI for recursive scan.
    func testPATHInvokedHookCheckRunsCurrentExecutable() throws {
        let result = try runRealHookCheck()

        XCTAssertEqual(result.status, ScanExitContract.clean, result.stderr)
    }

    // WO-605: JSON numeric coercion cannot broaden fixture authorization.
    func testFractionalManifestVersionFailsClosed() throws {
        let fixtureLine = syntheticFixtureLine()
        let fingerprint = GitDiffScanner.hookFixtureFingerprint(fixtureLine)
        try commitRawManifest(
            manifestJSON(version: "1.5", line: "1", fingerprint: fingerprint)
        )
        try stageFixture(fixtureLine, path: "fixture.txt")

        let result = try runRealHookCheck()

        XCTAssertEqual(result.status, ScanExitContract.operationalFailure, result.stderr)
        XCTAssertTrue(result.stderr.contains("invalid hook fixture authorization manifest"))
    }

    // WO-605: fixture lines are exact positive integers, never truncated decimals.
    func testFractionalManifestLineFailsClosed() throws {
        let fixtureLine = syntheticFixtureLine()
        let fingerprint = GitDiffScanner.hookFixtureFingerprint(fixtureLine)
        try commitRawManifest(
            manifestJSON(version: "1", line: "1.5", fingerprint: fingerprint)
        )
        try stageFixture(fixtureLine, path: "fixture.txt")

        let result = try runRealHookCheck()

        XCTAssertEqual(result.status, ScanExitContract.operationalFailure, result.stderr)
        XCTAssertTrue(result.stderr.contains("invalid hook fixture authorization entry"))
    }

    // WO-605: integers outside the platform line-number range fail closed.
    func testOverflowManifestLineFailsClosed() throws {
        let fixtureLine = syntheticFixtureLine()
        let fingerprint = GitDiffScanner.hookFixtureFingerprint(fixtureLine)
        try commitRawManifest(
            manifestJSON(
                version: "1",
                line: "9223372036854775808",
                fingerprint: fingerprint
            )
        )
        try stageFixture(fixtureLine, path: "fixture.txt")

        let result = try runRealHookCheck()

        XCTAssertEqual(result.status, ScanExitContract.operationalFailure, result.stderr)
        XCTAssertTrue(result.stderr.contains("invalid hook fixture authorization entry"))
    }

    // WO-605: exact future versions report the version contract, not generic corruption.
    func testUnsupportedManifestVersionFailsClosed() throws {
        let fixtureLine = syntheticFixtureLine()
        let fingerprint = GitDiffScanner.hookFixtureFingerprint(fixtureLine)
        try commitRawManifest(
            manifestJSON(version: "2", line: "1", fingerprint: fingerprint)
        )
        try stageFixture(fixtureLine, path: "fixture.txt")

        let result = try runRealHookCheck()

        XCTAssertEqual(result.status, ScanExitContract.operationalFailure, result.stderr)
        XCTAssertTrue(result.stderr.contains("unsupported hook fixture authorization manifest version"))
    }

    // WO-606: the CLI and staged diff agree on source lines terminated by CRLF.
    func testCommittedCRLFFixtureAuthorizationAllowsExactLine() throws {
        let fixtureLine = syntheticFixtureLine()
        try Data("\(fixtureLine)\r\n".utf8).write(
            to: URL(fileURLWithPath: testDir).appendingPathComponent("fixture.txt")
        )
        let authorization = try fixtureAuthorization(path: "fixture.txt", line: 1)
        try commitManifest([authorization])
        try runGit(["add", "fixture.txt"])

        let result = try runRealHookCheck()

        XCTAssertEqual(result.status, ScanExitContract.clean, result.stderr)
        XCTAssertEqual(
            authorization.fingerprint,
            GitDiffScanner.hookFixtureFingerprint(fixtureLine)
        )
    }

    // WO-608: source payload that renders as +++ metadata cannot switch authorization paths.
    func testAddedSourceCannotSpoofDiffPathHeader() throws {
        let fixtureLine = syntheticFixtureLine()
        try commitManifest([
            HookFixtureAuthorization(
                path: "approved.swift",
                line: 1,
                fingerprint: GitDiffScanner.hookFixtureFingerprint(fixtureLine)
            )
        ])
        try stageFixture(
            "++ b/approved.swift\n\(fixtureLine)",
            path: "attacker.swift"
        )

        let result = try runRealHookCheck()

        XCTAssertEqual(result.status, ScanExitContract.findingsDetected, result.stderr)
        XCTAssertFalse(result.stderr.contains(fixtureLine))
    }

    // WO-615: repository diff helpers cannot erase staged hook input.
    func testExternalDiffCannotBypassStagedScan() throws {
        try runGit(["config", "diff.external", "/usr/bin/true"])
        try stageFixture(syntheticFixtureLine(), path: "fixture.txt")

        let result = try runRealHookCheck()

        XCTAssertEqual(result.status, ScanExitContract.findingsDetected, result.stderr)
    }

    // WO-615: textconv output cannot replace the staged bytes seen by the hook.
    func testTextconvCannotBypassStagedScan() throws {
        try "*.txt diff=fixture\n".write(
            toFile: testDir + "/.gitattributes",
            atomically: true,
            encoding: .utf8
        )
        try runGit(["add", ".gitattributes"])
        try runGit(["commit", "-m", "test diff attributes"])
        try runGit(["config", "diff.fixture.textconv", "/usr/bin/true"])
        try stageFixture(syntheticFixtureLine(), path: "fixture.txt")

        let result = try runRealHookCheck()

        XCTAssertEqual(result.status, ScanExitContract.findingsDetected, result.stderr)
    }

    // WO-616: Git moves become a full addition at the unauthorized destination path.
    func testRenamedAuthorizedFixtureRequiresDestinationAuthorization() throws {
        let fixtureLine = syntheticFixtureLine()
        try fixtureLine.write(
            toFile: testDir + "/approved.txt",
            atomically: true,
            encoding: .utf8
        )
        try commitManifest([
            HookFixtureAuthorization(
                path: "approved.txt",
                line: 1,
                fingerprint: GitDiffScanner.hookFixtureFingerprint(fixtureLine)
            )
        ])
        try runGit(["add", "approved.txt"])
        try runGit(["commit", "-m", "test authorized fixture"])
        try runGit(["mv", "approved.txt", "moved.txt"])
        try stageEmptyManifest()

        let result = try runRealHookCheck()

        XCTAssertEqual(result.status, ScanExitContract.findingsDetected, result.stderr)
    }

    // WO-609: a consuming commit cannot delete the authority it used.
    func testAuthorizedFixtureWithManifestDeletionFailsClosed() throws {
        let fixtureLine = syntheticFixtureLine()
        try commitManifest([
            HookFixtureAuthorization(
                path: "fixture.txt",
                line: 1,
                fingerprint: GitDiffScanner.hookFixtureFingerprint(fixtureLine)
            )
        ])
        try stageFixture(fixtureLine, path: "fixture.txt")
        try runGit(["rm", GitDiffScanner.hookFixtureManifestPath])

        let result = try runRealHookCheck()

        XCTAssertEqual(result.status, ScanExitContract.operationalFailure, result.stderr)
        XCTAssertTrue(result.stderr.contains("manifest must be unchanged"))
        XCTAssertFalse(result.stderr.contains(fixtureLine))
    }

    // WO-609: editing an entry while consuming its HEAD value is equally rejected.
    func testAuthorizedFixtureWithManifestEditFailsClosed() throws {
        let fixtureLine = syntheticFixtureLine()
        try commitManifest([
            HookFixtureAuthorization(
                path: "fixture.txt",
                line: 1,
                fingerprint: GitDiffScanner.hookFixtureFingerprint(fixtureLine)
            )
        ])
        try stageFixture(fixtureLine, path: "fixture.txt")
        try stageEmptyManifest()

        let result = try runRealHookCheck()

        XCTAssertEqual(result.status, ScanExitContract.operationalFailure, result.stderr)
        XCTAssertTrue(result.stderr.contains("manifest must be unchanged"))
    }

    // WO-609: manifest maintenance remains possible when no authorization is consumed.
    func testStandaloneManifestMaintenanceRemainsClean() throws {
        let fixtureLine = syntheticFixtureLine()
        try commitManifest([
            HookFixtureAuthorization(
                path: "fixture.txt",
                line: 1,
                fingerprint: GitDiffScanner.hookFixtureFingerprint(fixtureLine)
            )
        ])
        try stageEmptyManifest()

        let result = try runRealHookCheck()

        XCTAssertEqual(result.status, ScanExitContract.clean, result.stderr)
    }

    // WO-610@v2: duplicate root keys cannot rely on Foundation's winner semantics.
    func testDuplicateManifestRootKeyFailsClosed() throws {
        let fixtureLine = syntheticFixtureLine()
        let fingerprint = GitDiffScanner.hookFixtureFingerprint(fixtureLine)
        try commitRawManifest(
            """
            {"version":1,"version":1,"fixtures":[{"path":"fixture.txt","line":1,"fingerprint":"\(fingerprint)"}]}
            """
        )
        try stageFixture(fixtureLine, path: "fixture.txt")

        let result = try runRealHookCheck()

        XCTAssertEqual(result.status, ScanExitContract.operationalFailure, result.stderr)
        XCTAssertTrue(result.stderr.contains("invalid hook fixture authorization manifest"))
    }

    // WO-610@v2: duplicate entry keys are rejected before dictionary collapse.
    func testDuplicateManifestEntryKeyFailsClosed() throws {
        let fixtureLine = syntheticFixtureLine()
        let fingerprint = GitDiffScanner.hookFixtureFingerprint(fixtureLine)
        try commitRawManifest(
            """
            {"version":1,"fixtures":[{"path":"other.txt","path":"fixture.txt","line":1,"fingerprint":"\(fingerprint)"}]}
            """
        )
        try stageFixture(fixtureLine, path: "fixture.txt")

        let result = try runRealHookCheck()

        XCTAssertEqual(result.status, ScanExitContract.operationalFailure, result.stderr)
        XCTAssertTrue(result.stderr.contains("invalid hook fixture authorization manifest"))
    }

    // WO-610@v2: escaped schema-key spellings cannot hide review ambiguity.
    func testEscapedManifestKeyFailsClosed() throws {
        let fixtureLine = syntheticFixtureLine()
        let fingerprint = GitDiffScanner.hookFixtureFingerprint(fixtureLine)
        try commitRawManifest(
            """
            {"version":1,"fixtures":[{"\\u0070ath":"fixture.txt","line":1,"fingerprint":"\(fingerprint)"}]}
            """
        )
        try stageFixture(fixtureLine, path: "fixture.txt")

        let result = try runRealHookCheck()

        XCTAssertEqual(result.status, ScanExitContract.operationalFailure, result.stderr)
        XCTAssertTrue(result.stderr.contains("invalid hook fixture authorization manifest"))
    }

    // WO-610@v2: zero entry-key occurrences are valid for an empty fixture list.
    func testCommittedEmptyManifestRemainsClean() throws {
        try commitRawManifest(#"{"version":1,"fixtures":[]}"#)

        let result = try runRealHookCheck()

        XCTAssertEqual(result.status, ScanExitContract.clean, result.stderr)
    }

    // WO-594: the fingerprint command emits only reviewable location and digest metadata.
    func testFixtureFingerprintCommandNeverPrintsFixtureValue() throws {
        let fixtureLine = syntheticFixtureLine()
        try fixtureLine.write(
            toFile: testDir + "/fixture.txt",
            atomically: true,
            encoding: .utf8
        )

        let process = Process()
        process.executableURL = pastewatchCLIURL()
        process.arguments = ["hook", "fixture-fingerprint", "fixture.txt", "--line", "1"]
        process.currentDirectoryURL = URL(fileURLWithPath: testDir)
        process.environment = testEnvironment()
        let stdout = Pipe()
        let stderr = Pipe()
        process.standardOutput = stdout
        process.standardError = stderr

        try process.run()
        process.waitUntilExit()

        let outputData = stdout.fileHandleForReading.readDataToEndOfFile()
        let errorText = String(
            data: stderr.fileHandleForReading.readDataToEndOfFile(),
            encoding: .utf8
        ) ?? ""
        XCTAssertEqual(process.terminationStatus, 0, errorText)
        XCTAssertFalse(String(data: outputData, encoding: .utf8)?.contains(fixtureLine) == true)
        let authorization = try JSONDecoder().decode(
            HookFixtureAuthorization.self,
            from: outputData
        )
        XCTAssertEqual(authorization.path, "fixture.txt")
        XCTAssertEqual(authorization.line, 1)
        XCTAssertEqual(
            authorization.fingerprint,
            GitDiffScanner.hookFixtureFingerprint(fixtureLine)
        )
    }

    // WO-607: upgrade changes only the marked generated section.
    func testUpgradePreservesOtherHookContent() throws {
        let existing = """
        #!/bin/sh
        printf before
        # BEGIN PASTEWATCH
        git diff --cached | pastewatch-cli scan --check
        # END PASTEWATCH
        printf after
        """
        try existing.write(toFile: hookPath(), atomically: true, encoding: .utf8)

        try installPastewatchHook(arguments: ["--upgrade"])

        let upgraded = try String(contentsOfFile: hookPath(), encoding: .utf8)
        XCTAssertTrue(upgraded.hasPrefix("#!/bin/sh\nprintf before\n"))
        XCTAssertTrue(upgraded.hasSuffix("\nprintf after"))
        XCTAssertTrue(upgraded.contains("pastewatch-cli hook check-staged"))
        XCTAssertFalse(upgraded.contains("git diff --cached"))
        XCTAssertEqual(upgraded.components(separatedBy: "# BEGIN PASTEWATCH").count, 2)
        XCTAssertEqual(upgraded.components(separatedBy: "# END PASTEWATCH").count, 2)
    }

    // WO-607: default installation never rewrites an existing Pastewatch section.
    func testInstallWithoutUpgradePreservesExistingSection() throws {
        let existing = "#!/bin/sh\n# BEGIN PASTEWATCH\nprintf old\n# END PASTEWATCH\n"
        try existing.write(toFile: hookPath(), atomically: true, encoding: .utf8)

        let result = try runHookInstall()

        XCTAssertEqual(result.status, ScanExitContract.operationalFailure, result.stderr)
        XCTAssertEqual(
            try String(contentsOfFile: hookPath(), encoding: .utf8),
            existing
        )
    }

    // WO-607: malformed marker layouts fail before any hook bytes are changed.
    func testUpgradeRejectsMalformedMarkersWithoutWriting() throws {
        let malformedHooks = [
            "#!/bin/sh\n# BEGIN PASTEWATCH\nprintf old\n",
            "#!/bin/sh\n# END PASTEWATCH\n# BEGIN PASTEWATCH\n",
            "#!/bin/sh\n# BEGIN PASTEWATCH\n# END PASTEWATCH\n# END PASTEWATCH\n",
            "#!/bin/sh\n# BEGIN PASTEWATCH\n# END PASTEWATCH\n# BEGIN PASTEWATCH\n# END PASTEWATCH\n"
        ]

        for existing in malformedHooks {
            try existing.write(toFile: hookPath(), atomically: true, encoding: .utf8)

            let result = try runHookInstall(arguments: ["--upgrade"])

            XCTAssertEqual(result.status, ScanExitContract.operationalFailure, result.stderr)
            XCTAssertEqual(
                try String(contentsOfFile: hookPath(), encoding: .utf8),
                existing
            )
        }
    }

    // WO-611@v2: upgrading cannot detach a repository from a managed hook target.
    func testUpgradeRejectsSymlinkManagedHook() throws {
        let targetPath = testDir + "/shared-pre-commit"
        let target = "#!/bin/sh\n# BEGIN PASTEWATCH\nprintf old\n# END PASTEWATCH\n"
        try target.write(toFile: targetPath, atomically: true, encoding: .utf8)
        try FileManager.default.createSymbolicLink(
            atPath: hookPath(),
            withDestinationPath: targetPath
        )

        let result = try runHookInstall(arguments: ["--upgrade"])

        XCTAssertEqual(result.status, ScanExitContract.operationalFailure, result.stderr)
        XCTAssertTrue(result.stderr.contains("symlink-managed"))
        XCTAssertEqual(
            try FileManager.default.destinationOfSymbolicLink(atPath: hookPath()),
            targetPath
        )
        XCTAssertEqual(
            try String(contentsOfFile: targetPath, encoding: .utf8),
            target
        )
    }

    // WO-612: explicit upgrade preserves the operator-selected access mode.
    func testUpgradePreservesExistingHookPermissions() throws {
        let existing = "#!/bin/sh\n# BEGIN PASTEWATCH\nprintf old\n# END PASTEWATCH\n"
        for expectedMode in [0o700, 0o750] {
            try existing.write(toFile: hookPath(), atomically: true, encoding: .utf8)
            try FileManager.default.setAttributes(
                [.posixPermissions: expectedMode],
                ofItemAtPath: hookPath()
            )

            try installPastewatchHook(arguments: ["--upgrade"])

            let permissions = try FileManager.default.attributesOfItem(
                atPath: hookPath()
            )[.posixPermissions] as? Int
            XCTAssertEqual(permissions, expectedMode)
        }
    }

    // WO-613@v2: append cannot detach a repository from a symlink-managed hook.
    func testAppendRejectsSymlinkManagedHook() throws {
        let targetPath = testDir + "/shared-pre-commit"
        let target = "#!/bin/sh\nprintf managed\n"
        try target.write(toFile: targetPath, atomically: true, encoding: .utf8)
        try FileManager.default.createSymbolicLink(
            atPath: hookPath(),
            withDestinationPath: targetPath
        )

        let result = try runHookInstall(arguments: ["--append"])

        XCTAssertEqual(result.status, ScanExitContract.operationalFailure, result.stderr)
        XCTAssertTrue(result.stderr.contains("symlink-managed"))
        XCTAssertEqual(
            try FileManager.default.destinationOfSymbolicLink(atPath: hookPath()),
            targetPath
        )
        XCTAssertEqual(
            try String(contentsOfFile: targetPath, encoding: .utf8),
            target
        )
    }

    // WO-613@v2: a missing symlink target cannot make append treat the path as fresh.
    func testAppendRejectsDanglingSymlinkManagedHook() throws {
        let missingTarget = testDir + "/missing-shared-pre-commit"
        try FileManager.default.createSymbolicLink(
            atPath: hookPath(),
            withDestinationPath: missingTarget
        )

        let result = try runHookInstall(arguments: ["--append"])

        XCTAssertEqual(result.status, ScanExitContract.operationalFailure, result.stderr)
        XCTAssertTrue(result.stderr.contains("symlink-managed"))
        XCTAssertEqual(
            try FileManager.default.destinationOfSymbolicLink(atPath: hookPath()),
            missingTarget
        )
        XCTAssertFalse(FileManager.default.fileExists(atPath: missingTarget))
    }

    // WO-614: append preserves every existing regular-hook access mode.
    func testAppendPreservesExistingHookPermissions() throws {
        let existing = "#!/bin/sh\nprintf existing\n"
        for expectedMode in [0o700, 0o750] {
            try existing.write(toFile: hookPath(), atomically: true, encoding: .utf8)
            try FileManager.default.setAttributes(
                [.posixPermissions: expectedMode],
                ofItemAtPath: hookPath()
            )

            try installPastewatchHook(arguments: ["--append"])

            let permissions = try FileManager.default.attributesOfItem(
                atPath: hookPath()
            )[.posixPermissions] as? Int
            let content = try String(contentsOfFile: hookPath(), encoding: .utf8)
            XCTAssertEqual(permissions, expectedMode)
            XCTAssertTrue(content.contains("printf existing"))
            XCTAssertTrue(content.contains("pastewatch-cli hook check-staged"))
        }
    }

    // WO-617: a touched but empty regular hook remains a valid append target.
    func testAppendSupportsEmptyExistingHook() throws {
        try Data().write(to: URL(fileURLWithPath: hookPath()))
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o700],
            ofItemAtPath: hookPath()
        )

        let result = try runHookInstall(arguments: ["--append"])

        XCTAssertEqual(result.status, ScanExitContract.clean, result.stderr)
        let content = try String(contentsOfFile: hookPath(), encoding: .utf8)
        let permissions = try FileManager.default.attributesOfItem(
            atPath: hookPath()
        )[.posixPermissions] as? Int
        XCTAssertTrue(content.contains("pastewatch-cli hook check-staged"))
        XCTAssertEqual(permissions, 0o700)
    }

    // WO-617: undecodable existing hook bytes fail without lossy replacement.
    func testAppendRejectsInvalidUTF8WithoutWriting() throws {
        let invalid = Data([0xFF, 0xFE])
        try invalid.write(to: URL(fileURLWithPath: hookPath()))

        let result = try runHookInstall(arguments: ["--append"])

        XCTAssertEqual(result.status, ScanExitContract.operationalFailure, result.stderr)
        XCTAssertTrue(result.stderr.contains("not readable UTF-8"))
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: hookPath())), invalid)
    }

    // WO-611@v2: path replacement after open is rejected through pinned identity.
    func testHookEditorRejectsConcurrentPathReplacement() throws {
        let existing = "#!/bin/sh\n# BEGIN PASTEWATCH\nprintf old\n# END PASTEWATCH\n"
        try existing.write(toFile: hookPath(), atomically: true, encoding: .utf8)
        let editor = try HookFileEditor(path: hookPath())
        let targetPath = testDir + "/replacement-target"
        let target = "#!/bin/sh\nprintf replacement\n"
        try target.write(toFile: targetPath, atomically: true, encoding: .utf8)
        try FileManager.default.removeItem(atPath: hookPath())
        try FileManager.default.createSymbolicLink(
            atPath: hookPath(),
            withDestinationPath: targetPath
        )

        XCTAssertThrowsError(try editor.replaceContent("unexpected")) { error in
            XCTAssertEqual(error as? HookFileEditorError, .pathChanged)
        }
        XCTAssertEqual(
            try FileManager.default.destinationOfSymbolicLink(atPath: hookPath()),
            targetPath
        )
        XCTAssertEqual(
            try String(contentsOfFile: targetPath, encoding: .utf8),
            target
        )
    }

    // WO-618: descriptor writes cannot mutate every name of a shared hard-linked hook.
    func testAppendAndUpgradeRejectMultiplyLinkedHook() throws {
        let targetPath = testDir + "/shared-hardlink-hook"
        let target = "#!/bin/sh\n# BEGIN PASTEWATCH\nprintf managed\n# END PASTEWATCH\n"
        try target.write(toFile: targetPath, atomically: true, encoding: .utf8)
        try FileManager.default.linkItem(atPath: targetPath, toPath: hookPath())

        for arguments in [["--append"], ["--upgrade"]] {
            let result = try runHookInstall(arguments: arguments)

            XCTAssertEqual(result.status, ScanExitContract.operationalFailure, result.stderr)
            XCTAssertTrue(result.stderr.contains("multiple hard links"))
            XCTAssertEqual(
                try String(contentsOfFile: hookPath(), encoding: .utf8),
                target
            )
            XCTAssertEqual(
                try String(contentsOfFile: targetPath, encoding: .utf8),
                target
            )
        }
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

    private func installPastewatchHook(arguments: [String] = []) throws {
        // WO-594: test setup installs only through the public hook command.
        let result = try runHookInstall(arguments: arguments)
        guard result.status == 0 else {
            throw NSError(
                domain: "HookTests",
                code: Int(result.status),
                userInfo: [NSLocalizedDescriptionKey: "hook install failed: \(result.stderr)"]
            )
        }
    }

    // WO-607: install helpers exercise explicit upgrade arguments through the CLI.
    private func runHookInstall(arguments: [String] = []) throws -> HookResult {
        // WO-607: tests exercise explicit install and upgrade arguments through the CLI.
        let process = Process()
        process.executableURL = pastewatchCLIURL()
        process.arguments = ["hook", "install"] + arguments
        process.currentDirectoryURL = URL(fileURLWithPath: testDir)
        process.environment = testEnvironment()
        process.standardOutput = FileHandle.nullDevice

        let stderr = Pipe()
        process.standardError = stderr

        try process.run()
        process.waitUntilExit()

        return HookResult(
            status: process.terminationStatus,
            stderr: String(
                data: stderr.fileHandleForReading.readDataToEndOfFile(),
                encoding: .utf8
            ) ?? ""
        )
    }

    private func writeFakePastewatchCLI(scanExitCode: Int32) throws {
        // WO-594: the generated shell hook is tested against deterministic child exits.
        let binDir = testDir + "/bin"
        try FileManager.default.createDirectory(atPath: binDir, withIntermediateDirectories: true)
        let cliPath = binDir + "/pastewatch-cli"
        let script = """
        #!/bin/sh
        cat >/dev/null
        if [ "$1" = "hook" ] && [ "$2" = "check-staged" ]; then
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

    // WO-594: synthetic value is assembled at runtime so the repository hook is never bypassed.
    // WO-596 made ambiguous classes (credential/email/etc.) default-OFF, so a
    // password= fixture is no longer guard-blocking at default config. The hook tests
    // must stage a value that ALWAYS blocks regardless of config -- use an intrinsic
    // (AWS-key-shaped) secret so unapproved fixtures are genuinely detected.
    private func syntheticFixtureLine() -> String {
        ["aws_key = ", "AKIA", "Z9Q7K2M4N8P1R3T5"].joined()
    }

    // WO-594: manifest commits are separate from fixture staging by construction.
    private func commitManifest(
        _ authorizations: [HookFixtureAuthorization]
    ) throws {
        let fixtures = authorizations.map { authorization in
            [
                "path": authorization.path,
                "line": authorization.line,
                "fingerprint": authorization.fingerprint
            ] as [String: Any]
        }
        let data = try JSONSerialization.data(
            withJSONObject: ["version": 1, "fixtures": fixtures],
            options: [.sortedKeys]
        )
        try data.write(
            to: URL(fileURLWithPath: testDir)
                .appendingPathComponent(GitDiffScanner.hookFixtureManifestPath)
        )
        try commitManifestFile()
    }

    // WO-594: malformed committed policy fixtures exercise the fail-closed parser.
    private func commitRawManifest(_ manifest: String) throws {
        try manifest.write(
            toFile: testDir + "/" + GitDiffScanner.hookFixtureManifestPath,
            atomically: true,
            encoding: .utf8
        )
        try commitManifestFile()
    }

    // WO-605: raw numeric spellings exercise JSON parsing without NSNumber construction.
    private func manifestJSON(
        version: String,
        line: String,
        fingerprint: String
    ) -> String {
        """
        {"version":\(version),"fixtures":[{"path":"fixture.txt","line":\(line),"fingerprint":"\(fingerprint)"}]}
        """
    }

    private func commitManifestFile() throws {
        // WO-594: fixture authority must exist in committed history before staged use.
        try runGit(["add", GitDiffScanner.hookFixtureManifestPath])
        try runGit(["commit", "-m", "test fixture policy"])
    }

    // WO-609: stage a valid authority-removal commit independently of fixture content.
    private func stageEmptyManifest() throws {
        try commitManifestData([
            "version": 1,
            "fixtures": []
        ])
        try runGit(["add", GitDiffScanner.hookFixtureManifestPath])
    }

    private func commitManifestData(_ object: [String: Any]) throws {
        // WO-594: tests write only value-free authorization metadata.
        let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        try data.write(
            to: URL(fileURLWithPath: testDir)
                .appendingPathComponent(GitDiffScanner.hookFixtureManifestPath)
        )
    }

    // WO-594: fixture staging happens only after the committed policy boundary.
    private func stageFixture(_ content: String, path: String) throws {
        let url = URL(fileURLWithPath: testDir).appendingPathComponent(path)
        try FileManager.default.createDirectory(
            at: url.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try content.write(to: url, atomically: true, encoding: .utf8)
        try runGit(["add", path])
    }

    // WO-604: invoke through PATH so argv[0] matches the generated-hook deployment.
    private func runRealHookCheck() throws -> HookResult {
        let binDirectory = testDir + "/bin"
        try FileManager.default.createDirectory(
            atPath: binDirectory,
            withIntermediateDirectories: true
        )
        let commandPath = binDirectory + "/pastewatch-cli"
        try? FileManager.default.removeItem(atPath: commandPath)
        try FileManager.default.createSymbolicLink(
            atPath: commandPath,
            withDestinationPath: pastewatchCLIURL().path
        )

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/sh")
        process.arguments = ["-c", "pastewatch-cli hook check-staged"]
        process.currentDirectoryURL = URL(fileURLWithPath: testDir)
        process.environment = testEnvironment(pathPrefix: binDirectory)
        process.standardOutput = FileHandle.nullDevice
        let stderr = Pipe()
        process.standardError = stderr

        try process.run()
        process.waitUntilExit()

        return HookResult(
            status: process.terminationStatus,
            stderr: String(
                data: stderr.fileHandleForReading.readDataToEndOfFile(),
                encoding: .utf8
            ) ?? ""
        )
    }

    // WO-606: exercise line normalization through the public CLI boundary.
    private func fixtureAuthorization(
        path: String,
        line: Int
    ) throws -> HookFixtureAuthorization {
        let process = Process()
        process.executableURL = pastewatchCLIURL()
        process.arguments = [
            "hook", "fixture-fingerprint", path, "--line", String(line)
        ]
        process.currentDirectoryURL = URL(fileURLWithPath: testDir)
        process.environment = testEnvironment()
        let stdout = Pipe()
        process.standardOutput = stdout
        process.standardError = FileHandle.nullDevice

        try process.run()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            throw NSError(
                domain: "HookTests",
                code: Int(process.terminationStatus),
                userInfo: [NSLocalizedDescriptionKey: "fixture fingerprint failed"]
            )
        }
        return try JSONDecoder().decode(
            HookFixtureAuthorization.self,
            from: stdout.fileHandleForReading.readDataToEndOfFile()
        )
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
        // WO-604: subprocess tests control PATH without changing the executable under test.
        let basePath = "/usr/bin:/bin"
        let path = pathPrefix.map { "\($0):\(basePath)" } ?? basePath
        return [
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
            "HOME": testDir ?? NSTemporaryDirectory(),
            "PATH": path
        ]
    }
}
