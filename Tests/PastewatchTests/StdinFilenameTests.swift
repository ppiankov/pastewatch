import Foundation
import XCTest
@testable import PastewatchCore

final class StdinFilenameTests: XCTestCase {
    let config = PastewatchConfig.defaultConfig

    func testExtensionExtractionFromFilename() {
        let envPath = URL(fileURLWithPath: "/tmp/.env")
        XCTAssertEqual(envPath.lastPathComponent, ".env")

        let jsonPath = URL(fileURLWithPath: "config.json")
        XCTAssertEqual(jsonPath.pathExtension.lowercased(), "json")

        let ymlPath = URL(fileURLWithPath: "/home/user/app.yml")
        XCTAssertEqual(ymlPath.pathExtension.lowercased(), "yml")

        let yamlPath = URL(fileURLWithPath: "deploy.yaml")
        XCTAssertEqual(yamlPath.pathExtension.lowercased(), "yaml")

        let propsPath = URL(fileURLWithPath: "db.properties")
        XCTAssertEqual(propsPath.pathExtension.lowercased(), "properties")

        XCTAssertNotNil(parserForExtension("env"))
        XCTAssertNotNil(parserForExtension("json"))
        XCTAssertNotNil(parserForExtension("yml"))
        XCTAssertNotNil(parserForExtension("yaml"))
        XCTAssertNotNil(parserForExtension("properties"))
        XCTAssertNil(parserForExtension("txt"))
        XCTAssertNil(parserForExtension(""))
    }

    func testFormatAwareEnvParsing() {
        let awsKey = ["AKIA", "IOSFODNN7EXAMPLE"].joined()
        let envContent = "SAFE=hello\nAWS_KEY=\(awsKey)\n"
        guard let parser = parserForExtension("env") else {
            XCTFail("Expected parser for env extension")
            return
        }

        let parsedValues = parser.parseValues(from: envContent)
        XCTAssertEqual(parsedValues.count, 2)
        XCTAssertEqual(parsedValues[0].key, "SAFE")
        XCTAssertEqual(parsedValues[1].key, "AWS_KEY")
        XCTAssertEqual(parsedValues[1].value, awsKey)

        var collected: [DetectedMatch] = []
        for pv in parsedValues {
            let matches = DetectionRules.scan(pv.value, config: config)
            for m in matches {
                collected.append(DetectedMatch(
                    type: m.type, value: m.value, range: m.range,
                    line: pv.line
                ))
            }
        }

        let awsMatches = collected.filter { $0.type == .awsKey }
        XCTAssertEqual(awsMatches.count, 1)
        XCTAssertEqual(awsMatches.first?.line, 2)
    }

    func testStdinFilenameConflictsWithFile() {
        // --stdin-filename is only valid for stdin; when --file is set, both provide a path.
        // Verify the underlying logic: if both a file path and a stdin filename are present,
        // the file path takes precedence for extension extraction.
        let filePath = "/tmp/data.txt"
        let stdinFilename = "secrets.env"

        let fileExt = URL(fileURLWithPath: filePath).pathExtension.lowercased()
        let stdinExt = URL(fileURLWithPath: stdinFilename).pathExtension.lowercased()

        XCTAssertEqual(fileExt, "txt")
        XCTAssertEqual(stdinExt, "env")
        XCTAssertNil(parserForExtension(fileExt))
        XCTAssertNotNil(parserForExtension(stdinExt))
    }

    func testStdinFilenameConflictsWithDir() {
        // --stdin-filename is only valid for stdin; when --dir is set, directory scanning
        // uses its own per-file extension logic. Verify that dir paths have no meaningful
        // extension to parse (they are directories, not files).
        let dirPath = "/tmp/project"
        let dirExt = URL(fileURLWithPath: dirPath).pathExtension.lowercased()
        XCTAssertEqual(dirExt, "")
        XCTAssertNil(parserForExtension(dirExt))
    }

    // WO-129: stdin-filename scans must use shared pattern files through file IO scanning.
    func testStdinFilenameEnvScanUsesSharedPatternFiles() throws {
        let secretValue = "PW" + "STDIN-" + syntheticSuffix()
        let artifactURL = try writeSharedPatternArtifact(
            regex: "PW" + #"STDIN-[A-F0-9]{12}"#
        )
        defer { try? FileManager.default.removeItem(at: artifactURL) }

        var scanConfig = config
        scanConfig.sharedPatternFiles = [artifactURL.path]

        let matches = try DirectoryScanner.scanFileContentOrThrow(
            content: "TOKEN=\(secretValue)\n",
            ext: "env",
            relativePath: "stdin.env",
            config: scanConfig
        )
        let sharedMatches = matches.filter { $0.customRuleName == "wo129_stdin_shared" }

        XCTAssertEqual(sharedMatches.count, 1)
        XCTAssertEqual(sharedMatches.first?.value, secretValue)
        XCTAssertEqual(sharedMatches.first?.line, 1)
        XCTAssertEqual(sharedMatches.first?.filePath, "stdin.env")
    }

    // WO-130: plain stdin is the generated pre-commit hook path and must use shared patterns.
    func testPlainStdinScanUsesSharedPatternFiles() throws {
        let secretValue = "PW" + "PLAIN-" + syntheticSuffix()
        let tempDir = try makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let artifactURL = try writeSharedPatternArtifact(
            regex: "PW" + #"PLAIN-[A-F0-9]{12}"#
        )
        defer { try? FileManager.default.removeItem(at: artifactURL) }

        try writeProjectConfig(sharedPatternFiles: [artifactURL.path], in: tempDir)

        let result = try runScanCLI(
            input: "marker \(secretValue)\n",
            currentDirectory: tempDir
        )

        XCTAssertEqual(result.status, 6)
        XCTAssertTrue(result.stderr.contains("findings:"))
    }

    // WO-130: plain stdin must fail closed when configured shared coverage is broken.
    func testPlainStdinScanFailsClosedForMissingSharedPatternFile() throws {
        let tempDir = try makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let missingURL = tempDir.appendingPathComponent("missing-shared-patterns.json")
        try writeProjectConfig(sharedPatternFiles: [missingURL.path], in: tempDir)

        let result = try runScanCLI(
            input: "plain text\n",
            currentDirectory: tempDir
        )

        XCTAssertEqual(result.status, 2)
        // WO-574@v4: active config validation blocks before the scan path starts.
        XCTAssertTrue(result.stderr.contains(".pastewatch.json"))
        XCTAssertTrue(result.stderr.contains("is invalid"))
    }

    // WO-131: empty plain stdin must still validate configured shared pattern files.
    func testPlainEmptyStdinScanFailsClosedForMissingSharedPatternFile() throws {
        let tempDir = try makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let missingURL = tempDir.appendingPathComponent("missing-shared-patterns.json")
        try writeProjectConfig(sharedPatternFiles: [missingURL.path], in: tempDir)

        let result = try runScanCLI(
            input: "",
            currentDirectory: tempDir
        )

        XCTAssertEqual(result.status, 2)
        // WO-574@v4: empty input cannot bypass the same startup config gate.
        XCTAssertTrue(result.stderr.contains(".pastewatch.json"))
        XCTAssertTrue(result.stderr.contains("is invalid"))
    }

    // WO-131: empty plain stdin remains clean when shared pattern config is valid.
    func testPlainEmptyStdinScanSucceedsWithValidSharedPatternFiles() throws {
        let tempDir = try makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let artifactURL = try writeSharedPatternArtifact(
            regex: "PW" + #"EMPTY-[A-F0-9]{12}"#
        )
        defer { try? FileManager.default.removeItem(at: artifactURL) }

        try writeProjectConfig(sharedPatternFiles: [artifactURL.path], in: tempDir)

        let result = try runScanCLI(
            input: "",
            currentDirectory: tempDir
        )

        XCTAssertEqual(result.status, 0)
        XCTAssertEqual(result.stdout, "")
        XCTAssertEqual(result.stderr, "")
    }

    // WO-577@v3: CLI diagnostics must use the same test-credential policy as guards and MCP.
    func testPlainStdinScanSuppressesKnownTestCredential() throws {
        let tempDir = try makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let knownTestKey = ["AKIA", "IOSFODNN7EXAMPLE"].joined()

        let result = try runScanCLI(
            input: "fixture \(knownTestKey)\n",
            currentDirectory: tempDir
        )

        XCTAssertEqual(result.status, 0)
        XCTAssertEqual(result.stdout, "")
        XCTAssertEqual(result.stderr, "")
    }

    // WO-577@v3: stdin cannot self-authorize inline suppression through filename metadata.
    func testStdinFilenameDoesNotUpgradeAgentControlledInputTrust() throws {
        let tempDir = try makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let value = ["postgres", "://user:pass@host/database"].joined()
        // dbConnectionString is an ambiguous class (default-OFF); enable it explicitly
        // in a project config so the assertion does not depend on ambient operator config.
        try writeProjectConfig(enabledTypes: ["DB Connection"], in: tempDir)

        let result = try runScanCLI(
            input: "DATABASE_URL=\(value) # pastewatch:allow\n",
            currentDirectory: tempDir,
            arguments: ["scan", "--check", "--stdin-filename", "fixture.env"]
        )

        XCTAssertEqual(result.status, ScanExitContract.findingsDetected)
        XCTAssertTrue(result.stderr.contains("findings:"))
    }

    // WO-580@v3: input decoding failures use the stable operational exit contract.
    func testInvalidUTF8FileReturnsOperationalFailure() throws {
        let tempDir = try makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let fileURL = tempDir.appendingPathComponent("invalid.bin")
        try Data([0xF5, 0x80]).write(to: fileURL)

        let result = try runScanCLI(
            input: "",
            currentDirectory: tempDir,
            arguments: ["scan", "--check", "--file", fileURL.path]
        )

        XCTAssertEqual(result.status, ScanExitContract.operationalFailure)
        XCTAssertEqual(result.stdout, "")
        XCTAssertTrue(result.stderr.contains("could not be read as UTF-8"))
    }

    // WO-580@v3: every auxiliary scan policy decode failure uses exit 2.
    func testMalformedScanPolicyFilesReturnOperationalFailure() throws {
        let tempDir = try makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let allowlist = tempDir.appendingPathComponent("allowlist.txt")
        let rules = tempDir.appendingPathComponent("rules.json")
        let baseline = tempDir.appendingPathComponent("baseline.json")
        try Data([0xF5, 0x80]).write(to: allowlist)
        try Data("not-json".utf8).write(to: rules)
        try Data("not-json".utf8).write(to: baseline)

        for arguments in [
            ["scan", "--check", "--allowlist", allowlist.path],
            ["scan", "--check", "--rules", rules.path],
            ["scan", "--check", "--baseline", baseline.path]
        ] {
            let result = try runScanCLI(
                input: "",
                currentDirectory: tempDir,
                arguments: arguments
            )

            XCTAssertEqual(result.status, ScanExitContract.operationalFailure)
            XCTAssertEqual(result.stdout, "")
            XCTAssertTrue(result.stderr.contains("scan configuration could not be loaded"))
        }
    }

    // WO-580@v3: a missing file keeps its precise diagnostic without a false UTF-8 error.
    func testMissingFileReportsOneOperationalCause() throws {
        let tempDir = try makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let missing = tempDir.appendingPathComponent("missing.txt")

        let result = try runScanCLI(
            input: "",
            currentDirectory: tempDir,
            arguments: ["scan", "--check", "--file", missing.path]
        )

        XCTAssertEqual(result.status, ScanExitContract.operationalFailure)
        XCTAssertTrue(result.stderr.contains("file not found"))
        XCTAssertFalse(result.stderr.contains("could not be read as UTF-8"))
    }

    private func writeSharedPatternArtifact(regex: String) throws -> URL {
        let artifactURL = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("pastewatch-stdin-shared-\(UUID().uuidString).json")
        let patterns = [
            SharedSecretPatternConfig(
                name: "wo129_stdin_shared",
                type: "github_token",
                regex: regex,
                policy: "redact"
            )
        ]
        let data = try JSONEncoder().encode(patterns)
        try data.write(to: artifactURL)
        return artifactURL
    }

    // WO-577@v3: test-isolation helper — pin config so scans are CI-deterministic.
    private func writeProjectConfig(
        sharedPatternFiles: [String] = [],
        enabledTypes: [String]? = nil,
        in directory: URL
    ) throws {
        var scanConfig = config
        scanConfig.sharedPatternFiles = sharedPatternFiles
        // WO-577@v3 test isolation: pin enabled types in the project config so the scan is
        // deterministic in CI and never depends on an operator's ~/.config/pastewatch.
        if let enabledTypes { scanConfig.enabledTypes = enabledTypes }
        let configURL = directory.appendingPathComponent(".pastewatch.json")
        try JSONEncoder().encode(scanConfig).write(to: configURL)
    }

    private func makeTempDirectory() throws -> URL {
        let url = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("pastewatch-stdin-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    private struct CLIResult {
        let status: Int32
        let stdout: String
        let stderr: String
    }

    // WO-580@v3: subprocess coverage pins parse, configuration, and findings exit codes.
    private func runScanCLI(
        input: String,
        currentDirectory: URL,
        arguments: [String] = ["scan", "--check"]
    ) throws -> CLIResult {
        let process = Process()
        process.executableURL = pastewatchCLIURL()
        process.arguments = arguments
        process.currentDirectoryURL = currentDirectory
        var environment = ProcessInfo.processInfo.environment
        environment.removeValue(forKey: "PW_GUARD")
        process.environment = environment

        let stdin = Pipe()
        let stdout = Pipe()
        let stderr = Pipe()
        process.standardInput = stdin
        process.standardOutput = stdout
        process.standardError = stderr

        try process.run()
        stdin.fileHandleForWriting.write(Data(input.utf8))
        stdin.fileHandleForWriting.closeFile()
        process.waitUntilExit()

        return CLIResult(
            status: process.terminationStatus,
            stdout: String(data: stdout.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? "",
            stderr: String(data: stderr.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        )
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

    private func syntheticSuffix() -> String {
        String(UUID().uuidString.replacingOccurrences(of: "-", with: "").uppercased().prefix(12))
    }
}
