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
        XCTAssertTrue(result.stderr.contains("shared pattern load failed"))
        XCTAssertTrue(result.stderr.contains("could not read"))
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

    private func writeProjectConfig(sharedPatternFiles: [String], in directory: URL) throws {
        var scanConfig = config
        scanConfig.sharedPatternFiles = sharedPatternFiles
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

    private func runScanCLI(input: String, currentDirectory: URL) throws -> CLIResult {
        let process = Process()
        process.executableURL = pastewatchCLIURL()
        process.arguments = ["scan", "--check"]
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
