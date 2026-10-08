import XCTest
@testable import PastewatchCore

// WO-662@v3: directory coverage must be observable independently of files with findings.
final class DirectoryScanCoverageTests: XCTestCase {
    // WO-662@v3: keep command metadata separate from captured output and diagnostics.
    private struct CLIResponse {
        let status: Int32
        let output: Data
        let errors: Data
    }

    // WO-662@v3: every encountered skip reason is measured without guessing files in pruned trees.
    func testCoreCountsSkipReasonsAndRetainsFindingsOnlyAPI() throws {
        try withFixture([
            "clean.md": "ordinary text", "ignored.txt": "ordinary text", "empty.txt": "", "source.unknown": "ordinary text"
        ]) { _, input in
            try Data([0, 65]).write(to: input.appendingPathComponent("binary.rs"))
            let build = input.appendingPathComponent("build", isDirectory: true)
            try FileManager.default.createDirectory(at: build, withIntermediateDirectories: true)
            try "ordinary text".write(to: build.appendingPathComponent("hidden.txt"), atomically: true, encoding: .utf8)
            let ignore = IgnoreFile(patterns: ["ignored.txt"])
            let report = try DirectoryScanner.scanWithStatistics(directory: input.path, config: .defaultConfig, ignoreFile: ignore)
            XCTAssertEqual(report.statistics.filesScanned, 1)
            XCTAssertEqual(report.statistics.skippedUnsupported, 1)
            XCTAssertEqual(report.statistics.skippedIgnored, 1)
            XCTAssertEqual(report.statistics.skippedBinary, 1)
            XCTAssertEqual(report.statistics.skippedEmpty, 1)
            XCTAssertEqual(report.statistics.skippedUnreadable, 0)
            XCTAssertEqual(report.statistics.skippedDirectories, 1)
            XCTAssertTrue(report.files.isEmpty)
            XCTAssertTrue(try DirectoryScanner.scan(directory: input.path, config: .defaultConfig, ignoreFile: ignore).isEmpty)
        }
    }

    // WO-662@v3: every added plain-text extension reaches the scanner rather than the skip path.
    func testAddedSourceExtensionsReachIntrinsicDetection() throws {
        let extensions = ["kt", "kts", "gradle", "c", "h", "cpp", "rs", "php", "cs", "html", "sql", "scala", "dart", "jsonl", "ndjson", "KT"]
        let key = "AKIA" + String(repeating: "Q", count: 16)
        let files = Dictionary(uniqueKeysWithValues: extensions.enumerated().map { ("source\($0.offset)." + $0.element, key + "\n") })
        try withFixture(files) { _, input in
            let report = try DirectoryScanner.scanWithStatistics(directory: input.path, config: .defaultConfig)
            XCTAssertEqual(report.statistics.filesScanned, extensions.count)
            XCTAssertEqual(report.statistics.skippedUnsupported, 0)
            XCTAssertEqual(report.files.count, extensions.count)
            XCTAssertTrue(report.files.allSatisfy { $0.matches.contains { $0.type == .awsKey } })
        }
    }

    // WO-662@v3: bail counts only successfully inspected files before stopping.
    func testBailDoesNotClaimFullCoverage() throws {
        let key = "AKIA" + String(repeating: "Q", count: 16)
        try withFixture(["one.txt": key, "two.txt": key]) { _, input in
            let report = try DirectoryScanner.scanWithStatistics(directory: input.path, config: .defaultConfig, bail: true)
            XCTAssertEqual(report.statistics.filesScanned, 1)
            XCTAssertEqual(report.files.count, 1)
        }
    }

    // WO-662@v3: clean supported files count as scanned in both CLI formats.
    func testCLICleanDirectoryReportsCoverage() throws {
        try withFixture(["readme.md": "ordinary text\n", "clean.xml": "<item>ordinary text</item>\n"]) { root, input in
            let json = try runCLI(["scan", "--dir", input.path, "--format", "json"], root: root)
            XCTAssertEqual(json.status, 0)
            XCTAssertTrue(json.output.isEmpty)
            XCTAssertTrue(try XCTUnwrap(String(data: json.errors, encoding: .utf8)).contains("Scanned 2 files."))
            let text = try runCLI(["scan", "--dir", input.path], root: root)
            XCTAssertEqual(text.status, 0)
            XCTAssertTrue(text.output.isEmpty)
            XCTAssertTrue(try XCTUnwrap(String(data: text.errors, encoding: .utf8)).contains("Scanned 2 files."))
        }
    }

    // WO-662@v3: a zero finding count must not conceal skipped text files.
    func testCLIUnsupportedOnlyDirectoryDoesNotClaimClean() throws {
        try withFixture(["source.unsupported": "ordinary text\n"]) { root, input in
            let response = try runCLI(["scan", "--dir", input.path, "--check", "--format", "json"], root: root)
            XCTAssertEqual(response.status, 0)
            XCTAssertTrue(response.output.isEmpty)
            let summary = try XCTUnwrap(String(data: response.errors, encoding: .utf8))
            XCTAssertTrue(summary.contains("Scanned 0 files."))
            XCTAssertTrue(summary.contains("unsupported=1"))
            XCTAssertTrue(summary.contains("not establish a clean directory"))
        }
    }

    // WO-662@v3: MCP summaries count clean scans and disclose unsupported-only scans.
    func testMCPCoverageCountsCleanAndUnsupportedFiles() throws {
        try withFixture(["readme.md": "ordinary text\n", "clean.xml": "<item>ordinary text</item>\n"]) { _, input in
            let session = try MCPProtocolTests.LiveMCPSession(executableURL: executable())
            defer { session.close() }
            let first = try scanMCP(session, path: input.path)
            XCTAssertTrue(first.contains("Scanned 2 files."))
            XCTAssertTrue(first.contains("unsupported=0"))
            let unsupported = input.appendingPathComponent("unsupported", isDirectory: true)
            try FileManager.default.createDirectory(at: unsupported, withIntermediateDirectories: true)
            try "ordinary text".write(to: unsupported.appendingPathComponent("source.unknown"), atomically: true, encoding: .utf8)
            let second = try scanMCP(session, path: unsupported.path)
            XCTAssertTrue(second.contains("Scanned 0 files."))
            XCTAssertTrue(second.contains("unsupported=1"))
            XCTAssertTrue(second.contains("not establish a clean directory"))
        }
    }

    // WO-662@v3: Kotlin source containing an intrinsic fixture cannot be skipped by extension.
    func testCLIKotlinIntrinsicFinding() throws {
        let key = "AKIA" + String(repeating: "Q", count: 16)
        try withFixture(["Main.kt": "val value = \"" + key + "\"\n"]) { root, input in
            let response = try runCLI(["scan", "--dir", input.path, "--check"], root: root)
            XCTAssertEqual(response.status, 6)
            let diagnostic = try XCTUnwrap(String(data: response.errors, encoding: .utf8))
            XCTAssertTrue(diagnostic.contains("AWS Key"))
            XCTAssertFalse(diagnostic.contains(key))
        }
    }

    // WO-662@v3: transcript copies at every depth count as scans, not unsupported skips.
    func testNestedJSONLinesCopiesContributeToCoverage() throws {
        let key = "AKIA" + String(repeating: "Q", count: 16)
        let content = "{\"value\":\"" + key + "\"}\n"
        try withFixture(["top.json": content, "top.jsonl": content]) { root, input in
            let nested = input.appendingPathComponent("depth1/depth2", isDirectory: true)
            try FileManager.default.createDirectory(at: nested, withIntermediateDirectories: true)
            for ext in ["json", "jsonl", "ndjson"] {
                try content.write(to: nested.appendingPathComponent("deep." + ext), atomically: true, encoding: .utf8)
            }
            let report = try DirectoryScanner.scanWithStatistics(directory: input.path, config: .defaultConfig)
            XCTAssertEqual(report.statistics.filesScanned, 5)
            XCTAssertEqual(report.statistics.skippedUnsupported, 0)
            XCTAssertEqual(report.files.count, 5)
            XCTAssertTrue(report.files.allSatisfy { $0.matches.contains { $0.type == .awsKey } })
            let response = try runCLI(["scan", "--dir", input.path, "--check", "--format", "json"], root: root)
            XCTAssertEqual(response.status, 6)
            let payload = try XCTUnwrap(JSONSerialization.jsonObject(with: response.output) as? [[String: Any]])
            XCTAssertEqual(payload.count, 5)
            XCTAssertTrue(try XCTUnwrap(String(data: response.errors, encoding: .utf8)).contains("Scanned 5 files."))
        }
    }

    // WO-662@v3: directory JSON retains the pre-branch array schema and per-file fields.
    func testDirectoryJSONRetainsLegacyArrayShape() throws {
        let key = "AKIA" + String(repeating: "Q", count: 16)
        try withFixture(["one.kt": key]) { root, input in
            let response = try runCLI(["scan", "--dir", input.path, "--check", "--format", "json"], root: root)
            XCTAssertEqual(response.status, 6)
            let array = try XCTUnwrap(JSONSerialization.jsonObject(with: response.output) as? [[String: Any]])
            XCTAssertEqual(array.count, 1)
            XCTAssertEqual(Set(try XCTUnwrap(array.first).keys), ["file", "findings", "count", "gitignored"])
        }
    }

    // WO-662@v3: Latin-1 source detection preserves raw bytes and byte-based line numbers.
    func testLatin1SourceAndLongLineCoverage() throws {
        try withFixture(["clean.md": "ordinary text\n"]) { root, input in
            let key = "AKIA" + String(repeating: "Q", count: 16)
            let sql = input.appendingPathComponent("source.sql")
            var bytes = Data([0xE9, 0x85, 0x0A, 0xE9, 0x20])
            bytes.append(Data((key + "\n").utf8))
            try bytes.write(to: sql)
            try Data([0xE9, 0x0A]).write(to: input.appendingPathComponent("clean.c"))
            let report = try DirectoryScanner.scanWithStatistics(directory: input.path, config: .defaultConfig)
            XCTAssertEqual(report.statistics.filesScanned, 3)
            XCTAssertEqual(report.files.first?.matches.first?.line, 2)
            XCTAssertTrue(try Data(contentsOf: sql) == bytes)
            let detected = try runCLI(["scan", "--dir", input.path, "--check"], root: root)
            XCTAssertEqual(detected.status, 6)
            try FileManager.default.removeItem(at: sql)
            XCTAssertEqual(try runCLI(["scan", "--dir", input.path, "--check"], root: root).status, 0)
            try Data(repeating: 0x78, count: 1_500_000).write(to: input.appendingPathComponent("long.jsonl"))
            let skipped = try runCLI(["scan", "--dir", input.path, "--check"], root: root)
            XCTAssertEqual(skipped.status, 0)
            let diagnostics = try XCTUnwrap(String(data: skipped.errors, encoding: .utf8))
            XCTAssertTrue(diagnostics.contains("long.jsonl"))
            XCTAssertTrue(diagnostics.contains("skippedOverLimit=1"))
        }
    }

    // WO-662@v3: subprocess fixtures select test-owned policy before global fallback.
    private func withFixture(_ files: [String: String], body: (URL, URL) throws -> Void) throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            try TestConfigHelper.ensureProjectConfig(in: root)
            // WO-662@v3: the tracked-file coverage contract needs a repository for Git-ignore classification.
            let git = Process()
            git.executableURL = URL(fileURLWithPath: "/usr/bin/git")
            git.arguments = ["init", "--quiet", root.path]
            git.environment = ["PATH": "/usr/bin:/bin", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1"]
            git.standardOutput = FileHandle.nullDevice
            git.standardError = FileHandle.nullDevice
            try git.run()
            git.waitUntilExit()
            XCTAssertEqual(git.terminationStatus, 0)
            let input = root.appendingPathComponent("input", isDirectory: true)
            try FileManager.default.createDirectory(at: input, withIntermediateDirectories: true)
            for (name, content) in files {
                try content.write(to: input.appendingPathComponent(name), atomically: true, encoding: .utf8)
            }
            try body(root, input)
        }
    }

    // WO-662@v3: executable lookup does not depend on the fixture CWD.
    private func executable() -> URL {
        URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().appendingPathComponent(".build/debug/PastewatchCLI")
    }

    // WO-662@v3: capture command output without emitting fixture contents or inheriting a guard bypass.
    private func runCLI(_ arguments: [String], root: URL) throws -> CLIResponse {
        let process = Process()
        let output = Pipe()
        let errors = Pipe()
        process.executableURL = executable()
        process.arguments = arguments
        process.currentDirectoryURL = root
        process.environment = ["PATH": "/usr/bin:/bin", "PW_GUARD": "1"]
        process.standardOutput = output
        process.standardError = errors
        try process.run()
        let data = output.fileHandleForReading.readDataToEndOfFile()
        let diagnostics = errors.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return CLIResponse(status: process.terminationStatus, output: data, errors: diagnostics)
    }

    // WO-662@v3: inspect metadata-only MCP summaries, not matched values.
    private func scanMCP(_ session: MCPProtocolTests.LiveMCPSession, path: String) throws -> String {
        let request = JSONRPCRequest(jsonrpc: "2.0", id: .int(1), method: "tools/call", params: .object([
            "name": .string("pastewatch_scan_dir"), "arguments": .object(["path": .string(path)])
        ]))
        try session.send(try JSONEncoder().encode(request) + Data([0x0A]))
        let response = try XCTUnwrap(session.response())
        guard case .object(let result) = response.result,
              case .array(let blocks) = result["content"],
              case .object(let first) = blocks.first,
              case .string(let text) = first["text"] else {
            throw CocoaError(.coderInvalidValue)
        }
        return text
    }
}
