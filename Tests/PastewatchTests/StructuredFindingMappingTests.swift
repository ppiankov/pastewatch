import XCTest
@testable import PastewatchCore

final class StructuredFindingMappingTests: XCTestCase {
    // WO-686@v1: one unmappable member cannot discard the other files' scan evidence.
    func testDirectoryContinuesAfterUnmappableJSON() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let fixture = try makeFixture(in: root)
            do {
                let report = try DirectoryScanner.scanWithStatistics(directory: fixture.directory.path, config: .defaultConfig)
                XCTAssertEqual(report.statistics.filesScanned, 3)
                XCTAssertEqual(report.files.count, 1)
                XCTAssertEqual(report.files.first?.filePath, "d-healthy.txt")
                XCTAssertEqual(report.files.first?.matches.count, 1)
            } catch {
                XCTFail("A mapping failure aborted the directory scan")
            }
        }
    }

    // WO-686@v1: unsafe mutation mapping keeps its refusal while diagnostics expose only a source location.
    func testMappingErrorReportsTypeSeverityAndJSONValueByteOffset() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let fixture = try makeFixture(in: root)
            XCTAssertThrowsError(try DirectoryScanner.scanFileContentOrThrow(
                content: fixture.content, ext: "json", relativePath: "a-unmappable.json", config: .defaultConfig
            )) { error in
                XCTAssertTrue(error is StructuredMatchRangeError)
                XCTAssertTrue(error.localizedDescription.contains(fixture.type))
                XCTAssertTrue(error.localizedDescription.contains("severity=" + fixture.severity))
                XCTAssertTrue(error.localizedDescription.contains("byte_offset=\(fixture.byteOffset)"))
                XCTAssertFalse(error.localizedDescription.contains(fixture.secret))
            }
        }
    }

    // WO-686@v1: MCP directory results retain healthy findings and separately identify incomplete members.
    func testMCPDirectoryReportsPartialResultsWithoutSecretValues() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let fixture = try makeFixture(in: root)
            let result = try mcp("pastewatch_scan_dir", path: fixture.directory.path, root: root)
            XCTAssertEqual(result["isError"] as? Bool, true)
            let blocks = try XCTUnwrap(result["content"] as? [[String: Any]])
            guard blocks.count == 3 else { return XCTFail("Missing separate unscannable-file diagnostics") }
            let summary = try XCTUnwrap(blocks[0]["text"] as? String)
            XCTAssertTrue(summary.contains("Scanned 3 files"))
            XCTAssertTrue(summary.contains("unscannable"))
            let findings = try decode(try XCTUnwrap(blocks[1]["text"] as? String)) as? [[String: Any]]
            XCTAssertEqual(findings?.count, 1)
            XCTAssertEqual(findings?.first?["file"] as? String, "d-healthy.txt")
            let failures = try XCTUnwrap(try decode(try XCTUnwrap(blocks[2]["text"] as? String)) as? [String: Any])
            let files = try XCTUnwrap(failures["unscannable_files"] as? [[String: Any]])
            XCTAssertEqual(files.count, 1)
            assertFailure(try XCTUnwrap(files.first), fixture: fixture)
            XCTAssertFalse(blocks.contains { ($0["text"] as? String)?.contains(fixture.secret) == true })
        }
    }

    // WO-686@v1: a single-file MCP mapping failure carries metadata, never its decoded secret value.
    func testMCPSingleFileReportsSafeLocationMetadata() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let fixture = try makeFixture(in: root)
            let result = try mcp("pastewatch_scan_file", path: fixture.path.path, root: root)
            XCTAssertEqual(result["isError"] as? Bool, true)
            let blocks = try XCTUnwrap(result["content"] as? [[String: Any]])
            guard blocks.count == 2 else { return XCTFail("Missing structured finding metadata") }
            let payload = try XCTUnwrap(try decode(try XCTUnwrap(blocks[1]["text"] as? String)) as? [String: Any])
            assertFailure(payload, fixture: fixture)
            XCTAssertFalse(blocks.contains { ($0["text"] as? String)?.contains(fixture.secret) == true })
        }
    }

    // WO-686@v1: mapped JSON findings also expose byte locations without adding a value to MCP diagnostics.
    func testMappedSingleLineJSONReportsByteOffset() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let fixture = try makeFixture(in: root)
            let prefix = jsonPrefix()
            try Data((prefix + "\"" + fixture.secret + "\"}").utf8).write(to: fixture.path)
            let result = try mcp("pastewatch_scan_file", path: fixture.path.path, root: root)
            XCTAssertNil(result["isError"])
            let blocks = try XCTUnwrap(result["content"] as? [[String: Any]])
            let findings = try XCTUnwrap(try decode(try XCTUnwrap(blocks[1]["text"] as? String)) as? [[String: Any]])
            XCTAssertEqual(findings.count, 1)
            XCTAssertEqual(findings.first?["byte_offset"] as? Int, prefix.utf8.count + 1)
            XCTAssertEqual(findings.first?["severity"] as? String, fixture.severity)
            XCTAssertNil(findings.first?["value"])
            XCTAssertFalse(blocks.contains { ($0["text"] as? String)?.contains(fixture.secret) == true })
        }
    }

    // WO-686@v1: CLI check output keeps the findings array and lists every failed member on stderr.
    func testCLIDirectoryRetainsJSONResultsAndListsEveryUnscannableFile() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let fixture = try makeFixture(in: root)
            try Data(fixture.content.utf8).write(to: fixture.directory.appendingPathComponent("b-unmappable.json"))
            let result = try command(["scan", "--dir", fixture.directory.path, "--check", "--format", "json"], root: root)
            XCTAssertEqual(result.status, ScanExitContract.operationalFailure)
            guard !result.output.isEmpty else { return XCTFail("The scan discarded healthy-file results") }
            let rows = try XCTUnwrap(JSONSerialization.jsonObject(with: result.output) as? [[String: Any]])
            XCTAssertEqual(rows.count, 1)
            XCTAssertEqual(rows.first?["file"] as? String, "d-healthy.txt")
            let diagnostics = String(data: result.errors, encoding: .utf8) ?? ""
            let paths = diagnostics.components(separatedBy: "\n").filter { $0.hasPrefix("UNSCANNABLE:") }
            XCTAssertEqual(paths.count, 2)
            XCTAssertTrue(paths.contains { $0.contains("a-unmappable.json") })
            XCTAssertTrue(paths.contains { $0.contains("b-unmappable.json") })
            XCTAssertTrue(diagnostics.contains("byte_offset=\(fixture.byteOffset)"))
            XCTAssertFalse(diagnostics.contains(fixture.secret))
        }
    }

    // WO-686@v1: zero reportable findings does not make an incomplete directory clean in either format.
    func testIncompleteFindingFreeDirectoryStillFailsCheck() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let fixture = try makeFixture(in: root, healthyFinding: false)
            for format in ["text", "json"] {
                let result = try command(["scan", "--dir", fixture.directory.path, "--check", "--format", format], root: root)
                XCTAssertEqual(result.status, ScanExitContract.operationalFailure)
                let diagnostics = String(data: result.errors, encoding: .utf8) ?? ""
                XCTAssertTrue(diagnostics.contains("Scanned 2 files"))
                XCTAssertTrue(diagnostics.contains("unscannable"))
                XCTAssertTrue(diagnostics.contains("UNSCANNABLE:"))
                XCTAssertFalse(diagnostics.contains(fixture.secret))
            }
        }
    }

    // WO-686@v1: CLI single-file JSON errors report only safe diagnostic fields.
    func testCLISingleFileJSONReportsFailureWithoutValue() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let fixture = try makeFixture(in: root)
            let result = try command(["scan", "--file", fixture.path.path, "--check", "--format", "json"], root: root)
            XCTAssertEqual(result.status, ScanExitContract.operationalFailure)
            guard !result.output.isEmpty else { return XCTFail("Missing JSON mapping-failure metadata") }
            let payload = try XCTUnwrap(JSONSerialization.jsonObject(with: result.output) as? [String: Any])
            assertFailure(payload, fixture: fixture)
            XCTAssertFalse(String(data: result.output + result.errors, encoding: .utf8)?.contains(fixture.secret) == true)
        }
    }

    // WO-686@v1: diagnostic fallback never enables native or MCP reads of unmappable protected content.
    func testUnmappableNativeAndMCPReadsStayRefused() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let fixture = try makeFixture(in: root)
            let native = try command(["guard-read", fixture.path.path], root: root)
            XCTAssertNotEqual(native.status, 0)
            XCTAssertFalse(String(data: native.output + native.errors, encoding: .utf8)?.contains(fixture.secret) == true)
            let result = try mcp("pastewatch_read_file", path: fixture.path.path, root: root)
            XCTAssertEqual(result["isError"] as? Bool, true)
            let blocks = try XCTUnwrap(result["content"] as? [[String: Any]])
            XCTAssertFalse(blocks.contains { ($0["text"] as? String)?.contains(fixture.secret) == true })
        }
    }

    // WO-686@v1: assertions inspect type, severity and location rather than matched values.
    private func assertFailure(_ payload: [String: Any], fixture: Fixture, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertEqual(payload["unscannable"] as? Bool, true, file: file, line: line)
        let findings = payload["findings"] as? [[String: Any]]
        XCTAssertEqual(findings?.count, 1, file: file, line: line)
        XCTAssertEqual(findings?.first?["type"] as? String, fixture.type, file: file, line: line)
        XCTAssertEqual(findings?.first?["severity"] as? String, fixture.severity, file: file, line: line)
        XCTAssertEqual(findings?.first?["line"] as? Int, 1, file: file, line: line)
        XCTAssertEqual(findings?.first?["byte_offset"] as? Int, fixture.byteOffset, file: file, line: line)
        XCTAssertNil(findings?.first?["value"], file: file, line: line)
    }

    // WO-686@v1: JSON escapes prevent exact source mapping while an earlier astral scalar proves UTF-8 offsets.
    private func makeFixture(in root: URL, healthyFinding: Bool = true) throws -> Fixture {
        let directory = root.appendingPathComponent("input", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let secret = "AIza" + String(repeating: "A", count: 35)
        let match = try XCTUnwrap(DetectionRules.scan(secret, config: .defaultConfig).first)
        let prefix = jsonPrefix()
        let content = prefix + "\"\\u0041" + secret.dropFirst() + "\"}"
        let path = directory.appendingPathComponent("a-unmappable.json")
        try Data(content.utf8).write(to: path)
        try Data("ordinary text\n".utf8).write(to: directory.appendingPathComponent("b-clean.md"))
        try Data("<root>ordinary text</root>\n".utf8).write(to: directory.appendingPathComponent("c-clean.xml"))
        if healthyFinding {
            let other = "AIza" + String(repeating: "B", count: 35)
            try Data(other.utf8).write(to: directory.appendingPathComponent("d-healthy.txt"))
        }
        return Fixture(directory: directory, path: path, content: content, secret: secret,
                       type: match.displayName, severity: match.effectiveSeverity.rawValue, byteOffset: prefix.utf8.count)
    }

    // WO-686@v1: runtime Unicode avoids source literals and distinguishes byte offsets from character counts.
    private func jsonPrefix() -> String { "{\"metadata\":\"\u{1F642}\",\"payload\":" }

    // WO-686@v1: child fixtures share only the scoped DEBUG configuration, never operator files.
    private func command(_ arguments: [String], root: URL, input: Data = Data()) throws -> CommandResult {
        let repository = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let process = Process()
        process.executableURL = repository.appendingPathComponent(".build/debug/PastewatchCLI")
        process.arguments = arguments
        process.currentDirectoryURL = root
        process.environment = TestConfigHelper.subprocessEnvironment(["PATH": "/usr/bin:/bin"])
        let stdin = Pipe(), stdout = Pipe(), stderr = Pipe()
        process.standardInput = stdin
        process.standardOutput = stdout
        process.standardError = stderr
        try process.run()
        stdin.fileHandleForWriting.write(input)
        try stdin.fileHandleForWriting.close()
        let output = stdout.fileHandleForReading.readDataToEndOfFile()
        let errors = stderr.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return CommandResult(status: process.terminationStatus, output: output, errors: errors)
    }

    // WO-686@v1: MCP responses are privately captured and only diagnostic metadata enters assertions.
    private func mcp(_ name: String, path: String, root: URL) throws -> [String: Any] {
        let request: [String: Any] = ["jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": ["name": name, "arguments": ["path": path]]]
        var input = try JSONSerialization.data(withJSONObject: request)
        input.append(0x0A)
        let response = try command(["mcp"], root: root, input: input)
        XCTAssertEqual(response.status, 0)
        let envelope = try XCTUnwrap(JSONSerialization.jsonObject(with: response.output) as? [String: Any])
        return try XCTUnwrap(envelope["result"] as? [String: Any])
    }

    // WO-686@v1: structured diagnostics are decoded with Foundation rather than textual field extraction.
    private func decode(_ text: String) throws -> Any { try JSONSerialization.jsonObject(with: Data(text.utf8)) }

    // WO-686@v1: fixture secrets stay in memory and captured streams, never assertion messages.
    private struct Fixture {
        let directory: URL
        let path: URL
        let content: String
        let secret: String
        let type: String
        let severity: String
        let byteOffset: Int
    }

    // WO-686@v1: subprocess streams are named without a large tuple or diagnostic value interpolation.
    private struct CommandResult {
        let status: Int32
        let output: Data
        let errors: Data
    }
}
