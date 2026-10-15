import XCTest
@testable import PastewatchCore

final class ProjectExemptionMetadataTests: XCTestCase {
    // WO-685@v1: subordinate exact exemptions retain operator-configured mutation evidence.
    func testOptedInEmailIsNotProjectExemptible() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            let content = emailFixture()
            let matches = DetectionRules.scan(content, config: optedConfig())
            let match = try XCTUnwrap(matches.first { $0.type == .email })
            XCTAssertTrue(match.mutationAuthorizationSources.contains(.configuredObfuscate))
            for source: AllowlistSource in [.project, .projectFile, .restrictedUser, .remedy] {
                XCTAssertFalse(permitsAllowlistSuppression(of: match, source: source, exactValue: true))
                let filtered = Allowlist(values: [match.value], source: source).filter([match])
                XCTAssertEqual(filtered.count, 1)
                let outcome = applyAuthorizedMutations(to: content, matches: filtered,
                    site: .cliScan, minAdvisorySeverity: .low)
                XCTAssertEqual(outcome.mutated.count, 1)
                XCTAssertFalse(outcome.text.contains(match.value))
            }
            for source: AllowlistSource in [.system, .user] {
                XCTAssertTrue(permitsAllowlistSuppression(of: match, source: source, exactValue: true))
                XCTAssertTrue(permitsAllowlistSuppression(of: match, source: source, exactValue: false))
                XCTAssertTrue(Allowlist(values: [match.value], source: source).filter([match]).isEmpty)
            }
        }
    }

    // WO-685@v1: CLI and MCP keep configured findings when either project exact-value source is present.
    func testProjectEntriesCannotUndoConfiguredEmailOnCLIOrMCP() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let config = optedConfig()
            try JSONEncoder().encode(config).write(to: PastewatchConfig.configPath)
            XCTAssertEqual(try run(["init", "--quiet"], root: root, executable: "/usr/bin/git").status, 0)
            let content = emailFixture()
            let match = try XCTUnwrap(DetectionRules.scan(content, config: config).first { $0.type == .email })
            let target = root.appendingPathComponent("fixture.txt")
            try Data((content + "\n").utf8).write(to: target)
            let arguments = ["scan", "--format", "json", "--file", target.path]
            let baseline = try run(arguments, root: root)
            XCTAssertEqual(baseline.status, 6)
            try assertProtectedScan(baseline, value: match.value)
            for source: AllowlistSource in [.project, .projectFile] {
                try writeProjectEntry(match.value, source: source, root: root)
                let result = try run(arguments, root: root)
                XCTAssertEqual(result.status, 6)
                if result.status == 6 { try assertProtectedScan(result, value: match.value) }
                XCTAssertEqual(try run(["guard-read", target.path, "--fail-on-severity", "low"], root: root).status, 2)
                let payload = try mcpRead(target, root: root)
                let redactions = try XCTUnwrap(payload["redactions"] as? [[String: Any]])
                XCTAssertEqual(redactions.count, 1)
                let rewritten = try XCTUnwrap(payload["content"] as? String)
                let placeholder = try XCTUnwrap(redactions.first?["placeholder"] as? String)
                XCTAssertTrue(rewritten.contains(placeholder))
                XCTAssertFalse(rewritten.contains(match.value))
            }
        }
    }

    // WO-685@v1: naturally emitted unopted Phone findings keep both project exemption routes.
    func testAdvisoryPhoneKeepsProjectExemptions() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let config = TestConfigHelper.configWithAmbiguousAdvisories([.phone])
            try JSONEncoder().encode(config).write(to: PastewatchConfig.configPath)
            XCTAssertEqual(try run(["init", "--quiet"], root: root, executable: "/usr/bin/git").status, 0)
            let content = "call me at " + ["+", "65", " ", "6123", " ", "4567"].joined() + " today\n"
            let match = try XCTUnwrap(DetectionRules.scan(content, config: config).first { $0.type == .phone })
            XCTAssertTrue(match.mutationAuthorizationSources.isEmpty)
            XCTAssertTrue(permitsAllowlistSuppression(of: match, source: .projectFile, exactValue: true))
            let target = root.appendingPathComponent("fixture.txt")
            try Data(content.utf8).write(to: target)
            let baseline = try run(["scan", "--format", "json", "--check", "--file", target.path], root: root)
            XCTAssertEqual(baseline.status, 6)
            let output = try XCTUnwrap(JSONSerialization.jsonObject(with: baseline.output) as? [String: Any])
            let findings = try XCTUnwrap(output["findings"] as? [[String: Any]])
            XCTAssertEqual(findings.count, 1)
            XCTAssertEqual(findings.first?["projectExemptible"] as? Bool, true)
            for source: AllowlistSource in [.project, .projectFile] {
                try writeProjectEntry(match.value, source: source, root: root)
                XCTAssertEqual(try run(["scan", "--check", "--file", target.path], root: root).status, 0)
            }
        }
    }

    // WO-685@v1: metadata assertions disclose only counts and decisions, not captured values.
    private func assertProtectedScan(_ result: CommandResult, value: String) throws {
        let output = try XCTUnwrap(JSONSerialization.jsonObject(with: result.output) as? [String: Any])
        let findings = try XCTUnwrap(output["findings"] as? [[String: Any]])
        XCTAssertEqual(findings.count, 1)
        XCTAssertEqual(findings.first?["projectExemptible"] as? Bool, false)
        let rewritten = try XCTUnwrap(output["obfuscated"] as? String)
        XCTAssertFalse(rewritten.contains(value))
    }

    // WO-685@v1: fixture entries come from the detector's own value and retain their real source tier.
    private func writeProjectEntry(_ value: String, source: AllowlistSource, root: URL) throws {
        let allowFile = root.appendingPathComponent(".pastewatch-allow")
        if FileManager.default.fileExists(atPath: allowFile.path) { try FileManager.default.removeItem(at: allowFile) }
        var project = PastewatchConfig.defaultConfig
        if source == .project { project.allowedValues = [value] }
        try JSONEncoder().encode(project).write(to: root.appendingPathComponent(".pastewatch.json"))
        if source == .projectFile { try Data((value + "\n").utf8).write(to: allowFile) }
    }

    // WO-685@v1: operator opt-ins are injected only through the scoped DEBUG fixture path.
    private func optedConfig() -> PastewatchConfig {
        var config = PastewatchConfig.defaultConfig
        config.enabledTypes.append(SensitiveDataType.email.rawValue)
        config.obfuscate = [ObfuscateEntry(type: "email", pattern: "@example.test")]
        config.mcpMinSeverity = "low"
        return config
    }

    // WO-685@v1: complete matched input exists only at runtime.
    private func emailFixture() -> String {
        ["configured", "@", "example", ".test"].joined()
    }

    // WO-685@v1: protocol checks inspect placeholder payloads without emitting child streams.
    private func mcpRead(_ target: URL, root: URL) throws -> [String: Any] {
        let request: [String: Any] = ["jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": ["name": "pastewatch_read_file", "arguments": ["path": target.path, "min_severity": "low"]]]
        var frames = try JSONSerialization.data(withJSONObject: request)
        frames.append(0x0A)
        let result = try run(["mcp"], root: root, input: frames)
        XCTAssertEqual(result.status, 0)
        let envelope = try XCTUnwrap(JSONSerialization.jsonObject(with: result.output) as? [String: Any])
        let tool = try XCTUnwrap(envelope["result"] as? [String: Any])
        XCTAssertNil(tool["isError"])
        let blocks = try XCTUnwrap(tool["content"] as? [[String: Any]])
        let text = try XCTUnwrap(blocks.first?["text"] as? String)
        return try XCTUnwrap(JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any])
    }

    // WO-685@v1: children share fixture policy, never the operator's config or inherited guard setting.
    private func run(_ arguments: [String], root: URL, input: Data = Data(), executable: String? = nil) throws -> CommandResult {
        let repository = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        let process = Process()
        process.executableURL = executable.map { URL(fileURLWithPath: $0) }
            ?? repository.appendingPathComponent(".build/debug/PastewatchCLI")
        process.arguments = arguments
        process.currentDirectoryURL = root
        // WO-687@v2: opt-in policy does not depend on an environment guard switch.
        process.environment = TestConfigHelper.subprocessEnvironment(["PATH": "/usr/bin:/bin", "HOME": root.path])
        let stdin = Pipe(), stdout = Pipe()
        process.standardInput = stdin
        process.standardOutput = stdout
        process.standardError = FileHandle.nullDevice
        try process.run()
        stdin.fileHandleForWriting.write(input)
        try stdin.fileHandleForWriting.close()
        let output = stdout.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return CommandResult(status: process.terminationStatus, output: output)
    }

    // WO-685@v1: captured child payloads remain local to test assertions.
    private struct CommandResult {
        let status: Int32
        let output: Data
    }
}
