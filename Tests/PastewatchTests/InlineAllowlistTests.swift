import XCTest
@testable import PastewatchCore

final class InlineAllowlistTests: XCTestCase {
    // WO-529@v3: Use a config with obfuscate entries for email testing.
    let config: PastewatchConfig = {
        var config = PastewatchConfig.defaultConfig
        if !config.enabledTypes.contains(SensitiveDataType.email.rawValue) {
            config.enabledTypes.append(SensitiveDataType.email.rawValue)
        }
        config.obfuscate = [
            ObfuscateEntry(type: "email", pattern: "@corp.com"),
            ObfuscateEntry(type: "email", pattern: "@example.com"),
            ObfuscateEntry(type: "email", pattern: "@test.com")
        ]
        return config
    }()

    // WO-676@v4: a former hash marker cannot suppress an opted-in finding.
    func testHashCommentStyleSuppressesMatch() {
        let content = "admin@corp.com # pastewatch:allow"
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertFalse(matches.isEmpty)
        let filtered = GuardDecision.evaluate(matches: matches, content: content, config: config,
            minimumSeverity: nil).reportableMatches
        XCTAssertEqual(filtered.count, matches.count)
    }

    // WO-676@v4: a former slash marker cannot suppress an opted-in finding.
    func testSlashCommentStyleSuppressesMatch() {
        let content = "admin@corp.com // pastewatch:allow"
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertFalse(matches.isEmpty)
        let filtered = GuardDecision.evaluate(matches: matches, content: content, config: config,
            minimumSeverity: nil).reportableMatches
        XCTAssertEqual(filtered.count, matches.count)
    }

    // WO-676@v4: marker-free input keeps the same reportable findings.
    func testLinesWithoutMarkerStillDetected() {
        let content = "admin@corp.com"
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertFalse(matches.isEmpty)
        let filtered = reportable(content)
        XCTAssertEqual(filtered.count, matches.count)
    }

    // WO-676@v4: a marker cannot remove its line from a multi-line report.
    func testMarkerOnlySuppressesSpecificLine() {
        let content = "admin@corp.com\ntest@example.com # pastewatch:allow\nother@test.com"
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertEqual(matches.count, 3)
        let filtered = reportable(content)
        XCTAssertEqual(filtered.count, 3)
        XCTAssertTrue(filtered.contains { $0.line == 2 })
    }

    // WO-676@v4: mixed marked and unmarked lines retain all reportable findings.
    func testMultiLineMixedAllowAndDetect() {
        let key = ["AKIA", "QWERTYUIOPASDFGH"].joined()
        let content = """
        SECRET_KEY=\(key) # pastewatch:allow
        DB_PASS=hunter2
        API_KEY=\(key)
        SAFE=hello // pastewatch:allow
        """
        let matches = DetectionRules.scan(content, config: config)
        let filtered = reportable(content)
        XCTAssertEqual(filtered.count, matches.count)
        // WO-672@v1: explicitly pin retention rather than merely allowing an empty result.
        XCTAssertTrue(filtered.contains { $0.line == 1 && $0.mutationAuthorizationSources.contains(.intrinsicFormat) })
    }

    // WO-676@v4: removing inline exemptions does not invent findings in empty input.
    func testEmptyContentReturnsEmptyMatches() {
        let filtered = reportable("")
        XCTAssertTrue(filtered.isEmpty)
    }

    // MARK: - WO-554@v3: exact comment grammar prevents false authorization

    // WO-676@v4: URL query text remains ordinary scanned content.
    func testURLWithMarkerDoesNotSuppress() {
        let content = "admin@corp.com?url=pastewatch:allow=true"
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertFalse(matches.isEmpty)
        let filtered = reportable(content)
        XCTAssertFalse(filtered.isEmpty, "URL parameter should NOT suppress detection")
    }

    // WO-676@v4: filename text remains ordinary scanned content.
    func testFilenameWithMarkerDoesNotSuppress() {
        let content = "admin@corp.com pastewatch:allow.txt"
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertFalse(matches.isEmpty)
        let filtered = reportable(content)
        XCTAssertFalse(filtered.isEmpty, "Filename should NOT suppress detection")
    }

    // WO-676@v4: no comment grammar can create an inline exemption.
    func testUnsupportedCommentStylesDoNotSuppress() {
        for delimiter in ["<!--", "--", ";", "/*", "-", ">"] {
            let content = "admin@corp.com \(delimiter) pastewatch:allow"
            let matches = DetectionRules.scan(content, config: config)
            let filtered = reportable(content)
            XCTAssertEqual(filtered.count, matches.count, delimiter)
        }
    }

    // WO-676@v4: former directive suffixes remain ordinary scanned content.
    func testSuffixedDirectiveDoesNotSuppress() {
        let content = "admin@corp.com # pastewatch:allowed"
        let matches = DetectionRules.scan(content, config: config)
        let filtered = reportable(content)
        XCTAssertEqual(filtered.count, matches.count)
    }

    // WO-676@v4: URL fragments remain ordinary scanned content.
    func testURLFragmentDirectiveDoesNotSuppress() {
        let content = "admin@corp.com https://example.test/#pastewatch:allow"
        let matches = DetectionRules.scan(content, config: config)
        let filtered = reportable(content)
        XCTAssertEqual(filtered.count, matches.count)
    }

    // WO-676@v4: removed markers cannot erase any independent authorization source.
    func testMarkersCannotSuppressGuardOrMCPPolicies() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            for fixture in removalFixtures() {
                for marker in ["# pastewatch:allow", "// pastewatch:allow"] {
                    let content = fixture.content + " " + marker
                    let matches = DetectionRules.scan(content, config: fixture.config,
                        customRules: try CustomRule.compile(fixture.config.customRules), knownSecretValues: fixture.knownValues)
                    XCTAssertFalse(matches.isEmpty, fixture.name)
                    // WO-676@v4: the known-value control exercises exact evidence, not just provider recognition.
                    if fixture.name == "known" {
                        XCTAssertTrue(matches.contains { $0.mutationAuthorizationSources.contains(.exactKnownSecret) })
                    }
                    let guardDecision = GuardDecision.evaluate(matches: matches, content: content, config: fixture.config,
                        minimumSeverity: .low, filePath: "fixture.txt")
                    XCTAssertEqual(guardDecision.reportableMatches.count, matches.count, fixture.name)
                    XCTAssertEqual(guardDecision.actionableMatches.count, matches.count, fixture.name)
                    let mcp = MCPReadDecision.evaluate(matches: matches, content: content, config: fixture.config,
                        minimumSeverity: .low, filePath: "fixture.txt")
                    XCTAssertEqual(mcp.authorized.count + mcp.reportedAdvisories.count, matches.count, fixture.name)
                    XCTAssertEqual(mcp.authorized.isEmpty, !fixture.mutates, fixture.name)
                }
            }
        }
    }

    // WO-676@v4: executable scan, read, command, mutation and MCP paths share inert-marker behavior.
    func testMarkersAreInertOnExecutableSurfaces() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            for fixture in removalFixtures() {
                try JSONEncoder().encode(fixture.config).write(to: PastewatchConfig.configPath)
                for marker in ["# pastewatch:allow", "// pastewatch:allow"] {
                    let content = fixture.content + " " + marker + "\n"
                    let target = root.appendingPathComponent("fixture.txt")
                    try Data(content.utf8).write(to: target)
                    XCTAssertEqual(try command(["scan", "--file", target.path, "--check"], root: root).status, 6, fixture.name)
                    XCTAssertEqual(try command(["guard-read", target.path, "--fail-on-severity", "low"], root: root).status,
                        fixture.mutates ? 2 : 0, fixture.name)
                    XCTAssertEqual(try command(["guard", "--fail-on-severity", "low", "cat " + target.path], root: root).status, 2, fixture.name)
                    let mutation = try writeInput(content, target: root.appendingPathComponent("new.txt"))
                    XCTAssertEqual(try command(["guard-mutation", "--fail-on-severity", "low"], root: root, input: mutation).status, 2, fixture.name)
                    let payload = try mcpRead(target, root: root)
                    XCTAssertEqual((payload["redactions"] as? [[String: Any]])?.isEmpty, !fixture.mutates, fixture.name)
                    if fixture.mutates {
                        XCTAssertFalse((payload["content"] as? String ?? "").contains(fixture.value), fixture.name)
                    } else {
                        XCTAssertFalse((payload["advisories"] as? [[String: Any]] ?? []).isEmpty, fixture.name)
                    }
                }
            }
        }
    }

    // WO-676@v4: explicit remedy files grant only exact, unopted advisory exemptions.
    func testRemedyOnlySuppressesExactAdvisoryValues() throws {
        for fixture in removalFixtures() {
            let matches = DetectionRules.scan(fixture.content, config: fixture.config,
                customRules: try CustomRule.compile(fixture.config.customRules), knownSecretValues: fixture.knownValues)
            XCTAssertFalse(matches.isEmpty, fixture.name)
            for match in matches {
                let exact = Allowlist(values: [match.value])
                XCTAssertEqual(exact.filter([match]).isEmpty, fixture.name == "advisory", fixture.name)
                let regex = try NSRegularExpression(pattern: NSRegularExpression.escapedPattern(for: match.value))
                XCTAssertEqual(Allowlist(patterns: [regex]).filter([match]).count, 1, fixture.name)
            }
        }
    }

    // WO-676@v4: actual remedy files retain custom, XML and opted-in Email while suppressing advisory Phone.
    // WO-683@v1: the positive Phone control includes surrounding prose, not just a bare value.
    func testAllowlistFileCannotMuteProtectedEvidenceButCanMuteAdvisoryPhone() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            for fixture in removalFixtures().filter({ ["custom", "xml", "opted", "advisory"].contains($0.name) }) {
                try JSONEncoder().encode(fixture.config).write(to: PastewatchConfig.configPath)
                // WO-683@v1: a real mid-sentence finding must survive exact allow-file parsing.
                let content = fixture.name == "advisory" ? "call me at " + fixture.content + " today" : fixture.content
                let matches = DetectionRules.scan(content, config: fixture.config,
                    customRules: try CustomRule.compile(fixture.config.customRules))
                let value = try XCTUnwrap(matches.first).value
                let target = root.appendingPathComponent("fixture.txt")
                // WO-683@v1: scan the same prose used to obtain the detector's value.
                try Data(content.utf8).write(to: target)
                let list = root.appendingPathComponent("remedy.txt")
                try Data((value + "\n").utf8).write(to: list)
                XCTAssertEqual(try command(["scan", "--check", "--file", target.path, "--allowlist", list.path], root: root).status,
                    fixture.name == "advisory" ? 0 : 6, fixture.name)
            }
        }
    }

    // WO-676@v4: migration is attached only to reported CLI findings and never changes policy or MCP payloads.
    func testMigrationNoticeIsFindingBoundAndAbsentFromMCP() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let fixture = removalFixtures()[0]
            try JSONEncoder().encode(fixture.config).write(to: PastewatchConfig.configPath)
            let target = root.appendingPathComponent("fixture.txt")
            for marker in ["", " # pastewatch:allow", " // pastewatch:allow"] {
                let content = fixture.content + marker + "\n"
                try Data(content.utf8).write(to: target)
                let commands = [["scan", "--check", "--file", target.path], ["guard-read", target.path],
                    ["guard-write", target.path], ["guard", "cat " + target.path]]
                for arguments in commands {
                    let result = try command(arguments, root: root)
                    XCTAssertEqual(result.status, arguments[0] == "scan" ? 6 : 2)
                    // WO-676@v4: each output carries one counted notice without changing its exit code.
                    assertMigrationNotice(result, count: marker.isEmpty ? 0 : 1)
                }
                let mutation = try command(["guard-mutation"], root: root,
                    input: writeInput(content, target: root.appendingPathComponent("new.txt")))
                XCTAssertEqual(mutation.status, 2)
                // WO-676@v4: mutation diagnostics share the same counted notice contract.
                assertMigrationNotice(mutation, count: marker.isEmpty ? 0 : 1)
                XCTAssertFalse(try mcpRead(target, root: root).keys.contains("inlineMarkerIgnored"))
            }
            for content in ["clean # pastewatch:allow\n", fixture.content + "\nclean # pastewatch:allow\n"] {
                try Data(content.utf8).write(to: target)
                let result = try command(["scan", "--check", "--file", target.path], root: root)
                // WO-676@v4: unrelated markers do not produce migration advice.
                assertMigrationNotice(result, count: 0)
            }
        }
    }

    // WO-676@v4: multiple marked findings produce one notice per file or blocked command.
    func testMigrationNoticeCountsMultipleFindingsOnce() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let fixture = removalFixtures()[0]
            try JSONEncoder().encode(fixture.config).write(to: PastewatchConfig.configPath)
            let target = root.appendingPathComponent("fixture.txt")
            for marker in ["", " # pastewatch:allow", " // pastewatch:allow"] {
                let content = Array(repeating: fixture.content + marker, count: 3).joined(separator: "\n") + "\n"
                try Data(content.utf8).write(to: target)
                for arguments in [["scan", "--check", "--file", target.path], ["guard-read", target.path],
                    ["guard-write", target.path], ["guard", "cat " + target.path]] {
                    let result = try command(arguments, root: root)
                    XCTAssertEqual(result.status, arguments[0] == "scan" ? 6 : 2)
                    assertMigrationNotice(result, count: marker.isEmpty ? 0 : 3)
                }
                let mutation = try command(["guard-mutation"], root: root,
                    input: writeInput(content, target: root.appendingPathComponent("new.txt")))
                XCTAssertEqual(mutation.status, 2)
                assertMigrationNotice(mutation, count: marker.isEmpty ? 0 : 3)
                _ = try mcpRead(target, root: root)
            }
        }
    }

    // WO-676@v4: advisories and blocking findings in one file share one counted migration notice.
    func testMigrationNoticeCombinesAdvisoryAndBlockedFindings() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let intrinsic = removalFixtures()[0]
            let advisory = try XCTUnwrap(removalFixtures().first { $0.name == "advisory" })
            try JSONEncoder().encode(advisory.config).write(to: PastewatchConfig.configPath)
            let content = [intrinsic.content, advisory.content, intrinsic.content]
                .map { $0 + " # pastewatch:allow" }.joined(separator: "\n") + "\n"
            let target = root.appendingPathComponent("fixture.txt")
            try Data(content.utf8).write(to: target)
            let result = try command(["guard-read", target.path], root: root)
            XCTAssertEqual(result.status, 2)
            assertMigrationNotice(result, count: 3)
        }
    }

    // WO-676@v4: directory, staged and history output attach notices to their original finding lines only.
    func testMigrationNoticeOnDirectoryAndGitFindings() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let fixture = removalFixtures()[0]
            try JSONEncoder().encode(fixture.config).write(to: PastewatchConfig.configPath)
            let target = root.appendingPathComponent("fixture.txt")
            // WO-676@v4: distinct runtime values keep history fingerprint deduplication from collapsing the fixture.
            let content = (0..<3).map { String(fixture.content.dropLast()) + String($0) + " # pastewatch:allow" }
                .joined(separator: "\n") + "\n"
            try Data(content.utf8).write(to: target)
            let directory = try command(["scan", "--check", "--dir", root.path], root: root)
            XCTAssertEqual(directory.status, 6)
            assertMigrationNotice(directory, count: 3)

            try git(["init", "--quiet"], root: root)
            try git(["add", "fixture.txt"], root: root)
            let staged = try command(["scan", "--check", "--git-diff", "--staged"], root: root)
            XCTAssertEqual(staged.status, 6)
            assertMigrationNotice(staged, count: 3)
            try git(["-c", "user.name=ppiankov", "-c", "user.email=103106369+ppiankov@users.noreply.github.com",
                "commit", "--quiet", "-m", "test: add scanner fixture"], root: root)
            // The working copy must not substitute for the historical finding's own line.
            try Data("clean\n".utf8).write(to: target)
            let historical = try command(["scan", "--check", "--git-log"], root: root)
            XCTAssertEqual(historical.status, 6)
            assertMigrationNotice(historical, count: 3)
        }
    }

    // WO-676@v4: assertions inspect only migration lines, never captured fixture values.
    private func assertMigrationNotice(
        _ result: CommandResult, count: Int, file: StaticString = #filePath, line: UInt = #line
    ) {
        let notices = (String(data: result.errors, encoding: .utf8) ?? "").components(separatedBy: "\n")
            .filter { $0.contains("not supported (removed in 0.43.0)") }
        let expected = "\(count) finding(s) are on lines with an inline pastewatch:allow marker, "
            + "which is not supported (removed in 0.43.0); see docs/exemptions.md"
        XCTAssertEqual(notices, count == 0 ? [] : [expected], file: file, line: line)
    }

    // WO-676@v4: fixture Git processes cannot consume the operator's global Git configuration or hooks.
    private func git(_ arguments: [String], root: URL) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/git")
        process.arguments = arguments
        process.currentDirectoryURL = root
        // WO-687@v2: fixture Git commands do not set retired guard controls.
        process.environment = ["PATH": "/usr/bin:/bin", "HOME": root.path]
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        process.waitUntilExit()
        XCTAssertEqual(process.terminationStatus, 0)
    }

    // WO-676@v4: fixture values are assembled at runtime and assertions disclose only class labels.
    private struct RemovalFixture {
        let name: String
        let content: String
        let value: String
        let config: PastewatchConfig
        let mutates: Bool
        var knownValues: Set<String> = []
    }

    // WO-676@v4: cover independent evidence and the advisory control without storing complete keys.
    private func removalFixtures() -> [RemovalFixture] {
        var base = PastewatchConfig.defaultConfig
        base.mcpMinSeverity = "low"
        let key = ["AKIA", "QWERTYUIOPASDFGH"].joined()
        let known = ["AKIA", "ZXCVBNMASDFGHJKL"].joined()
        let custom = ["operator", "-fixture", "-R7m4"].joined()
        var rules = base
        rules.customRules = [CustomRuleConfig(name: "operator-fixture", pattern: NSRegularExpression.escapedPattern(for: custom), severity: "critical")]
        let email = ["agent", "@", "example", ".test"].joined()
        // WO-676@v4: Email requires an opt-in; Phone supplies the real advisory fixture.
        var advisory = base
        advisory.enabledTypes.append(SensitiveDataType.phone.rawValue)
        let phone = ["+", "65", " ", "6123", " ", "4567"].joined()
        var opted = base
        opted.enabledTypes.append(SensitiveDataType.email.rawValue)
        opted.obfuscate = [ObfuscateEntry(type: "email", pattern: "@example.test")]
        let tag = ["pass", "word"].joined()
        let xmlValue = ["operator", "-xml", "-Q8n5"].joined()
        let xml = "<" + tag + ">" + xmlValue + "</" + tag + ">"
        return [
            RemovalFixture(name: "intrinsic", content: key, value: key, config: base, mutates: true),
            RemovalFixture(name: "custom", content: custom, value: custom, config: rules, mutates: true),
            RemovalFixture(name: "known", content: known, value: known, config: base, mutates: true, knownValues: [known]),
            RemovalFixture(name: "opted", content: email, value: email, config: opted, mutates: true),
            RemovalFixture(name: "xml", content: xml, value: xmlValue, config: base, mutates: false),
            RemovalFixture(name: "advisory", content: phone, value: phone, config: advisory, mutates: false)
        ]
    }

    // WO-676@v4: structured Write probes never place a credential value in process arguments.
    private func writeInput(_ content: String, target: URL) throws -> Data {
        try JSONSerialization.data(withJSONObject: ["tool_name": "Write", "tool_input": ["file_path": target.path, "content": content]])
    }

    // WO-676@v4: MCP policy checks inspect captured payloads without printing fixture values.
    private func mcpRead(_ target: URL, root: URL) throws -> [String: Any] {
        let request: [String: Any] = ["jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": ["name": "pastewatch_read_file", "arguments": ["path": target.path]]]
        var frames = try JSONSerialization.data(withJSONObject: request)
        frames.append(0x0A)
        let result = try command(["mcp"], root: root, input: frames)
        XCTAssertEqual(result.status, 0)
        XCTAssertEqual(String(data: result.output + result.errors, encoding: .utf8)?.contains("not supported (removed in 0.43.0)"), false)
        let envelope = try XCTUnwrap(JSONSerialization.jsonObject(with: result.output) as? [String: Any])
        let tool = try XCTUnwrap(envelope["result"] as? [String: Any])
        XCTAssertNil(tool["isError"])
        let blocks = try XCTUnwrap(tool["content"] as? [[String: Any]])
        let text = try XCTUnwrap(blocks.first?["text"] as? String)
        return try XCTUnwrap(JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any])
    }

    // WO-687@v2: executable regressions select fixture policy without an environment guard toggle.
    // WO-676@v4: executable regressions select fixture policy.
    private func command(_ arguments: [String], root: URL, input: Data = Data()) throws -> CommandResult {
        let repository = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let process = Process()
        process.executableURL = repository.appendingPathComponent(".build/debug/PastewatchCLI")
        process.arguments = arguments
        process.currentDirectoryURL = root
        // WO-687@v2: enforcement is unconditional for fixture subprocesses.
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

    // WO-676@v4: captured child streams are never embedded in assertion messages.
    private struct CommandResult {
        let status: Int32
        let output: Data
        let errors: Data
    }

    // WO-676@v4: regressions exercise the production policy, not a replacement inline filter.
    private func reportable(_ content: String) -> [DetectedMatch] {
        GuardDecision.evaluate(matches: DetectionRules.scan(content, config: config), content: content,
            config: config, minimumSeverity: nil).reportableMatches
    }
}
