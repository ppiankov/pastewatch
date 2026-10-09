import XCTest
@testable import PastewatchCore

// WO-672@v1: subordinate exemptions cannot discard non-advisory or operator rule evidence.
final class ProjectExemptionSecurityTests: XCTestCase {
    // WO-672@v1: child output remains private even when a regression assertion fails.
    private struct CommandResult {
        let status: Int32
        let output: Data
        let errors: Data
    }

    // WO-672@v1: project configuration must retain non-ambiguous XML findings.
    func testXMLCredentialProjectValueCannotSuppress() throws {
        try verifyXMLCredentialExemption(source: .project)
    }

    // WO-672@v1: the project allow file follows the same non-advisory restriction.
    func testXMLCredentialAllowFileCannotSuppress() throws {
        try verifyXMLCredentialExemption(source: .projectFile)
    }

    // WO-672@v1: user rule matches retain reporting and MCP mutation through subordinate exact entries.
    func testUserCustomRuleCannotBeSuppressedByProjectValue() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let content = ["review-", "rule-", "fixture-", "T7r3"].joined()
            var user = PastewatchConfig.defaultConfig
            user.customRules = [CustomRuleConfig(name: "review-rule", pattern: NSRegularExpression.escapedPattern(for: content), severity: "critical")]
            try JSONEncoder().encode(user).write(to: PastewatchConfig.configPath)
            let matches = try DetectionRules.scanFileIOOrThrow(content, config: user, customRules: CustomRule.compile(user.customRules))
            let match = try XCTUnwrap(matches.first { $0.customRuleName == "review-rule" })
            let target = root.appendingPathComponent("custom.txt")
            try Data(content.utf8).write(to: target)
            var project = PastewatchConfig.defaultConfig
            project.allowedValues = [match.value]
            try writeProject(project, root: root)
            XCTAssertEqual(try command(["scan", "--file", target.path, "--check"], root: root).status, 6)
            XCTAssertEqual(try command(["guard-write", target.path], root: root).status, 2)
            let payload = try mcpRead(target, root: root)
            XCTAssertEqual((payload["redactions"] as? [[String: Any]])?.count, 1)
            XCTAssertFalse(try XCTUnwrap(payload["content"] as? String).contains(match.value))
        }
    }

    // WO-672@v1: project-authored rules cannot grant themselves subordinate exact-value exemptions.
    func testProjectCannotExemptItsOwnCustomRule() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let content = ["review-", "project-", "rule-", "G6n8"].joined()
            var project = PastewatchConfig.defaultConfig
            project.customRules = [CustomRuleConfig(name: "project-rule", pattern: NSRegularExpression.escapedPattern(for: content), severity: "critical")]
            let match = try XCTUnwrap(DetectionRules.scanFileIOOrThrow(content, config: project,
                customRules: CustomRule.compile(project.customRules)).first { $0.customRuleName == "project-rule" })
            project.allowedValues = [match.value]
            try writeProject(project, root: root)
            let target = root.appendingPathComponent("project-rule.txt")
            try Data(content.utf8).write(to: target)
            XCTAssertEqual(try command(["scan", "--file", target.path, "--check"], root: root).status, 6)
            XCTAssertEqual(try command(["guard-write", target.path], root: root).status, 2)
            let payload = try mcpRead(target, root: root)
            XCTAssertEqual((payload["redactions"] as? [[String: Any]])?.count, 1)
            XCTAssertFalse(try XCTUnwrap(payload["content"] as? String).contains(match.value))
        }
    }

    // WO-672@v1: diagnostic counts use the same custom-rule authority as file filtering.
    func testAllowFileCountsCustomRuleEntryAsIgnored() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let content = ["review-", "custom-", "entry-", "R8m4"].joined()
            var user = PastewatchConfig.defaultConfig
            user.customRules = [CustomRuleConfig(name: "review-rule", pattern: NSRegularExpression.escapedPattern(for: content), severity: "critical")]
            try JSONEncoder().encode(user).write(to: PastewatchConfig.configPath)
            let match = try XCTUnwrap(DetectionRules.scanFileIOOrThrow(content, config: user,
                customRules: CustomRule.compile(user.customRules)).first { $0.customRuleName == "review-rule" })
            try writeProject(.defaultConfig, root: root)
            try Data((match.value + "\n").utf8).write(to: root.appendingPathComponent(".pastewatch-allow"))
            let doctor = try command(["doctor", "--explain", "--json"], root: root)
            XCTAssertEqual(doctor.status, 0)
            let report = try XCTUnwrap(JSONSerialization.jsonObject(with: doctor.output) as? [String: Any])
            let allowFile = try XCTUnwrap(report["projectAllowlist"] as? [String: Any])
            XCTAssertEqual(allowFile["effectiveEntries"] as? Int, 0)
            XCTAssertEqual(allowFile["ignoredIntrinsicEntries"] as? Int, 1)
            XCTAssertEqual(allowFile["status"] as? String, "warn")
            XCTAssertFalse(try XCTUnwrap(String(data: doctor.output + doctor.errors, encoding: .utf8)).contains(match.value))
            let text = try command(["doctor", "--explain"], root: root)
            XCTAssertTrue(try XCTUnwrap(String(data: text.output, encoding: .utf8)).contains("[warn]"))
        }
    }

    // WO-672@v1: advisory values remain suppressible through both project exemption sources.
    func testAdvisoryPhoneProjectExemptionsStillApply() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let content = ["+1", " 415", " 555", " 0132"].joined()
            let config = TestConfigHelper.configWithAmbiguousAdvisories([.phone])
            let match = try XCTUnwrap(DetectionRules.scanFileIO(content, config: config).first { $0.type == .phone })
            let target = root.appendingPathComponent("contact.txt")
            try Data(content.utf8).write(to: target)
            for source: AllowlistSource in [.project, .projectFile] {
                var project = config
                project.allowedValues = source == .project ? [match.value] : []
                try writeProject(project, root: root)
                try Data((source == .projectFile ? match.value + "\n" : "# no entries\n").utf8)
                    .write(to: root.appendingPathComponent(".pastewatch-allow"))
                XCTAssertEqual(try command(["scan", "--file", target.path, "--check"], root: root).status, 0)
                XCTAssertEqual(try command(["guard-write", target.path], root: root).status, 0)
            }
        }
    }

    // WO-672@v1: the ruling preserves inline XML exemptions; only tighten-only tiers change.
    func testInlineXMLCredentialSuppressionStaysUnchanged() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let content = xmlFixture() + " // pastewatch:allow\n"
            try writeProject(.defaultConfig, root: root)
            let target = root.appendingPathComponent("inline.txt")
            try Data(content.utf8).write(to: target)
            let matches = DetectionRules.scanFileIO(content, config: .defaultConfig)
            let match = try XCTUnwrap(matches.first { $0.type == .xmlCredential })
            XCTAssertTrue(permitsAllowlistSuppression(of: match, source: .inlineDirective, exactValue: false))
            XCTAssertTrue(Allowlist.filterInlineAllow(matches: matches, content: content).isEmpty)
            XCTAssertEqual(try command(["scan", "--file", target.path, "--check"], root: root).status, 0)
            XCTAssertEqual(try command(["guard-write", target.path], root: root).status, 0)
        }
    }

    // WO-672@v1: each disqualifying evidence kind independently constrains all subordinate sources.
    func testTightenOnlySourcesRequirePureAdvisoryEvidence() throws {
        let text = "fixture"
        let range = text.startIndex..<text.endIndex
        let evidence: [Set<MutationAuthorizationSource>] = [[], [.customRule], [.intrinsicFormat], [.exactKnownSecret]]
        for source: AllowlistSource in [.project, .projectFile, .restrictedUser] {
            for sources in evidence {
                let match = DetectedMatch(type: .phone, value: text, range: range, line: 1, mutationAuthorizationSources: sources)
                XCTAssertEqual(permitsAllowlistSuppression(of: match, source: source, exactValue: true), sources.isEmpty)
            }
            let namedRule = DetectedMatch(type: .phone, value: text, range: range, line: 1, customRuleName: "review-rule")
            XCTAssertFalse(permitsAllowlistSuppression(of: namedRule, source: source, exactValue: true))
            let xml = try XCTUnwrap(DetectionRules.scanFileIO(xmlFixture(), config: .defaultConfig).first { $0.type == .xmlCredential })
            XCTAssertFalse(permitsAllowlistSuppression(of: xml, source: source, exactValue: true))
            for unchanged: AllowlistSource in [.system, .user, .remedy, .inlineDirective] {
                XCTAssertTrue(permitsAllowlistSuppression(of: xml, source: unchanged, exactValue: true))
            }
        }
    }

    // WO-672@v1: exact exemptions use the detector's original value, never reconstructed credential text.
    private func verifyXMLCredentialExemption(source: AllowlistSource) throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let content = xmlFixture()
            let match = try XCTUnwrap(DetectionRules.scanFileIO(content, config: .defaultConfig).first { $0.type == .xmlCredential })
            XCTAssertFalse(match.type.isAmbiguousClass)
            XCTAssertFalse(match.mutationAuthorizationSources.contains(.intrinsicFormat))
            var project = PastewatchConfig.defaultConfig
            project.allowedValues = source == .project ? [match.value] : []
            try writeProject(project, root: root)
            let target = root.appendingPathComponent("config.txt")
            try Data(content.utf8).write(to: target)
            if source == .projectFile {
                try Data((match.value + "\n").utf8).write(to: root.appendingPathComponent(".pastewatch-allow"))
                let report = Allowlist.projectFile(for: target.path)
                XCTAssertEqual(report.effectiveEntries, 0)
                XCTAssertEqual(report.ignoredIntrinsicEntries, 1)
                XCTAssertEqual(report.status, "warn")
            }
            XCTAssertEqual(try command(["scan", "--file", target.path, "--check"], root: root).status, 6)
            XCTAssertEqual(try command(["guard-write", target.path], root: root).status, 2)
        }
    }

    // WO-672@v1: fixture tags and values are assembled without storing a complete credential literal.
    private func xmlFixture() -> String {
        let tag = ["pass", "word"].joined()
        let value = ["review", "-fixture", "-Z8m4"].joined()
        return "<" + tag + ">" + value + "</" + tag + ">"
    }

    // WO-672@v1: all project policies are valid fixture-owned configurations.
    private func writeProject(_ config: PastewatchConfig, root: URL) throws {
        try JSONEncoder().encode(config).write(to: root.appendingPathComponent(".pastewatch.json"))
    }

    // WO-672@v1: MCP response assertions inspect metadata without exposing any returned value.
    private func mcpRead(_ target: URL, root: URL) throws -> [String: Any] {
        let request: [String: Any] = ["jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": ["name": "pastewatch_read_file", "arguments": ["path": target.path]]]
        var input = try JSONSerialization.data(withJSONObject: request)
        input.append(0x0A)
        let result = try command(["mcp"], root: root, input: input)
        XCTAssertEqual(result.status, 0)
        let response = try XCTUnwrap(JSONSerialization.jsonObject(with: result.output) as? [String: Any])
        let toolResult = try XCTUnwrap(response["result"] as? [String: Any])
        let content = try XCTUnwrap(toolResult["content"] as? [[String: Any]])
        let text = try XCTUnwrap(content.first?["text"] as? String)
        return try XCTUnwrap(JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any])
    }

    // WO-672@v1: DEBUG subprocesses inherit only fixture policy and never print captured matched values.
    private func command(_ arguments: [String], root: URL, input: Data = Data()) throws -> CommandResult {
        let repository = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        let process = Process()
        process.executableURL = repository.appendingPathComponent(".build/debug/PastewatchCLI")
        process.arguments = arguments
        process.currentDirectoryURL = root
        process.environment = TestConfigHelper.subprocessEnvironment(["PATH": "/usr/bin:/bin", "PW_GUARD": "1"])
        let stdin = Pipe()
        let stdout = Pipe()
        let stderr = Pipe()
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
}
