import XCTest
@testable import PastewatchCore
@testable import PastewatchCLI

// WO-672@v1: tier restrictions protect intrinsic evidence independently of surface.
final class ConfigSecurityTests: XCTestCase {
    // WO-672@v1: command evidence keeps transport bytes private even on assertion failures.
    private struct CommandResult {
        let status: Int32
        let output: Data
        let errors: Data
    }

    // WO-672@v1: the executable guard and MCP use the same tier-aware decisions after initialization.
    func testInitializedProjectCannotExemptIntrinsicAndCannotCreateOperatorFiles() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            XCTAssertEqual(try command(["init"], root: root).status, 0)
            var project = PastewatchConfig.defaultConfig
            project.allowedPatterns = [".*"]
            try JSONEncoder().encode(project).write(to: root.appendingPathComponent(".pastewatch.json"))
            let secret = intrinsicFixture()
            let target = root.appendingPathComponent("fixture.txt")
            try Data(secret.utf8).write(to: target)
            let guardResult = try command(["guard-read", target.path], root: root)
            XCTAssertEqual(guardResult.status, 2)
            let requests: [[String: Any]] = [
                ["jsonrpc": "2.0", "id": 1, "method": "initialize", "params": [:]],
                ["jsonrpc": "2.0", "id": 2, "method": "tools/call",
                 "params": ["name": "pastewatch_read_file", "arguments": ["path": target.path]]],
            ]
            var frames = Data()
            for request in requests {
                frames.append(try JSONSerialization.data(withJSONObject: request))
                frames.append(0x0A)
            }
            let mcp = try command(["mcp"], root: root, input: frames)
            XCTAssertEqual(mcp.status, 0)
            XCTAssertTrue(try XCTUnwrap(String(data: mcp.output, encoding: .utf8)).contains("__PW"))
            for result in [guardResult, mcp] {
                XCTAssertFalse(try XCTUnwrap(String(data: result.output + result.errors, encoding: .utf8)).contains(secret))
            }
            let newRoot = root.appendingPathComponent("new", isDirectory: true)
            try FileManager.default.createDirectory(at: newRoot, withIntermediateDirectories: true)
            for name in [".pastewatch.json", ".pastewatch-allow"] {
                let path = newRoot.appendingPathComponent(name).path
                let write = try command(["guard-write", path], root: root)
                XCTAssertEqual(write.status, 2)
                XCTAssertTrue(try XCTUnwrap(String(data: write.errors, encoding: .utf8)).contains(GuardDecision.operatorOwnedFileMessage))
                let payload: [String: Any] = ["tool_name": "Write", "tool_input": ["file_path": path, "content": "{}"]]
                let mutation = try command(["guard-mutation"], root: root,
                                           input: JSONSerialization.data(withJSONObject: payload))
                XCTAssertEqual(mutation.status, 2)
                XCTAssertTrue(try XCTUnwrap(String(data: mutation.errors, encoding: .utf8)).contains(GuardDecision.operatorOwnedFileMessage))
                XCTAssertFalse(FileManager.default.fileExists(atPath: path))
            }
        }
    }

    // WO-672@v1: loader-owned source evidence cannot be forged in serialized project policy.
    func testSerializedSourceClaimsCannotGrantAuthority() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let secret = intrinsicFixture()
            var project = PastewatchConfig.defaultConfig
            project.allowedValues = [secret]
            var object = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(project)) as? [String: Any])
            object["allowedValueSources"] = [secret: ["user", "system"]]
            try JSONSerialization.data(withJSONObject: object).write(to: root.appendingPathComponent(".pastewatch.json"))
            let config = try resolve(root).config
            XCTAssertTrue(Allowlist.fromConfig(config).filter(DetectionRules.scanFileIO(secret, config: config)).count == 1)
            let encoded = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(config)) as? [String: Any])
            XCTAssertNil(encoded["allowedValueSources"])
            XCTAssertNil(encoded["fieldSources"])
        }
    }

    // WO-672@v1: one shared suppression predicate preserves intrinsic evidence at every mutation site.
    func testEveryUnprivilegedAllowlistSourcePreservesMutation() throws {
        let secret = intrinsicFixture()
        let match = try XCTUnwrap(DetectionRules.scanFileIO(secret, config: .defaultConfig).first)
        // WO-672@v1: subordinate user policy is another unprivileged allowlist source.
        for source: AllowlistSource in [.system, .user, .restrictedUser, .project, .projectFile, .remedy, .inlineDirective] {
            let exact = Allowlist(values: [secret], source: source)
            XCTAssertEqual(exact.filter([match]).count, source == .system || source == .user ? 0 : 1)
            let patterns = Allowlist(patterns: [try NSRegularExpression(pattern: ".*")], source: source)
            let filtered = patterns.filter([match])
            XCTAssertEqual(filtered.count, 1)
            for site in MutationSite.allCases {
                let outcome = applyAuthorizedMutations(to: secret, matches: filtered, site: site, minAdvisorySeverity: .high)
                XCTAssertEqual(outcome.mutated.count, 1)
                XCTAssertFalse(outcome.text.contains(secret))
            }
        }
    }

    // WO-672@v1: restrictions cannot remove operator paths, replace patterns or lower severities.
    func testProjectRestrictionsOnlyTightenAndKeepAttribution() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            var user = TestConfigHelper.configWithAmbiguousAdvisories([.credential])
            user.mcpMinSeverity = "critical"
            user.documentationPolicy = .enforce
            user.customRules = [CustomRuleConfig(name: "operator-rule", pattern: "operator-" + "fixture", severity: "critical")]
            try JSONEncoder().encode(user).write(to: PastewatchConfig.configPath)
            var project = PastewatchConfig.defaultConfig
            project.enabled = false
            project.mcpMinSeverity = "low"
            project.customRules = [CustomRuleConfig(name: "operator-rule", pattern: "different-" + "fixture", severity: "low")]
            project.allowedPatterns = [".*"]
            try JSONEncoder().encode(project).write(to: root.appendingPathComponent(".pastewatch.json"))
            let config = try resolve(root).config
            XCTAssertTrue(config.enabled)
            XCTAssertTrue(config.isTypeEnabled(.credential))
            // WO-672@v1: a lower threshold reports more advisories without changing mutation authority.
            XCTAssertEqual(config.mcpMinSeverity, "low")
            XCTAssertEqual(config.documentationPolicy, .enforce)
            XCTAssertEqual(config.customRules.count, 2)
            XCTAssertEqual(config.customRules.first?.severity, "critical")
            XCTAssertTrue(config.allowedPatterns.isEmpty)
            XCTAssertTrue(config.fieldSources["customRules"]?.contains("user") == true)
            XCTAssertTrue(config.fieldSources["customRules"]?.contains("project") == true)
        }
    }

    // WO-672@v1: a project contribution cannot discard operator rules or enabled detectors.
    func testProjectKeepsOperatorPolicy() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            var user = PastewatchConfig.defaultConfig
            user.enabledTypes.append(SensitiveDataType.credential.rawValue)
            user.customRules = [CustomRuleConfig(name: "operator-rule", pattern: "fixture-" + "marker")]
            user.protectedPaths = [root.appendingPathComponent("protected").path]
            try JSONEncoder().encode(user).write(to: PastewatchConfig.configPath)
            try TestConfigHelper.ensureProjectConfig(in: root)
            let resolved = try resolve(root)
            XCTAssertTrue(resolved.config.isTypeEnabled(.credential))
            XCTAssertEqual(resolved.config.customRules.count, 1)
            XCTAssertTrue(resolved.config.protectedPaths.contains(user.protectedPaths[0]))
            XCTAssertEqual(PastewatchConfig.resolve().customRules.count, 1)
        }
    }

    // WO-672@v1: project patterns, exact entries and inline directives cannot erase intrinsic evidence.
    func testProjectAndInlineEntriesKeepIntrinsicMatches() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let secret = intrinsicFixture()
            for exact in [false, true] {
                var project = PastewatchConfig.defaultConfig
                project.allowedPatterns = [".*"]
                project.allowedValues = exact ? [secret] : []
                try JSONEncoder().encode(project).write(to: root.appendingPathComponent(".pastewatch.json"))
                let config = try resolve(root).config
                let content = secret + " // pastewatch:allow"
                let matches = DetectionRules.scanFileIO(content, config: config)
                let decision = MCPReadDecision.evaluate(matches: matches, content: content, config: config,
                                                       minimumSeverity: .high, filePath: "fixture.txt")
                XCTAssertEqual(decision.authorized.count, 1)
                let outcome = applyAuthorizedMutations(to: content, matches: decision.authorized,
                                                      site: .mcpRead, minAdvisorySeverity: .high)
                XCTAssertFalse(outcome.text.contains(secret))
            }
        }
    }

    // WO-672@v1: operator exact values remain explicit exemptions, while operator patterns do not.
    func testUserExactWholeValueOnly() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let secret = intrinsicFixture()
            for exact in [false, true] {
                var user = PastewatchConfig.defaultConfig
                user.allowedValues = exact ? [secret] : []
                user.allowedPatterns = [".*"]
                try JSONEncoder().encode(user).write(to: PastewatchConfig.configPath)
                let config = try resolve(root).config
                let matches = DetectionRules.scanFileIO(secret, config: config)
                let decision = MCPReadDecision.evaluate(matches: matches, content: secret, config: config,
                                                       minimumSeverity: .high, filePath: "fixture.txt")
                XCTAssertEqual(decision.authorized.count, exact ? 0 : 1)
            }
        }
    }

    // WO-672@v1: exact project values still suppress advisory recognition.
    func testProjectExactAdvisoryStillApplies() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let phone = ["+1", " 415", " 555", " 0132"].joined()
            var project = TestConfigHelper.configWithAmbiguousAdvisories([.phone])
            project.allowedValues = [phone]
            try JSONEncoder().encode(project).write(to: root.appendingPathComponent(".pastewatch.json"))
            let config = try resolve(root).config
            let matches = DetectionRules.scanFileIO(phone, config: config)
            XCTAssertEqual(matches.count, 1)
            XCTAssertTrue(GuardDecision.evaluate(matches: matches, content: phone, config: config,
                                                contentTrust: .trustedFile, minimumSeverity: .high).reportableMatches.isEmpty)
        }
    }

    // WO-672@v1: protection applies to empty and nonexistent operator-owned targets.
    func testOperatorFileCreationIsRefused() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let previous = ProcessInfo.processInfo.environment["PW_GUARD"]
            setenv("PW_GUARD", "1", 1)
            defer {
                if let previous { setenv("PW_GUARD", previous, 1) } else { unsetenv("PW_GUARD") }
            }
            for name in [".pastewatch.json", ".pastewatch-allow"] {
                let path = root.appendingPathComponent(name).path
                XCTAssertThrowsError(try FileGuard.check(filePath: path, failOnSeverity: .high, operation: .write))
                let decision = try GuardMutationEvaluator.evaluateWrite(
                    currentContent: "", proposedContent: "{}", filePath: path, config: .defaultConfig, minimumSeverity: .high
                )
                if case .allow = decision { XCTFail("Operator-owned creation was admitted") }
            }
        }
    }

    // WO-672@v1: equivalent policy basenames cannot bypass file or structured mutation guards.
    func testPolicyFileNameNormalizationAcrossGuardEntryPoints() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let names = [".PASTEWATCH.JSON", ".Pastewatch-Allow",
                         // WO-672@v1: the complete path may use decomposed Unicode directory spelling.
                         "caf\u{00E9}/.Pastewatch-Allow".decomposedStringWithCanonicalMapping]
            for name in names {
                let path = root.appendingPathComponent(name).path
                XCTAssertTrue(GuardDecision.isOperatorOwnedPath(path))
                XCTAssertEqual(try command(["guard-write", path], root: root).status, 2)
                let payload: [String: Any] = ["tool_name": "Write", "tool_input": ["file_path": path, "content": "{}"]]
                XCTAssertEqual(try command(["guard-mutation"], root: root,
                                           input: JSONSerialization.data(withJSONObject: payload)).status, 2)
                XCTAssertEqual(try GuardMutationEvaluator.evaluateWrite(currentContent: "", proposedContent: "{}",
                                filePath: path, config: .defaultConfig, minimumSeverity: .high), .block(.operatorOwnedFile))
                XCTAssertEqual(try GuardMutationEvaluator.evaluateEdit(currentContent: "before", oldString: "before",
                                newString: "after", replaceAll: false, filePath: path, config: .defaultConfig,
                                minimumSeverity: .high), .block(.operatorOwnedFile))
            }
            let ordinary = root.appendingPathComponent("notes.txt").path
            XCTAssertFalse(GuardDecision.isOperatorOwnedPath(ordinary))
            XCTAssertEqual(try command(["guard-write", ordinary], root: root).status, 0)
            let payload: [String: Any] = ["tool_name": "Write", "tool_input": ["file_path": ordinary, "content": "notes"]]
            XCTAssertEqual(try command(["guard-mutation"], root: root,
                                       input: JSONSerialization.data(withJSONObject: payload)).status, 0)
        }
    }

    // WO-672@v1: subordinate user policy may add restrictions but never system-policy exemptions.
    func testUserTierOnlyTightensSystemPolicy() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let secret = intrinsicFixture()
            var system = PastewatchConfig.defaultConfig
            system.mcpMinSeverity = "medium"
            system.documentationPolicy = .enforce
            system.placeholderPrefix = "ADMIN"
            let systemPath = root.appendingPathComponent("system.json")
            try JSONEncoder().encode(system).write(to: systemPath)
            var user = TestConfigHelper.configWithAmbiguousAdvisories([.phone])
            user.allowedValues = [secret]
            user.allowedPatterns = [".*"]
            user.enabled = false
            user.mcpMinSeverity = "critical"
            user.placeholderPrefix = "USER"
            user.customRules = [CustomRuleConfig(name: "user-rule", pattern: "user-" + "fixture")]
            try JSONEncoder().encode(user).write(to: PastewatchConfig.configPath)
            // WO-672@v1: default resolution exercises both DEBUG fixture paths without operator I/O.
            let config = try ConfigValidator.resolveValidated().config
            XCTAssertTrue(config.enabled)
            XCTAssertEqual(config.placeholderPrefix, "ADMIN")
            XCTAssertEqual(config.documentationPolicy, .enforce)
            XCTAssertEqual(config.mcpMinSeverity, "medium")
            XCTAssertTrue(config.isTypeEnabled(.phone))
            XCTAssertEqual(config.customRules.count, 1)
            XCTAssertTrue(config.allowedPatterns.isEmpty)
            let matches = DetectionRules.scanFileIO(secret, config: config)
            XCTAssertEqual(Allowlist.fromConfig(config).filter(matches).count, 1)
            user.mcpMinSeverity = "low"
            try JSONEncoder().encode(user).write(to: PastewatchConfig.configPath)
            XCTAssertEqual(try ConfigValidator.resolveValidated().config.mcpMinSeverity, "low")
            let noSystem = try resolve(root).config
            XCTAssertEqual(Allowlist.fromConfig(noSystem).filter(matches).count, 0)
            XCTAssertEqual(noSystem.allowedPatterns.count, 1)
        }
    }

    // WO-672@v1: subordinate thresholds may increase visibility, never hide existing advisory reports.
    func testProjectThresholdCanOnlyIncreaseAdvisoryReporting() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            var user = PastewatchConfig.defaultConfig
            user.mcpMinSeverity = "medium"
            try JSONEncoder().encode(user).write(to: PastewatchConfig.configPath)
            for (requested, expected) in [("critical", "medium"), ("low", "low")] {
                var project = PastewatchConfig.defaultConfig
                project.mcpMinSeverity = requested
                try JSONEncoder().encode(project).write(to: root.appendingPathComponent(".pastewatch.json"))
                XCTAssertEqual(try resolve(root).config.mcpMinSeverity, expected)
            }
        }
    }

    // WO-672@v1: all file paths in these tests belong to the fixture scope.
    private func resolve(_ root: URL) throws -> ResolvedPastewatchConfig {
        try ConfigValidator.resolveValidated(currentDirectory: root.path,
                                             systemConfigPath: root.appendingPathComponent("absent-admin.json").path,
                                             userConfigPath: PastewatchConfig.configPath.path)
    }

    // WO-672@v1: no complete intrinsic token is stored in source or diagnostics.
    private func intrinsicFixture() -> String {
        ["gh", "p_", String(repeating: "A7b3", count: 9)].joined()
    }

    // WO-672@v1: only the DEBUG executable receives the fixture-only global policy channel.
    private func command(_ arguments: [String], root: URL, input: Data = Data()) throws -> CommandResult {
        let repository = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        let process = Process()
        process.executableURL = repository.appendingPathComponent(".build/debug/PastewatchCLI")
        process.arguments = arguments
        process.currentDirectoryURL = root
        process.environment = TestConfigHelper.subprocessEnvironment(["PW_GUARD": "1"])
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
