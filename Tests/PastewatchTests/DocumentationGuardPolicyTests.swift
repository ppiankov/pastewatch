import Foundation
import XCTest
@testable import PastewatchCore
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

// WO-635: exercise documentation policy through real entrypoints without operator config.
final class DocumentationGuardPolicyTests: XCTestCase {
    // WO-672@v1: whole-value exemptions belong to the user tier, not the project tier.
    // WO-639: the real guard compares whole values rather than adopting password-only matching.
    func testDSNWholeValueAllowlistPreservesGuardExitCodes() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let password = ["Q7m", "N4r", "Z9T", "2xV", "6k"].joined()
            let content = ["post", "gres", "://", "app:", password, "@db:5432/prod"].joined()
            let path = try writeFixture(content, name: "guide.md", in: root)
            for (allowed, expected): (String, Int32) in [(content, 0), (password, 2)] {
                var config = fixtureConfig()
                config.allowedValues = [allowed]
                // WO-672@v1: operator-owned fixture policy retains its exact DSN exemption.
                try JSONEncoder().encode(config).write(to: PastewatchConfig.configPath)
                try TestConfigHelper.ensureProjectConfig(in: root)
                XCTAssertEqual(try runCLI(cliURL(), ["guard-read", path], in: root).status, expected)
            }
        }
    }

    // WO-639: real password evidence blocks docs and the MCP response replaces precisely that raw span.
    func testDSNPasswordEvidenceBlocksDocsAndRedactsOnlyPassword() throws {
        let passwords = [["Q7m", "N4r", "Z9T", "2xV", "6k"], ["%51", "7mN4rZ9T2xV6k"],
                         ["Q7mN", "@", "4rZ9T2xV6k"], ["%", "zz"]].map { $0.joined() }
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let config = fixtureConfig()
            try writeConfig(config, to: root)
            let session = try MCPProtocolTests.LiveMCPSession(executableURL: cliURL(), maximumLineBytes: 65_536, config: config)
            defer { session.close() }
            for password in passwords {
                let prefix = ["post", "gres", "://", "app:"].joined()
                let suffix = "@db:5432/prod"
                let content = prefix + password + suffix
                for name in ["guide.md", "doc.env"] {
                    let path = try writeFixture(content, name: name, in: root)
                    XCTAssertEqual(try runCLI(cliURL(), ["guard-read", path], in: root).status, 2)
                    let payload = try readPayload(session, path: path)
                    let redactions = try XCTUnwrap(payload["redactions"] as? [[String: Any]])
                    XCTAssertEqual(redactions.count, 1)
                    let placeholder = try XCTUnwrap(redactions.first?["placeholder"] as? String)
                    let redacted = try XCTUnwrap(payload["content"] as? String)
                    XCTAssertTrue(redacted == prefix + placeholder + suffix, "bytes outside the password must remain intact")
                    XCTAssertFalse(redacted.contains(password), "the original password must not be returned")
                    XCTAssertEqual(redactions.first?["type"] as? String, "DB Connection")
                    XCTAssertEqual(redactions.first?["line"] as? Int, 1)
                }
            }
        }
    }

    // WO-639: documentation placeholders retain advisory detection and are never replaced by MCP.
    func testDSNPlaceholderDocsStayAdvisoryAndMCPPreservesContent() throws {
        let passwords = [["pass", "word"], ["PASS", "WORD"], ["%70", "assword"], ["${", "DB_PASS", "}"],
                         ["__PW_", "DB_CONNECTION_1", "__"]].map { $0.joined() }
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let config = fixtureConfig()
            try writeConfig(config, to: root)
            let session = try MCPProtocolTests.LiveMCPSession(executableURL: cliURL(), maximumLineBytes: 65_536, config: config)
            defer { session.close() }
            for password in passwords {
                let content = ["post", "gres", "://", "app:", password, "@localhost/prod"].joined()
                let path = try writeFixture(content, name: "guide.md", in: root)
                XCTAssertEqual(try runCLI(cliURL(), ["guard-read", path], in: root).status, 0)
                let payload = try readPayload(session, path: path)
                XCTAssertEqual((payload["redactions"] as? [[String: Any]])?.count, 0)
                XCTAssertEqual((payload["advisories"] as? [[String: Any]])?.count, 1)
                XCTAssertTrue(payload["content"] as? String == content)
            }
        }
    }

    // WO-639: password-only placeholders preserve the existing two-way MCP write contract.
    func testDSNPasswordPlaceholdersRestoreOnMCPWrite() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            let config = fixtureConfig()
            let session = try MCPProtocolTests.LiveMCPSession(executableURL: cliURL(), maximumLineBytes: 65_536, config: config)
            defer { session.close() }
            let password = ["Q7m", "N4r", "Z9T", "2xV", "6k"].joined()
            let content = ["post", "gres", "://", "app:", password, "@db:5432/prod"].joined()
            let path = try writeFixture(content, name: "guide.md", in: session.directory)
            let payload = try readPayload(session, path: path)
            XCTAssertEqual((payload["redactions"] as? [[String: Any]])?.count, 1)
            let redacted = try XCTUnwrap(payload["content"] as? String)
            XCTAssertFalse(redacted.contains(password))
            let request = JSONRPCRequest(jsonrpc: "2.0", id: .int(2), method: "tools/call", params: .object([
                "name": .string("pastewatch_write_file"),
                "arguments": .object(["path": .string(path), "content": .string("updated\n" + redacted)])
            ]))
            try session.send(JSONEncoder().encode(request) + Data([0x0A]))
            let response = try XCTUnwrap(session.response(), "MCP write deadline expired")
            XCTAssertNil(response.error)
            XCTAssertTrue(try String(contentsOfFile: path, encoding: .utf8) == "updated\n" + content,
                          "MCP must restore the original password while applying the edit")
        }
    }

    private enum EntryPoint: CaseIterable {
        case scan, guardRead, mcpRead, watcher
    }

    // WO-635: one fixture must have the same protection boundary on every file surface.
    func testDocumentationPolicyAcrossEntrypoints() throws {
        let binary = cliURL()
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let config = fixtureConfig()
            try writeConfig(config, to: root)
            for entrypoint in EntryPoint.allCases {
                switch entrypoint {
                case .scan:
                    let path = try writeFixture(example(), name: "guide.md", in: root)
                    let result = try runCLI(binary, ["scan", "--file", path, "--check", "--format", "json"], in: root)
                    XCTAssertEqual(result.status, 0, "Documentation scan must not block")
                    let object = try jsonObject(result.output)
                    let findings = try XCTUnwrap(object["findings"] as? [[String: Any]])
                    XCTAssertEqual(findings.count, 1)
                    XCTAssertEqual(findings.first?["severity"] as? String, "medium")
                case .guardRead:
                    let path = try writeFixture(example(), name: "guide.md", in: root)
                    let result = try runCLI(binary, ["guard-read", path], in: root)
                    XCTAssertEqual(result.status, 0, "Documentation guard must not block")
                case .mcpRead:
                    let session = try MCPProtocolTests.LiveMCPSession(
                        executableURL: binary, maximumLineBytes: 65_536, config: config
                    )
                    defer { session.close() }
                    let path = try writeFixture(example(), name: "guide.md", in: session.directory)
                    let payload = try readPayload(session, path: path)
                    XCTAssertEqual((payload["advisories"] as? [[String: Any]])?.count, 1)
                    XCTAssertEqual((payload["redactions"] as? [[String: Any]])?.count, 0)
                    XCTAssertTrue(payload["content"] as? String == example())
                case .watcher:
                    let output = try watchMixedFixture(binary, in: root)
                    XCTAssertGreaterThanOrEqual(output.components(separatedBy: "AWS Key:").count - 1, 1)
                    XCTAssertEqual(output.components(separatedBy: "Credential:").count - 1, 0)
                }
            }
        }
    }

    // WO-635: real intrinsic formats stay blocked even beside documentation examples.
    func testIntrinsicSecretStillBlocksDocumentation() throws {
        let binary = cliURL()
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            try writeConfig(fixtureConfig(), to: root)
            let path = try writeFixture(example() + "\n" + intrinsic(), name: "guide.md", in: root)
            XCTAssertEqual(try runCLI(binary, ["guard-read", path], in: root).status, 2)
            let scan = try runCLI(binary, ["scan", "--file", path, "--check", "--format", "json"], in: root)
            XCTAssertEqual(scan.status, 6)
            let findings = try XCTUnwrap(try jsonObject(scan.output)["findings"] as? [[String: Any]])
            XCTAssertEqual(findings.filter { $0["type"] as? String == "AWS Key" }.count, 1)
            XCTAssertEqual(findings.first { $0["type"] as? String == "AWS Key" }?["severity"] as? String, "critical")
        }
    }

    // WO-635: pathless input and non-document extensions retain existing blocking behavior.
    // WO-659@v1: advisory-only native Read remains allowed while stdin scan enforcement is unchanged.
    // WO-672@v1: process isolation must not depend on project replacement semantics.
    func testNonDocumentAndStdinRemainBlocking() throws {
        let binary = cliURL()
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            try writeConfig(fixtureConfig(), to: root)
            for name in ["guide.env", "guide.yaml", "guide.swift", "guide.txt"] {
                let path = try writeFixture(example(), name: name, in: root)
                // WO-659@v1: capture advisory diagnostics without changing the shared subprocess helper.
                let process = Process()
                let stderr = Pipe()
                process.executableURL = binary
                process.arguments = ["guard-read", path]
                process.currentDirectoryURL = root
                // WO-672@v1: the subprocess guard shares only the DEBUG fixture path.
                process.environment = TestConfigHelper.subprocessEnvironment(["PW_GUARD": "1"])
                process.standardOutput = FileHandle.nullDevice
                process.standardError = stderr
                try process.run()
                let diagnostics = String(data: stderr.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
                process.waitUntilExit()
                XCTAssertEqual(process.terminationStatus, 0, name)
                XCTAssertTrue(diagnostics.contains("ADVISORY: Credential line 1 count=1"), name)
                XCTAssertFalse(diagnostics.contains(example()), name)
            }
            let result = try runCLI(
                binary, ["scan", "--check", "--stdin-filename", "guide.md"], in: root, input: example()
            )
            XCTAssertEqual(result.status, 6, "A stdin filename is parsing metadata, not a real file")
        }
    }

    // WO-635: admins may restore enforcement; the existing cascade must not merge in project overrides.
    // WO-659@v1: admin enforcement remains observable in scan, independently of native Read authorization.
    func testEnforcePolicyAndAdminPrecedence() throws {
        let binary = cliURL()
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let config = fixtureConfig()
            var encoded = try jsonObject(JSONEncoder().encode(config))
            encoded["documentationPolicy"] = "enforce"
            let admin = root.appendingPathComponent("admin.json")
            try JSONSerialization.data(withJSONObject: encoded).write(to: admin)
            try writeConfig(config, to: root)
            let resolved = try ConfigValidator.resolveValidated(
                currentDirectory: root.path, systemConfigPath: admin.path,
                userConfigPath: root.appendingPathComponent("absent.json").path
            )
            XCTAssertEqual(resolved.source, .system)
            try writeConfig(resolved.config, to: root)
            let path = try writeFixture(example(), name: "guide.md", in: root)
            // WO-659@v1: enforce affects the scan outcome but cannot promote advisory findings into Read blocks.
            XCTAssertEqual(try runCLI(binary, ["scan", "--file", path, "--check"], in: root).status, 6)
            XCTAssertEqual(try runCLI(binary, ["guard-read", path], in: root).status, 0)
        }
    }

    // WO-635: SARIF must retain the finding as a warning without a failing scan exit.
    func testDocumentationFindingIsSarifWarning() throws {
        let binary = cliURL()
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            try writeConfig(fixtureConfig(), to: root)
            let path = try writeFixture(example(), name: "guide.MDX", in: root)
            let result = try runCLI(binary, ["scan", "--file", path, "--check", "--format", "sarif"], in: root)
            XCTAssertEqual(result.status, 0)
            let runs = try XCTUnwrap(try jsonObject(result.output)["runs"] as? [[String: Any]])
            let findings = try XCTUnwrap(runs.first?["results"] as? [[String: Any]])
            XCTAssertEqual(findings.count, 1)
            XCTAssertEqual(findings.first?["level"] as? String, "warning")
        }
    }

    // WO-635: every named extension is case-insensitive; a docs directory alone authorizes nothing.
    func testOnlyNamedExtensionsGetAdvisoryPolicyAtEveryThreshold() throws {
        let content = example()
        let config = fixtureConfig()
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertEqual(matches.count, 1)
        for name in ["guide.md", "guide.MDX", "guide.MarkDown", "guide.RST", "guide.ADOC"] {
            for threshold in [nil] + Severity.allCases.map(Optional.some) {
                let result = GuardDecision.evaluate(
                    matches: matches, content: content, config: config,
                    contentTrust: .trustedFile, minimumSeverity: threshold, filePath: name
                )
                XCTAssertEqual(result.reportableMatches.count, 1)
                XCTAssertEqual(result.reportableMatches.first?.advisory, .documentationPolicy)
                XCTAssertTrue(result.actionableMatches.isEmpty, name)
            }
        }
        for path in [nil, "", "docs/guide", "docs/guide.swift", "guide.md.txt"] {
            let result = GuardDecision.evaluate(
                matches: matches, content: content, config: config,
                contentTrust: .trustedFile, minimumSeverity: .high, filePath: path
            )
            XCTAssertEqual(result.actionableMatches.count, 1)
            XCTAssertEqual(result.reportableMatches.first?.effectiveSeverity, .critical)
        }
    }

    // WO-635: match metadata cannot stand in for an explicit file path on a pathless call.
    func testUnknownPathNeverInheritsDocumentationFromMatchMetadata() {
        let text = intrinsic()
        let match = DetectedMatch(type: .credential, value: text, range: text.startIndex..<text.endIndex, filePath: "guide.md")
        let result = GuardDecision.evaluate(
            matches: [match], content: text, config: fixtureConfig(),
            contentTrust: .agentControlled, minimumSeverity: .high
        )
        XCTAssertEqual(result.actionableMatches.count, 1)
    }

    // WO-635: provenance survives a broad detector label; these independent authorizations stay blocking.
    func testIndependentAuthorizationNeverDowngradesAmbiguousType() {
        let text = intrinsic()
        for source in [MutationAuthorizationSource.intrinsicFormat, .exactKnownSecret, .customRule] {
            let match = DetectedMatch(
                type: .genericApiKey, value: text, range: text.startIndex..<text.endIndex,
                mutationAuthorizationSources: [source]
            )
            let result = GuardDecision.evaluate(
                matches: [match], content: text, config: fixtureConfig(),
                contentTrust: .trustedFile, minimumSeverity: .high, filePath: "guide.md"
            )
            XCTAssertEqual(result.actionableMatches.count, 1)
            XCTAssertEqual(result.reportableMatches.first?.effectiveSeverity, .critical)
            XCTAssertNil(result.reportableMatches.first?.advisory)
        }
    }

    // WO-635: generic provider formats exercise intrinsic protection through the real detector.
    func testIntrinsicFormatOnGenericDetectorStillBlocks() {
        let text = "sk" + "_live_" + String(repeating: "Ab78", count: 6)
        var config = fixtureConfig()
        config.enabledTypes.append(SensitiveDataType.genericApiKey.rawValue)
        let matches = DetectionRules.scan(text, config: config)
        XCTAssertEqual(matches.count, 1)
        XCTAssertTrue(matches.first?.mutationAuthorizationSources.contains(.intrinsicFormat) == true)
        let result = GuardDecision.evaluate(
            matches: matches, content: text, config: config,
            contentTrust: .trustedFile, minimumSeverity: .high, filePath: "guide.md"
        )
        XCTAssertEqual(result.actionableMatches.count, 1)
    }

    // WO-635: an overlapping explicit custom rule cannot lose protection to documentation classification.
    func testCustomRuleStillBlocksDocumentation() throws {
        let binary = cliURL()
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let content = example()
            var config = fixtureConfig()
            let match = try XCTUnwrap(DetectionRules.scan(content, config: config).first)
            config.customRules = [CustomRuleConfig(
                name: "operator-rule", pattern: NSRegularExpression.escapedPattern(for: match.value), severity: "critical"
            )]
            try writeConfig(config, to: root)
            let path = try writeFixture(content, name: "guide.md", in: root)
            XCTAssertEqual(try runCLI(binary, ["guard-read", path], in: root).status, 2)
        }
    }

    // WO-635: broad configured obfuscation is not independent proof of an intrinsic or known secret.
    func testConfiguredAmbiguousFindingIsAdvisoryWithoutMutation() {
        let text = intrinsic()
        let match = DetectedMatch(
            type: .credential, value: text, range: text.startIndex..<text.endIndex,
            mutationAuthorizationSources: [.configuredObfuscate]
        )
        let decision = GuardDecision.evaluate(
            matches: [match], content: text, config: fixtureConfig(),
            contentTrust: .trustedFile, minimumSeverity: .low, filePath: "guide.md"
        )
        XCTAssertTrue(decision.actionableMatches.isEmpty)
        let result = applyAuthorizedMutations(to: text, matches: decision.reportableMatches, site: .cliScan, minAdvisorySeverity: .low)
        XCTAssertTrue(result.text == text)
        XCTAssertTrue(result.mutated.isEmpty)
        XCTAssertEqual(result.advisory.count, 1)
    }

    // WO-635: old configs default to advisory; invalid explicit policy fails closed.
    func testPolicyDecodingDefaultsAndRejectsUnknownValues() throws {
        var object = try jsonObject(JSONEncoder().encode(fixtureConfig()))
        object.removeValue(forKey: "documentationPolicy")
        let oldConfig = try JSONDecoder().decode(PastewatchConfig.self, from: JSONSerialization.data(withJSONObject: object))
        XCTAssertEqual(oldConfig.documentationPolicy, .advisory)
        object["documentationPolicy"] = "unsupported"
        XCTAssertThrowsError(try JSONDecoder().decode(PastewatchConfig.self, from: JSONSerialization.data(withJSONObject: object)))
    }

    // WO-635: opt in only to the ambiguous detectors needed by this regression fixture.
    private func fixtureConfig() -> PastewatchConfig {
        TestConfigHelper.configWithAmbiguousAdvisories([.credential, .dbConnectionString])
    }

    // WO-635: construct synthetic sensitive shapes only at runtime, never in diagnostics.
    private func example() -> String {
        "- CLI example: `--" + "pass" + "word=" + "Q7mN" + "4rZ9" + "T2xV`"
    }

    // WO-635: intrinsic control value assembled at runtime so no literal key lands in source.
    private func intrinsic() -> String {
        "AK" + "IA" + String(repeating: "7B", count: 8)
    }

    // WO-635: subprocesses always resolve a test-owned project configuration first.
    private func writeConfig(_ config: PastewatchConfig, to root: URL) throws {
        try JSONEncoder().encode(config).write(to: root.appendingPathComponent(".pastewatch.json"))
    }

    // WO-635: fixtures live only in the isolated temp root, never in the repo or operator dirs.
    private func writeFixture(_ content: String, name: String, in root: URL) throws -> String {
        let url = root.appendingPathComponent(name)
        try content.write(to: url, atomically: true, encoding: .utf8)
        return url.path
    }

    // WO-635: run the freshly built CLI so subprocess tests exercise the code under review.
    private func cliURL() -> URL {
        let bundled = Bundle.main.bundleURL.deletingLastPathComponent().appendingPathComponent("PastewatchCLI")
        if FileManager.default.fileExists(atPath: bundled.path) { return bundled }
        return URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().appendingPathComponent(".build/debug/PastewatchCLI")
    }

    // WO-635: capture command output without ever including matched values in assertions.
    // WO-672@v1: private child environments retain the fixture global policy channel.
    private func runCLI(_ binary: URL, _ arguments: [String], in root: URL, input: String = "") throws -> (status: Int32, output: Data) {
        let process = Process()
        let stdin = Pipe()
        let stdout = Pipe()
        process.executableURL = binary
        process.arguments = arguments
        process.currentDirectoryURL = root
        // WO-672@v1: global configuration remains isolated after tier merging.
        process.environment = TestConfigHelper.subprocessEnvironment(["PW_GUARD": "1"])
        process.standardInput = stdin
        process.standardOutput = stdout
        process.standardError = FileHandle.nullDevice
        try process.run()
        stdin.fileHandleForWriting.write(Data(input.utf8))
        stdin.fileHandleForWriting.closeFile()
        let output = stdout.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return (process.terminationStatus, output)
    }

    // WO-635: use the real MCP server and decode only structural response metadata for assertions.
    private func readPayload(_ session: MCPProtocolTests.LiveMCPSession, path: String) throws -> [String: Any] {
        let request = JSONRPCRequest(jsonrpc: "2.0", id: .int(1), method: "tools/call", params: .object([
            "name": .string("pastewatch_read_file"), "arguments": .object(["path": .string(path)])
        ]))
        try session.send(JSONEncoder().encode(request) + Data([0x0A]))
        let response = try XCTUnwrap(session.response(), "MCP response deadline expired")
        guard case .object(let result) = response.result,
              case .array(let blocks) = result["content"],
              case .object(let block) = blocks.first,
              case .string(let text) = block["text"] else {
            throw NSError(domain: "DocumentationGuardPolicyTests", code: 1)
        }
        return try jsonObject(Data(text.utf8))
    }

    // WO-635: assertions read structured output as JSON objects, never as raw matched text.
    private func jsonObject(_ data: Data) throws -> [String: Any] {
        try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    // WO-635: an intrinsic event proves the watcher scanned the mixed document; no blind sleep assertion.
    // WO-672@v1: watch probes never load operator configuration at startup.
    private func watchMixedFixture(_ binary: URL, in root: URL) throws -> String {
        let watched = root.appendingPathComponent("watched")
        try FileManager.default.createDirectory(at: watched, withIntermediateDirectories: true)
        let path = try writeFixture(example() + "\n" + intrinsic(), name: "guide.md", in: watched)
        let process = Process()
        let stderr = Pipe()
        process.executableURL = binary
        process.arguments = ["watch", "--dir", watched.path]
        process.currentDirectoryURL = root
        // WO-672@v1: custom child environments retain fixture global policy.
        process.environment = TestConfigHelper.subprocessEnvironment(["PW_GUARD": "1"])
        process.standardOutput = FileHandle.nullDevice
        process.standardError = stderr
        try process.run()
        defer {
            if process.isRunning { process.terminate() }
            process.waitUntilExit()
        }
        let deadline = ProcessInfo.processInfo.systemUptime + 15
        var output = Data()
        while ProcessInfo.processInfo.systemUptime < deadline {
            try FileManager.default.setAttributes([.modificationDate: Date()], ofItemAtPath: path)
            var descriptor = pollfd(fd: stderr.fileHandleForReading.fileDescriptor, events: Int16(POLLIN), revents: 0)
            if poll(&descriptor, 1, 100) > 0 {
                let chunk = stderr.fileHandleForReading.availableData
                if chunk.isEmpty { break }
                output.append(chunk)
                let text = String(data: output, encoding: .utf8) ?? ""
                if text.contains("AWS Key:") { return text }
            }
        }
        XCTFail("Watcher did not report the intrinsic control before the deadline")
        return ""
    }
}
