import ArgumentParser
import XCTest
@testable import PastewatchCLI
@testable import PastewatchCore
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

// WO-637: check must expose real surface outcomes without exposing the input.
final class CheckCommandTests: XCTestCase {
    // WO-637: prove the command is absent before adding its implementation.
    func testCheckIsRegistered() throws {
        let command = try PastewatchCLI.parseAsRoot(["check"])
        XCTAssertEqual(String(describing: type(of: command)), "Check")
    }

    // WO-637: pin each specified example against real authorization, not a mock detector.
    func testExampleVerdicts() throws {
        let cases = [
            Example(input: aws(), classification: "intrinsic", mutates: true),
            Example(input: custom(), classification: "custom rule", mutates: true),
            Example(input: credential(), classification: "ambiguous opt-in", mutates: false)
        ]
        try withFixture { _, explanation in
            for example in cases {
                let report = try ValueVerdict(content: example.input, filePath: nil, explanation: explanation)
                let finding = try XCTUnwrap(report.findings.first)
                XCTAssertEqual(report.findings.count, 1)
                XCTAssertEqual(finding.classification, example.classification)
                XCTAssertEqual(finding.mutationAuthorized, example.mutates)
                XCTAssertEqual(finding.guardVerdict, "blocks")
                XCTAssertEqual(finding.scanExitCode, 6)
                XCTAssertEqual(finding.mcp, example.mutates ? "placeholder, restored on write" : "advisory, unchanged")
                XCTAssertEqual(finding.proxy, example.mutates ? "redacted outbound" : "forwarded unchanged")
                XCTAssertEqual(finding.placeholderShape != nil, example.mutates)
                XCTAssertTrue(report.mcpRoundTripVerified)
            }
        }
    }

    // WO-637: parity includes the extracted decisions and the actual whole-request redactor.
    func testSurfaceParity() throws {
        try withFixture { root, explanation in
            let config = try explanation.validatedConfiguration()
            let content = [aws(), custom(), credential()].joined(separator: "\n")
            let path = root.appendingPathComponent("input.md").path
            let matches = try DirectoryScanner.scanFileContentOrThrow(
                content: content, ext: "md", relativePath: path, config: config)
            let guardDecision = GuardDecision.evaluate(matches: matches, content: content, config: config,
                                                       contentTrust: .trustedFile, minimumSeverity: .high, filePath: path)
            let mcp = MCPReadDecision.evaluate(matches: matches, content: content, config: config,
                                              minimumSeverity: .high, filePath: path)
            let proxy = ProxyServer(config: config, quietLog: true)
            let outbound = proxy.outboundTextDecision(content, site: .proxyUserText)
            let body = try JSONSerialization.data(withJSONObject: ["messages": [["role": "user", "content": content]]])
            let request = proxy.scanAndRedactBody(try XCTUnwrap(String(data: body, encoding: .utf8)))
            let report = try ValueVerdict(content: content, filePath: path, explanation: explanation)
            XCTAssertEqual(report.findings.filter { $0.guardVerdict == "blocks" }.count, guardDecision.actionableMatches.count)
            XCTAssertEqual(report.findings.filter { $0.mcp == "placeholder, restored on write" }.count, mcp.authorized.count)
            XCTAssertEqual(report.findings.filter { $0.mcp == "advisory, unchanged" }.count, mcp.reportedAdvisories.count)
            XCTAssertEqual(report.findings.filter { $0.proxy == "redacted outbound" }.count, outbound.mutated.count)
            XCTAssertEqual(outbound.mutated.count, request.redacted)
            XCTAssertFalse(request.serializationFailed)
            XCTAssertNil(request.blockingAdvisory)
        }
    }

    // WO-637: a real documentation path changes guard/MCP policy but never proxy policy.
    func testDocumentationPolicyAndEnforce() throws {
        for enforce in [false, true] {
            var config = fixtureConfig()
            if enforce { config.documentationPolicy = .enforce }
            try withFixture(config: config) { root, explanation in
                let report = try ValueVerdict(content: credential(), filePath: root.appendingPathComponent("notes.MD").path,
                                              explanation: explanation)
                let finding = try XCTUnwrap(report.findings.first)
                XCTAssertEqual(finding.guardVerdict, enforce ? "blocks" : "reports")
                XCTAssertEqual(finding.guardSeverity, enforce ? "critical" : "medium")
                XCTAssertEqual(report.scanExitCode, enforce ? 6 : 0)
                XCTAssertEqual(finding.mcp, "advisory, unchanged")
                XCTAssertEqual(finding.proxy, "forwarded unchanged")
            }
        }
    }

    // WO-637: the documentation exception must not downgrade intrinsic or custom evidence.
    func testDocumentationStillBlocksAuthorizedSecrets() throws {
        try withFixture { root, explanation in
            for input in [aws(), custom()] {
                let report = try ValueVerdict(content: input, filePath: root.appendingPathComponent("notes.md").path,
                                              explanation: explanation)
                XCTAssertEqual(report.findings.first?.guardVerdict, "blocks")
                XCTAssertEqual(report.findings.first?.mcp, "placeholder, restored on write")
            }
        }
    }

    // WO-637: documentation policy may veto configured ambiguous mutation on file surfaces only.
    func testDocumentationMutationReasonUsesEffectiveDecision() throws {
        var config = fixtureConfig()
        config.obfuscate = [ObfuscateEntry(type: "email", pattern: "@quartzcorp.net")]
        try withFixture(config: config) { root, explanation in
            let input = ["operator", "@", "quartzcorp", ".net"].joined()
            let report = try ValueVerdict(content: input, filePath: root.appendingPathComponent("guide.md").path,
                                          explanation: explanation)
            let finding = try XCTUnwrap(report.findings.first)
            XCTAssertFalse(finding.mutationAuthorized)
            XCTAssertEqual(finding.mcp, "advisory, unchanged")
            XCTAssertEqual(finding.proxy, "redacted outbound")
            XCTAssertTrue(finding.mutationReasons.contains { $0.contains("documentationPolicy") })
        }
    }

    // WO-637: advisory thresholds do not revoke explicit mutation authorization.
    func testLowCustomRuleStillMutatesBelowGuardThreshold() throws {
        var config = fixtureConfig()
        config.customRules = [CustomRuleConfig(name: "acme-token", pattern: custom(), severity: "low")]
        config.mcpMinSeverity = "critical"
        try withFixture(config: config) { _, explanation in
            let report = try ValueVerdict(content: custom(), filePath: nil, explanation: explanation)
            XCTAssertEqual(report.findings.first?.guardVerdict, "reports")
            XCTAssertEqual(report.findings.first?.mcp, "placeholder, restored on write")
            XCTAssertEqual(report.findings.first?.proxy, "redacted outbound")
            XCTAssertEqual(report.scanExitCode, 6)
        }
    }

    // WO-637: distinguish an unreported below-threshold MCP match from an emitted advisory.
    func testMCPAdvisoryThresholdIsHonored() throws {
        var config = fixtureConfig()
        config.enabledTypes.append(SensitiveDataType.uuid.rawValue)
        config.mcpMinSeverity = "high"
        try withFixture(config: config) { _, explanation in
            let input = ["8c5f7a21", "62bd", "4e91", "b036", "09ca1254fd78"].joined(separator: "-")
            let report = try ValueVerdict(content: input, filePath: nil, explanation: explanation)
            let finding = try XCTUnwrap(report.findings.first)
            XCTAssertEqual(finding.guardVerdict, "reports")
            XCTAssertEqual(finding.mcp, "unchanged, not reported")
            XCTAssertEqual(finding.proxy, "forwarded unchanged")
            XCTAssertFalse(finding.mutationAuthorized)
        }
    }

    // WO-637: actual shared-pattern compilation determines classification and per-surface coverage.
    func testSharedPatternVerdicts() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let manifest = root.appendingPathComponent("patterns.json")
            try JSONEncoder().encode(SharedSecretPatternManifest(patterns: [
                SharedSecretPatternConfig(name: "shared-rule", regex: custom(), policy: "block")
            ])).write(to: manifest)
            var config = PastewatchConfig.defaultConfig
            config.sharedPatternFiles = [manifest.path]
            try JSONEncoder().encode(config).write(to: root.appendingPathComponent(".pastewatch.json"))
            let explanation = ConfigExplanation(currentDirectory: root.path,
                                                systemConfigPath: root.appendingPathComponent("admin.json").path,
                                                userConfigPath: PastewatchConfig.configPath.path)
            let report = try ValueVerdict(content: custom(), filePath: nil, explanation: explanation)
            let finding = try XCTUnwrap(report.findings.first)
            XCTAssertEqual(finding.classification, "shared pattern")
            XCTAssertEqual(finding.mcp, "placeholder, restored on write")
            XCTAssertEqual(finding.proxy, "redacted outbound")
            XCTAssertFalse(report.text().contains(custom()))
        }
    }

    // WO-672@v1: pattern exemptions require operator-tier policy rather than project relaxation.
    // WO-637: expose actual allowlist differences without claiming the proxy shares MCP filtering.
    func testAllowlistSuppressionsAndProxyParity() throws {
        for pattern in [false, true] {
            var config = fixtureConfig()
            if pattern { config.allowedPatterns = [custom()] } else { config.allowedValues = [custom()] }
            try withFixture(config: config) { _, _ in
                // WO-672@v1: retain the same suppression control under the user tier.
                try JSONEncoder().encode(config).write(to: PastewatchConfig.configPath)
                let operatorExplanation = ConfigExplanation(userConfigPath: PastewatchConfig.configPath.path)
                let report = try ValueVerdict(content: custom(), filePath: nil, explanation: operatorExplanation)
                let finding = try XCTUnwrap(report.findings.first)
                XCTAssertEqual(finding.allowlistSuppression, [pattern ? "allowedPatterns" : "allowedValues"])
                XCTAssertEqual(finding.guardVerdict, "not reported")
                XCTAssertEqual(finding.scanExitCode, 0)
                XCTAssertEqual(finding.mcp, "unchanged, not reported")
                XCTAssertEqual(finding.proxy, "redacted outbound")
            }
        }
    }

    // WO-637: stdin cannot authorize inline suppression for guard/scan, unlike a trusted file.
    func testInlineAllowTrustIsSurfaceSpecific() throws {
        try withFixture { root, explanation in
            let content = custom() + " # pastewatch:" + "allow"
            for path in [nil, root.appendingPathComponent("input.txt").path] {
                let report = try ValueVerdict(content: content, filePath: path, explanation: explanation)
                XCTAssertEqual(report.findings.first?.guardVerdict, path == nil ? "blocks" : "not reported")
                XCTAssertEqual(report.findings.first?.allowlistSuppression, path == nil ? [] : ["inline allow"])
                XCTAssertEqual(report.findings.first?.mcp, "unchanged, not reported")
                XCTAssertEqual(report.findings.first?.proxy, "redacted outbound")
            }
        }
    }

    // WO-637: default-config no-match output identifies loaded policy instead of implying coverage.
    func testNoMatchReportsConfigurationAndRuleCount() throws {
        try withFixture { _, explanation in
            let report = try ValueVerdict(content: "hello", filePath: nil, explanation: explanation)
            XCTAssertTrue(report.findings.isEmpty)
            XCTAssertEqual(report.configSource, "project")
            XCTAssertEqual(report.customRulesLoaded, 1)
            XCTAssertEqual(report.scanExitCode, 0)
            XCTAssertTrue(report.text().contains("No match."))
            XCTAssertTrue(report.text().contains("1 custom rules loaded"))
        }
    }

    // WO-637: stdout, stderr and JSON must never disclose intrinsic/custom/allowlisted inputs or patterns.
    func testInputNeverAppearsInCommandOutput() throws {
        var allowed = fixtureConfig()
        allowed.allowedValues = [custom()]
        for config in [fixtureConfig(), allowed] {
            try withFixture(config: config) { root, explanation in
                for input in [aws(), custom(), credential()] {
                    for json in [false, true] {
                        let command = try Check.parse(json ? ["--json"] : [])
                        let result = try capture(root: root, input: Data(input.utf8)) { try command.run(explanation: explanation) }
                        XCTAssertEqual(result.exitCode, 0)
                        XCTAssertFalse(result.stdout.contains(input))
                        XCTAssertFalse(result.stderr.contains(input))
                        XCTAssertFalse(result.stdout.contains(custom()))
                        XCTAssertFalse(result.stderr.contains(custom()))
                        if json { XCTAssertNoThrow(try JSONSerialization.jsonObject(with: Data(result.stdout.utf8))) }
                    }
                }
            }
        }
    }

    // WO-637: low-entropy stdin must expose neither positional structure nor a brute-force hash oracle.
    func testLowEntropyStdinHasNoShapeOrFingerprint() throws {
        let secret = ["har", "bor", "29"].joined()
        let input = ["pass", "word", "=", secret].joined()
        try withFixture { root, explanation in
            for json in [false, true] {
                let command = try Check.parse(json ? ["--json"] : [])
                let result = try capture(root: root, input: Data((input + "\n").utf8)) {
                    try command.run(explanation: explanation)
                }
                XCTAssertEqual(result.exitCode, 0)
                let normalized: String
                if json {
                    let object = try JSONSerialization.jsonObject(with: Data(result.stdout.utf8))
                    let data = try JSONSerialization.data(withJSONObject: object, options: [.withoutEscapingSlashes])
                    normalized = try XCTUnwrap(String(data: data, encoding: .utf8))
                } else {
                    normalized = result.stdout
                }
                let printable = normalized.replacingOccurrences(of: root.path, with: "[fixture]")
                XCTAssertFalse(printable.contains(secret))
                XCTAssertFalse(result.stderr.contains(secret))
                XCTAssertFalse(printable.contains("shape="))
                XCTAssertFalse(printable.contains("maskedShape"))
                XCTAssertFalse(printable.contains("sha256"))
                XCTAssertTrue(printable.range(of: #"(?i)\b[0-9a-f]{8,}\b"#, options: .regularExpression) == nil)
                XCTAssertTrue(result.stderr.isEmpty)
                if json {
                    let report = try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(result.stdout.utf8)) as? [String: Any])
                    let findings = try XCTUnwrap(report["findings"] as? [[String: Any]])
                    XCTAssertEqual(findings.count, 1)
                    XCTAssertEqual(findings.first?["type"] as? String, SensitiveDataType.credential.rawValue)
                    let metadata = try XCTUnwrap(findings.first?["value"] as? [String: Any])
                    XCTAssertEqual(Set(metadata.keys), Set(["lengthBytes", "characterClasses"]))
                    XCTAssertEqual(metadata["lengthBytes"] as? Int, input.utf8.count)
                    XCTAssertEqual(metadata["characterClasses"] as? [String], ["digits", "letters", "symbols"])
                }
            }
        }
    }

    // WO-637: user-controlled names cannot smuggle the literal pattern back into diagnostics.
    func testSecretBearingRuleNameIsMasked() throws {
        var config = fixtureConfig()
        config.customRules = [CustomRuleConfig(name: custom(), pattern: custom())]
        try withFixture(config: config) { _, explanation in
            let report = try ValueVerdict(content: custom(), filePath: nil, explanation: explanation)
            XCTAssertEqual(report.findings.first?.ruleName, "[masked]")
            XCTAssertFalse(report.text().contains(custom()))
            XCTAssertFalse(try XCTUnwrap(String(data: report.jsonData(), encoding: .utf8)).contains(custom()))
        }
    }

    // WO-637: file reads use the actual path so documentation policy is visible in the command output.
    func testFileCommandUsesDocumentationPolicy() throws {
        try withFixture { root, explanation in
            let file = root.appendingPathComponent("guide.md")
            try Data(credential().utf8).write(to: file)
            let command = try Check.parse(["--file", file.path, "--json"])
            let result = try capture(root: root, input: Data()) { try command.run(explanation: explanation) }
            let json = try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(result.stdout.utf8)) as? [String: Any])
            XCTAssertEqual(result.exitCode, 0)
            XCTAssertEqual(json["scanExitCode"] as? Int, 0)
            XCTAssertFalse(result.stdout.contains(credential()))
        }
    }

    // WO-637: argv rejection occurs before configuration access and never echoes the refused value.
    func testPositionalValuesAreRefusedWithoutEcho() throws {
        try withFixture { root, _ in
            for arguments in [[custom()], ["--", custom()], ["--unknown-" + custom()]] {
                var command = try Check.parse(arguments)
                let result = try capture(root: root, input: Data()) { try command.run() }
                XCTAssertEqual(result.exitCode, 64)
                XCTAssertTrue(result.stderr.contains("shell history"))
                XCTAssertTrue(result.stderr.contains("ps"))
                XCTAssertFalse(result.stderr.contains(custom()))
                XCTAssertTrue(result.stdout.isEmpty)
            }
        }
    }

    // WO-637: invalid input and missing paths produce operational errors without echoing values.
    func testInputFailuresArePrivate() throws {
        try withFixture { root, explanation in
            let commands = [try Check.parse([]), try Check.parse(["--file", root.appendingPathComponent(custom()).path])]
            for command in commands {
                let result = try capture(root: root, input: Data([0xFF])) { try command.run(explanation: explanation) }
                XCTAssertEqual(result.exitCode, 2)
                XCTAssertTrue(result.stdout.isEmpty)
                XCTAssertFalse(result.stderr.contains(custom()))
            }
        }
    }

    // WO-637: invalid active policy must not become a successful defaults-based verdict.
    func testInvalidRuleFailsClosedWithoutPatternLeak() throws {
        var config = fixtureConfig()
        let pattern = "[" + custom()
        config.customRules = [CustomRuleConfig(name: "invalid", pattern: pattern)]
        try withFixture(config: config) { root, explanation in
            let command = try Check.parse(["--json"])
            let result = try capture(root: root, input: Data(custom().utf8)) { try command.run(explanation: explanation) }
            XCTAssertEqual(result.exitCode, 2)
            XCTAssertTrue(result.stdout.isEmpty)
            XCTAssertFalse(result.stderr.contains(pattern))
            XCTAssertFalse(result.stderr.contains(custom()))
        }
    }

    // WO-637: structured file checks retain the parser's source-span containment guarantee.
    func testStructuredFileUsesRealParser() throws {
        try withFixture { root, explanation in
            let input = "{\"value\":\"" + custom() + "\"}"
            let report = try ValueVerdict(content: input, filePath: root.appendingPathComponent("data.json").path,
                                          explanation: explanation)
            XCTAssertTrue(report.findings.contains { $0.mcp == "placeholder, restored on write" })
            XCTAssertTrue(report.mcpRoundTripVerified)
        }
    }

    // WO-637: an unrepresentable source span must preserve the scanner's refusal, not report clean.
    func testUnmappableEscapedFileFailsClosed() throws {
        try withFixture { root, explanation in
            let input = "{\"value\":\"" + custom().replacingOccurrences(of: "acme", with: "\\u0061cme") + "\"}"
            let file = root.appendingPathComponent("data.json")
            try Data(input.utf8).write(to: file)
            let command = try Check.parse(["--file", file.path])
            let result = try capture(root: root, input: Data()) { try command.run(explanation: explanation) }
            XCTAssertEqual(result.exitCode, 2)
            XCTAssertTrue(result.stdout.isEmpty)
            XCTAssertFalse(result.stderr.contains(custom()))
        }
    }

    // WO-637: a private-key containment failure is a proxy refusal, not unchanged forwarding.
    func testMalformedContainerReportsProxyRefusal() throws {
        try withFixture { _, explanation in
            let input = "-----BEGIN " + "PRIVATE KEY-----\n" + "truncated"
            let report = try ValueVerdict(content: input, filePath: nil, explanation: explanation)
            XCTAssertFalse(report.findings.isEmpty)
            XCTAssertTrue(report.findings.allSatisfy { $0.proxy == "refused, not forwarded" })
        }
    }

    // WO-637: exercise termios on an actual PTY, including restored flags and an empty echo stream.
    func testTerminalInputIsNotEchoedAndSettingsAreRestored() throws {
        try terminalCheck(input: Data((custom() + "\n").utf8), expectedExit: 0)
    }

    // WO-637: cancellation must restore the terminal instead of terminating with echo disabled.
    func testTerminalCancellationRestoresSettings() throws {
        try terminalCheck(input: Data([3]), expectedExit: 2)
    }

    // WO-637: all fixture secrets are assembled at runtime, never committed as literals.
    private func aws() -> String { ["AK", "IA", "R7M2", "Q8N4", "T6W9", "Z3K5"].joined() }

    // WO-637: keep expected metadata separate from fixture input to avoid leaking assertion values.
    private struct Example {
        let input: String
        let classification: String
        let mutates: Bool
    }

    // WO-637: a literal-pattern custom rule proves both detection and reporting privacy.
    private func custom() -> String { ["acme", "_", "Q7r9", "T2w6", "P4m8", "Z3k5"].joined() }

    // WO-637: opt-in detection alone must not imply permission to replace an ambiguous credential.
    private func credential() -> String { ["pass", "word", "=", "harbor", "quartz29"].joined() }

    // WO-637: explicit fixture policy keeps every test independent of operator rules.
    private func fixtureConfig() -> PastewatchConfig {
        var config = TestConfigHelper.configWithAmbiguousAdvisories([.credential])
        config.customRules = [CustomRuleConfig(name: "acme-token", pattern: custom(), severity: "high")]
        return config
    }

    // WO-637: inject owned paths for both config candidates, never read the admin or user policy.
    private func withFixture(
        config: PastewatchConfig? = nil, _ body: (URL, ConfigExplanation) throws -> Void
    ) throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            try JSONEncoder().encode(config ?? fixtureConfig()).write(to: root.appendingPathComponent(".pastewatch.json"))
            let explanation = ConfigExplanation(currentDirectory: root.path,
                                                systemConfigPath: root.appendingPathComponent("admin.json").path,
                                                userConfigPath: PastewatchConfig.configPath.path)
            try body(root, explanation)
        }
    }

    // WO-637: capture through regular files to avoid pipe-capacity deadlocks and secret-bearing assertion output.
    private struct Output {
        let stdout: String
        let stderr: String
        let exitCode: Int32
    }

    // WO-637: real command I/O can be exercised in-process with the scoped config seam.
    private func capture(root: URL, input: Data, terminal: Int32? = nil, _ body: () throws -> Void) throws -> Output {
        let inputURL = root.appendingPathComponent("stdin.bin")
        let outputURL = root.appendingPathComponent("stdout.txt")
        let errorURL = root.appendingPathComponent("stderr.txt")
        try input.write(to: inputURL)
        try Data().write(to: outputURL)
        try Data().write(to: errorURL)
        let inputHandle = try FileHandle(forReadingFrom: inputURL)
        let outputHandle = try FileHandle(forWritingTo: outputURL)
        let errorHandle = try FileHandle(forWritingTo: errorURL)
        defer { inputHandle.closeFile(); outputHandle.closeFile(); errorHandle.closeFile() }
        fflush(nil)
        let saved = [dup(STDIN_FILENO), dup(STDOUT_FILENO), dup(STDERR_FILENO)]
        defer {
            fflush(nil)
            for (descriptor, original) in saved.enumerated() {
                dup2(original, Int32(descriptor))
                close(original)
            }
        }
        dup2(terminal ?? inputHandle.fileDescriptor, STDIN_FILENO)
        dup2(outputHandle.fileDescriptor, STDOUT_FILENO)
        dup2(errorHandle.fileDescriptor, STDERR_FILENO)
        var exitCode: Int32 = 0
        do { try body() } catch let code as ExitCode { exitCode = code.rawValue }
        fflush(nil)
        return Output(stdout: try String(contentsOf: outputURL, encoding: .utf8),
                      stderr: try String(contentsOf: errorURL, encoding: .utf8), exitCode: exitCode)
    }

    // WO-654@v1: report PTY syscall errors and retry interrupted echo checks.
    // WO-637: wait for no-echo mode before injecting input; a deadline makes a broken prompt fail, not hang.
    private func terminalCheck(input: Data, expectedExit: Int32) throws {
        var controller: Int32 = -1
        var terminal: Int32 = -1
        // WO-654@v1: openpty supplies errno before any descriptor cleanup can change it.
        guard openpty(&controller, &terminal, nil, nil, nil) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        defer { close(controller); close(terminal) }
        var before = termios()
        XCTAssertEqual(tcgetattr(terminal, &before), 0)
        let writer = expectation(description: "terminal writer completed")
        let controllerFD = controller
        let terminalFD = terminal
        DispatchQueue.global().async {
            let deadline = ProcessInfo.processInfo.systemUptime + 5
            var hidden = false
            while ProcessInfo.processInfo.systemUptime < deadline {
                var state = termios()
                if tcgetattr(terminalFD, &state) == 0 && state.c_lflag & tcflag_t(ECHO) == 0 { hidden = true; break }
                Thread.sleep(forTimeInterval: 0.001)
            }
            XCTAssertTrue(hidden, "prompt must disable echo before accepting input")
            let bytes = hidden ? input : Data([4])
            bytes.withUnsafeBytes { buffer in _ = write(controllerFD, buffer.baseAddress, buffer.count) }
            writer.fulfill()
        }
        try withFixture { root, explanation in
            let command = try Check.parse([])
            let result = try capture(root: root, input: Data(), terminal: terminal) { try command.run(explanation: explanation) }
            XCTAssertEqual(result.exitCode, expectedExit)
            XCTAssertTrue(result.stderr.contains("Value (hidden)"))
            XCTAssertFalse(result.stdout.contains(custom()))
            XCTAssertFalse(result.stderr.contains(custom()))
        }
        wait(for: [writer], timeout: 10)
        var after = termios()
        XCTAssertEqual(tcgetattr(terminal, &after), 0)
        // WO-637: macOS may set PENDIN itself; assert only the flags the prompt changes.
        let changedFlags = tcflag_t(ECHO | ECHONL | ICANON | ISIG)
        XCTAssertEqual(after.c_lflag & changedFlags, before.c_lflag & changedFlags)
        XCTAssertEqual(fcntl(controller, F_SETFL, O_NONBLOCK), 0)
        var echoed = [UInt8](repeating: 0, count: 512)
        // WO-654@v1: an interrupted read must not falsely prove that echo was disabled.
        var count: Int
        repeat {
            count = read(controller, &echoed, echoed.count)
        } while count < 0 && errno == EINTR
        XCTAssertLessThanOrEqual(count, 0, "the PTY must not echo any checked bytes")
    }
}
