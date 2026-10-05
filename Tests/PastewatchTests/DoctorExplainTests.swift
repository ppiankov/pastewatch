import XCTest
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif
@testable import PastewatchCLI
@testable import PastewatchCore

// WO-636@v2: diagnostics must be opt-in without changing plain doctor.
final class DoctorExplainTests: XCTestCase {
    // WO-649@v1: dependency status identifies a resolved path or the same actionable refusal.
    func testDoctorCurlStatusUsesInjectedLookup() {
        let found = doctorCurlStatus(lookup: { "/fixture/bin/curl" })
        XCTAssertEqual(found.status, "ok")
        XCTAssertEqual(found.detail, "/fixture/bin/curl")
        let missing = doctorCurlStatus(lookup: { nil })
        XCTAssertEqual(missing.status, "warn")
        XCTAssertEqual(missing.detail, CurlExecutable.missingDependencyMessage)
    }

    #if os(Linux)
    // WO-649@v1: both plain Linux output formats identify a found transport dependency.
    func testLinuxDoctorReportsResolvedCurlInTextAndJSON() throws {
        try assertDoctorCurlOutput(path: "/fixture/bin/curl")
    }

    // WO-649@v1: both plain Linux output formats expose a missing dependency and its remedy.
    func testLinuxDoctorReportsMissingCurlInTextAndJSON() throws {
        try assertDoctorCurlOutput(path: nil)
    }

    // WO-649@v1: invoke actual health renderers under isolated project policy.
    private func assertDoctorCurlOutput(path: String?) throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            try TestConfigHelper.ensureProjectConfig(in: root)
            for json in [false, true] {
                let command = try Doctor.parse(json ? ["--json"] : [])
                let output = try capture { try command.run(curlLookup: { path }) }
                XCTAssertTrue(output.stderr.isEmpty)
                if json {
                    let rows = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(output.stdout.utf8)) as? [[String: Any]])
                    let curl = try XCTUnwrap(rows.first { $0["check"] as? String == "curl" })
                    XCTAssertEqual(curl["status"] as? String, path == nil ? "warn" : "ok")
                    XCTAssertEqual(curl["detail"] as? String, path ?? CurlExecutable.missingDependencyMessage)
                } else {
                    XCTAssertTrue(output.stdout.contains("curl"))
                    XCTAssertTrue(output.stdout.contains(path ?? CurlExecutable.missingDependencyMessage))
                    XCTAssertTrue(output.stdout.contains(path == nil ? "[WARN]" : "[ok]"))
                }
            }
        }
    }
    #endif

    // WO-636@v2: the public flag is the regression boundary for the new walkthrough.
    func testExplainFlagIsAccepted() throws {
        XCTAssertNoThrow(try Doctor.parse(["--explain"]))
        XCTAssertNoThrow(try Doctor.parse(["--explain", "--json"]))
    }

    // WO-636@v2: default doctor must not enter the new reporting path.
    func testPlainDoctorRemainsOptOut() throws {
        let doctor = try Doctor.parse([])
        XCTAssertFalse(doctor.explain)
        XCTAssertFalse(doctor.json)
    }

    // WO-636@v2: first-wins must name the exact lost count and project-config remedy.
    func testProjectShadowsUserRulesWithoutMerging() throws {
        var user = PastewatchConfig.defaultConfig
        user.customRules = [rule("alpha", .high), rule("beta", .medium), rule("gamma", nil)]
        user.allowedPatterns = ["allowed" + "-fixture"]
        try withFixture(project: .defaultConfig, user: user) { report, root in
            XCTAssertEqual(report.source, "project")
            XCTAssertTrue(report.customRules.isEmpty)
            XCTAssertTrue(report.warnings.contains { $0.contains("3 customRules") && $0.contains("Fix:") })
            XCTAssertTrue(report.warnings.contains { $0.contains(root.appendingPathComponent(".pastewatch.json").path) })
            XCTAssertEqual(report.resolution.first { $0.source == "user" }?.disposition, "SHADOWED")
            XCTAssertEqual(try report.validatedConfiguration().customRules.count, 0)
        }
    }

    // WO-636@v2: opt-in coverage can disappear even when the user has no custom rules.
    func testShadowedCredentialOptInProducesWarning() throws {
        let user = TestConfigHelper.configWithAmbiguousAdvisories([.credential])
        try withFixture(project: .defaultConfig, user: user) { report, _ in
            XCTAssertTrue(report.customRules.isEmpty)
            XCTAssertTrue(report.warnings.contains {
                $0.contains("Credential") && $0.contains("1 detector types") && $0.contains("Fix:")
            })
        }
    }

    // WO-636@v2: warn on policy missing from the winner, without ever naming allowed values.
    func testShadowedAllowlistAndSharedFilesProduceCountOnlyWarning() throws {
        var project = PastewatchConfig.defaultConfig
        let privateValue = ["private", "-fixture-", "7139"].joined()
        project.allowedValues = ["retained"]
        var user = project
        user.allowedValues.append(privateValue)
        user.allowedPatterns = [privateValue]
        user.sharedPatternFiles = ["nonexistent-" + "shared-fixture.json"]
        try withFixture(project: project, user: user) { report, _ in
            XCTAssertTrue(report.warnings.contains {
                $0.contains("2 allowlist entries") && $0.contains("1 sharedPatternFiles")
            })
            XCTAssertFalse(report.text().contains(privateValue))
            XCTAssertFalse(String(data: try report.jsonData(), encoding: .utf8)?.contains(privateValue) == true)
        }
    }

    // WO-636@v2: equivalent non-rule policy is not lost just because its source is shadowed.
    func testIdenticalDetectorAndAllowlistPolicyDoesNotWarn() throws {
        var config = TestConfigHelper.configWithAmbiguousAdvisories([.credential])
        config.allowedValues = ["retained"]
        config.allowedPatterns = ["retained" + "-pattern"]
        try withFixture(project: config, user: config) { report, _ in
            XCTAssertTrue(report.warnings.isEmpty)
        }
    }

    // WO-636@v2: obfuscate entries activate detectors even when enabledTypes omits them.
    func testShadowedObfuscateEntryCountsEffectiveDetector() throws {
        var config = PastewatchConfig.defaultConfig
        config.obfuscate = [ObfuscateEntry(type: "email", pattern: "@fixture.example")]
        try withFixture(project: .defaultConfig, user: config) { report, _ in
            XCTAssertTrue(report.warnings.contains { $0.contains("1 detector types [Email]") })
        }
    }

    // WO-636@v2: resolve and explain must agree on admin precedence without touching real admin policy.
    func testAdminWinnerAndDefaultsUseSharedResolution() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let admin = root.appendingPathComponent("admin.json")
            let initial = explain(root)
            XCTAssertEqual(initial.source, "defaults")
            var config = PastewatchConfig.defaultConfig
            config.documentationPolicy = .enforce
            try JSONEncoder().encode(config).write(to: admin)
            let resolved = try ConfigValidator.resolveValidated(currentDirectory: root.path,
                systemConfigPath: admin.path, userConfigPath: PastewatchConfig.configPath.path)
            let report = explain(root)
            XCTAssertEqual(report.path, resolved.path)
            XCTAssertEqual(report.source, "system (admin)")
            XCTAssertEqual(report.documentationPolicy, "enforce")
        }
    }

    // WO-636@v2: mutation authorization is independent of the MCP advisory threshold.
    func testRuleSeveritiesAndSurfaceVerdicts() throws {
        var config = PastewatchConfig.defaultConfig
        config.mcpMinSeverity = "critical"
        config.customRules = [rule("high", .high), rule("medium", .medium), rule("low", .low), rule("default", nil)]
        try withFixture(project: config) { report, _ in
            XCTAssertTrue(report.valid)
            XCTAssertEqual(report.customRules.map(\.guardHook), ["blocks", "reports only", "reports only", "blocks"])
            XCTAssertEqual(report.customRules.map(\.severity), ["high", "medium", "low", "high"])
            XCTAssertTrue(report.customRules.last?.severityDefaulted == true)
            XCTAssertTrue(report.customRules.allSatisfy { $0.scan == "blocks (exit 6)" })
            XCTAssertTrue(report.customRules.allSatisfy { $0.mcp == "placeholder (two-way)" })
            XCTAssertTrue(report.customRules.allSatisfy { $0.proxy == "redacted (one-way)" })
            XCTAssertTrue(report.summary.hasPrefix("2 of 4"))
        }
    }

    // WO-636@v2: compiler rejection and strict runtime validation must be visible, never silently dropped.
    func testInvalidRuleFailsClosedLikeScannerConfiguration() throws {
        var config = PastewatchConfig.defaultConfig
        config.customRules = [CustomRuleConfig(name: "broken", pattern: "[", severity: "high")]
        XCTAssertThrowsError(try CustomRule.compile(config.customRules))
        try withFixture(project: config) { report, root in
            XCTAssertThrowsError(try ConfigValidator.resolveValidated(currentDirectory: root.path,
                systemConfigPath: root.appendingPathComponent("admin.json").path,
                userConfigPath: PastewatchConfig.configPath.path))
            XCTAssertFalse(report.valid)
            XCTAssertThrowsError(try report.validatedConfiguration())
            XCTAssertEqual(report.customRules.first?.compileStatus, "error: invalid regex")
            XCTAssertEqual(report.customRules.first?.guardHook, "fail closed")
            XCTAssertEqual(report.customRules.first?.scan, "fail closed")
            XCTAssertEqual(report.customRules.first?.mcp, "fail closed")
            XCTAssertEqual(report.customRules.first?.proxy, "fail closed")
        }
    }

    // WO-636@v2: missing and malformed manifests use the real shared-rule loader.
    func testSharedPatternFailuresAreReported() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            var config = PastewatchConfig.defaultConfig
            let broken = root.appendingPathComponent("broken.json")
            try Data("{".utf8).write(to: broken)
            config.sharedPatternFiles = [root.appendingPathComponent("missing.json").path, broken.path]
            try JSONEncoder().encode(config).write(to: root.appendingPathComponent(".pastewatch.json"))
            let report = explain(root)
            XCTAssertFalse(report.valid)
            XCTAssertEqual(report.sharedPatterns.map(\.status), ["missing/error", "error"])
            XCTAssertEqual(report.sharedPatterns.map(\.patternCount), [0, 0])
        }
    }

    // WO-636@v2: report loaded manifest counts rather than treating shared coverage as custom config rows.
    func testSharedPatternsLoadThroughRealCompiler() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let manifest = root.appendingPathComponent("patterns.json")
            let entry = SharedSecretPatternConfig(name: "shared", regex: "shared" + "-probe", policy: "block")
            try JSONEncoder().encode(SharedSecretPatternManifest(patterns: [entry])).write(to: manifest)
            var config = PastewatchConfig.defaultConfig
            config.sharedPatternFiles = [manifest.path]
            try JSONEncoder().encode(config).write(to: root.appendingPathComponent(".pastewatch.json"))
            let report = explain(root)
            XCTAssertTrue(report.valid)
            XCTAssertEqual(report.sharedPatterns.first?.status, "loaded")
            XCTAssertEqual(report.sharedPatterns.first?.patternCount, 1)
        }
    }

    // WO-636@v2: duplicates and a rule-name suppression probe are separate diagnostics.
    func testDuplicatesAndPossibleAllowlistSuppression() throws {
        var config = PastewatchConfig.defaultConfig
        config.customRules = [CustomRuleConfig(name: "probe", pattern: "pro" + "be"),
                              CustomRuleConfig(name: "probe", pattern: "other" + "-probe")]
        config.allowedPatterns = ["pro" + "be"]
        try withFixture(project: config) { report, _ in
            XCTAssertTrue(report.customRules.allSatisfy(\.duplicateName))
            XCTAssertEqual(report.possibleSuppression.count, 1)
        }
    }

    // WO-637: policy summaries retain byte lengths, but never a digest of literal patterns.
    // WO-636@v2: literal patterns and allowlist values must be absent from all CLI output channels.
    func testLiteralSecretsNeverAppearInTextStderrOrJSON() throws {
        let secret = ["AK", "IA", "7K9M2P4R6T8V3X5Z"].joined()
        let allowed = ["fixture", "-private-", "4831", "-allow"].joined()
        var config = PastewatchConfig.defaultConfig
        config.customRules = [CustomRuleConfig(name: "private-rule", pattern: secret)]
        config.allowedValues = [allowed]
        config.allowedPatterns = [allowed]
        try withFixture(project: config) { report, _ in
            for args in [["--explain"], ["--explain", "--json"]] {
                let command = try Doctor.parse(args)
                let output = try capture { try command.printExplanation(report) }
                for value in [secret, allowed] {
                    XCTAssertFalse(output.stdout.contains(value), "stdout must not contain policy material")
                    XCTAssertFalse(output.stderr.contains(value), "stderr must not contain policy material")
                }
                if args.contains("--json") {
                    XCTAssertNoThrow(try JSONSerialization.jsonObject(with: Data(output.stdout.utf8)))
                }
            }
            // WO-637: the only non-length metadata is an unordered character-class set.
            XCTAssertEqual(report.customRules.first?.pattern.characterClasses, ["digits", "letters"])
            XCTAssertEqual(report.allowedValues.first?.lengthBytes, allowed.utf8.count)
        }
    }

    // WO-637: literal policy values must not become shape or digest oracles in either renderer.
    func testLiteralPolicyMetadataHasNoShapeOrFingerprint() throws {
        let secret = ["har", "bor", "29"].joined()
        var config = PastewatchConfig.defaultConfig
        config.customRules = [
            CustomRuleConfig(name: "literal-rule", pattern: secret),
            CustomRuleConfig(name: secret, pattern: secret)
        ]
        config.allowedValues = [secret]
        config.allowedPatterns = [secret]
        try withFixture(project: config) { report, root in
            for args in [["--explain"], ["--explain", "--json"]] {
                let command = try Doctor.parse(args)
                let output = try capture { try command.printExplanation(report) }
                let normalized: String
                if args.contains("--json") {
                    let object = try JSONSerialization.jsonObject(with: Data(output.stdout.utf8))
                    let data = try JSONSerialization.data(withJSONObject: object, options: [.withoutEscapingSlashes])
                    normalized = try XCTUnwrap(String(data: data, encoding: .utf8))
                } else {
                    normalized = output.stdout
                }
                let printable = normalized.replacingOccurrences(of: root.path, with: "[fixture]")
                XCTAssertFalse(printable.contains(secret))
                XCTAssertFalse(output.stderr.contains(secret))
                XCTAssertFalse(printable.contains("shape="))
                XCTAssertFalse(printable.contains("maskedShape"))
                XCTAssertFalse(printable.contains("sha256"))
                XCTAssertTrue(printable.range(of: #"(?i)\b[0-9a-f]{8,}\b"#, options: .regularExpression) == nil)
                XCTAssertTrue(output.stderr.isEmpty)
            }
            let json = try XCTUnwrap(try JSONSerialization.jsonObject(with: report.jsonData()) as? [String: Any])
            let rules = try XCTUnwrap(json["customRules"] as? [[String: Any]])
            let patterns = try rules.map { try XCTUnwrap($0["pattern"] as? [String: Any]) }
            let allowedValues = try XCTUnwrap(json["allowedValues"] as? [[String: Any]])
            let allowedPatterns = try XCTUnwrap(json["allowedPatterns"] as? [[String: Any]])
            for metadata in patterns + allowedValues + allowedPatterns {
                XCTAssertEqual(Set(metadata.keys), Set(["lengthBytes", "characterClasses"]))
                XCTAssertEqual(metadata["lengthBytes"] as? Int, secret.utf8.count)
                XCTAssertEqual(metadata["characterClasses"] as? [String], ["digits", "letters"])
            }
        }
    }

    // WO-637: metadata is bounded to four class names regardless of position or repetitions.
    func testMaskedMetadataIsBounded() {
        let value = String(repeating: "A9", count: 80)
        let summary = DiagnosticValueSummary(value)
        XCTAssertEqual(summary.lengthBytes, 160)
        XCTAssertEqual(summary.characterClasses, ["digits", "letters"])
        XCTAssertEqual(summary.characterClasses, DiagnosticValueSummary(String(value.reversed())).characterClasses)
        XCTAssertEqual(summary.characterClasses, DiagnosticValueSummary("9AA9").characterClasses)
        XCTAssertEqual(DiagnosticValueSummary("").characterClasses, [])
        XCTAssertEqual(DiagnosticValueSummary("\u{00E9}9 \t\n!\u{1F512}").characterClasses,
                       ["digits", "letters", "symbols", "whitespace"])
    }

    // WO-636@v2: a support-sized policy must render with correct cardinality in under a second.
    func testTwoHundredRulesRenderPromptly() throws {
        var config = PastewatchConfig.defaultConfig
        config.customRules = (0..<200).map { rule("synthetic-\($0)", .high) }
        try withFixture(project: config) { report, _ in
            let start = Date()
            _ = report.text()
            _ = try report.jsonData()
            XCTAssertLessThan(Date().timeIntervalSince(start), 1)
            XCTAssertEqual(report.customRules.count, 200)
            XCTAssertTrue(report.summary.hasPrefix("200 of 200"))
        }
    }

    // WO-636@v2: fixture rules never embed real or secret-shaped literals in source.
    private func rule(_ name: String, _ severity: Severity?) -> CustomRuleConfig {
        CustomRuleConfig(name: name, pattern: "fixture-" + name, severity: severity?.rawValue)
    }

    // WO-636@v2: every explanation reads only fixture-owned admin/project/global candidates.
    private func explain(_ root: URL) -> ConfigExplanation {
        ConfigExplanation(currentDirectory: root.path, systemConfigPath: root.appendingPathComponent("admin.json").path,
                          userConfigPath: PastewatchConfig.configPath.path)
    }

    // WO-636@v2: reset config and CWD even when a diagnostic assertion throws.
    private func withFixture(
        project: PastewatchConfig? = nil, user: PastewatchConfig? = nil,
        body: (ConfigExplanation, URL) throws -> Void
    ) throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            if let project { try JSONEncoder().encode(project).write(to: root.appendingPathComponent(".pastewatch.json")) }
            if let user { try JSONEncoder().encode(user).write(to: PastewatchConfig.configPath) }
            try body(explain(root), root)
        }
    }

    // WO-636@v2: inspect actual CLI renderer output without launching a process that can read operator policy.
    private func capture(_ body: () throws -> Void) throws -> (stdout: String, stderr: String) {
        let output = Pipe()
        let error = Pipe()
        fflush(nil)
        let savedOutput = dup(STDOUT_FILENO)
        let savedError = dup(STDERR_FILENO)
        defer {
            dup2(savedOutput, STDOUT_FILENO)
            dup2(savedError, STDERR_FILENO)
            close(savedOutput)
            close(savedError)
        }
        dup2(output.fileHandleForWriting.fileDescriptor, STDOUT_FILENO)
        dup2(error.fileHandleForWriting.fileDescriptor, STDERR_FILENO)
        try body()
        fflush(nil)
        dup2(savedOutput, STDOUT_FILENO)
        dup2(savedError, STDERR_FILENO)
        try output.fileHandleForWriting.close()
        try error.fileHandleForWriting.close()
        return (try XCTUnwrap(String(data: output.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)),
                try XCTUnwrap(String(data: error.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)))
    }
}
