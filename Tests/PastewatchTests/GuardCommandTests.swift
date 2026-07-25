import XCTest
@testable import PastewatchCore

final class GuardCommandTests: XCTestCase {

    private var testDir: String!
    // WO-529@v3: Default config only enables intrinsic detectors.
    private let config = PastewatchConfig.defaultConfig

    // WO-529@v3: Config with credential type enabled for inline credential tests.
    private let credentialConfig: PastewatchConfig = {
        var config = PastewatchConfig.defaultConfig
        if !config.enabledTypes.contains(SensitiveDataType.credential.rawValue) {
            config.enabledTypes.append(SensitiveDataType.credential.rawValue)
        }
        return config
    }()

    override func setUp() {
        super.setUp()
        testDir = NSTemporaryDirectory() + "pastewatch-guard-test-\(UUID().uuidString)"
        try? FileManager.default.createDirectory(atPath: testDir, withIntermediateDirectories: true)
    }

    override func tearDown() {
        try? FileManager.default.removeItem(atPath: testDir)
        super.tearDown()
    }

    // MARK: - Core scanning logic (exercises CommandParser + DetectionRules together)

    func testBlocksFileWithSecrets() throws {
        let testFile = testDir + "/config.env"
        let key = ["AKIA", "IOSFODNN7EXAMPLE"].joined()
        try "AWS_KEY=\(key)".write(toFile: testFile, atomically: true, encoding: .utf8)

        let paths = CommandParser.extractFilePaths(from: "cat \(testFile)")
        XCTAssertEqual(paths.count, 1)

        let content = try String(contentsOfFile: paths[0], encoding: .utf8)
        let matches = DetectionRules.scan(content, config: config)
        let filtered = matches.filter { $0.effectiveSeverity >= .high }

        XCTAssertFalse(filtered.isEmpty, "Should find high+ severity secrets")
    }

    // WO-502: an agent can write `# pastewatch:allow` into a file it controls and then
    // `cat` it. Files referenced by an agent-controlled command must be scanned as
    // .agentControlled so the inline allow comment cannot self-authorize the secret.
    func testAgentReferencedFileCannotSelfAuthorizeWithInlineAllow() throws {
        let testFile = testDir + "/agent-written.env"
        // WO-542: use an intrinsic detector so this trust test does not depend on ambiguous defaults.
        let secret = "AWS_KEY=" + "AKIA" + "QWERTYUIOPASDFGH"
        try "\(secret) # pastewatch:allow".write(toFile: testFile, atomically: true, encoding: .utf8)

        let paths = CommandParser.extractFilePaths(from: "cat \(testFile)")
        XCTAssertEqual(paths.count, 1)

        let content = try String(contentsOfFile: paths[0], encoding: .utf8)
        let decision = GuardDecision.evaluate(
            matches: DetectionRules.scan(content, config: config),
            content: content,
            config: config,
            contentTrust: .agentControlled,
            minimumSeverity: .high
        )

        XCTAssertFalse(
            decision.actionableMatches.isEmpty,
            "Agent-referenced file must not be allow-comment-bypassable"
        )
    }

    func testAllowsCleanFile() throws {
        let testFile = testDir + "/readme.txt"
        try "Hello world, nothing sensitive here".write(toFile: testFile, atomically: true, encoding: .utf8)

        let paths = CommandParser.extractFilePaths(from: "cat \(testFile)")
        XCTAssertEqual(paths.count, 1)

        let content = try String(contentsOfFile: paths[0], encoding: .utf8)
        let matches = DetectionRules.scan(content, config: config)
        let filtered = matches.filter { $0.effectiveSeverity >= .high }

        XCTAssertTrue(filtered.isEmpty, "Clean file should have no high+ findings")
    }

    func testAllowsNonExistentFile() {
        let paths = CommandParser.extractFilePaths(from: "cat /nonexistent/file.txt")
        XCTAssertEqual(paths.count, 1)

        // File doesn't exist → should not block (command will fail on its own)
        let exists = FileManager.default.fileExists(atPath: paths[0])
        XCTAssertFalse(exists)
    }

    func testSeverityThresholdFiltering() throws {
        let testFile = testDir + "/hosts.txt"
        // WO-542: declare ambiguous fixture intent instead of relying on defaults.
        // Phone is high severity, IP is medium.
        try "contact: +1-415-555-2671\nserver: 10.0.1.50".write(
            toFile: testFile, atomically: true, encoding: .utf8)

        let content = try String(contentsOfFile: testFile, encoding: .utf8)
        // WO-542: preserve threshold coverage with explicit ambiguous detectors.
        let matches = DetectionRules.scan(
            content,
            config: TestConfigHelper.configWithAmbiguousAdvisories([.phone, .ipAddress])
        )

        let criticalOnly = matches.filter { $0.effectiveSeverity >= .critical }
        let highAndUp = matches.filter { $0.effectiveSeverity >= .high }

        // Critical threshold: nothing should match
        XCTAssertTrue(criticalOnly.isEmpty)
        // High threshold: phone should match.
        XCTAssertFalse(highAndUp.isEmpty)
    }

    func testNoFileCommandAllowed() {
        let paths = CommandParser.extractFilePaths(from: "echo hello world")
        XCTAssertTrue(paths.isEmpty, "Non-file command should extract no paths")
    }

    func testSedCommandExtractsFile() throws {
        let testFile = testDir + "/app.conf"
        try "password=s3cr3t_value_here123!".write(toFile: testFile, atomically: true, encoding: .utf8)

        let paths = CommandParser.extractFilePaths(from: "sed -i 's/old/new/' \(testFile)")
        XCTAssertEqual(paths.count, 1)
        XCTAssertEqual(paths[0], testFile)
    }

    // WO-138: guard must exercise command-text credential scanning, not only file reads.
    func testGuardQuietAllowsInlineEnvReferences() throws {
        let cleanCommands = [
            "env api_key=$PTOK gh api",
            "env secret=${VAULT_KEY} gh api",
            "env api_key=\"$PTOK\" gh api",
            "env secret=\"${VAULT_KEY}\" gh api",
            "env token='$X' gh api",
            "env password=\"${A:-fallback}\" gh api",
            "env token=\"%VAR%\" gh api",
        ]

        for command in cleanCommands {
            let result = try runGuardCLI(arguments: ["guard", "--quiet", command])
            XCTAssertEqual(result.status, 0, "env reference should not block")
            XCTAssertTrue(result.stdout.isEmpty, "quiet mode should not write stdout")
            XCTAssertTrue(result.stderr.isEmpty, "quiet mode should not write stderr")
        }
    }

    // WO-138: literal env assignments in command text must block without leaking values.
    // WO-529@v3: Enable credential type for this test.
    func testGuardQuietBlocksInlineLiteralCredentials() throws {
        try writeConfig(credentialConfig)
        let literal = syntheticCredentialLiteral()
        let blockedCommands = [
            "env api_key=\(literal) gh api",
            "env api_key=\"\(literal)\" gh api",
            "env api_key='\(literal)' gh api",
            "env api_key=`\(literal)` gh api",
        ]

        for command in blockedCommands {
            let result = try runGuardCLI(arguments: ["guard", "--quiet", command])
            XCTAssertEqual(result.status, 1, "literal credential assignment should block")
            XCTAssertTrue(result.stdout.isEmpty, "quiet mode should not write stdout")
            XCTAssertTrue(result.stderr.isEmpty, "quiet mode should not write stderr")
        }
    }

    // WO-138: machine-readable output must not echo inline credential literals.
    // WO-529@v3: Enable credential type for this test.
    func testGuardJSONRedactsInlineLiteralCommand() throws {
        try writeConfig(credentialConfig)
        let literal = syntheticCredentialLiteral()
        let command = "env api_key=\(literal) gh api"

        let result = try runGuardCLI(arguments: ["guard", "--json", command])

        XCTAssertEqual(result.status, 1)
        XCTAssertFalse(result.stdout.contains(literal), "JSON output must not contain literal credential values")
        XCTAssertTrue(result.stdout.contains("<CREDENTIAL_1>"))
        XCTAssertTrue(result.stderr.isEmpty)
    }

    // WO-138: human output should report counts/types only, never the literal value.
    // WO-529@v3: Enable credential type for this test.
    func testGuardTextOutputOmitsInlineLiteralValue() throws {
        try writeConfig(credentialConfig)
        let literal = syntheticCredentialLiteral()
        let command = "env api_key=\(literal) gh api"

        let result = try runGuardCLI(arguments: ["guard", command])

        XCTAssertEqual(result.status, 1)
        XCTAssertTrue(result.stdout.isEmpty)
        XCTAssertFalse(result.stderr.contains(literal), "text output must not contain literal credential values")
        XCTAssertTrue(result.stderr.contains("command contains inline secret"))
    }

    // WO-139: JSON command redaction must not depend on block threshold.
    func testGuardJSONRedactsLowerSeverityInlineFindingBelowThreshold() throws {
        let email = ["admin", "@", "corp.com"].joined()
        try writeConfig(TestConfigHelper.configWithEmailObfuscation())
        let result = try runGuardCLI(arguments: [
            "guard", "--json", "--fail-on-severity", "critical", "echo \(email)",
        ])
        let payload = try guardJSON(from: result.stdout)
        let commandText = try XCTUnwrap(payload["command"] as? String)

        XCTAssertEqual(result.status, 0)
        XCTAssertEqual(payload["blocked"] as? Bool, false)
        XCTAssertTrue(commandText.contains("<EMAIL_1>"), "JSON command should contain placeholder")
        XCTAssertFalse(commandText.contains(email), "JSON command should redact inline values")
        XCTAssertFalse(result.stdout.contains(email), "JSON output must redact inline values")
        XCTAssertTrue(result.stderr.isEmpty)
    }

    // WO-139: file blocking must not leak below-threshold inline findings in JSON command context.
    func testGuardJSONRedactsLowerSeverityInlineFindingWhenFileBlocks() throws {
        let email = ["admin", "@", "corp.com"].joined()
        let testFile = testDir + "/config.env"
        try writeConfig(TestConfigHelper.configWithEmailObfuscation())
        let intrinsicKey = "AKIA" + "QWERTYUIOPASDFGH"
        try "AWS_KEY=\(intrinsicKey)".write(
            toFile: testFile, atomically: true, encoding: .utf8)

        let result = try runGuardCLI(arguments: [
            "guard", "--json", "--fail-on-severity", "critical",
            "cat \(testFile) && echo \(email)",
        ])
        let payload = try guardJSON(from: result.stdout)
        let commandText = try XCTUnwrap(payload["command"] as? String)
        let inlineFindings = try XCTUnwrap(payload["inlineFindings"] as? [[String: Any]])

        XCTAssertEqual(result.status, 1)
        XCTAssertEqual(payload["blocked"] as? Bool, true)
        XCTAssertTrue(commandText.contains("<EMAIL_1>"), "JSON command should contain placeholder")
        XCTAssertFalse(commandText.contains(email), "JSON command should redact inline values")
        XCTAssertTrue(inlineFindings.isEmpty)
        XCTAssertFalse(result.stdout.contains(email), "JSON output must redact inline values")
        XCTAssertTrue(result.stderr.isEmpty)
    }

    // WO-139: display redaction must preserve the existing known-test-credential filter.
    func testGuardJSONDoesNotRedactKnownTestCredential() throws {
        let testKey = ["AKIA", "IOSFODNN7EXAMPLE"].joined()
        let matches = DetectionRules.scan(testKey, config: config)

        XCTAssertFalse(matches.isEmpty, "known test credential should exercise scanning")
        XCTAssertTrue(matches.allSatisfy { DetectionRules.isTestCredential($0.value) })

        let result = try runGuardCLI(arguments: ["guard", "--json", "echo \(testKey)"])
        let payload = try guardJSON(from: result.stdout)
        let commandText = try XCTUnwrap(payload["command"] as? String)

        XCTAssertEqual(result.status, 0)
        XCTAssertEqual(payload["blocked"] as? Bool, false)
        XCTAssertTrue(commandText.contains(testKey), "known test credential should remain visible")
        XCTAssertFalse(commandText.contains("<AWS"), "known test credential should not be redacted")
        XCTAssertTrue(result.stderr.isEmpty)
    }

    func testGuardHonorsConfigAllowlistForInlineAndReferencedFile() throws {
        let key = "AKIA" + "QWERTYUIOPASDFGH"
        let testFile = testDir + "/config.env"
        try "AWS_KEY=\(key)".write(toFile: testFile, atomically: true, encoding: .utf8)
        var allowedConfig = config
        allowedConfig.allowedValues = [key]
        let configData = try JSONEncoder().encode(allowedConfig)
        try configData.write(to: URL(fileURLWithPath: testDir + "/.pastewatch.json"))

        let result = try runGuardCLI(arguments: ["guard", "--json", "cat \(testFile) && echo \(key)"])
        let payload = try guardJSON(from: result.stdout)

        XCTAssertEqual(result.status, 0)
        XCTAssertEqual(payload["blocked"] as? Bool, false)
        XCTAssertTrue((payload["files"] as? [[String: Any]])?.isEmpty == true)
        XCTAssertTrue((payload["inlineFindings"] as? [[String: Any]])?.isEmpty == true)
    }

    func testGuardCommandCannotSelfAuthorizeWithInlineAllowComment() throws {
        let key = "AKIA" + "QWERTYUIOPASDFGH"

        let result = try runGuardCLI(arguments: [
            "guard", "--quiet", "echo \(key) # pastewatch:allow",
        ])

        XCTAssertEqual(result.status, 1)
        XCTAssertTrue(result.stdout.isEmpty)
        XCTAssertTrue(result.stderr.isEmpty)
    }

    private struct CLIResult {
        let status: Int32
        let stdout: String
        let stderr: String
    }

    private func runGuardCLI(arguments: [String]) throws -> CLIResult {
        let process = Process()
        process.executableURL = pastewatchCLIURL()
        process.arguments = arguments
        process.currentDirectoryURL = URL(fileURLWithPath: testDir)
        process.environment = testEnvironment()

        let stdout = Pipe()
        let stderr = Pipe()
        process.standardOutput = stdout
        process.standardError = stderr

        try process.run()
        process.waitUntilExit()

        return CLIResult(
            status: process.terminationStatus,
            stdout: String(data: stdout.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? "",
            stderr: String(data: stderr.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        )
    }

    // WO-542: subprocess tests must declare ambiguous obfuscation instead of inheriting it.
    private func writeConfig(_ config: PastewatchConfig) throws {
        let configData = try JSONEncoder().encode(config)
        try configData.write(to: URL(fileURLWithPath: testDir + "/.pastewatch.json"))
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

    private func testEnvironment() -> [String: String] {
        var environment = ProcessInfo.processInfo.environment
        environment["HOME"] = testDir
        environment["XDG_CONFIG_HOME"] = testDir + "/.config"
        environment["PW_GUARD"] = "1"
        return environment
    }

    private func guardJSON(from stdout: String) throws -> [String: Any] {
        let data = Data(stdout.utf8)
        let object = try JSONSerialization.jsonObject(with: data)
        return try XCTUnwrap(object as? [String: Any])
    }

    private func syntheticCredentialLiteral() -> String {
        "Alpha" + String(repeating: "A1", count: 18) + "_tail"
    }
}
