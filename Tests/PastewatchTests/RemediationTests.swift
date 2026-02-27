import XCTest
@testable import PastewatchCore

final class RemediationTests: XCTestCase {
    let config = PastewatchConfig.defaultConfig

    // MARK: - Env var name suggestion

    func testSuggestEnvVarFromKeyContext() {
        let content = "api_key = \"sk_live_abc123def456ghi789\""
        let match = DetectedMatch(
            type: .genericApiKey, value: "sk_live_abc123def456ghi789",
            range: content.range(of: "sk_live_abc123def456ghi789")!,
            line: 1, filePath: "config.py"
        )
        let name = Remediation.suggestEnvVarName(match: match, fileContent: content)
        XCTAssertEqual(name, "API_KEY")
    }

    func testSuggestEnvVarFromType() {
        let awsKey = ["AKIA", "IOSFODNN7EXAMPLE"].joined()
        let content = "key = \(awsKey)"
        let match = DetectedMatch(
            type: .awsKey, value: awsKey,
            range: content.range(of: awsKey)!,
            line: 1, filePath: "config.txt"
        )
        // "key" is too generic — the type default should win for AWS
        // But extractKeyFromLine will find "key", so let's test with no key context
        let contentNoKey = awsKey
        let matchNoKey = DetectedMatch(
            type: .awsKey, value: awsKey,
            range: contentNoKey.range(of: awsKey)!,
            line: 1, filePath: "config.txt"
        )
        let name = Remediation.suggestEnvVarName(match: matchNoKey, fileContent: contentNoKey)
        XCTAssertEqual(name, "AWS_ACCESS_KEY_ID")
    }

    func testSuggestEnvVarFromCredentialPrefix() {
        let content = "password=SuperSecret123"
        let match = DetectedMatch(
            type: .credential, value: "password=SuperSecret123",
            range: content.range(of: "password=SuperSecret123")!,
            line: 1, filePath: "config.env"
        )
        let name = Remediation.suggestEnvVarName(match: match, fileContent: content)
        // Credential type — falls back to type default if no key found
        XCTAssertFalse(name.isEmpty)
    }

    func testEnvVarDeduplication() {
        let conn1 = ["postgres", "://user:pass@host1/db1"].joined()
        let conn2 = ["postgres", "://user:pass@host2/db2"].joined()
        let fr1 = FileScanResult(
            filePath: "a.txt", matches: [
                DetectedMatch(type: .dbConnectionString, value: conn1,
                              range: conn1.startIndex..<conn1.endIndex, line: 1, filePath: "a.txt")
            ], content: conn1
        )
        let fr2 = FileScanResult(
            filePath: "b.txt", matches: [
                DetectedMatch(type: .dbConnectionString, value: conn2,
                              range: conn2.startIndex..<conn2.endIndex, line: 1, filePath: "b.txt")
            ], content: conn2
        )
        let plan = Remediation.buildPlan(results: [fr1, fr2], minSeverity: .low)
        let names = plan.actions.map { $0.envVarName }
        XCTAssertEqual(names[0], "DATABASE_URL")
        XCTAssertEqual(names[1], "DATABASE_URL_2")
    }

    // MARK: - Language-aware references

    func testEnvVarReferencePython() {
        XCTAssertEqual(Remediation.envVarReference(name: "API_KEY", ext: "py"),
                       "os.environ[\"API_KEY\"]")
    }

    func testEnvVarReferenceJavaScript() {
        XCTAssertEqual(Remediation.envVarReference(name: "API_KEY", ext: "js"),
                       "process.env.API_KEY")
    }

    func testEnvVarReferenceTypeScript() {
        XCTAssertEqual(Remediation.envVarReference(name: "API_KEY", ext: "ts"),
                       "process.env.API_KEY")
    }

    func testEnvVarReferenceGo() {
        XCTAssertEqual(Remediation.envVarReference(name: "API_KEY", ext: "go"),
                       "os.Getenv(\"API_KEY\")")
    }

    func testEnvVarReferenceRuby() {
        XCTAssertEqual(Remediation.envVarReference(name: "API_KEY", ext: "rb"),
                       "ENV[\"API_KEY\"]")
    }

    func testEnvVarReferenceSwift() {
        XCTAssertEqual(Remediation.envVarReference(name: "API_KEY", ext: "swift"),
                       "ProcessInfo.processInfo.environment[\"API_KEY\"] ?? \"\"")
    }

    func testEnvVarReferenceShell() {
        XCTAssertEqual(Remediation.envVarReference(name: "API_KEY", ext: "sh"),
                       "${API_KEY}")
    }

    func testEnvVarReferenceEnvFile() {
        XCTAssertEqual(Remediation.envVarReference(name: "API_KEY", ext: "env"), "")
    }

    func testEnvVarReferenceUnknown() {
        XCTAssertEqual(Remediation.envVarReference(name: "API_KEY", ext: "txt"),
                       "${API_KEY}")
    }

    // MARK: - Normalize

    func testNormalizeToEnvVar() {
        XCTAssertEqual(Remediation.normalizeToEnvVar("apiKey"), "API_KEY")
        XCTAssertEqual(Remediation.normalizeToEnvVar("api_key"), "API_KEY")
        XCTAssertEqual(Remediation.normalizeToEnvVar("api-key"), "API_KEY")
        XCTAssertEqual(Remediation.normalizeToEnvVar("API_KEY"), "API_KEY")
        XCTAssertEqual(Remediation.normalizeToEnvVar("db.url"), "DB_URL")
    }

    // MARK: - Plan building

    func testBuildPlanFiltersBySeverity() {
        let conn = ["postgres", "://user:pass@host/db"].joined()
        let fr = FileScanResult(
            filePath: "config.txt", matches: [
                DetectedMatch(type: .dbConnectionString, value: conn,
                              range: conn.startIndex..<conn.endIndex, line: 1, filePath: "config.txt"),
                DetectedMatch(type: .email, value: "test@company.com",
                              range: "test@company.com".startIndex..<"test@company.com".endIndex,
                              line: 2, filePath: "config.txt")
            ], content: "\(conn)\ntest@company.com"
        )

        let planCritical = Remediation.buildPlan(results: [fr], minSeverity: .critical)
        XCTAssertEqual(planCritical.actions.count, 1, "only critical DB connection should be included")

        let planLow = Remediation.buildPlan(results: [fr], minSeverity: .low)
        XCTAssertEqual(planLow.actions.count, 2, "both findings should be included at low threshold")
    }

    // MARK: - Apply plan

    func testApplyPlanPatchesFile() throws {
        let testDir = NSTemporaryDirectory() + "pastewatch-fix-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: testDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: testDir) }

        let conn = ["postgres", "://user:pass@host/db"].joined()
        let pyContent = "db_url = \"\(conn)\"\n"
        let pyPath = testDir + "/config.py"
        try pyContent.write(toFile: pyPath, atomically: true, encoding: .utf8)

        let plan = FixPlan(actions: [
            FixAction(filePath: "config.py", line: 1, secretValue: conn,
                      envVarName: "DATABASE_URL",
                      replacement: "os.environ[\"DATABASE_URL\"]",
                      type: .dbConnectionString, severity: .critical)
        ])

        try Remediation.apply(plan: plan, dirPath: testDir, envFilePath: ".env")

        let patched = try String(contentsOfFile: pyPath, encoding: .utf8)
        XCTAssertTrue(patched.contains("os.environ[\"DATABASE_URL\"]"))
        XCTAssertFalse(patched.contains(conn))
        // Verify surrounding quotes were stripped — should not have "os.environ or os.environ"
        XCTAssertTrue(patched.contains("db_url = os.environ"),
                       "surrounding quotes should be stripped: got \(patched)")
    }

    func testApplyPlanGeneratesEnvFile() throws {
        let testDir = NSTemporaryDirectory() + "pastewatch-fix-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: testDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: testDir) }

        // Create a dummy source file so patchFile has something to work with
        let conn = ["postgres", "://user:pass@host/db"].joined()
        try "url = \"\(conn)\"".write(toFile: testDir + "/app.py", atomically: true, encoding: .utf8)

        let plan = FixPlan(actions: [
            FixAction(filePath: "app.py", line: 1, secretValue: conn,
                      envVarName: "DATABASE_URL",
                      replacement: "os.environ[\"DATABASE_URL\"]",
                      type: .dbConnectionString, severity: .critical)
        ])

        try Remediation.apply(plan: plan, dirPath: testDir, envFilePath: ".env")

        let envContent = try String(contentsOfFile: testDir + "/.env", encoding: .utf8)
        XCTAssertTrue(envContent.contains("DATABASE_URL="))
        XCTAssertTrue(envContent.contains(conn))
    }

    func testApplyPlanSkipsExistingEnvKey() throws {
        let testDir = NSTemporaryDirectory() + "pastewatch-fix-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: testDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: testDir) }

        let conn = ["postgres", "://user:pass@host/db"].joined()
        try "url = \"\(conn)\"".write(toFile: testDir + "/app.py", atomically: true, encoding: .utf8)
        try "DATABASE_URL=existing_value\n".write(toFile: testDir + "/.env", atomically: true, encoding: .utf8)

        let plan = FixPlan(actions: [
            FixAction(filePath: "app.py", line: 1, secretValue: conn,
                      envVarName: "DATABASE_URL",
                      replacement: "os.environ[\"DATABASE_URL\"]",
                      type: .dbConnectionString, severity: .critical)
        ])

        try Remediation.apply(plan: plan, dirPath: testDir, envFilePath: ".env")

        let envContent = try String(contentsOfFile: testDir + "/.env", encoding: .utf8)
        // Should still have existing value, not overwritten
        XCTAssertTrue(envContent.contains("existing_value"))
        // Should NOT contain the new secret (key already exists)
        XCTAssertFalse(envContent.contains(conn))
    }

    // MARK: - Gitignore check

    func testGitignoreContainsEnv() throws {
        let testDir = NSTemporaryDirectory() + "pastewatch-fix-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: testDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: testDir) }

        try ".env\nnode_modules/\n".write(toFile: testDir + "/.gitignore", atomically: true, encoding: .utf8)
        XCTAssertTrue(Remediation.gitignoreContainsEnv(dirPath: testDir))
    }

    func testGitignoreMissingEnv() throws {
        let testDir = NSTemporaryDirectory() + "pastewatch-fix-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: testDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: testDir) }

        try "node_modules/\n".write(toFile: testDir + "/.gitignore", atomically: true, encoding: .utf8)
        XCTAssertFalse(Remediation.gitignoreContainsEnv(dirPath: testDir))
    }
}
