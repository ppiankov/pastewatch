import XCTest
@testable import PastewatchCore

// WO-587@v3: named fixtures keep exact-range format expectations reviewable.
private struct StructuredAssignmentFixture {
    let path: String
    let content: String
    let expected: String
}

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

    // WO-587@v3: repeated values bind to the assignment containing the exact source range.
    func testSuggestEnvVarUsesSecondRepeatedJSONValueRange() {
        let content = #"{"primary_token":"same","backup_token":"same"}"#
        let first = content.range(of: "same")!
        let second = content.range(of: "same", range: first.upperBound..<content.endIndex)!
        let match = DetectedMatch(
            type: .genericApiKey, value: "same", range: second, line: 1, filePath: "config.json"
        )

        XCTAssertEqual(Remediation.suggestEnvVarName(match: match, fileContent: content), "BACKUP_TOKEN")
    }

    // WO-587@v3: a short substring in a later value cannot bind to the first key.
    func testSuggestEnvVarDoesNotCrossAssociateShortValue() {
        let content = "first = none; second = prefixabcdsuffix"
        let range = content.range(of: "abcd")!
        let match = DetectedMatch(
            type: .genericApiKey, value: "abcd", range: range, line: 1, filePath: "config.env"
        )

        XCTAssertEqual(Remediation.suggestEnvVarName(match: match, fileContent: content), "SECOND")
    }

    // WO-587@v3: URI and quoted assignment-like text remain part of their owning values.
    func testSuggestEnvVarIgnoresAssignmentSyntaxInsideValues() {
        let uriValue = ["postgres://user:", "pass@host/db"].joined()
        let uri = "primary_dsn: \(uriValue)"
        let uriMatch = DetectedMatch(
            type: .dbConnectionString,
            value: uriValue,
            range: uri.range(of: uriValue)!,
            line: 1,
            filePath: "config.yaml"
        )
        XCTAssertEqual(
            Remediation.suggestEnvVarName(match: uriMatch, fileContent: uri),
            "PRIMARY_DSN"
        )

        let quoted = #"description = "token=abcd"; actual_token = abcd"#
        let valueRange = quoted.range(of: "abcd", options: .backwards)!
        let quotedMatch = DetectedMatch(
            type: .genericApiKey,
            value: "abcd",
            range: valueRange,
            line: 1,
            filePath: "config.env"
        )
        XCTAssertEqual(
            Remediation.suggestEnvVarName(match: quotedMatch, fileContent: quoted),
            "ACTUAL_TOKEN"
        )
    }

    // WO-587@v3: assignment ownership works for dotenv quoting and YAML line ranges.
    func testSuggestEnvVarUsesExactDotenvAndYAMLValueRanges() {
        let dotenv = #"serviceToken = "alpha""#
        let dotenvRange = dotenv.range(of: "alpha")!
        let dotenvMatch = DetectedMatch(
            type: .genericApiKey, value: "alpha", range: dotenvRange, line: 1, filePath: ".env"
        )
        XCTAssertEqual(
            Remediation.suggestEnvVarName(match: dotenvMatch, fileContent: dotenv),
            "SERVICE_TOKEN"
        )

        let yaml = "first: alpha\nservice_token: alpha"
        let first = yaml.range(of: "alpha")!
        let second = yaml.range(of: "alpha", range: first.upperBound..<yaml.endIndex)!
        let yamlMatch = DetectedMatch(
            type: .genericApiKey, value: "alpha", range: second, line: 2, filePath: "config.yaml"
        )
        XCTAssertEqual(
            Remediation.suggestEnvVarName(match: yamlMatch, fileContent: yaml),
            "SERVICE_TOKEN"
        )
    }

    // WO-587@v3: stale source ranges fall back rather than guessing from matching text.
    func testSuggestEnvVarFallsBackWhenRangeDoesNotMatchValue() {
        let content = "wrong_key = prefixabcdsuffix"
        let range = content.range(of: "prefix")!
        let match = DetectedMatch(
            type: .genericApiKey, value: "abcd", range: range, line: 1, filePath: "config.env"
        )

        XCTAssertEqual(Remediation.suggestEnvVarName(match: match, fileContent: content), "API_KEY")
    }

    // WO-587@v3: member and keyword assignments retain their local key ownership.
    func testSuggestEnvVarSupportsMemberAndKeywordAssignments() {
        let value = ["postgres://user:", "pass@host/db"].joined()
        let member = #"settings.serviceDsn = "\#(value)""#
        let keyword = #"connect(serviceDsn = "\#(value)")"#

        for content in [member, keyword] {
            let match = DetectedMatch(
                type: .dbConnectionString,
                value: value,
                range: content.range(of: value)!,
                line: 1,
                filePath: "config.py"
            )
            XCTAssertEqual(
                Remediation.suggestEnvVarName(match: match, fileContent: content),
                "SERVICE_DSN"
            )
        }
    }

    // WO-587@v3: trailing code and comments are outside the preceding assignment value.
    func testSuggestEnvVarDoesNotAssociateTrailingCodeOrComment() {
        let fixtures = [
            #"label = "safe"; print("abcd")"#,
            "label = safe # abcd"
        ]

        for content in fixtures {
            let range = content.range(of: "abcd")!
            let match = DetectedMatch(
                type: .genericApiKey,
                value: "abcd",
                range: range,
                line: 1,
                filePath: "config.py"
            )

            XCTAssertEqual(
                Remediation.suggestEnvVarName(match: match, fileContent: content),
                "API_KEY"
            )
        }
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

    // WO-587@v3: applying a plan mutates only the detected repeated occurrence.
    func testApplyBuiltPlanReplacesOnlyAuthorizedRepeatedValue() throws {
        let testDir = NSTemporaryDirectory() + "pastewatch-fix-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: testDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: testDir) }

        let content = #"primary_token = "same"; backup_token = "same""#
        let first = content.range(of: "same")!
        let second = content.range(of: "same", range: first.upperBound..<content.endIndex)!
        let match = DetectedMatch(
            type: .genericApiKey,
            value: "same",
            range: second,
            line: 1,
            filePath: "config.py"
        )
        let plan = Remediation.buildPlan(
            results: [FileScanResult(
                filePath: "config.py",
                matches: [match],
                content: content
            )],
            minSeverity: .low
        )
        try content.write(
            toFile: testDir + "/config.py",
            atomically: true,
            encoding: .utf8
        )

        try Remediation.patchFiles(plan: plan, dirPath: testDir)

        let patched = try String(contentsOfFile: testDir + "/config.py", encoding: .utf8)
        XCTAssertTrue(patched.contains(#"primary_token = "same""#), patched)
        XCTAssertTrue(patched.contains(#"backup_token = os.environ["BACKUP_TOKEN"]"#), patched)
    }

    // WO-587@v3: exact built-plan ranges preserve dotenv, JSON, and YAML neighbors.
    func testApplyBuiltPlanAcrossStructuredAssignmentFormats() throws {
        let testDir = NSTemporaryDirectory() + "pastewatch-fix-formats-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: testDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: testDir) }

        let fixtures = [
            StructuredAssignmentFixture(
                path: ".env",
                content: "SAFE=keep\nservice_token=\"abcd\"\n",
                expected: "SAFE=keep\nservice_token=\n"
            ),
            StructuredAssignmentFixture(
                path: "config.json",
                content: #"{"safe":"keep","service_token":"abcd"}"#,
                expected: #"{"safe":"keep","service_token":${SERVICE_TOKEN_2}}"#
            ),
            StructuredAssignmentFixture(
                path: "config.yaml",
                content: "safe: keep\nservice_token: abcd\n",
                expected: "safe: keep\nservice_token: ${SERVICE_TOKEN_3}\n"
            )
        ]
        var results: [FileScanResult] = []
        for fixture in fixtures {
            try fixture.content.write(
                toFile: testDir + "/" + fixture.path,
                atomically: true,
                encoding: .utf8
            )
            let range = fixture.content.range(of: "abcd")!
            results.append(FileScanResult(
                filePath: fixture.path,
                matches: [DetectedMatch(
                    type: .genericApiKey,
                    value: "abcd",
                    range: range,
                    line: fixture.path == ".env" ? 2 : 1,
                    filePath: fixture.path
                )],
                content: fixture.content
            ))
        }

        let plan = Remediation.buildPlan(results: results, minSeverity: .low)
        try Remediation.patchFiles(plan: plan, dirPath: testDir)

        for fixture in fixtures {
            XCTAssertEqual(
                try String(contentsOfFile: testDir + "/" + fixture.path, encoding: .utf8),
                fixture.expected
            )
        }
    }

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
