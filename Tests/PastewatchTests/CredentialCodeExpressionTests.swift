import XCTest
@testable import PastewatchCore

// WO-668@v1: focused checks and the golden corpus share the same language and literal controls.
enum CredentialCodeExpressionFixtures {
    // WO-668@v1: fixture names identify controls without exposing their values.
    struct LiteralControl {
        let name: String
        let content: String
        let ext: String

        // WO-668@v1: structured controls exercise the same parsing path as file scans.
        func matches(config: PastewatchConfig) throws -> [DetectedMatch] {
            try DirectoryScanner.scanFileContentOrThrow(
                content: content, ext: ext, relativePath: "fixture." + ext, config: config
            ).filter { $0.type == .credential }
        }
    }

    // WO-668@v1: every supported spelling is assembled without scanner-triggering literal assignments.
    static var rowsByLanguage: [String: [String]] {
        let passwd = "pass" + "wd"
        let password = "pass" + "word"
        let secret = "sec" + "ret"
        return [
            "code-assignment-rust": [
                "let \(passwd) = std::fs::read_to_string(\"/etc/\(passwd)\").unwrap_or_default();",
                "let \(passwd) = readFile(\"config/app.yaml\");",
                "let \(passwd) = arbitrary(\"./app\");",
                "let \(passwd) = arbitrary(\"../app\");",
                "let \(passwd) = arbitrary(\"~/app\");",
                "let \(passwd) = arbitrary(\"C:/config/app.yaml\");",
                "let \(passwd) = arbitrary(\"C:\\\\config\\\\app.yaml\");",
                "let \(passwd) = arbitrary(\"config\\\\app.yaml\");",
                "let \(password) = crate::settings::CREDENTIAL_VALUE;",
                "let \(secret) = retrieve(\n    source,\n);"
            ],
            "code-assignment-go": [
                "var \(passwd) = config.\(password)().String()",
                "\(password) := getenv(\"DATA\")",
                "\(passwd) := getenv(\"DB_PASS\")",
                "\(secret) := readFile(path).String()"
            ],
            "code-assignment-python": [
                "\(passwd) = read_file(path).decode()",
                "\(password) = os.environ.get(\"DATA\")",
                "\(passwd) = os.environ.get(\"DB_PASS\")",
                "\(secret) = self.\(secret)"
            ],
            "code-assignment-js": [
                "const \(passwd) = readFile(path).toString();",
                "let \(password) = config.\(password)();"
            ],
            "code-assignment-ts": [
                "var \(passwd) = config.getPassword().trim();",
                "let \(password): string = getenv(\"DATA\");"
            ],
            "code-assignment-kotlin": [
                "val \(passwd) = config.\(password)().trim()",
                "var \(secret) = config.\(secret)"
            ],
            "code-assignment-swift": [
                "let \(passwd) = settings.\(password)().trimmingCharacters(in: .whitespacesAndNewlines)",
                "var \(secret) = self.\(secret)"
            ]
        ]
    }

    // WO-668@v1: quoted literals and parsed config values retain their original critical severity.
    static var literalControls: [LiteralControl] {
        let password = "pass" + "word"
        let passwd = "pass" + "wd"
        let value = ["Q7mN", "4rZ9", "T2xV", "8bD5"].joined()
        let callableValue = "config." + password + "()"
        return [
            LiteralControl(name: "double-quoted", content: password + "=\"" + value + "\"", ext: "txt"),
            LiteralControl(name: "single-quoted", content: passwd + "='" + value + "'", ext: "txt"),
            LiteralControl(name: "yaml", content: password + ": " + value, ext: "yaml"),
            LiteralControl(name: "env", content: passwd + "=" + value, ext: "env"),
            LiteralControl(name: "quoted-call", content: password + "=\"" + callableValue + "\"", ext: "txt"),
            LiteralControl(name: "yaml-call", content: password + ": " + callableValue, ext: "yaml"),
            LiteralControl(name: "env-call", content: passwd + "=" + callableValue, ext: "env")
        ] + literalCallControls(value: value, key: password)
    }

    // WO-668@v1: quoted first arguments and quoted receivers remain real credential evidence.
    private static func literalCallControls(value: String, key: String) -> [LiteralControl] {
        let quoted = "\"" + value + "\""
        let expressions = [
            ("rust-string-from", "String::from(" + quoted + ")"),
            ("rust-spaced-constructor", "String::from( " + quoted + " )"),
            ("callee-agnostic-literal", "readFile(" + quoted + ")"),
            ("rust-to-string", quoted + ".to_string()"),
            ("rust-to-owned", quoted + ".to_owned()"),
            ("rust-into", quoted + ".into()"),
            ("python-str", "str(" + quoted + ")"),
            ("kotlin-string", "String(" + quoted + ")"),
            ("java-string", "new String(" + quoted + ")"),
            ("go-string", "string(" + quoted + ")"),
            ("secret-new", "Secret::new(" + quoted + ")")
        ]
        return expressions.map { LiteralControl(name: $0.0, content: key + " = " + $0.1, ext: "txt") }
    }

    // WO-668@v1: reference-shaped credential literals are deliberately indistinguishable from references.
    static var documentedFalseNegatives: [LiteralControl] {
        let key = "pass" + "word"
        let value = ["Q7mN", "4rZ9", "T2xV", "8bD5"].joined()
        let path = "/vault/" + value
        let keyName = "DB_" + "PASS"
        return [
            LiteralControl(name: "accepted-path-shaped-literal", content: key + " = Wrapper(\"" + path + "\")", ext: "txt"),
            LiteralControl(name: "accepted-key-shaped-literal", content: key + " = Wrapper(\"" + keyName + "\")", ext: "txt"),
            LiteralControl(name: "accepted-getenv-quoted-default", content: key + " = os.getenv(\"" + keyName + "\", \"" + value + "\")", ext: "txt")
        ]
    }
}

// WO-668@v1: recognition precision cannot weaken literal coverage or mutation authorization.
final class CredentialCodeExpressionTests: XCTestCase {
    // WO-668@v1: the operator accepts these misses instead of adding callee-specific exceptions.
    func testDocumentedFalseNegativesForReferenceShapedLiteralsAndGetenvDefault() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            let config = TestConfigHelper.configWithAmbiguousAdvisories([.credential])
            for control in CredentialCodeExpressionFixtures.documentedFalseNegatives {
                XCTAssertTrue(try control.matches(config: config).isEmpty, control.name)
            }
        }
    }
    // WO-668@v1: pin the overlap between the quoted-argument rule and the founding file-read control.
    func testFoundingFileReadArgumentAlsoPassesValueValidator() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            let argument = "/etc/" + "pass" + "wd"
            XCTAssertTrue(DetectionRules.isValidCredentialValue(argument))
            let binding = "let " + "pass" + "wd = std::fs::read_to_string(\"" + argument + "\").unwrap_or_default();"
            let config = TestConfigHelper.configWithAmbiguousAdvisories([.credential])
            XCTAssertFalse(DetectionRules.scan(binding, config: config).contains { $0.type == .credential })
        }
    }

    // WO-668@v1: source paths and raw scans must agree for every pinned language spelling.
    func testCodeExpressionsAreNotCredentials() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            let config = TestConfigHelper.configWithAmbiguousAdvisories([.credential])
            let extensions = [
                "rust": "rs", "go": "go", "python": "py", "js": "js", "ts": "ts", "kotlin": "kt", "swift": "swift"
            ]
            for (language, ext) in extensions {
                let rows = try XCTUnwrap(CredentialCodeExpressionFixtures.rowsByLanguage["code-assignment-" + language])
                for (index, content) in rows.enumerated() {
                    let raw = DetectionRules.scan(content, config: config).filter { $0.type == .credential }
                    XCTAssertTrue(raw.isEmpty, "\(language) line \(index + 1): Credential count=\(raw.count)")
                    let parsed = try DirectoryScanner.scanFileContentOrThrow(
                        content: content, ext: ext, relativePath: "fixture." + ext, config: config
                    ).filter { $0.type == .credential }
                    XCTAssertTrue(parsed.isEmpty, "\(language) line \(index + 1): Credential count=\(parsed.count)")
                }
            }
        }
    }

    // WO-668@v1: neither quoting nor a call-shaped literal may erase real value evidence.
    func testLiteralControlsKeepCriticalSeverity() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            let config = TestConfigHelper.configWithAmbiguousAdvisories([.credential])
            for control in CredentialCodeExpressionFixtures.literalControls {
                let matches = try control.matches(config: config)
                XCTAssertEqual(matches.count, 1, control.name)
                XCTAssertEqual(matches.first?.effectiveSeverity, .critical, control.name)
            }
        }
    }

    // WO-668@v1: enabling ambiguous recognition alone never authorizes an MCP or proxy mutation.
    func testCredentialRemainsAdvisoryAndIntrinsicCallArgumentStillMutates() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            let config = TestConfigHelper.configWithAmbiguousAdvisories([.credential])
            let control = try XCTUnwrap(CredentialCodeExpressionFixtures.literalControls.first)
            let matches = try control.matches(config: config)
            XCTAssertEqual(matches.count, 1)
            let decision = MCPReadDecision.evaluate(
                matches: matches, content: control.content, config: config, minimumSeverity: .high, filePath: "fixture.txt"
            )
            XCTAssertTrue(decision.authorized.isEmpty)
            XCTAssertEqual(decision.reportedAdvisories.count, 1)
            let outcome = applyAuthorizedMutations(
                to: control.content, matches: matches, site: .proxyUserText, minAdvisorySeverity: .high
            )
            XCTAssertTrue(outcome.text == control.content)
            XCTAssertTrue(outcome.mutated.isEmpty)
            let key = "AKIA" + String(repeating: "Q", count: 16)
            let source = "let " + "pass" + "wd = readFile(\"" + key + "\");"
            let intrinsic = DetectionRules.scan(source, config: .defaultConfig)
            XCTAssertTrue(intrinsic.contains { $0.type == .awsKey })
            let protected = applyAuthorizedMutations(
                to: source, matches: intrinsic, site: .proxyUserText, minAdvisorySeverity: .high
            )
            XCTAssertEqual(protected.mutated.count, 1)
            XCTAssertFalse(protected.text.contains(key))
        }
    }
}
