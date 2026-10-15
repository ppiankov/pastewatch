import XCTest
@testable import PastewatchCore

// WO-688@v1: shared runtime fixtures measure keyed expressions without embedding credential assignments.
private enum KeyedCredentialCallFixtures {
    // WO-688@v1: fixture labels identify regressions without exposing the scanned text.
    struct Row {
        let name: String
        let content: String
        let ext: String

        // WO-688@v1: file scans and raw detection must agree on the same keyed expression.
        func matches(config: PastewatchConfig) throws -> [DetectedMatch] {
            try DirectoryScanner.scanFileContentOrThrow(
                content: content, ext: ext, relativePath: "fixture." + ext, config: config
            ).filter { $0.type == .credential }
        }
    }

    // WO-688@v1: assemble sensitive field names independently of their source syntax.
    static var auth: String { "Au" + "th" }
    static var password: String { "pass" + "word" }
    static var literal: String { ["Q7mN", "4rZ9", "T2xV", "8bD5"].joined() }

    // WO-688@v1: keyed calls and paths remain code across object literals and named arguments.
    static var negatives: [Row] {
        [
            Row(name: "go-receiver-call", content:
                    "cfg := pkg.Config{Endpoint: endpoint, " + auth + ": p.resolvedXCredential()}", ext: "go"),
            Row(name: "go-direct-call", content: "Config{" + auth + ": resolveCredential()}", ext: "go"),
            Row(name: "go-selector", content: "Config{" + auth + ": p.cfg.Credential}", ext: "go"),
            Row(name: "go-environment-key", content:
                    "Config{" + password + ": os.Getenv(\"ALL_CAPS_NAME\")}", ext: "go"),
            Row(name: "js-property", content: "const cfg = {" + auth.lowercased() + ": resolveCredential()};", ext: "js"),
            Row(name: "ts-property", content: "const cfg: Config = {" + auth + ": p.resolveCredential()};", ext: "ts"),
            Row(name: "python-keyword", content: "configure(" + password + "=resolveCredential())", ext: "py"),
            Row(name: "swift-named-argument", content: "Config(" + password + ": p.resolveCredential())", ext: "swift"),
            Row(name: "kotlin-named-argument", content: "Config(" + password + "=resolveCredential())", ext: "kt"),
            Row(name: "go-multiline-comma", content:
                    "cfg := pkg.Config{\n" + auth + ": p.resolvedXCredential(),\n}", ext: "go"),
            Row(name: "js-multiline-comma", content:
                    "const cfg = {\n" + auth.lowercased() + ": resolveCredential(),\n};", ext: "js"),
            Row(name: "go-nested-call", content:
                    "Config{" + auth + ": resolveCredential(2024, nested(7))}", ext: "go"),
            Row(name: "go-spaced-call", content: "Config{" + auth + ": resolveCredential (2024)}", ext: "go"),
            Row(name: "swift-selector-close", content: "Config(" + auth + ": self.cfg.value)", ext: "swift"),
            Row(name: "swift-selector-comma", content: "Config(" + auth + ": self.cfg.value, other: x)", ext: "swift")
        ]
    }

    // WO-688@v1: literal evidence has identical severity in direct and constructor-wrapped keyed values.
    static var positives: [Row] {
        let quoted = "\"" + literal + "\""
        return [
            Row(name: "go-literal", content: "Config{" + auth + ": " + quoted + "}", ext: "go"),
            Row(name: "go-constructor", content: "Config{" + auth + ": Wrapper(" + quoted + ")}", ext: "go"),
            Row(name: "js-literal", content: "const cfg = {" + auth + ": " + quoted + "};", ext: "js"),
            Row(name: "js-constructor", content: "const cfg = {" + auth + ": Wrapper(" + quoted + ")};", ext: "js"),
            Row(name: "python-literal", content: "configure(" + password + "=" + quoted + ")", ext: "py"),
            Row(name: "python-constructor", content: "configure(" + password + "=Wrapper(" + quoted + "))", ext: "py")
        ]
    }

    // WO-688@v1: config controls retain the pre-existing raw-detection gaps tracked separately.
    static var configValues: [String] { ["Sum" + "mer.Breeze" + "2024", "Sec" + "ret(" + "2024)"] }

    // WO-688@v1: the same unquoted values exercise raw detection and every requested config fixture path.
    static var configPositives: [Row] {
        ["yaml", "yml", "properties", "toml", "env"].flatMap { ext in
            configValues.enumerated().map { index, value in
                Row(name: ext + "-end-of-line-\(index)", content: password + ": " + value, ext: ext)
            }
        }
    }
}

// WO-688@v1: precision tests retain literal recognition and the existing advisory-only policy.
final class KeyedCredentialCallTests: XCTestCase {
    // WO-688@v1: enclosing object punctuation cannot turn an unquoted source expression into a value.
    func testKeyedCallsAndPathsDoNotProduceCredentialFindings() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            let config = TestConfigHelper.configWithAmbiguousAdvisories([.credential])
            for row in KeyedCredentialCallFixtures.negatives {
                let raw = DetectionRules.scan(row.content, config: config).filter { $0.type == .credential }
                XCTAssertEqual(raw.count, 0, row.name + ": raw Credential count")
                XCTAssertEqual(try row.matches(config: config).count, 0, row.name + ": file Credential count")
            }
        }
    }

    // WO-688@v1: keyed calls reuse WO-668's first-argument reference shapes without a callee vocabulary.
    func testFirstQuotedReferenceArgumentsUseExistingShapeRule() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            let config = TestConfigHelper.configWithAmbiguousAdvisories([.credential])
            let references = ["/etc/app.conf", "./app", "../app", "~/app", "config/app.yaml", "C:/app.conf", "ALL_CAPS_NAME"]
            for (index, reference) in references.enumerated() {
                let row = KeyedCredentialCallFixtures.Row(
                    name: "reference-\(index)",
                    content: "Config{" + KeyedCredentialCallFixtures.auth + ": resolve(\"" + reference + "\")}", ext: "go"
                )
                XCTAssertEqual(try row.matches(config: config).count, 0, row.name + ": Credential count")
            }
        }
    }

    // WO-688@v1: constructor arguments stay on the unchanged credential-value validation path.
    func testQuotedLiteralAndConstructorControlsKeepCriticalSeverity() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            let config = TestConfigHelper.configWithAmbiguousAdvisories([.credential])
            XCTAssertTrue(DetectionRules.isValidCredentialValue(KeyedCredentialCallFixtures.literal))
            for row in KeyedCredentialCallFixtures.positives {
                let matches = try row.matches(config: config)
                XCTAssertEqual(matches.count, 1, row.name + ": Credential count")
                XCTAssertEqual(matches.first?.effectiveSeverity, .critical, row.name)
            }
        }
    }

    // WO-688@v1: quoting code-shaped text retains the same value validator instead of applying code exclusions.
    func testQuotedCodeShapedValuesKeepExistingValidation() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            let config = TestConfigHelper.configWithAmbiguousAdvisories([.credential])
            for value in ["p.resolveCredential()", "p.cfg.Credential"] {
                let row = KeyedCredentialCallFixtures.Row(
                    name: "quoted-expression", content: "Config{" + KeyedCredentialCallFixtures.auth + ": \"" + value + "\"}",
                    ext: "go"
                )
                XCTAssertEqual(try row.matches(config: config).count, 1, "Quoted Credential count")
            }
        }
    }

    // WO-688@v1: enabling recognition alone cannot authorize mutation of a keyed credential value.
    func testKeyedCredentialFindingsRemainAdvisory() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            let config = TestConfigHelper.configWithAmbiguousAdvisories([.credential])
            let row = try XCTUnwrap(KeyedCredentialCallFixtures.positives.first)
            let matches = try row.matches(config: config)
            let decision = MCPReadDecision.evaluate(
                matches: matches, content: row.content, config: config, minimumSeverity: .high, filePath: "fixture.go"
            )
            XCTAssertEqual(matches.count, 1)
            XCTAssertTrue(decision.authorized.isEmpty)
            XCTAssertEqual(decision.reportedAdvisories.count, 1)
            let outcome = applyAuthorizedMutations(
                to: row.content, matches: matches, site: .proxyUserText, minAdvisorySeverity: .high
            )
            XCTAssertTrue(outcome.mutated.isEmpty)
            XCTAssertTrue(outcome.text == row.content)
        }
    }

    // WO-688@v1: pre-existing config false negatives are tracked separately, not fixed by source precision.
    func testPreExistingConfigFalseNegativesRemainTrackedSeparately() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            let config = TestConfigHelper.configWithAmbiguousAdvisories([.credential])
            for row in KeyedCredentialCallFixtures.configPositives {
                let raw = DetectionRules.scan(row.content, config: config).filter { $0.type == .credential }
                let parsed = try row.matches(config: config)
                XCTAssertEqual(raw.count, 0, row.name + ": pre-existing raw false negative")
                let expected = ["yaml", "yml", "properties"].contains(row.ext) ? 1 : 0
                XCTAssertEqual(parsed.count, expected, row.name + ": baseline file Credential count")
                if expected == 1 {
                    XCTAssertEqual(parsed.first?.effectiveSeverity, .critical, row.name + ": file severity")
                }
            }
        }
    }

    // WO-688@v1: undelimited colon expressions retain WO-390's pre-existing reference exclusions.
    func testColonExpressionsWithoutSameLineDelimiterPreserveBaseline() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            let config = TestConfigHelper.configWithAmbiguousAdvisories([.credential])
            let expressions = [
                "resolveCredential()", "resolveCredential() // note", "resolveCredential() # note",
                "resolveCredential() /* note */", "resolveCredential(\n2024)}",
                "p.cfg.Credential", "p.cfg.Credential // note", "resolveCredential( // )}",
                "resolveCredential()\n}", "p.cfg.Credential\n}"
            ]
            for (index, expression) in expressions.enumerated() {
                let source = KeyedCredentialCallFixtures.auth + ": " + expression
                let matches = DetectionRules.scan(source, config: config).filter { $0.type == .credential }
                let expected = [4, 7].contains(index) ? 1 : 0
                XCTAssertEqual(matches.count, expected, "Boundary case \(index): baseline Credential count")
                if expected == 1 {
                    XCTAssertEqual(matches.first?.effectiveSeverity, .critical, "Boundary case \(index): severity")
                }
            }
        }
    }

    // WO-688@v1: raw flow-style YAML shares source delimiters; parsed key-aware detection remains stricter.
    func testAcceptedRawFlowStyleYAMLCallExclusion() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            let config = TestConfigHelper.configWithAmbiguousAdvisories([.credential])
            let row = KeyedCredentialCallFixtures.Row(
                name: "accepted-flow-yaml", content: "{" + KeyedCredentialCallFixtures.password + ": "
                    + KeyedCredentialCallFixtures.configValues[1] + "}", ext: "yaml"
            )
            XCTAssertEqual(DetectionRules.scan(row.content, config: config).filter { $0.type == .credential }.count, 0)
            XCTAssertEqual(try row.matches(config: config).count, 1)
        }
    }

    // WO-688@v1: a comma-free final JS property keeps its pre-existing WO-390 reference exclusion.
    func testLastJavaScriptPropertyPreservesWO390Exclusion() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            let config = TestConfigHelper.configWithAmbiguousAdvisories([.credential])
            let row = KeyedCredentialCallFixtures.Row(
                name: "accepted-js-last-property", content: "const cfg = {\n" + KeyedCredentialCallFixtures.auth
                    + ": resolveCredential()\n};", ext: "js"
            )
            let matches = try row.matches(config: config)
            XCTAssertEqual(DetectionRules.scan(row.content, config: config).filter { $0.type == .credential }.count, 0)
            XCTAssertEqual(matches.count, 0)
            let decision = MCPReadDecision.evaluate(
                matches: matches, content: row.content, config: config, minimumSeverity: .high, filePath: "fixture.js"
            )
            XCTAssertTrue(decision.authorized.isEmpty)
            XCTAssertEqual(decision.reportedAdvisories.count, 0)
        }
    }

    // WO-688@v1: Swift named-selector arguments accept closing parentheses and commas without assignment changes.
    func testSwiftNamedSelectorsAcceptClosingDelimiters() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            let config = TestConfigHelper.configWithAmbiguousAdvisories([.credential])
            let rows = KeyedCredentialCallFixtures.negatives.filter { $0.name.hasPrefix("swift-selector-") }
            XCTAssertEqual(rows.count, 2)
            for row in rows {
                let raw = DetectionRules.scan(row.content, config: config).filter { $0.type == .credential }
                XCTAssertEqual(raw.count, 0, row.name + ": raw Credential count")
                XCTAssertEqual(try row.matches(config: config).count, 0, row.name + ": file Credential count")
            }
        }
    }

    // WO-688@v1: a comma-free final Swift selector retains the pre-existing WO-390 reference exclusion.
    func testMultilineSwiftSelectorPreservesWO390Exclusion() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            let config = TestConfigHelper.configWithAmbiguousAdvisories([.credential])
            let row = KeyedCredentialCallFixtures.Row(
                name: "accepted-swift-last-selector", content: "Config(\n" + KeyedCredentialCallFixtures.auth
                    + ": self.cfg.value\n)", ext: "swift"
            )
            let raw = DetectionRules.scan(row.content, config: config).filter { $0.type == .credential }
            let matches = try row.matches(config: config)
            XCTAssertEqual(raw.count, 0)
            XCTAssertEqual(matches.count, 0)
            let decision = MCPReadDecision.evaluate(
                matches: matches, content: row.content, config: config, minimumSeverity: .high, filePath: "fixture.swift"
            )
            XCTAssertTrue(decision.authorized.isEmpty)
            XCTAssertEqual(decision.reportedAdvisories.count, 0)
        }
    }

    // WO-688@v1: count keyed regressions separately while the existing golden corpus remains unchanged.
    func testKeyedCorpusCounts() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            let config = TestConfigHelper.configWithAmbiguousAdvisories([.credential])
            let falsePositives = KeyedCredentialCallFixtures.negatives.reduce(0) { count, row in
                count + DetectionRules.scan(row.content, config: config).filter { $0.type == .credential }.count
            }
            // WO-688@v1: config controls count a miss on either the raw or parsed surface as a false negative.
            let controls = KeyedCredentialCallFixtures.positives + KeyedCredentialCallFixtures.configPositives
            let falseNegatives = try controls.filter { row in
                let raw = DetectionRules.scan(row.content, config: config).filter { $0.type == .credential }
                let parsed = try row.matches(config: config)
                return raw.isEmpty || parsed.isEmpty
            }.count
            print("WO-688 keyed corpus FP=\(falsePositives) FN=\(falseNegatives)")
            XCTAssertEqual(falsePositives, 0, "Keyed Credential false-positive count")
            XCTAssertEqual(falseNegatives, KeyedCredentialCallFixtures.configPositives.count,
                           "Pre-existing config false negatives remain tracked separately")
        }
    }
}
