// WO-691@v3: display-read parity exercises the same native read entrypoint as guard-read.
import ArgumentParser
import XCTest
@testable import PastewatchCore
@testable import PastewatchCLI

final class GuardCommandTests: XCTestCase {
    // WO-712@v3: a refusal of a compound command cannot imply that earlier steps executed.
    func testCompoundRefusalStatesThatNoPartRan() throws {
        let executableURL = pastewatchCLIURL()
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            let value = try writeRefusalFixture(filename: "flagged.go")
            try Data("package fixture\nconst IDENT = true\n".utf8)
                .write(to: URL(fileURLWithPath: testDir + "/clean.go"))
            let result = try runGuardCLI(
                arguments: ["guard", "cp clean.go copy.go && grep -n IDENT *.go"],
                executableURL: executableURL
            )
            assertWholeCommandRefusal(result, excluding: value)
            XCTAssertTrue(result.stderr.contains("contains 1 secret(s)"))
            XCTAssertFalse(FileManager.default.fileExists(atPath: testDir + "/copy.go"))
        }
    }

    // WO-712@v3: a single reader retains its original finding and exit status after the notice.
    func testSingleReaderRefusalStatesThatNoPartRan() throws {
        let executableURL = pastewatchCLIURL()
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            let value = try writeRefusalFixture(filename: "flagged.txt")
            let result = try runGuardCLI(arguments: ["guard", "cat flagged.txt"], executableURL: executableURL)
            assertWholeCommandRefusal(result, excluding: value)
            XCTAssertTrue(result.stderr.contains("contains 1 secret(s)"))
            XCTAssertTrue(result.stderr.contains("Use pastewatch_read_file / pastewatch_edit_file"))
        }
    }

    // WO-712@v3: inline refusals carry execution context without echoing their matched values.
    func testInlineRefusalStatesThatNoPartRan() throws {
        let executableURL = pastewatchCLIURL()
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            let value = ["AKIA", String(repeating: "Q", count: 16)].joined()
            let result = try runGuardCLI(
                arguments: ["guard", "printf '%s' '" + value + "'"], executableURL: executableURL
            )
            assertWholeCommandRefusal(result, excluding: value)
            XCTAssertTrue(result.stderr.contains("command contains inline secret(s)"))
        }
    }

    // WO-712@v3: refusals without findings use the same first line without replacing their remedies.
    func testOtherGuardRefusalsStateThatNoPartRan() throws {
        let executableURL = pastewatchCLIURL()
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            try Data([0xFF, 0x61]).write(to: URL(fileURLWithPath: testDir + "/binary.dat"))
            try FileManager.default.createDirectory(atPath: testDir + "/folder", withIntermediateDirectories: true)
            let cases = [
                ("cat binary.dat", "cannot be scanned safely"),
                ("cat folder", "is a directory"),
                ("pastewatch-cli allow-binary binary.dat", "Operator-only binary transfer grant"),
                ("pastewatch-cli read \"$F\"", "requires a literal path")
            ]
            for (command, message) in cases {
                let result = try runGuardCLI(arguments: ["guard", command], executableURL: executableURL)
                assertWholeCommandRefusal(result)
                XCTAssertTrue(result.stderr.contains(message))
            }
            try Data("ordinary text".utf8).write(to: URL(fileURLWithPath: testDir + "/bounded.txt"))
            let bounded = try runGuardCLI(
                arguments: ["guard", "cat bounded.txt"],
                environmentOverrides: [ScanInputLimits.fileBytesEnvironmentKey: "5"], executableURL: executableURL
            )
            assertWholeCommandRefusal(bounded)
            XCTAssertTrue(bounded.stderr.contains("exceeds scan limit 5 bytes"))
        }
    }

    // WO-712@v3: unsupported-source diagnostics cannot precede a later refusal of the command.
    func testWholeCommandRefusalPrecedesUnsupportedSourceDiagnostic() throws {
        let executableURL = pastewatchCLIURL()
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            let value = ["AKIA", String(repeating: "Q", count: 16)].joined()
            let result = try runGuardCLI(
                arguments: ["guard", "cp -t; printf '%s' '" + value + "'"], executableURL: executableURL
            )
            assertWholeCommandRefusal(result, excluding: value)
            XCTAssertEqual(result.stderr.components(separatedBy: "Unsupported source scanning for: cp.").count - 1, 1)
        }
    }

    // WO-712@v3: the extra human-facing line leaves quiet and machine-readable refusal output unchanged.
    func testWholeCommandRefusalKeepsQuietAndJSONOutput() throws {
        let executableURL = pastewatchCLIURL()
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            let value = try writeRefusalFixture(filename: "flagged.txt")
            for command in ["cat flagged.txt", "printf '%s' '" + value + "'"] {
                let quiet = try runGuardCLI(arguments: ["guard", "--quiet", command], executableURL: executableURL)
                XCTAssertEqual(quiet.status, 2)
                XCTAssertTrue(quiet.stdout.isEmpty)
                XCTAssertTrue(quiet.stderr.isEmpty)
                let json = try runGuardCLI(arguments: ["guard", "--json", command], executableURL: executableURL)
                XCTAssertEqual(json.status, 2)
                XCTAssertTrue(json.stderr.isEmpty)
                XCTAssertFalse(json.stdout.contains(value))
                let payload = try guardJSON(from: json.stdout)
                XCTAssertEqual(Set(payload.keys), ["blocked", "command", "files", "inlineFindings"])
                XCTAssertEqual(payload["blocked"] as? Bool, true)
            }
        }
    }

    // WO-712@v3: the shared validation printer remains outside command-refusal presentation.
    func testConfigurationValidationKeepsItsExistingOutput() throws {
        let executableURL = pastewatchCLIURL()
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            let data = try JSONEncoder().encode(PastewatchConfig.defaultConfig)
            var payload = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
            payload["enabled"] = "invalid type"
            try JSONSerialization.data(withJSONObject: payload)
                .write(to: URL(fileURLWithPath: testDir + "/.pastewatch.json"))
            for flags in [[], ["--quiet"], ["--json"]] {
                let result = try runGuardCLI(
                    arguments: ["guard"] + flags + ["echo ordinary"], executableURL: executableURL
                )
                XCTAssertEqual(result.status, 2)
                XCTAssertTrue(result.stdout.isEmpty)
                XCTAssertTrue(result.stderr.hasPrefix("error: "))
                XCTAssertFalse(result.stderr.contains("whole command refused"))
            }
        }
    }

    // WO-712@v3: runtime fixtures exercise intrinsic blocking without putting complete values in source.
    private func writeRefusalFixture(filename: String) throws -> String {
        let value = ["AKIA", String(repeating: "Q", count: 16)].joined()
        try Data(("key=" + value + "\n").utf8).write(to: URL(fileURLWithPath: testDir + "/" + filename))
        return value
    }

    // WO-712@v3: assertions expose only decision metadata even when captured output is wrong.
    private func assertWholeCommandRefusal(
        _ result: CLIResult, excluding value: String? = nil, file: StaticString = #filePath, line: UInt = #line
    ) {
        XCTAssertEqual(result.status, 2, file: file, line: line)
        XCTAssertTrue(result.stdout.isEmpty, file: file, line: line)
        XCTAssertTrue(result.stderr.split(separator: "\n").first ==
                      "BLOCKED: whole command refused; no part of it ran.", file: file, line: line)
        if let value {
            XCTAssertFalse(result.stdout.contains(value), file: file, line: line)
            XCTAssertFalse(result.stderr.contains(value), file: file, line: line)
        }
    }

    // WO-691@v3: fixture labels and expected types keep parity diagnostics free of matched values.
    private struct ReadVerdictFixture {
        let name: String
        let filename: String
        let content: String
        let config: PastewatchConfig
        let type: SensitiveDataType?
    }

    // WO-691@v3: output-capable filters and preprocessors retain the strict command-read decision.
    func testWritingFiltersAndRipgrepPreprocessorsKeepStrictVerdicts() throws {
        let executableURL = pastewatchCLIURL()
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let content = ["pass", "word=", "Z9aB8cD7", "eF6gH5iJ"].joined()
            let config = TestConfigHelper.configWithAmbiguousAdvisories([.credential])
            try writeConfig(config)
            try JSONEncoder().encode(config).write(to: root.appendingPathComponent(".pastewatch.json"))
            try Data(content.utf8).write(to: URL(fileURLWithPath: testDir + "/filter-input.txt"))
            let commands = [
                "cat filter-input.txt | sort -o out",
                "cat filter-input.txt | uniq - out",
                "cat filter-input.txt | less -o out",
                "cat filter-input.txt | rg --pre cat x"
            ]
            for (index, command) in commands.enumerated() {
                let result = try runGuardCLI(arguments: ["guard", "--quiet", command], executableURL: executableURL)
                XCTAssertEqual(result.status, 2, "Strict pipeline case \(index)")
                XCTAssertFalse(result.stdout.contains(content), "Strict pipeline stdout case \(index)")
                XCTAssertFalse(result.stderr.contains(content), "Strict pipeline stderr case \(index)")
            }
        }
    }

    // WO-691@v3: classification excludes pagers and every ripgrep preprocessing-prefix token.
    func testPagersWritingFiltersAndRipgrepPreTokensAreNotDisplay() {
        let commands = [
            "cat f | sort -o out", "cat f | uniq - out", "cat f | less -o out", "cat f | more",
            "less f", "more f", "cat f | rg --pre cat x", "cat f | rg --pre-glob '*.txt' x",
            "rg --pre cat x f", "rg --pre-glob '*.txt' x f", "/usr/bin/rg --pre=cat x f",
            "rg --pretty x f", "rg -- --pre x f"
        ]
        for (index, command) in commands.enumerated() {
            let access = CommandParser.fileAccess(from: command, workingDirectory: testDir)
            XCTAssertFalse(access.reads.isEmpty, "Strict parser case \(index) has read operands")
            XCTAssertTrue(access.reads.allSatisfy { !$0.displaysToModel }, "Strict parser case \(index)")
        }
    }

    // WO-691@v3: a closed display pipeline adopts native Read without changing transfers or inline text.
    func testRawReaderParityKeepsTransferAndInlineVerdicts() throws {
        let executableURL = pastewatchCLIURL()
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let advisory = ["pass", "word=", "Z9aB8cD7eF6gH5iJ"].joined()
            let intrinsic = ["AWS_KEY=", "AKIA", "QWERTYUIOPASDFGH"].joined()
            let config = TestConfigHelper.configWithAmbiguousAdvisories([.credential])
            var documentationConfig = config
            documentationConfig.documentationPolicy = .enforce
            let fixtures = [
                ReadVerdictFixture(name: "clean", filename: "clean.txt", content: "ordinary prose", config: config, type: nil),
                ReadVerdictFixture(name: "advisory-only", filename: "advisory.txt", content: advisory,
                                   config: config, type: .credential),
                ReadVerdictFixture(name: "intrinsic", filename: "intrinsic.txt", content: intrinsic,
                                   config: config, type: .awsKey),
                ReadVerdictFixture(name: "documentation-policy", filename: "guide.md", content: advisory,
                                   config: documentationConfig, type: .credential)
            ]
            for fixture in fixtures {
                try writeConfig(fixture.config)
                try JSONEncoder().encode(fixture.config).write(to: root.appendingPathComponent(".pastewatch.json"))
                let path = testDir + "/" + fixture.filename
                try Data(fixture.content.utf8).write(to: URL(fileURLWithPath: path))
                let matches = try DirectoryScanner.scanFileContentOrThrow(
                    content: fixture.content, ext: (path as NSString).pathExtension,
                    relativePath: path, config: fixture.config
                )
                if let type = fixture.type {
                    XCTAssertEqual(matches.filter { $0.type == type }.count, 1, fixture.name + ": fixture type count")
                } else {
                    XCTAssertTrue(matches.isEmpty, fixture.name + ": fixture must be clean")
                }
                let file = fixture.filename
                let commands: [(name: String, text: String)] = [
                    ("cat", "cat " + file), ("grep", "grep x " + file),
                    ("redirect", "cat " + file + " > destination.txt"), ("ssh", "cat " + file + " | ssh h"),
                    ("cp", "cp " + file + " destination.txt"), ("mv", "mv " + file + " destination.txt"),
                    // WO-691@v3: a file-writing filter is a strict read for every parity fixture class.
                    ("sort-output", "cat " + file + " | sort -o destination.txt"),
                    ("inline", "printf '%s\\n' '" + fixture.content + "'")
                ]
                let results = try commands.map {
                    try runGuardCLI(arguments: ["guard", "--quiet", $0.text], executableURL: executableURL)
                }
                let expectedRead: Int32 = fixture.type == .awsKey ? GuardExitContract.blocked : 0
                let expectedOther: Int32 = fixture.type == nil ? 0 : GuardExitContract.blocked
                var nativeRead: Int32 = 0
                do {
                    try FileGuard.check(filePath: path, failOnSeverity: .high, operation: .read)
                } catch let code as ExitCode {
                    nativeRead = code.rawValue
                }
                let cells = zip(commands, results).map { "\($0.0.name)=\($0.1.status)" }.joined(separator: " ")
                print("WO691_MATRIX \(fixture.name) \(cells)")
                for (command, result) in zip(commands, results) {
                    let display = ["cat", "grep"].contains(command.name)
                    XCTAssertEqual(result.status, display ? expectedRead : expectedOther,
                                   fixture.name + ": " + command.name + " exit")
                    if display {
                        XCTAssertEqual(result.status, nativeRead, fixture.name + ": display/native parity")
                    }
                    XCTAssertFalse(result.stdout.contains(fixture.content), fixture.name + ": stdout value absent")
                    XCTAssertFalse(result.stderr.contains(fixture.content), fixture.name + ": stderr value absent")
                }
                for command in ["head " + file, "cat " + file + " | grep x | head"] {
                    XCTAssertEqual(try runGuardCLI(arguments: ["guard", "--quiet", command],
                                                  executableURL: executableURL).status, expectedRead,
                                   fixture.name + ": display pipeline exit")
                }
                for command in ["cat " + file + " | tee destination.txt", "cat " + file + " | base64",
                                "sed -n 1p " + file, "tr a b < " + file] {
                    XCTAssertEqual(try runGuardCLI(arguments: ["guard", "--quiet", command],
                                                  executableURL: executableURL).status, expectedOther,
                                   fixture.name + ": non-display exit")
                }
            }
        }
    }

    // WO-691@v3: only closed display pipelines qualify, independently for each command-chain segment.
    func testDisplayReadClassificationKeepsGrantRolesIndependent() {
        let cases: [(command: String, expected: [Bool])] = [
            ("cat f", [true]), ("grep x f", [true]), ("head f", [true]),
            ("cat f | grep x | head", [true]), ("cat f > out", [false]),
            ("cat f >> out", [false]), ("cat f | tee out", [false]),
            ("cat f | ssh h", [false]), ("cat f | base64", [false]),
            ("sed -n 1p f", [false]), ("tr a b < f", [false]),
            ("mv f d/", [false]), ("cp f d/", [false]),
            ("cat f && cat g > out", [true, false]),
            ("cat f || cat g > out", [true, false]),
            ("cat f; cat g > out", [true, false]),
            ("cat f | grep x | head > out", [false]),
            ("echo $(cat f)", [false]), ("echo `cat f`", [false]),
            ("cat 'f", [false]), ("cat f |", [false]),
            ("env cat f", [])
        ]
        for (index, fixture) in cases.enumerated() {
            let access = CommandParser.fileAccess(from: fixture.command, workingDirectory: testDir)
            XCTAssertEqual(access.reads.map(\.displaysToModel), fixture.expected, "Display parser case \(index)")
        }
        let transfer = CommandParser.fileAccess(from: "cp f d/", workingDirectory: testDir)
        XCTAssertEqual(transfer.reads.count, 1)
        XCTAssertTrue(transfer.reads.first?.role == .transferSource)
        let move = CommandParser.fileAccess(from: "mv f d/", workingDirectory: testDir)
        XCTAssertEqual(move.reads.count, 1)
        XCTAssertTrue(move.reads.first?.role == .rawReader)
        XCTAssertFalse(CommandParser.FileRead(path: "f", role: .rawReader).displaysToModel)
    }

    // WO-658@v2: redefining a sanctioned executable name cannot bypass a protected-file read.
    func testRedactedRemedyFunctionAndAliasShadowingBlock() throws {
        let secret = ["AKIA", String(repeating: "Q", count: 16)].joined()
        try Data(("key=" + secret + "\n").utf8).write(to: URL(fileURLWithPath: testDir + "/remedy.env"))
        for definition in ["pastewatch-cli() { cat \"$2\"; }", "function pastewatch-cli { cat \"$2\"; }",
                           "alias pastewatch-cli='cat'"] {
            let chain = definition + "; pastewatch-cli read remedy.env"
            for command in [chain, "(" + chain + ")", "echo \"$(" + chain + ")\""] {
                let result = try runGuardCLI(arguments: ["guard", command])
                XCTAssertEqual(result.status, 2)
                XCTAssertFalse(result.stdout.contains(secret))
                XCTAssertFalse(result.stderr.contains(secret))
                XCTAssertFalse(result.stderr.contains(command))
            }
        }
        XCTAssertEqual(try runGuardCLI(arguments: ["guard", "pastewatch-cli read remedy.env", "--quiet"]).status, 0)
    }

    // WO-658@v2: sanctioned literal remedies are allowed, but subsequent raw readers remain guarded.
    func testRedactedRemediesAllowOnlyTheirOwnSegments() throws {
        let secret = ["AKIA", String(repeating: "Q", count: 16)].joined()
        let path = testDir + "/remedy.env"
        try Data(("key=" + secret + "\n").utf8).write(to: URL(fileURLWithPath: path))
        for command in ["pastewatch-cli read remedy.env", "pastewatch-cli read remedy.env > out.txt",
                        "pastewatch-cli edit remedy.env --old before --new after --expect-view-token " + String(repeating: "0", count: 64)] {
            XCTAssertEqual(try runGuardCLI(arguments: ["guard", command, "--quiet"]).status, 0)
        }
        for command in ["pastewatch-cli read remedy.env; cat remedy.env", "pastewatch-cli read remedy.env | cat remedy.env"] {
            XCTAssertEqual(try runGuardCLI(arguments: ["guard", command, "--quiet"]).status, 2)
        }
    }

    // WO-658@v2: unresolved path expansions cannot acquire the sanctioned-tool exemption.
    func testRedactedRemedyExpansionsAreNotExempt() throws {
        for command in ["pastewatch-cli read \"$F\"", "pastewatch-cli read $(printf file)",
                        "pastewatch-cli read *.env", "pastewatch-cli edit ~/file.env --old before --new after"] {
            let result = try runGuardCLI(arguments: ["guard", command])
            XCTAssertEqual(result.status, 2)
            XCTAssertTrue(result.stderr.contains("literal"))
            XCTAssertFalse(result.stderr.contains(command))
        }
    }

    // WO-644@v2: ordinary and unknown flags cannot bypass a protected copy source.
    func testCopyUnknownOptionsStillBlockSources() throws {
        try writeConfig(credentialConfig)
        let content = ["pass", "word", "=", syntheticCredentialLiteral()].joined()
        try content.write(toFile: testDir + "/doc.env", atomically: true, encoding: .utf8)
        for command in ["cp --unknown doc.env notes.md", "cp --unknown=value doc.env notes.md",
                        "cp --preserve=all doc.env notes.md", "cp -b doc.env notes.md",
                        "cp --parents doc.env docs/", "mv -u doc.env notes.md"] {
            let result = try runGuardCLI(arguments: ["guard", "--quiet", command])
            XCTAssertEqual(result.status, 2)
        }
    }

    // WO-644@v2: unsupported copy syntax allows with one diagnostic that never echoes operands.
    func testUnparseableCopyCommandsReportUnsupportedWithoutValues() throws {
        try writeConfig(credentialConfig)
        for command in ["cp 'private-path destination", "cp -t", "mv -S"] {
            let result = try runGuardCLI(arguments: ["guard", command])
            XCTAssertEqual(result.status, 0)
            XCTAssertTrue(result.stdout.isEmpty)
            XCTAssertEqual(result.stderr.split(separator: "\n").count, 1)
            XCTAssertTrue(result.stderr.contains("Unsupported"))
            XCTAssertFalse(result.stderr.contains("private-path"))
            XCTAssertFalse(result.stderr.contains("destination"))
        }
    }

    // WO-638: literal protected sources stay guarded when unrelated operands expand.
    func testCopyExpandedDestinationsStillBlockSource() throws {
        try writeConfig(credentialConfig)
        let content = ["pass", "word", "=", syntheticCredentialLiteral()].joined()
        try content.write(toFile: testDir + "/doc.env", atomically: true, encoding: .utf8)
        let commands = ["cp doc.env \"$HOME/notes.md\"", "cp doc.env notes-$(date +%F).md",
                        "mv doc.env \"$HOME/notes.md\"", "install doc.env \"$HOME/notes.md\"",
                        "cp -t \"$DIR\" doc.env", "cp --target-directory=\"$DIR\" doc.env"]
        for command in commands {
            let result = try runGuardCLI(arguments: ["guard", "--quiet", command])
            XCTAssertEqual(result.status, 2)
            XCTAssertTrue(result.stdout.isEmpty)
            XCTAssertTrue(result.stderr.isEmpty)
        }
        try "clean text".write(toFile: testDir + "/clean.txt", atomically: true, encoding: .utf8)
        let clean = try runGuardCLI(arguments: ["guard", "--quiet", "cp clean.txt \"$HOME/x.md\""])
        XCTAssertEqual(clean.status, 0)
    }

    // WO-638: destination suffixes cannot downgrade a non-documentation source's guard decision.
    func testCopySourceSecretsBlockRegardlessOfDestination() throws {
        try writeConfig(credentialConfig)
        let content = ["pass", "word", "=", syntheticCredentialLiteral()].joined()
        try content.write(toFile: testDir + "/doc.env", atomically: true, encoding: .utf8)
        for command in ["cp", "mv", "install", "rsync", "ditto"] {
            for destination in ["notes.md", "notes.txt"] {
                let result = try runGuardCLI(arguments: ["guard", "--quiet", "\(command) doc.env \(destination)"])
                XCTAssertEqual(result.status, 2, "source must block for \(command)")
                XCTAssertTrue(result.stdout.isEmpty)
                XCTAssertTrue(result.stderr.isEmpty)
            }
        }
    }

    // WO-638: clean sources and documentation-only advisory sources remain allowed.
    func testCopyCleanAndAdvisorySourcesRemainAllowed() throws {
        try writeConfig(credentialConfig)
        let content = ["pass", "word", "=", syntheticCredentialLiteral()].joined()
        try "clean text".write(toFile: testDir + "/clean.txt", atomically: true, encoding: .utf8)
        try content.write(toFile: testDir + "/source.md", atomically: true, encoding: .utf8)
        try content.write(toFile: testDir + "/destination.env", atomically: true, encoding: .utf8)
        for command in ["cp clean.txt notes.md", "cp source.md notes.md", "cp clean.txt destination.env",
                        "mv -f clean.txt destination.env", "install -m 600 clean.txt destination.env",
                        "ditto clean.txt destination.env", "rsync clean.txt destination.env"] {
            let result = try runGuardCLI(arguments: ["guard", "--quiet", command])
            XCTAssertEqual(result.status, 0, "destination must not become a new read target")
            XCTAssertTrue(result.stderr.isEmpty)
        }
    }

    // WO-638: cat and input-redirection sources keep their own path when writing documentation.
    func testRedirectSourceSecretsBlockDocumentationWrites() throws {
        try writeConfig(credentialConfig)
        let content = ["pass", "word", "=", syntheticCredentialLiteral()].joined()
        try content.write(toFile: testDir + "/doc.env", atomically: true, encoding: .utf8)
        for command in ["cat doc.env > notes.md", "cat doc.env >> notes.md", "cat doc.env | tee notes.md", "tee notes.md < doc.env"] {
            let result = try runGuardCLI(arguments: ["guard", "--quiet", command])
            XCTAssertEqual(result.status, 2)
            XCTAssertTrue(result.stderr.isEmpty)
        }
    }

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

    // WO-558@v2: the guard family shares one blocked-exit contract, and it is exit 2
    // (the Claude Code PreToolUse deny code). guard moved from 1 to 2; this pins the
    // value so an accidental change fails CI. guard-read/write/mutation and the
    // generated hooks all throw ExitCode(rawValue: GuardExitContract.blocked).
    func testGuardBlockedExitContractIsTwo() {
        XCTAssertEqual(GuardExitContract.blocked, 2,
            "Guard-family block exit code must be 2 (PreToolUse deny)")
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
            // WO-676@v4: referenced content never supplies an inline exemption.
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
            XCTAssertEqual(result.status, 2, "literal credential assignment should block")
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

        XCTAssertEqual(result.status, 2)
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

        XCTAssertEqual(result.status, 2)
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

        XCTAssertEqual(result.status, 2)
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

    // WO-672@v1: operator-tier exact values retain command and referenced-file parity.
    func testGuardHonorsConfigAllowlistForInlineAndReferencedFile() throws {
        // WO-672@v1: select this case's private global path before writing its operator-tier fixture.
        try TestConfigHelper.ensureProjectConfig(in: URL(fileURLWithPath: testDir))
        let key = "AKIA" + "QWERTYUIOPASDFGH"
        let testFile = testDir + "/config.env"
        try "AWS_KEY=\(key)".write(toFile: testFile, atomically: true, encoding: .utf8)
        var allowedConfig = config
        allowedConfig.allowedValues = [key]
        let configData = try JSONEncoder().encode(allowedConfig)
        // WO-672@v1: write only the fixture-owned global policy selected by the test helper.
        try configData.write(to: PastewatchConfig.configPath)

        let result = try runGuardCLI(arguments: ["guard", "--json", "cat \(testFile) && echo \(key)"])
        let payload = try guardJSON(from: result.stdout)

        XCTAssertEqual(result.status, 0)
        XCTAssertEqual(payload["blocked"] as? Bool, false)
        XCTAssertTrue((payload["files"] as? [[String: Any]])?.isEmpty == true)
        XCTAssertTrue((payload["inlineFindings"] as? [[String: Any]])?.isEmpty == true)
    }

    // WO-554@v3: agent-authored command comments cannot self-authorize a secret.
    func testGuardCommandCannotSelfAuthorizeWithInlineAllowComment() throws {
        let key = "AKIA" + "QWERTYUIOPASDFGH"

        let result = try runGuardCLI(arguments: [
            "guard", "--quiet", "echo \(key) # pastewatch:allow",
        ])

        XCTAssertEqual(result.status, 2)
        XCTAssertTrue(result.stdout.isEmpty)
        XCTAssertTrue(result.stderr.isEmpty)
    }

    // WO-598@v2: referenced-file limits use the guard blocked contract.
    func testGuardBlocksReferencedFileOverInputLimit() throws {
        let testFile = testDir + "/bounded.txt"
        try "123456".write(toFile: testFile, atomically: true, encoding: .utf8)

        let result = try runGuardCLI(
            arguments: ["guard", "cat \(testFile)"],
            environmentOverrides: [ScanInputLimits.fileBytesEnvironmentKey: "5"]
        )

        XCTAssertEqual(result.status, GuardExitContract.blocked)
        XCTAssertTrue(result.stderr.contains("file size 6 bytes exceeds scan limit 5 bytes"))
        XCTAssertFalse(result.stderr.contains("123456"))
    }

    // WO-601@v2: malformed referenced files cannot bypass the command guard.
    func testGuardBlocksReferencedFileWithInvalidLeadingByte() throws {
        let testFile = testDir + "/invalid-leading.txt"
        try Data([0xFF, 0x61]).write(to: URL(fileURLWithPath: testFile))

        let result = try runGuardCLI(arguments: ["guard", "cat \(testFile)"])

        XCTAssertEqual(result.status, GuardExitContract.blocked)
        XCTAssertTrue(result.stderr.contains("cannot be scanned safely"))
        XCTAssertFalse(result.stderr.contains("secret"))
    }

    // WO-601@v2: valid prefixes do not hide malformed bytes later in a referenced file.
    func testGuardBlocksReferencedFileWithEmbeddedInvalidSequence() throws {
        let testFile = testDir + "/invalid-embedded.txt"
        try Data([0x61, 0x62, 0xC3, 0x28]).write(to: URL(fileURLWithPath: testFile))

        let result = try runGuardCLI(arguments: ["guard", "cat \(testFile)"])

        XCTAssertEqual(result.status, GuardExitContract.blocked)
        XCTAssertTrue(result.stderr.contains("cannot be scanned safely"))
    }

    // WO-601@v2: empty text is fully scannable and remains allowed.
    func testGuardAllowsReferencedEmptyFile() throws {
        let testFile = testDir + "/empty.txt"
        try Data().write(to: URL(fileURLWithPath: testFile))

        let result = try runGuardCLI(arguments: ["guard", "--quiet", "cat \(testFile)"])

        XCTAssertEqual(result.status, 0)
        XCTAssertTrue(result.stderr.isEmpty)
    }

    // WO-601@v2: absent path tokens remain outside referenced-file enforcement.
    func testGuardIgnoresMissingReferencedFile() throws {
        let testFile = testDir + "/missing.txt"

        let result = try runGuardCLI(arguments: ["guard", "--quiet", "cat \(testFile)"])

        XCTAssertEqual(result.status, 0)
        XCTAssertTrue(result.stderr.isEmpty)
    }

    private struct CLIResult {
        let status: Int32
        let stdout: String
        let stderr: String
    }

    // WO-691@v3: an explicit binary path remains valid when config isolation changes the process CWD.
    // WO-601@v2: invoke the real guard process for referenced-file failure coverage.
    private func runGuardCLI(
        arguments: [String],
        environmentOverrides: [String: String] = [:],
        executableURL: URL? = nil
    ) throws -> CLIResult {
        // WO-634: preserve explicit test configs and isolate every default subprocess case.
        try TestConfigHelper.ensureProjectConfig(in: URL(fileURLWithPath: testDir))
        let process = Process()
        // WO-691@v3: existing callers retain their original binary lookup when no path is supplied.
        process.executableURL = executableURL ?? pastewatchCLIURL()
        process.arguments = arguments
        process.currentDirectoryURL = URL(fileURLWithPath: testDir)
        process.environment = testEnvironment().merging(environmentOverrides) { _, new in new }

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

    // WO-687@v2: fixture subprocesses inherit only isolated config, not session-specific migration settings.
    private func testEnvironment() -> [String: String] {
        return TestConfigHelper.subprocessEnvironment(["PATH": "/usr/bin:/bin"])
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
