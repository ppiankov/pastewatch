import XCTest
@testable import PastewatchCore

final class AmbiguousGuardDefaultsTests: XCTestCase {
    // WO-651@v2: source fixtures that no longer contain Credential findings permit an append-only Edit.
    func testAppendToTrivialRustCredentialFixtureIsAllowed() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            let config = TestConfigHelper.configWithAmbiguousAdvisories([.credential])
            let content = ["fs::write(&file, \"", "SEC", "RET=", "1", "\\n", "\").unwrap();"].joined()
            let decision = try GuardMutationEvaluator.evaluateEdit(
                currentContent: content, oldString: ";", newString: ";\n// appended fixture",
                replaceAll: false, filePath: "fixture.rs", config: config, minimumSeverity: .high
            )
            XCTAssertEqual(decision, .allow)
        }
    }

    // WO-596: default configuration keeps every ambiguous detector out of the CLI guard path.
    func testDefaultConfigKeepsAmbiguousClassesGuardClean() throws {
        let entropyValue = ["Z9aB8cD7", "eF6gH5iJ", "4kL3mN2p", "Q1rS0tU"].joined()
        let cases = [
            ["operator", "@", "private.example"].joined(),
            "db-primary.prod.private.example",
            "10.23.45.67",
            ["/home/", "operator/.ssh/config"].joined(),
            "+44 20 7946 0958",
            ["postgres", "://user:pass@db.private/app"].joined(),
            ["jdbc:postgresql", "://db.private/app"].joined(),
            ["token_", entropyValue].joined(),
            ["password=", entropyValue].joined(),
            "550e8400-e29b-41d4-a716-446655440000",
            "<user>deployadmin</user>",
            "<host>node.private</host>",
            entropyValue,
        ]

        for input in cases {
            let result = try runScan(input: input)
            XCTAssertEqual(result.status, ScanExitContract.clean, result.stderr)
        }
    }

    // WO-659@v1: report advisory type and line even when native Read is allowed.
    func testReadAllowsAndReportsAdvisoryOnlyCredential() throws {
        let config = TestConfigHelper.configWithAmbiguousAdvisories([.credential])
        let content = ["pass", "word=", "Z9aB8cD7eF6gH5iJ"].joined()
        let result = try runReadFixture(content: content, config: config)
        XCTAssertEqual(result.status, 0)
        XCTAssertTrue(result.stderr.contains("ADVISORY: Credential line 1 count=1"))
        XCTAssertFalse(result.stderr.contains(content))
        let matches = try DirectoryScanner.scanFileContentOrThrow(
            content: content, ext: "txt", relativePath: "fixture.txt", config: config
        )
        let decision = MCPReadDecision.evaluate(
            matches: matches, content: content, config: config, minimumSeverity: .high, filePath: "fixture.txt"
        )
        let (_, entries) = try decision.redact(content: content, store: RedactionStore(), filePath: "fixture.txt")
        XCTAssertTrue(entries.isEmpty)
    }

    // WO-659@v1: invalid active policy remains fail-closed for otherwise ordinary content.
    func testReadStillBlocksInvalidConfig() throws {
        let result = try runReadFixture(content: "ordinary prose", config: .defaultConfig, invalidConfig: true)
        XCTAssertEqual(result.status, GuardExitContract.blocked)
    }

    // WO-659@v1: subprocess policy is an explicit valid project fixture, not operator HOME.
    private func runReadFixture(
        content: String, config: PastewatchConfig, invalidConfig: Bool = false
    ) throws -> (status: Int32, stderr: String) {
        let root = try TestConfigHelper.makeProjectDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let configData = invalidConfig ? Data("{".utf8) : try JSONEncoder().encode(config)
        try configData.write(to: root.appendingPathComponent(".pastewatch.json"))
        let file = root.appendingPathComponent("fixture.txt")
        try Data(content.utf8).write(to: file)
        let process = Process()
        process.executableURL = pastewatchCLIURL()
        process.arguments = ["guard-read", file.path]
        process.currentDirectoryURL = root
        var environment = ProcessInfo.processInfo.environment
        environment["PW_GUARD"] = "1"
        process.environment = environment
        let stdout = Pipe()
        let stderr = Pipe()
        process.standardOutput = stdout
        process.standardError = stderr
        try process.run()
        process.waitUntilExit()
        _ = stdout.fileHandleForReading.readDataToEndOfFile()
        let errorText = String(data: stderr.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        return (process.terminationStatus, errorText)
    }

    // WO-596: exercise the isolated CLI process with production defaults.
    private func runScan(input: String) throws -> (status: Int32, stderr: String) {
        let home = FileManager.default.temporaryDirectory
            .appendingPathComponent("pastewatch-ambiguous-home-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: home) }
        // WO-634: HOME is not a config override; defaults come from an explicit project fixture.
        try TestConfigHelper.ensureProjectConfig(in: home)

        let process = Process()
        process.executableURL = pastewatchCLIURL()
        process.arguments = [
            "scan",
            "--check",
            "--fail-on-severity", "high",
            "--stdin-filename", "fixture.txt",
        ]
        process.currentDirectoryURL = home
        var environment = ProcessInfo.processInfo.environment
        // WO-634: retain the ordinary process environment, not Foundation home redirection.
        environment["PW_GUARD"] = "1"
        process.environment = environment

        let stdin = Pipe()
        let stdout = Pipe()
        let stderr = Pipe()
        process.standardInput = stdin
        process.standardOutput = stdout
        process.standardError = stderr

        try process.run()
        stdin.fileHandleForWriting.write(Data(input.utf8))
        stdin.fileHandleForWriting.closeFile()
        process.waitUntilExit()

        _ = stdout.fileHandleForReading.readDataToEndOfFile()
        let errorText = String(
            data: stderr.fileHandleForReading.readDataToEndOfFile(),
            encoding: .utf8
        ) ?? ""
        return (process.terminationStatus, errorText)
    }

    // WO-596: resolve the built CLI used by the defaults regression fixture.
    private func pastewatchCLIURL() -> URL {
        let productsDirectory = Bundle.main.bundleURL.deletingLastPathComponent()
        let bundled = productsDirectory.appendingPathComponent("PastewatchCLI")
        if FileManager.default.fileExists(atPath: bundled.path) {
            return bundled
        }
        return URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
            .appendingPathComponent(".build/debug/PastewatchCLI")
    }
}
