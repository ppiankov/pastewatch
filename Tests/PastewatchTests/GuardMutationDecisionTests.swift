import XCTest
@testable import PastewatchCore
@testable import PastewatchCLI

final class GuardMutationDecisionTests: XCTestCase {
    // WO-526@v2: subprocess results keep streams named without a lint-exempt tuple.
    private struct CommandResult {
        let status: Int32
        let stdout: String
        let stderr: String
    }

    private let path = "/tmp/fixture.swift"
    private let config = PastewatchConfig.defaultConfig

    // WO-526@v2: an edit outside an existing finding must remain usable.
    func testUnrelatedEditAllowsExistingFinding() throws {
        let token = providerToken("A")
        let content = "let fixture = \"\(token)\"\nlet count = 1\n"

        let decision = try GuardMutationEvaluator.evaluateEdit(
            currentContent: content,
            oldString: "let count = 1",
            newString: "let count = 2",
            replaceAll: false,
            filePath: path,
            config: config,
            minimumSeverity: .high
        )

        XCTAssertEqual(decision, .allow)
    }

    // WO-526@v2: changing bytes that contain a finding remains blocked.
    func testEditOverlappingFindingBlocks() throws {
        let token = providerToken("B")
        let content = "let fixture = \"\(token)\"\n"

        let decision = try GuardMutationEvaluator.evaluateEdit(
            currentContent: content,
            oldString: token,
            newString: "replacement",
            replaceAll: false,
            filePath: path,
            config: config,
            minimumSeverity: .high
        )

        XCTAssertEqual(decision, .block(.touchesExistingFinding))
    }

    // WO-526@v2: a clean region cannot be used to introduce a new finding.
    func testEditIntroducingFindingBlocks() throws {
        let content = "let value = \"clean\"\n"

        let decision = try GuardMutationEvaluator.evaluateEdit(
            currentContent: content,
            oldString: "clean",
            newString: providerToken("C"),
            replaceAll: false,
            filePath: path,
            config: config,
            minimumSeverity: .high
        )

        XCTAssertEqual(decision, .block(.changesFindingSet))
    }

    // WO-526@v2: whole-file writes may move findings but not change their multiset.
    func testWritePreservingFindingAllows() throws {
        let token = providerToken("D")
        let current = "let fixture = \"\(token)\"\n"
        let proposed = "// annotation\n\(current)"

        let decision = try GuardMutationEvaluator.evaluateWrite(
            currentContent: current,
            proposedContent: proposed,
            filePath: path,
            config: config,
            minimumSeverity: .high
        )

        XCTAssertEqual(decision, .allow)
    }

    // WO-526@v2: changed, missing, and newly added findings are all blocked.
    func testWriteFindingSetChangesBlock() throws {
        let first = providerToken("E")
        let second = providerToken("F")
        let current = "let fixture = \"\(first)\"\n"

        for proposed in [
            "let fixture = \"\(second)\"\n",
            "let fixture = \"clean\"\n",
            current + "let added = \"\(second)\"\n",
        ] {
            let decision = try GuardMutationEvaluator.evaluateWrite(
                currentContent: current,
                proposedContent: proposed,
                filePath: path,
                config: config,
                minimumSeverity: .high
            )
            XCTAssertEqual(decision, .block(.changesFindingSet))
        }
    }

    // WO-526@v2: duplicate values are compared by count, not set membership.
    func testWriteDuplicateFindingCountMustRemainStable() throws {
        let token = providerToken("G")
        let current = "\(token)\n\(token)\n"

        let same = try GuardMutationEvaluator.evaluateWrite(
            currentContent: current,
            proposedContent: "header\n\(current)",
            filePath: path,
            config: config,
            minimumSeverity: .high
        )
        let missing = try GuardMutationEvaluator.evaluateWrite(
            currentContent: current,
            proposedContent: "\(token)\n",
            filePath: path,
            config: config,
            minimumSeverity: .high
        )

        XCTAssertEqual(same, .allow)
        XCTAssertEqual(missing, .block(.changesFindingSet))
    }

    // WO-526@v2: replace-all evaluates every clean occurrence deterministically.
    func testReplaceAllCleanOccurrencesAllows() throws {
        let token = providerToken("H")
        let content = "\(token)\nmarker\nmarker\n"

        let decision = try GuardMutationEvaluator.evaluateEdit(
            currentContent: content,
            oldString: "marker",
            newString: "renamed",
            replaceAll: true,
            filePath: path,
            config: config,
            minimumSeverity: .high
        )

        XCTAssertEqual(decision, .allow)
    }

    // WO-526@v2: ambiguous single replacement fails closed before mutation.
    func testAmbiguousSingleEditBlocks() throws {
        let decision = try GuardMutationEvaluator.evaluateEdit(
            currentContent: "marker\nmarker\n",
            oldString: "marker",
            newString: "renamed",
            replaceAll: false,
            filePath: path,
            config: config,
            minimumSeverity: .high
        )

        XCTAssertEqual(decision, .block(.invalidInput))
    }

    // WO-526@v2: scanner configuration failures propagate to the fail-closed CLI boundary.
    func testSharedPatternFailureThrows() {
        var invalidConfig = config
        invalidConfig.sharedPatternFiles = ["/tmp/does-not-exist-shared-patterns.json"]

        XCTAssertThrowsError(
            try GuardMutationEvaluator.evaluateWrite(
                currentContent: "clean",
                proposedContent: "still clean",
                filePath: path,
                config: invalidConfig,
                minimumSeverity: .high
            )
        )
    }

    // WO-526@v2: malformed hook JSON fails before any file or secret data is inspected.
    func testStructuredInputRequiresCompleteEditPayload() throws {
        let data = Data(#"{"tool_name":"Edit","tool_input":{"file_path":"/tmp/a"}}"#.utf8)

        XCTAssertThrowsError(try GuardMutationInput.parse(data))
    }

    // WO-526@v2: structured Write input retains content in stdin rather than argv.
    func testStructuredWriteInputParsesContent() throws {
        let data = Data(#"{"tool_name":"Write","tool_input":{"file_path":"/tmp/a","content":"clean"}}"#.utf8)

        let input = try GuardMutationInput.parse(data)

        XCTAssertEqual(input.filePath, "/tmp/a")
        guard case .write(let content) = input.operation else {
            return XCTFail("expected Write operation")
        }
        XCTAssertEqual(content, "clean")
    }

    // WO-526@v2: the executable consumes structured stdin and never prints matched values.
    func testGuardMutationCommandAllowsUnrelatedEditAndBlocksOverlap() throws {
        let testDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent("pastewatch-guard-mutation-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: testDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: testDirectory) }

        let token = providerToken("J")
        let fileURL = testDirectory.appendingPathComponent("fixture.swift")
        try "let fixture = \"\(token)\"\nlet count = 1\n".write(
            to: fileURL, atomically: true, encoding: .utf8
        )

        let allowed = try runGuardMutation([
            "tool_name": "Edit",
            "tool_input": [
                "file_path": fileURL.path,
                "old_string": "let count = 1",
                "new_string": "let count = 2",
            ],
        ], home: testDirectory)
        let blocked = try runGuardMutation([
            "tool_name": "Edit",
            "tool_input": [
                "file_path": fileURL.path,
                "old_string": token,
                "new_string": "replacement",
            ],
        ], home: testDirectory)

        XCTAssertEqual(allowed.status, 0, allowed.stderr)
        XCTAssertEqual(blocked.status, 2, blocked.stderr)
        XCTAssertFalse((blocked.stdout + blocked.stderr).contains(token))
    }

    // WO-526@v2: exercise the executable boundary with structured stdin.
    private func runGuardMutation(
        _ payload: [String: Any],
        home: URL
    ) throws -> CommandResult {
        let process = Process()
        process.executableURL = pastewatchCLIURL()
        process.arguments = ["guard-mutation", "--fail-on-severity", "high"]
        process.environment = [
            "HOME": home.path,
            "PATH": "/usr/bin:/bin",
        ]

        let input = Pipe()
        let output = Pipe()
        let error = Pipe()
        process.standardInput = input
        process.standardOutput = output
        process.standardError = error
        try process.run()
        input.fileHandleForWriting.write(try JSONSerialization.data(withJSONObject: payload))
        try input.fileHandleForWriting.close()
        process.waitUntilExit()

        return CommandResult(
            status: process.terminationStatus,
            stdout: String(data: output.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? "",
            stderr: String(data: error.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        )
    }

    // WO-526@v2: resolve the test-built executable on local and CI runners.
    private func pastewatchCLIURL() -> URL {
        let productsDirectory = Bundle.main.bundleURL.deletingLastPathComponent()
        let bundled = productsDirectory.appendingPathComponent("PastewatchCLI")
        if FileManager.default.fileExists(atPath: bundled.path) {
            return bundled
        }
        return URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
            .appendingPathComponent(".build/debug/PastewatchCLI")
    }

    // WO-526@v2: deterministic provider-shaped fixtures avoid live credentials.
    private func providerToken(_ suffix: String) -> String {
        "AIza" + String(repeating: suffix, count: 35)
    }
}
