import XCTest

final class ConfigEnforcementTests: XCTestCase {
    private struct CommandResult {
        let status: Int32
        let stdout: String
        let stderr: String
    }

    // WO-574@v4: every enforcement entry point rejects the same corrupt active config.
    func testEnforcementCommandsFailBeforeProtectedWorkOnInvalidConfig() throws {
        let root = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("pastewatch-config-enforcement-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }

        let marker = "CONFIG-MARKER-MUST-NOT-BE-ECHOED"
        try "{ \"marker\": \"\(marker)\"".write(
            to: root.appendingPathComponent(".pastewatch.json"),
            atomically: true,
            encoding: .utf8
        )
        let target = root.appendingPathComponent("target.txt")
        try "ordinary content".write(to: target, atomically: true, encoding: .utf8)

        let commands: [([String], String)] = [
            (["scan", "--check"], ""),
            (["mcp"], ""),
            (["proxy", "--port", "0"], ""),
            (["launch", "--no-startup-sweep", "--", "/usr/bin/true"], ""),
            (["guard", "echo ok"], ""),
            (["guard-read", target.path], ""),
            (["guard-write", target.path], ""),
            ([
                "guard-mutation"
            ], #"{"tool_name":"Write","tool_input":{"file_path":"\#(target.path)","content":"ordinary"}}"#),
            (["baseline", "create", "--dir", root.path], ""),
            (["fix", "--dir", root.path, "--dry-run"], ""),
            (["watch", "--dir", root.path], ""),
            (["inventory", "--dir", root.path], ""),
            (["posture", "--repos", "example/repository"], "")
        ]

        for (arguments, stdin) in commands {
            let result = try runCLI(
                arguments: arguments,
                stdin: stdin,
                currentDirectory: root
            )
            XCTAssertEqual(result.status, 2, arguments.joined(separator: " "))
            XCTAssertFalse(result.stdout.contains(marker), arguments.joined(separator: " "))
            XCTAssertFalse(result.stderr.contains(marker), arguments.joined(separator: " "))
        }

        // WO-574@v4: MCP validates before creating its optional audit artifact.
        let auditLog = root.appendingPathComponent("mcp-audit.log")
        let mcpResult = try runCLI(
            arguments: ["mcp", "--audit-log", auditLog.path],
            stdin: "",
            currentDirectory: root
        )
        XCTAssertEqual(mcpResult.status, 2)
        XCTAssertFalse(FileManager.default.fileExists(atPath: auditLog.path))
    }

    // WO-574@v4: subprocess coverage proves every enforcement entry point fails closed.
    private func runCLI(
        arguments: [String],
        stdin: String,
        currentDirectory: URL
    ) throws -> CommandResult {
        let process = Process()
        process.executableURL = pastewatchCLIURL()
        process.arguments = arguments
        process.currentDirectoryURL = currentDirectory

        var environment = ProcessInfo.processInfo.environment
        environment.removeValue(forKey: "PW_GUARD")
        process.environment = environment

        let inputPipe = Pipe()
        let outputPipe = Pipe()
        let errorPipe = Pipe()
        process.standardInput = inputPipe
        process.standardOutput = outputPipe
        process.standardError = errorPipe

        try process.run()
        inputPipe.fileHandleForWriting.write(Data(stdin.utf8))
        inputPipe.fileHandleForWriting.closeFile()
        process.waitUntilExit()

        return CommandResult(
            status: process.terminationStatus,
            stdout: String(
                data: outputPipe.fileHandleForReading.readDataToEndOfFile(),
                encoding: .utf8
            ) ?? "",
            stderr: String(
                data: errorPipe.fileHandleForReading.readDataToEndOfFile(),
                encoding: .utf8
            ) ?? ""
        )
    }

    // WO-574@v4: resolve the built CLI consistently for enforcement subprocess tests.
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
