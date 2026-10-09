import XCTest
@testable import PastewatchCore
@testable import PastewatchCLI

// WO-670@v1: project exact exemptions use target context consistently across file surfaces.
final class ProjectAllowlistTests: XCTestCase {
    // WO-670@v1: captured child bytes never enter failure messages.
    private struct CommandResult {
        let status: Int32
        let output: Data
        let errors: Data
    }

    // WO-670@v1: every file guard and MCP read/edit uses the target repo, not the hook CWD.
    func testFileSurfaceParityFromOutsideRepository() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let repo = try directory("repo", in: root)
            let nested = try directory("nested", in: repo)
            let outside = try directory("outside", in: root)
            XCTAssertEqual(try git(["init", "--quiet"], root: repo).status, 0)
            let email = ["contact", "@", "publisher", ".test"].joined()
            var config = TestConfigHelper.configWithAmbiguousAdvisories([.email])
            config.obfuscate = [ObfuscateEntry(type: "email", pattern: "@publisher.test")]
            try JSONEncoder().encode(config).write(to: PastewatchConfig.configPath)
            try Data((email + "\n").utf8).write(to: outside.appendingPathComponent(".pastewatch-allow"))
            let file = nested.appendingPathComponent("contact.txt")
            for allowed in [false, true] {
                try Data((email + "\n").utf8).write(to: file)
                try Data((allowed ? email + "\n" : "# no entries\n").utf8)
                    .write(to: repo.appendingPathComponent(".pastewatch-allow"))
                XCTAssertEqual(try command(["scan", "--file", file.path, "--check"], root: outside).status, allowed ? 0 : 6)
                for guardName in ["guard-read", "guard-write"] {
                    XCTAssertEqual(try command([guardName, file.path], root: outside).status, allowed ? 0 : 2)
                }
                XCTAssertEqual(try command(["guard", "cat " + file.path], root: outside).status, allowed ? 0 : 2)
                let mutation: [String: Any] = ["tool_name": "Edit", "tool_input": [
                    "file_path": file.path, "old_string": email, "new_string": "contact"]]
                XCTAssertEqual(try command(["guard-mutation"], root: outside,
                               input: JSONSerialization.data(withJSONObject: mutation)).status, allowed ? 0 : 2)
                let responses = try mcp([
                    tool("pastewatch_read_file", ["path": file.path]),
                    tool("pastewatch_edit_file", ["path": file.path, "old_string": email, "new_string": "contact"]),
                    tool("pastewatch_write_file", ["path": file.path, "content": email])
                ], root: outside)
                let read = try payload(responses[0])
                XCTAssertEqual((read["redactions"] as? [[String: Any]])?.count, allowed ? 0 : 1)
                XCTAssertEqual((read["content"] as? String)?.contains(email), allowed)
                XCTAssertEqual((responses[1]["result"] as? [String: Any])?["isError"] as? Bool ?? false, !allowed)
                XCTAssertEqual((responses[2]["result"] as? [String: Any])?["isError"] as? Bool ?? false, !allowed)
            }
        }
    }

    // WO-670@v1: a published contact in multiple formats is omitted from file diagnostics in every CWD.
    func testPublishedPhoneFormsAcrossFileScans() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let repo = try directory("repo", in: root)
            let nested = try directory("nested", in: repo)
            XCTAssertEqual(try git(["init", "--quiet"], root: repo).status, 0)
            let forms = phoneForms()
            let config = TestConfigHelper.configWithAmbiguousAdvisories([.phone])
            try JSONEncoder().encode(config).write(to: PastewatchConfig.configPath)
            let file = nested.appendingPathComponent("contact.html")
            let text = forms.map { "<p>" + $0 + "</p>" }.joined(separator: "\n") + "\n"
            try Data(text.utf8).write(to: file)
            try Data((forms.joined(separator: "\n") + "\n").utf8).write(to: repo.appendingPathComponent(".pastewatch-allow"))
            XCTAssertEqual(DetectionRules.scanFileIO(text, config: config).filter { $0.type == .phone }.count, 3)
            for cwd in [repo, nested, root] {
                XCTAssertEqual(try command(["scan", "--file", file.path, "--check"], root: cwd).status, 0)
                for guardName in ["guard-read", "guard-write"] {
                    XCTAssertEqual(try command([guardName, file.path], root: cwd).status, 0)
                }
                let mutation: [String: Any] = ["tool_name": "Write", "tool_input": ["file_path": file.path, "content": "contact"]]
                XCTAssertEqual(try command(["guard-mutation"], root: cwd,
                               input: JSONSerialization.data(withJSONObject: mutation)).status, 0)
                let responses = try mcp([tool("pastewatch_scan_file", ["path": file.path]),
                                         tool("pastewatch_scan_dir", ["path": repo.path])], root: cwd)
                XCTAssertTrue(try contentText(responses[0]).contains("No sensitive data found."))
                XCTAssertTrue(try contentText(responses[1]).contains("Found 0 findings."))
            }
            XCTAssertEqual(try git(["add", "nested/contact.html"], root: repo).status, 0)
            XCTAssertEqual(try command(["scan", "--git-diff", "--staged", "--check"], root: repo).status, 0)
            XCTAssertEqual(try command(["scan", "--git-diff", "--staged", "--check"], root: nested).status, 0)
            XCTAssertEqual(try git(["-c", "user.name=Fixture", "-c", "user.email=fixture@example.test",
                                   "commit", "--quiet", "-m", "fixture"], root: repo).status, 0)
            XCTAssertEqual(try command(["scan", "--git-log", "--check"], root: nested).status, 0)
        }
    }

    // WO-670@v1: deleted historical parents cannot discard the explicitly scanned repository context.
    func testDeletedHistoricalDirectoryRetainsProjectRoot() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let repo = try directory("repo", in: root)
            let nested = try directory("nested", in: repo)
            XCTAssertEqual(try git(["init", "--quiet"], root: repo).status, 0)
            let phone = phoneForms()[0]
            try JSONEncoder().encode(TestConfigHelper.configWithAmbiguousAdvisories([.phone])).write(to: PastewatchConfig.configPath)
            try Data(phone.utf8).write(to: nested.appendingPathComponent("contact.txt"))
            XCTAssertEqual(try git(["add", "nested/contact.txt"], root: repo).status, 0)
            XCTAssertEqual(try git(["-c", "user.name=Fixture", "-c", "user.email=fixture@example.test",
                                   "commit", "--quiet", "-m", "fixture"], root: repo).status, 0)
            try FileManager.default.removeItem(at: nested)
            for allowed in [false, true] {
                try Data((allowed ? phone + "\n" : "# no entries\n").utf8).write(to: repo.appendingPathComponent(".pastewatch-allow"))
                XCTAssertEqual(try command(["scan", "--git-log", "--check"], root: repo).status, allowed ? 0 : 6)
            }
        }
    }

    // WO-670@v1: rootless input must not inherit a project exemption from its process directory.
    func testPathlessSurfacesKeepReportingAdvisories() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let phone = phoneForms()[0]
            let config = TestConfigHelper.configWithAmbiguousAdvisories([.phone])
            try JSONEncoder().encode(config).write(to: PastewatchConfig.configPath)
            try Data((phone + "\n").utf8).write(to: root.appendingPathComponent(".pastewatch-allow"))
            XCTAssertEqual(try command(["scan", "--check"], root: root, input: Data(phone.utf8)).status, 6)
            XCTAssertEqual(try command(["scan", "--check", "--stdin-filename", "contact.txt"],
                                       root: root, input: Data(phone.utf8)).status, 6)
            let response = try mcp([tool("pastewatch_scan", ["text": phone])], root: root)[0]
            XCTAssertTrue(try contentText(response).contains("Phone"))
            XCTAssertEqual(try command(["guard", "printf '" + phone + "'"], root: root).status, 2)
        }
    }

    // WO-670@v1: ineffective intrinsic entries cannot weaken file protection and must be reported truthfully.
    func testIntrinsicEntryIsIgnoredAndDoctorWarns() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let repo = try directory("repo", in: root)
            let nested = try directory("nested", in: repo)
            XCTAssertEqual(try git(["init", "--quiet"], root: repo).status, 0)
            let phone = phoneForms()[0]
            let secret = intrinsicFixture()
            try JSONEncoder().encode(TestConfigHelper.configWithAmbiguousAdvisories([.phone])).write(to: PastewatchConfig.configPath)
            let file = nested.appendingPathComponent("contact.txt")
            try Data((phone + "\n" + secret + "\n").utf8).write(to: file)
            try Data((phone + "\n" + secret + "\n").utf8).write(to: repo.appendingPathComponent(".pastewatch-allow"))
            XCTAssertEqual(try command(["guard-read", file.path], root: root).status, 2)
            let read = try payload(mcp([tool("pastewatch_read_file", ["path": file.path])], root: root)[0])
            XCTAssertEqual((read["redactions"] as? [[String: Any]])?.count, 1)
            XCTAssertFalse((read["content"] as? String ?? "").contains(secret))
            for arguments in [["doctor", "--json"], ["doctor", "--explain", "--json"]] {
                let result = try command(arguments, root: nested)
                XCTAssertEqual(result.status, 0)
                XCTAssertFalse(try XCTUnwrap(String(data: result.output + result.errors, encoding: .utf8)).contains(secret))
                let output = try XCTUnwrap(String(data: result.output, encoding: .utf8))
                XCTAssertTrue(output.contains("ignoredIntrinsicEntries"))
                XCTAssertTrue(output.contains("warn"))
                XCTAssertTrue(output.contains(".pastewatch-allow"))
            }
        }
    }

    // WO-670@v1: nested non-git watch decisions use only the explicit root, not ancestors or CWD.
    func testNestedNonGitWatchUsesOnlyWatchRoot() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let watched = try directory("watched", in: root)
            let nested = try directory("nested", in: watched)
            let outside = try directory("outside", in: root)
            let forms = phoneForms()
            let config = TestConfigHelper.configWithAmbiguousAdvisories([.phone])
            let path = nested.appendingPathComponent("contact.txt").path
            try Data((forms[0] + "\n").utf8).write(to: watched.appendingPathComponent(".pastewatch-allow"))
            try Data((forms[1] + "\n").utf8).write(to: nested.appendingPathComponent(".pastewatch-allow"))
            try Data((forms[1] + "\n").utf8).write(to: outside.appendingPathComponent(".pastewatch-allow"))
            XCTAssertTrue(FileManager.default.changeCurrentDirectoryPath(outside.path))
            let watcher = FileWatcher(directory: watched.path, config: config)
            for (index, value) in forms.prefix(2).enumerated() {
                let matches = DetectionRules.scanFileIO(value, config: config)
                XCTAssertEqual(matches.filter { $0.type == .phone }.count, 1)
                let decision = watcher.fileDecision(matches: matches, content: value, filePath: path)
                XCTAssertEqual(decision.reportableMatches.count, index)
            }
        }
    }

    // WO-670@v1: a directory scan carries its non-git root through every relative member path.
    func testNestedNonGitDirectoryScanUsesExplicitRoot() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let scanned = try directory("scanned", in: root)
            let nested = try directory("nested", in: scanned)
            let phone = phoneForms()[0]
            try JSONEncoder().encode(TestConfigHelper.configWithAmbiguousAdvisories([.phone])).write(to: PastewatchConfig.configPath)
            try Data(phone.utf8).write(to: nested.appendingPathComponent("contact.txt"))
            try Data((phone + "\n").utf8).write(to: scanned.appendingPathComponent(".pastewatch-allow"))
            XCTAssertEqual(try command(["scan", "--dir", scanned.path, "--check"], root: root).status, 0)
            let response = try mcp([tool("pastewatch_scan_dir", ["path": scanned.path])], root: root)[0]
            XCTAssertTrue(try contentText(response).contains("Found 0 findings."))
        }
    }

    // WO-670@v1: project files cannot exempt custom rules and metadata never serializes their values.
    func testCustomRuleRemainsProtectedAndMetadataContainsNoValues() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let value = ["operator", "-defined", "-fixture"].joined()
            var config = PastewatchConfig.defaultConfig
            config.customRules = [CustomRuleConfig(name: "fixture-rule", pattern: NSRegularExpression.escapedPattern(for: value))]
            let path = root.appendingPathComponent("fixture.txt").path
            try Data((value + "\n").utf8).write(to: root.appendingPathComponent(".pastewatch-allow"))
            let matches = DetectionRules.scanFileIO(value, config: config)
            let decision = GuardDecision.evaluate(matches: matches, content: value, config: config,
                               contentTrust: .trustedFile, minimumSeverity: nil, filePath: path)
            XCTAssertEqual(decision.actionableMatches.filter { $0.customRuleName == "fixture-rule" }.count, 1)
            let report = Allowlist.projectFile(for: path)
            XCTAssertTrue(report.loaded)
            XCTAssertFalse(try XCTUnwrap(String(data: JSONEncoder().encode(report), encoding: .utf8)).contains(value))
        }
    }

    // WO-670@v1: missing and unreadable files grant no exemptions and are never marked active.
    func testUnloadedAllowFilesAreNotReportedOK() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let path = root.appendingPathComponent("fixture.txt").path
            let absent = Allowlist.projectFile(for: path)
            XCTAssertFalse(absent.loaded)
            XCTAssertEqual(absent.status, "absent")
            let file = root.appendingPathComponent(".pastewatch-allow")
            try FileManager.default.createDirectory(at: file, withIntermediateDirectories: true)
            let unreadable = Allowlist.projectFile(for: path)
            XCTAssertFalse(unreadable.loaded)
            XCTAssertEqual(unreadable.status, "warn")
            XCTAssertEqual(unreadable.effectiveEntries, 0)
            let result = try command(["doctor", "--explain", "--json"], root: root)
            let json = try XCTUnwrap(JSONSerialization.jsonObject(with: result.output) as? [String: Any])
            let report = try XCTUnwrap(json["projectAllowlist"] as? [String: Any])
            XCTAssertEqual(report["loaded"] as? Bool, false)
            XCTAssertEqual(report["status"] as? String, "warn")
        }
    }

    // WO-670@v1: opt-in intrinsic families are also ineffective project-file exemptions.
    func testOptInIntrinsicEntryIsReportedIneffective() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let value = ["post", "gres", "://", "app", ":", String(repeating: "R7k4", count: 4), "@", "db.internal", "/app"].joined()
            let path = root.appendingPathComponent("fixture.txt").path
            try Data((value + "\n").utf8).write(to: root.appendingPathComponent(".pastewatch-allow"))
            let report = Allowlist.projectFile(for: path)
            XCTAssertEqual(report.ignoredIntrinsicEntries, 1)
            XCTAssertEqual(report.effectiveEntries, 0)
            XCTAssertEqual(report.status, "warn")
        }
    }

    // WO-670@v1: fixture directories are private and explicit, never inferred from operator state.
    private func directory(_ name: String, in root: URL) throws -> URL {
        let result = root.appendingPathComponent(name, isDirectory: true)
        try FileManager.default.createDirectory(at: result, withIntermediateDirectories: true)
        return result
    }

    // WO-670@v1: telephone examples are assembled only in fixture memory.
    private func phoneForms() -> [String] {
        [["+1", " 415", " 555", " 0132"].joined(), ["(415)", " 555", "-0132"].joined(),
         ["+1", "-415", "-555", "-0132"].joined()]
    }

    // WO-670@v1: no complete intrinsic token is stored in source or failure diagnostics.
    private func intrinsicFixture() -> String {
        ["gh", "p_", String(repeating: "A7b3", count: 9)].joined()
    }

    // WO-670@v1: MCP requests remain captured bytes, not shell arguments or log text.
    private func tool(_ name: String, _ arguments: [String: String]) -> [String: Any] {
        ["jsonrpc": "2.0", "method": "tools/call", "params": ["name": name, "arguments": arguments]]
    }

    // WO-670@v1: each fixture session validates complete responses before interpreting private payloads.
    private func mcp(_ requests: [[String: Any]], root: URL) throws -> [[String: Any]] {
        var input = Data()
        for (index, var request) in requests.enumerated() {
            request["id"] = index + 1
            input.append(try JSONSerialization.data(withJSONObject: request))
            input.append(0x0A)
        }
        let result = try command(["mcp"], root: root, input: input)
        XCTAssertEqual(result.status, 0)
        return try result.output.split(separator: 0x0A).map {
            try XCTUnwrap(JSONSerialization.jsonObject(with: Data($0)) as? [String: Any])
        }
    }

    // WO-670@v1: transport error assertions use structural metadata without dumping returned content.
    private func contentText(_ response: [String: Any]) throws -> String {
        let result = try XCTUnwrap(response["result"] as? [String: Any])
        let content = try XCTUnwrap(result["content"] as? [[String: Any]])
        return content.compactMap { $0["text"] as? String }.joined(separator: "\n")
    }

    // WO-670@v1: read results are decoded privately so assertions never print a matched value.
    private func payload(_ response: [String: Any]) throws -> [String: Any] {
        try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentText(response).utf8)) as? [String: Any])
    }

    // WO-670@v1: Git discovery fixtures have no operator credentials or configuration.
    private func git(_ arguments: [String], root: URL) throws -> CommandResult {
        try command(arguments, root: root, executable: URL(fileURLWithPath: "/usr/bin/git"))
    }

    // WO-670@v1: only DEBUG children receive isolated policy paths and captured fixture input.
    private func command(_ arguments: [String], root: URL, input: Data = Data(), executable: URL? = nil) throws -> CommandResult {
        let repo = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let process = Process()
        process.executableURL = executable ?? repo.appendingPathComponent(".build/debug/PastewatchCLI")
        process.arguments = arguments
        process.currentDirectoryURL = root
        process.environment = TestConfigHelper.subprocessEnvironment(["PATH": "/usr/bin:/bin", "PW_GUARD": "1"])
        let stdin = Pipe()
        let stdout = Pipe()
        let stderr = Pipe()
        process.standardInput = stdin
        process.standardOutput = stdout
        process.standardError = stderr
        try process.run()
        stdin.fileHandleForWriting.write(input)
        try stdin.fileHandleForWriting.close()
        let output = stdout.fileHandleForReading.readDataToEndOfFile()
        let errors = stderr.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return CommandResult(status: process.terminationStatus, output: output, errors: errors)
    }
}
