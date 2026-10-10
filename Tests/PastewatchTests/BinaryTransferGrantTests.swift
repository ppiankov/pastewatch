import Foundation
import XCTest
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
@testable import PastewatchCore
@testable import PastewatchCLI

// WO-673@v2: grant fixtures use only isolated user policy and generated opaque bytes.
final class BinaryTransferGrantTests: XCTestCase {
    // WO-673@v2: admission and doctor use a controllable clock without a production environment bypass.
    func testInjectedClockPinsExpiryAndDoctorRows() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let now = Date(timeIntervalSince1970: 1_700_000_000)
            let file = try binary(in: root)
            try BinaryTransferGrants.record(path: file.path, ttl: 60, now: now)
            let bytes = try Data(contentsOf: file)
            XCTAssertTrue(BinaryTransferGrants.permitsTransfer(path: file.path, bytes: bytes, now: now))
            XCTAssertFalse(BinaryTransferGrants.permitsTransfer(path: file.path, bytes: bytes, now: now.addingTimeInterval(60)))
            XCTAssertTrue(Doctor().checkBinaryGrants(clock: { now })[0].detail.contains("1 active, 0 expired"))
            XCTAssertTrue(Doctor().checkBinaryGrants(clock: { now.addingTimeInterval(60) })[0].detail.contains("0 active, 1 expired"))
        }
    }

    // WO-673@v2: one malformed row invalidates the whole store and cannot admit another valid entry.
    func testPartiallyMalformedGrantArrayContributesNoAuthority() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let file = try binary(in: root)
            var rows = try XCTUnwrap(JSONSerialization.jsonObject(with: grantData(
                file, expires: Date().addingTimeInterval(3_600))) as? [[String: Any]])
            rows.append(["realpath": file.path, "sha256": "bad", "expiresAt": "future"])
            try JSONSerialization.data(withJSONObject: rows).write(to: storeURL())
            XCTAssertEqual(BinaryTransferGrants.load().grants.count, 0)
            XCTAssertNotNil(BinaryTransferGrants.load().warning)
            XCTAssertFalse(BinaryTransferGrants.permitsTransfer(path: file.path, bytes: try Data(contentsOf: file)))
        }
    }

    // WO-673@v2: missing grants keep the binary block and name an operator-only remedy.
    func testMissingGrantBlocksWithOperatorRemedy() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let file = try binary(in: root)
            let result = try run(["guard", "scp \(file.path) host:dst"], in: root)
            XCTAssertEqual(result.status, 2)
            XCTAssertTrue(result.output.contains("cannot be scanned safely"))
            XCTAssertTrue(result.output.contains("agents cannot grant this"))
        }
    }

    // WO-673@v2: valid user grants admit only transfer-source roles, not subsequent raw readers.
    func testValidGrantAdmitsTransfersButNotAnotherReader() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let file = try binary(in: root)
            try grant(file, expires: Date().addingTimeInterval(3_600))
            for command in ["scp -q \(file.path) host:dst", "rsync -q \(file.path) host:dst",
                            "cp -p \(file.path) dst", "cat \(file.path) | ssh host 'cat > dst'",
                            "cat < \(file.path) | ssh host 'cat > dst'"] {
                XCTAssertEqual(try run(["guard", command], in: root).status, 0)
            }
            for command in ["cat \(file.path)", "cp \(file.path) dst; cat \(file.path)",
                            "cat \(file.path); ssh host true", "cat \(file.path) || ssh host true",
                            "rsync --password-file \(file.path) clean.txt host:dst",
                            "rsync --password-file \(file.path) \(file.path) host:dst",
                            "scp -i \(file.path) \(file.path) host:dst"] {
                XCTAssertEqual(try run(["guard", command], in: root).status, 2)
            }
        }
    }

    // WO-673@v2: expiry, byte changes and symlink retargeting cannot reuse a previous grant.
    func testExpiredChangedAndRetargetedGrantsBlock() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let file = try binary(in: root)
            try grant(file, expires: Date().addingTimeInterval(-1))
            XCTAssertEqual(try run(["guard", "cp \(file.path) dst"], in: root).status, 2)
            try grant(file, expires: Date().addingTimeInterval(3_600))
            try Data([0xFF, 0x62]).write(to: file)
            XCTAssertEqual(try run(["guard", "cp \(file.path) dst"], in: root).status, 2)
            let link = root.appendingPathComponent("link.dat")
            try FileManager.default.createSymbolicLink(at: link, withDestinationURL: file)
            try grant(link, expires: Date().addingTimeInterval(3_600))
            XCTAssertEqual(try run(["guard", "cp \(link.path) dst"], in: root).status, 0)
            let other = try binary(in: root, name: "other.dat")
            try FileManager.default.removeItem(at: link)
            try FileManager.default.createSymbolicLink(at: link, withDestinationURL: other)
            XCTAssertEqual(try run(["guard", "cp \(link.path) dst"], in: root).status, 2)
        }
    }

    // WO-673@v2: project configuration and a project-local grant file never contribute admission.
    func testProjectGrantsAreIgnoredAndTextTransfersUnchanged() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let project = root.appendingPathComponent("project")
            try FileManager.default.createDirectory(at: project, withIntermediateDirectories: true)
            try TestConfigHelper.ensureProjectConfig(in: root)
            let file = try binary(in: project)
            let rows = try grantData(file, expires: Date().addingTimeInterval(3_600))
            try rows.write(to: project.appendingPathComponent("binary-grants.json"))
            var config = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(
                PastewatchConfig.defaultConfig)) as? [String: Any])
            config["binaryTransferGrants"] = try JSONSerialization.jsonObject(with: rows)
            try JSONSerialization.data(withJSONObject: config).write(to: project.appendingPathComponent(".pastewatch.json"))
            XCTAssertEqual(try run(["guard", "cp \(file.path) dst"], in: project).status, 2)
            let text = project.appendingPathComponent("clean.txt")
            try Data("clean text\n".utf8).write(to: text)
            XCTAssertEqual(try run(["guard", "scp \(text.path) host:dst"], in: project).status, 0)
        }
    }

    // WO-673@v2: wrappers, aliases and nested shells cannot invoke the operator valve through an agent.
    func testSelfGrantSpellingsBlockWithoutEchoingArguments() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let commands = ["env MODE=test pastewatch-cli allow-binary file.dat",
                            "command pastewatch-cli allow-binary file.dat",
                            "/opt/bin/pastewatch-cli allow-binary file.dat",
                            "alias grant='pastewatch-cli allow-binary'; grant file.dat",
                            "sh -c 'pastewatch-cli allow-binary file.dat'",
                            "bash -lc 'pastewatch-cli allow-binary file.dat'",
                            "/usr/bin/env MODE=test pastewatch-cli allow-binary file.dat",
                            "alias grant=pastewatch-cli; grant allow-binary file.dat",
                            "function grant { pastewatch-cli allow-binary file.dat; }"]
            for command in commands {
                let result = try run(["guard", command], in: root)
                XCTAssertEqual(result.status, 2)
                XCTAssertTrue(result.output.contains("agents cannot grant"))
                XCTAssertFalse(result.output.contains(command))
            }
            XCTAssertEqual(try run(["guard", "printf '%s' 'pastewatch-cli allow-binary'"], in: root).status, 0)
            XCTAssertEqual(try run(["guard", "printf '%s' 'x()' pastewatch-cli allow-binary"], in: root).status, 0)
            // WO-673@v2: a function declaration is outside the pure-printing exception.
            XCTAssertEqual(try run(["guard", "function printer { printf '%s' pastewatch-cli allow-binary; }"], in: root).status, 2)
        }
    }

    // WO-673@v2: an indirect executable cannot invoke the operator-only grant command.
    func testVariableExecutableCannotGrantTransfers() throws {
        try assertGrantExpansionRefused("pw=pastewatch-cli; $pw allow-binary file.dat")
    }

    // WO-673@v2: an indirect subcommand cannot acquire operator-only grant authority.
    func testVariableSubcommandCannotGrantTransfers() throws {
        try assertGrantExpansionRefused("x=allow-binary; pastewatch-cli $x file.dat")
    }

    // WO-673@v2: separately expanded subcommand fragments still cross the same boundary.
    func testConcatenatedVariableSubcommandCannotGrantTransfers() throws {
        try assertGrantExpansionRefused("a=allow; b=-binary; pastewatch-cli $a$b file.dat")
    }

    // WO-673@v2: command substitution cannot conceal the executable's grant authority.
    func testCommandSubstitutionExecutableCannotGrantTransfers() throws {
        try assertGrantExpansionRefused("$(echo pastewatch-cli) allow-binary file.dat")
    }

    // WO-673@v2: backtick substitution has the same authority boundary as dollar substitution.
    func testBacktickExecutableCannotGrantTransfers() throws {
        try assertGrantExpansionRefused("`echo pastewatch-cli` allow-binary file.dat")
    }

    // WO-673@v2: evaluating a quoted command cannot cross the operator-only boundary.
    func testEvalCannotGrantTransfers() throws {
        try assertGrantExpansionRefused("eval 'pastewatch-cli allow-binary file.dat'")
    }

    // WO-673@v2: stdin-driven argv execution cannot acquire grant authority.
    func testXargsCannotGrantTransfers() throws {
        try assertGrantExpansionRefused("xargs pastewatch-cli allow-binary <<< file.dat")
    }

    // WO-673@v2: a command dispatched by a file traversal cannot grant transfers.
    func testFindExecCannotGrantTransfers() throws {
        try assertGrantExpansionRefused("find . -name x -exec pastewatch-cli allow-binary {} \\;")
    }

    // WO-673@v2: a time-limited execution wrapper does not convey operator authority.
    func testTimeoutCannotGrantTransfers() throws {
        try assertGrantExpansionRefused("timeout 5 pastewatch-cli allow-binary file.dat")
    }

    // WO-673@v2: detached execution retains the same grant boundary.
    func testNohupCannotGrantTransfers() throws {
        try assertGrantExpansionRefused("nohup pastewatch-cli allow-binary file.dat")
    }

    // WO-673@v2: a privilege wrapper cannot make an agent command operator-owned.
    func testSudoCannotGrantTransfers() throws {
        try assertGrantExpansionRefused("sudo pastewatch-cli allow-binary file.dat")
    }

    // WO-673@v2: a split-string executable retains the literal grant marker.
    func testEnvSplitStringCannotGrantTransfers() throws {
        try assertGrantExpansionRefused("env -S 'pastewatch-cli allow-binary file.dat'")
    }

    // WO-673@v2: pure printing and commands missing either grant marker remain allowed.
    func testPurePrintingAndUnrelatedCommandsRemainAllowed() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            for command in ["echo pastewatch-cli allow-binary is operator only",
                            "printf '%s\\n' 'pastewatch-cli allow-binary'",
                            "grep -r allow-binary docs/", "pastewatch-cli version"] {
                XCTAssertEqual(try run(["guard", command], in: root).status, 0)
            }
        }
    }

    // WO-673@v2: unrelated expansions and prose mentions cannot become grant invocations.
    func testUnrelatedExpansionsAndMentionOnlyCommandsRemainAllowed() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let file = root.appendingPathComponent("clean.txt")
            try "ordinary text".write(to: file, atomically: true, encoding: .utf8)
            for command in ["echo $HOME", "scp $F host:/tmp/x",
                            "echo pastewatch-cli allow-binary is operator only", "MODE=$HOME pastewatch-cli check --help",
                            "env MODE=$HOME /opt/bin/PastewatchCLI check --help"] {
                XCTAssertEqual(try run(["guard", command], in: root, environment: ["F": file.path]).status, 0)
            }
            // WO-673@v2: an assignment-only segment is not a pure echo or printf.
            XCTAssertEqual(try run(["guard", "pw=$HOME; echo pastewatch-cli allow-binary is operator only"],
                                   in: root, environment: ["F": file.path]).status, 2)
        }
    }

    // WO-673@v2: each CLI regression uses isolated policy and checks value-free operator guidance.
    private func assertGrantExpansionRefused(_ command: String) throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let result = try run(["guard", command], in: root)
            XCTAssertEqual(result.status, 2)
            XCTAssertTrue(result.output.contains("agents cannot grant this"))
            XCTAssertFalse(result.output.contains(command))
        }
    }

    // WO-673@v2: malformed user stores fail closed and are visible in both doctor forms.
    func testMalformedStoreBlocksAndDoctorWarns() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let file = try binary(in: root)
            try Data("not-json".utf8).write(to: storeURL())
            XCTAssertEqual(try run(["guard", "cp \(file.path) dst"], in: root).status, 2)
            for arguments in [["doctor", "--json"], ["doctor", "--explain", "--json"]] {
                let output = try run(arguments, in: root).output
                XCTAssertTrue(output.contains("binary-grants"))
                XCTAssertTrue(output.contains("warn"))
            }
        }
    }

    // WO-673@v2: grant creation is atomic and private without rewriting the isolated user config.
    func testCommandStoresPrivateCoexistingGrantsAndPreservesConfigBytes() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            try TestConfigHelper.ensureProjectConfig(in: root)
            let original = try Data(contentsOf: PastewatchConfig.configPath)
            let file = try binary(in: root)
            let other = try binary(in: root, name: "other.dat")
            XCTAssertEqual(try run(["allow-binary", file.path], in: root).status, 0)
            XCTAssertEqual(try run(["allow-binary", other.path, "--ttl", "24h"], in: root).status, 0)
            let rows = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: storeURL())) as? [[String: Any]])
            XCTAssertEqual(rows.count, 2)
            XCTAssertEqual(Set(rows.first?.keys.map { $0 } ?? []), ["realpath", "sha256", "expiresAt"])
            let mode = try FileManager.default.attributesOfItem(atPath: storeURL().path)[.posixPermissions] as? NSNumber
            XCTAssertEqual(mode?.intValue, 0o600)
            XCTAssertTrue(try Data(contentsOf: PastewatchConfig.configPath) == original)
            XCTAssertNotEqual(try run(["allow-binary", file.path, "--ttl", "25h"], in: root).status, 0)
        }
    }

    // WO-673@v2: native hooks protect canonical policy targets, including aliases and nonexistent stores.
    func testAgentHooksRefuseUserPolicyFiles() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let alias = root.appendingPathComponent("alias.json")
            try FileManager.default.createSymbolicLink(at: alias, withDestinationURL: PastewatchConfig.configPath)
            for file in [PastewatchConfig.configPath, storeURL(), alias] {
                XCTAssertTrue(GuardDecision.isOperatorOwnedPath(file.path))
                XCTAssertEqual(try run(["guard-write", file.path], in: root).status, 2)
                let input = try JSONSerialization.data(withJSONObject: [
                    "tool_name": "Write", "tool_input": ["file_path": file.path, "content": "clean"]
                ])
                XCTAssertEqual(try run(["guard-mutation"], in: root, input: input).status, 2)
            }
        }
    }

    // WO-673@v2: MCP write and span edit refuse both user policy files before content inspection.
    func testMCPRefusesPolicyWriteAndEdit() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            let session = try MCPProtocolTests.LiveMCPSession(executableURL: cliURL(), maximumLineBytes: 65_536)
            defer { session.close() }
            for file in [PastewatchConfig.configPath, storeURL()] {
                for name in ["pastewatch_write_file", "pastewatch_edit_file"] {
                    let request = JSONRPCRequest(jsonrpc: "2.0", id: .int(1), method: "tools/call", params: .object([
                        "name": .string(name), "arguments": .object([
                            "path": .string(file.path), "content": .string("clean"),
                            "old_string": .string("before"), "new_string": .string("after")
                        ])
                    ]))
                    try session.send(JSONEncoder().encode(request) + Data([0x0A]))
                    guard case .object(let result) = try XCTUnwrap(session.response()).result else {
                        return XCTFail("Missing tool refusal")
                    }
                    XCTAssertEqual(result["isError"], .bool(true))
                    let encoded = try JSONEncoder().encode(JSONValue.object(result))
                    XCTAssertTrue(try XCTUnwrap(String(data: encoded, encoding: .utf8)).contains(GuardDecision.operatorOwnedFileMessage))
                }
            }
        }
    }

    // WO-673@v2: generated invalid UTF-8 fixtures never contain credential material.
    private func binary(in root: URL, name: String = "fixture.dat") throws -> URL {
        let file = root.appendingPathComponent(name)
        try Data([0xFF, 0x61]).write(to: file)
        return file
    }

    // WO-673@v2: test stores share the production user-directory resolver through the DEBUG seam.
    private func storeURL() -> URL {
        PastewatchConfig.configPath.deletingLastPathComponent().appendingPathComponent("binary-grants.json")
    }

    // WO-673@v2: fixtures preserve the public grant schema without reaching any operator file.
    private func grantData(_ file: URL, expires: Date) throws -> Data {
        let hash = SHA256.hash(data: try Data(contentsOf: file)).map { String(format: "%02x", $0) }.joined()
        let path = try XCTUnwrap(realpath(file.path, nil))
        defer { free(path) }
        return try JSONSerialization.data(withJSONObject: [[
            "realpath": String(cString: path), "sha256": hash,
            "expiresAt": ISO8601DateFormatter().string(from: expires)
        ]])
    }

    // WO-673@v2: fixture grants are written only inside a scoped test-owned user directory.
    private func grant(_ file: URL, expires: Date) throws {
        try grantData(file, expires: expires).write(to: storeURL())
    }

    // WO-673@v2: capture only fixed diagnostics and never include file bytes in failure output.
    private struct Output {
        let status: Int32
        let output: String
    }

    // WO-673@v2: subprocesses inherit only the DEBUG policy fixture and pipe mutation inputs through stdin.
    private func run(
        _ arguments: [String], in root: URL, input: Data = Data(), environment: [String: String] = [:]
    ) throws -> Output {
        let process = Process()
        process.executableURL = cliURL()
        process.arguments = arguments
        process.currentDirectoryURL = root
        // WO-673@v2: expansion controls receive only named fixture variables, never the inherited environment.
        process.environment = TestConfigHelper.subprocessEnvironment(
            ["PATH": "/usr/bin:/bin", "PW_GUARD": "1"].merging(environment) { _, value in value })
        let stdin = Pipe()
        let stdout = Pipe()
        let stderr = Pipe()
        process.standardInput = stdin
        process.standardOutput = stdout
        process.standardError = stderr
        try process.run()
        try stdin.fileHandleForWriting.write(contentsOf: input)
        try stdin.fileHandleForWriting.close()
        let output = stdout.fileHandleForReading.readDataToEndOfFile()
        let errors = stderr.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return Output(status: process.terminationStatus, output: try XCTUnwrap(String(data: output + errors, encoding: .utf8)))
    }

    // WO-673@v2: execute the freshly built debug binary, never an installed server.
    private func cliURL() -> URL {
        URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().appendingPathComponent(".build/debug/PastewatchCLI")
    }
}
