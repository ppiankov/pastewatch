import XCTest
@testable import PastewatchCore

final class ScanProjectExemptionTests: XCTestCase {
    // WO-692@v1: file and directory JSON locate the same existing fixture without inspecting its value.
    func testFileAndDirectoryJSONFindingsCarryOneBasedLine() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let fixture = fixtures()[0]
            try JSONEncoder().encode(fixture.config).write(to: PastewatchConfig.configPath)
            let directory = root.appendingPathComponent("files")
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            let target = directory.appendingPathComponent("fixture.txt")
            try Data(("first line\nsecond line\n" + fixture.content + "\n").utf8).write(to: target)
            for arguments in [["--file", target.path], ["--dir", directory.path]] {
                let result = try run(["scan", "--format", "json"] + arguments, root: root)
                XCTAssertEqual(result.status, 6)
                let decoded = try JSONSerialization.jsonObject(with: result.output)
                let output = try XCTUnwrap(decoded as? [String: Any] ?? (decoded as? [[String: Any]])?.first)
                let findings = try XCTUnwrap(output["findings"] as? [[String: Any]])
                XCTAssertEqual(findings.count, 1)
                XCTAssertEqual(findings.first?["line"] as? Int, 3)
            }
        }
    }

    // WO-682@v2: file and stdin JSON derive eligibility from real detector evidence.
    func testFileAndStdinJSONExposeProjectExemptionEligibility() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            for fixture in fixtures() {
                try JSONEncoder().encode(fixture.config).write(to: PastewatchConfig.configPath)
                let target = root.appendingPathComponent("fixture.txt")
                try Data(fixture.content.utf8).write(to: target)
                for checked in [false, true] {
                    let arguments = ["scan", "--format", "json"] + (checked ? ["--check"] : [])
                    let fileResult = try run(arguments + ["--file", target.path], root: root)
                    let stdinResult = try run(arguments, root: root, input: Data(fixture.content.utf8))
                    for result in [fileResult, stdinResult] {
                        XCTAssertEqual(result.status, 6, fixture.name)
                        let output = try XCTUnwrap(JSONSerialization.jsonObject(with: result.output) as? [String: Any])
                        let findings = try XCTUnwrap(output["findings"] as? [[String: Any]])
                        assertEligibility(findings, fixture: fixture)
                        XCTAssertEqual(output["count"] as? Int, findings.count)
                    }
                }
            }
        }
    }

    // WO-682@v2: directory JSON remains a per-file array with additive finding metadata.
    func testDirectoryJSONPreservesArrayShapeAndAddsEligibility() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let fixture = fixtures()[0]
            try JSONEncoder().encode(fixture.config).write(to: PastewatchConfig.configPath)
            let directory = root.appendingPathComponent("files")
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            try Data(fixture.content.utf8).write(to: directory.appendingPathComponent("fixture.txt"))
            for checked in [false, true] {
                let result = try run(["scan", "--dir", directory.path, "--format", "json"]
                    + (checked ? ["--check"] : []), root: root)
                XCTAssertEqual(result.status, 6)
                let files = try XCTUnwrap(JSONSerialization.jsonObject(with: result.output) as? [[String: Any]])
                XCTAssertEqual(files.count, 1)
                let output = try XCTUnwrap(files.first)
                XCTAssertEqual(Set(output.keys), ["file", "findings", "count", "gitignored"])
                let findings = try XCTUnwrap(output["findings"] as? [[String: Any]])
                assertEligibility(findings, fixture: fixture)
            }
        }
    }

    // WO-682@v3: compatibility checks compare metadata without printing matched values.
    // WO-707@v3: scan authority is independent of project-exemption eligibility.
    private func assertEligibility(
        _ findings: [[String: Any]], fixture: Fixture, file: StaticString = #filePath, line: UInt = #line
    ) {
        XCTAssertEqual(findings.count, 1, fixture.name, file: file, line: line)
        for finding in findings {
            // WO-692@v2: the source line is additive; all existing finding fields remain present.
            // WO-707@v3: authority adds a verdict without implying a non-mutating scan masked its value.
            XCTAssertEqual(Set(finding.keys), ["type", "value", "severity", "projectExemptible", "line", "authority"], file: file, line: line)
            XCTAssertEqual(finding["authority"] as? String, fixture.authority, fixture.name, file: file, line: line)
            XCTAssertEqual(finding["projectExemptible"] as? Bool, fixture.exemptible, fixture.name, file: file, line: line)
            XCTAssertTrue(finding["value"] as? String == fixture.content, file: file, line: line)
        }
    }

    // WO-682@v3: policy controls assemble values at runtime instead of storing complete fixtures.
    // WO-707@v3: each fixture pins authority independently of its exemption expectation.
    private func fixtures() -> [Fixture] {
        let intrinsic = ["AKIA", "QWERTYUIOPASDFGH"].joined()
        let custom = ["operator", "-fixture", "-R7m4"].joined()
        let phone = ["+", "65", " ", "6123", " ", "4567"].joined()
        var advisory = PastewatchConfig.defaultConfig
        advisory.enabledTypes.append(SensitiveDataType.phone.rawValue)
        var rules = PastewatchConfig.defaultConfig
        rules.customRules = [CustomRuleConfig(name: "operator-fixture",
            pattern: NSRegularExpression.escapedPattern(for: custom), severity: "critical")]
        return [
            // WO-707@v3: advisory, intrinsic and custom evidence exercise distinct policy outcomes.
            Fixture(name: "Phone", content: phone, config: advisory, exemptible: true, authority: "advisory"),
            Fixture(name: "intrinsic", content: intrinsic, config: .defaultConfig, exemptible: false, authority: "mutate"),
            Fixture(name: "custom", content: custom, config: rules, exemptible: false, authority: "mutate")
        ]
    }

    // WO-682@v2: child processes preserve DEBUG policy isolation and explicitly enable guard enforcement.
    private func run(_ arguments: [String], root: URL, input: Data = Data()) throws -> CommandResult {
        let repository = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        let process = Process()
        process.executableURL = repository.appendingPathComponent(".build/debug/PastewatchCLI")
        process.arguments = arguments
        process.currentDirectoryURL = root
        // WO-687@v2: scanning runs under fixture policy without guard toggles.
        process.environment = TestConfigHelper.subprocessEnvironment(["PATH": "/usr/bin:/bin"])
        let stdin = Pipe(), stdout = Pipe()
        process.standardInput = stdin
        process.standardOutput = stdout
        process.standardError = FileHandle.nullDevice
        try process.run()
        stdin.fileHandleForWriting.write(input)
        try stdin.fileHandleForWriting.close()
        let output = stdout.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return CommandResult(status: process.terminationStatus, output: output)
    }

    // WO-682@v3: fixture metadata is distinct from captured secret-bearing output.
    private struct Fixture {
        let name: String
        let content: String
        let config: PastewatchConfig
        let exemptible: Bool
        // WO-707@v3: expected authority is an explicit fixture contract, not inferred from exemption metadata.
        let authority: String
    }

    // WO-682@v2: tests never emit captured child payloads in assertion messages.
    private struct CommandResult {
        let status: Int32
        let output: Data
    }
}
