import XCTest
@testable import PastewatchCore

final class PhoneMatchBoundaryTests: XCTestCase {
    // WO-683@v1: offsets and values refer only to the phone, including after an astral prefix.
    func testPhoneSpansExcludeSurroundingWhitespaceAndDelimiters() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            let config = TestConfigHelper.configWithAmbiguousAdvisories([.phone])
            let astral = String(try XCTUnwrap(UnicodeScalar(0x1F680)))
            for phone in phoneFixtures() {
                for context in contexts(phone) {
                    let content = "heading\n" + astral + " " + context + "\n"
                    let matches = DetectionRules.scan(content, config: config).filter { $0.type == .phone }
                    XCTAssertEqual(matches.count, 1)
                    let match = try XCTUnwrap(matches.first)
                    XCTAssertTrue(match.value == phone)
                    XCTAssertTrue(String(content[match.range]) == phone)
                    XCTAssertEqual(NSRange(match.range, in: content), (content as NSString).range(of: phone))
                    XCTAssertEqual(match.line, 2)
                }
            }
        }
    }

    // WO-683@v1: exact advisory values work in both remedy files and the target project's allow file.
    func testExactPhoneExemptionsWorkInProse() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let config = TestConfigHelper.configWithAmbiguousAdvisories([.phone])
            try JSONEncoder().encode(config).write(to: PastewatchConfig.configPath)
            XCTAssertEqual(try run(["init", "--quiet"], root: root, executable: "/usr/bin/git"), 0)
            let target = root.appendingPathComponent("fixture.txt")
            let remedy = root.appendingPathComponent("remedy.txt")
            let project = root.appendingPathComponent(".pastewatch-allow")
            for phone in phoneFixtures() {
                for content in contexts(phone) {
                    try Data((content + "\n").utf8).write(to: target)
                    let scan = ["scan", "--check", "--file", target.path]
                    XCTAssertEqual(try run(scan, root: root), 6)
                    try Data((phone + "\n").utf8).write(to: remedy)
                    XCTAssertEqual(try run(scan + ["--allowlist", remedy.path], root: root), 0)
                    try Data((phone + "\n").utf8).write(to: project)
                    XCTAssertEqual(try run(scan, root: root), 0)
                    try FileManager.default.removeItem(at: project)
                    try Data((phone + "x\n").utf8).write(to: remedy)
                    XCTAssertEqual(try run(scan + ["--allowlist", remedy.path], root: root), 6)
                }
            }
        }
    }

    // WO-683@v1: the other audited detector families do not claim external whitespace.
    func testOtherDetectorFamiliesExcludeOuterWhitespace() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            for fixture in auditFixtures() {
                var config = PastewatchConfig.defaultConfig
                config.enabledTypes = [fixture.type.rawValue]
                config.obfuscate = [ObfuscateEntry(type: "email", pattern: "@example.test"),
                    ObfuscateEntry(type: "host", pattern: ".corp")]
                let content = " \t" + fixture.content + "\t \n"
                let matches = DetectionRules.scan(content, config: config).filter { $0.type == fixture.type }
                XCTAssertEqual(matches.count, 1, fixture.type.rawValue)
                let match = try XCTUnwrap(matches.first)
                XCTAssertTrue(match.value == match.value.trimmingCharacters(in: .whitespacesAndNewlines), fixture.type.rawValue)
                XCTAssertTrue(String(content[match.range]) == match.value, fixture.type.rawValue)
            }
        }
    }

    // WO-683@v1: source contexts exercise whitespace, sentence punctuation, quotes and tel prefixes.
    private func contexts(_ phone: String) -> [String] {
        ["call me at " + phone + " today", phone + " follows", "tel:" + phone + " next",
         "number=\"" + phone + "\"", "(" + phone + ")", phone + ".", phone + "- next"]
    }

    // WO-683@v1: runtime fragments keep complete phone fixtures out of source.
    private func phoneFixtures() -> [String] {
        [["+", "65", " ", "6123", " ", "4567"], ["+", "1", "415", "555", "0132"],
         ["(", "415", ") ", "555", "-", "0132"]].map { $0.joined() }
    }

    // WO-683@v1: audit examples are assembled without embedding complete matched values.
    private func auditFixtures() -> [AuditFixture] {
        let key = ["pass", "word"].joined()
        let value = ["range", "-fixture", "-Q8n5", "R4m2"].joined()
        return [
            AuditFixture(type: .email, content: ["range", "@", "example", ".test"].joined()),
            AuditFixture(type: .hostname, content: ["vault", ".", "dept", ".", "corp"].joined()),
            AuditFixture(type: .ipAddress, content: ["10", "23", "45", "67"].joined(separator: ".")),
            AuditFixture(type: .filePath, content: ["/var", "/lib", "/fixture", "/data"].joined()),
            AuditFixture(type: .uuid, content: ["8d7e3f21", "2b46", "4c89", "a1b2", "c3d4e5f60718"].joined(separator: "-")),
            AuditFixture(type: .credential, content: key + "=\"" + value + "\""),
            AuditFixture(type: .xmlCredential, content: "<" + key + ">" + value + "</" + key + ">"),
            AuditFixture(type: .xmlUsername, content: "<user>" + ["range", "-user"].joined() + "</user>"),
            AuditFixture(type: .xmlHostname, content: "<host>" + ["vault", ".dept", ".corp"].joined() + "</host>")
        ]
    }

    // WO-683@v1: subprocess scans never use operator config or expose captured fixture output.
    private func run(_ arguments: [String], root: URL, executable: String? = nil) throws -> Int32 {
        let repository = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        let process = Process()
        process.executableURL = executable.map { URL(fileURLWithPath: $0) }
            ?? repository.appendingPathComponent(".build/debug/PastewatchCLI")
        process.arguments = arguments
        process.currentDirectoryURL = root
        // WO-687@v2: fixture processes need no guard environment switch.
        process.environment = TestConfigHelper.subprocessEnvironment(["PATH": "/usr/bin:/bin", "HOME": root.path])
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        process.waitUntilExit()
        return process.terminationStatus
    }

    // WO-683@v1: audit metadata identifies families without disclosing their fixture values.
    private struct AuditFixture {
        let type: SensitiveDataType
        let content: String
    }
}
