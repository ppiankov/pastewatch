import XCTest
@testable import PastewatchCore

// WO-718@v2: skipping unused scans must preserve every source of structured-file custom evidence.
final class ParsedFormatRawScanGuardTests: XCTestCase {
    // WO-718@v2: comparisons carry locations and rule identity, never matched values.
    private struct Finding: Hashable {
        let type: SensitiveDataType
        let line: Int
        let customRuleName: String?
        let bytes: Range<Int>
    }

    // WO-718@v2: source-only anchors distinguish the raw pass from parsed-value detection.
    private struct Fixture {
        let ext: String
        let content: String
        let anchor: String
        let baseline: Set<Finding>
        let customFinding: Finding

        // WO-718@v2: fixed source context cannot match a parser's isolated value.
        var rule: CustomRuleConfig {
            CustomRuleConfig(name: "source-context",
                pattern: "(?<=" + NSRegularExpression.escapedPattern(for: anchor) + ")[A-Za-z0-9]+")
        }
    }

    // WO-718@v2: fixture prefixes provide independent byte-coordinate expectations.
    private struct Layout {
        let ext: String
        let prefix: String
        let separator: String
        let anchor: String
        let suffix: String
        let entryLine: Int
        let noteLine: Int
    }

    // WO-718@v2: configured rules and injected rules reach the scanner through different inputs.
    private enum RuleSource {
        case none, argument, configuration, sharedFile
    }

    // WO-718@v2: XML still needs raw tag detection when no custom source exists.
    func testNoRulesPreserveBuiltInFindings() throws {
        try assertFindings(source: .none)
    }

    // WO-718@v2: explicitly supplied rules retain their key-anchored source match.
    func testExplicitRulesKeepSourceContext() throws {
        try assertFindings(source: .argument)
    }

    // WO-718@v2: MCP-style callers rely on configuration despite the default-empty argument.
    func testConfiguredRulesKeepSourceContext() throws {
        try assertFindings(source: .configuration)
    }

    // WO-718@v2: shared artifacts are effective rule sources without either customRules list.
    func testSharedPatternRulesKeepSourceContext() throws {
        try assertFindings(source: .sharedFile)
    }

    // WO-718@v2: invalid configured rules must not change the existing built-in findings.
    func testInvalidConfiguredRulePreservesBuiltInFindings() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            for fixture in fixtures() {
                var config = PastewatchConfig.defaultConfig
                config.customRules = [.init(name: "invalid-control", pattern: "[")]
                let matches = try DirectoryScanner.scanFileContentOrThrow(content: fixture.content,
                    ext: fixture.ext, relativePath: "fixture." + fixture.ext, config: config)
                XCTAssertEqual(locations(matches, in: fixture.content), fixture.baseline, fixture.ext)
                XCTAssertEqual(matches.count, fixture.baseline.count, fixture.ext)
            }
        }
    }

    // WO-718@v2: unreadable configured artifacts remain a failure rather than proof of no rules.
    func testUnreadableSharedPatternFileStillFailsClosed() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            for fixture in fixtures() {
                var config = PastewatchConfig.defaultConfig
                config.sharedPatternFiles = [root.appendingPathComponent("missing-patterns.json").path]
                XCTAssertThrowsError(try DirectoryScanner.scanFileContentOrThrow(content: fixture.content,
                    ext: fixture.ext, relativePath: "fixture." + fixture.ext, config: config)) { error in
                    XCTAssertTrue(error is SharedSecretPatternLoadError, fixture.ext)
                }
            }
        }
    }

    // WO-718@v2: independent pre-change expectations cover all sixteen format/source combinations.
    private func assertFindings(source: RuleSource) throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            for fixture in fixtures() {
                let matches = try scan(fixture, source: source, root: root)
                var expected = fixture.baseline
                if source != .none { expected.insert(fixture.customFinding) }
                XCTAssertEqual(locations(matches, in: fixture.content), expected, fixture.ext)
                XCTAssertEqual(matches.count, expected.count, fixture.ext)
            }
        }
    }

    // WO-718@v2: configuration-only cases deliberately omit the explicit argument, like MCP read.
    private func scan(_ fixture: Fixture, source: RuleSource, root: URL) throws -> [DetectedMatch] {
        var config = PastewatchConfig.defaultConfig
        switch source {
        case .none, .argument:
            break
        case .configuration:
            config.customRules = [fixture.rule]
        case .sharedFile:
            let file = root.appendingPathComponent("patterns-" + fixture.ext + ".json")
            let manifest = SharedSecretPatternManifest(patterns: [
                .init(name: fixture.rule.name, regex: fixture.rule.pattern)
            ])
            try JSONEncoder().encode(manifest).write(to: file)
            config.sharedPatternFiles = [file.path]
        }
        if source == .argument {
            return try DirectoryScanner.scanFileContentOrThrow(content: fixture.content,
                ext: fixture.ext, relativePath: "fixture." + fixture.ext, config: config,
                customRules: CustomRule.compile([fixture.rule]))
        }
        return try DirectoryScanner.scanFileContentOrThrow(content: fixture.content,
            ext: fixture.ext, relativePath: "fixture." + fixture.ext, config: config)
    }

    // WO-718@v2: expected ranges come from literal fixture layout, not the detector under test.
    private func fixtures() -> [Fixture] {
        let value = "AK" + "IA" + String(repeating: "Q", count: 16)
        let note = ["fixture", "note", "7"].joined()
        let layouts = [
            Layout(ext: "json", prefix: "{\n  \"entry\": \"", separator: "\",\n  ",
                   anchor: "\"note\": \"", suffix: "\"\n}\n", entryLine: 2, noteLine: 3),
            Layout(ext: "yaml", prefix: "entry: \"", separator: "\"\n",
                   anchor: "note: \"", suffix: "\"\n", entryLine: 1, noteLine: 2),
            Layout(ext: "properties", prefix: "entry=", separator: "\n",
                   anchor: "note=", suffix: "\n", entryLine: 1, noteLine: 2)
        ]
        return layouts.map { layout in
            let beforeNote = layout.prefix + value + layout.separator + layout.anchor
            let lower = layout.prefix.utf8.count
            return Fixture(ext: layout.ext, content: beforeNote + note + layout.suffix, anchor: layout.anchor,
                baseline: [Finding(type: .awsKey, line: layout.entryLine, customRuleName: nil,
                                   bytes: lower..<(lower + value.utf8.count))],
                customFinding: Finding(type: .credential, line: layout.noteLine, customRuleName: "source-context",
                                       bytes: beforeNote.utf8.count..<(beforeNote.utf8.count + note.utf8.count)))
        } + [xmlFixture(note: note)]
    }

    // WO-718@v2: parsed XML credentials and raw tag findings are separate pre-change results.
    private func xmlFixture(note: String) -> Fixture {
        let tag = ["pass", "word"].joined()
        let value = ["fixture", "phrase", "7"].joined()
        let prefix = "<config>\n  "
        let opening = "<" + tag + ">"
        let element = opening + value + "</" + tag + ">"
        let anchor = "<note>"
        let beforeNote = prefix + element + "\n  " + anchor
        let valueStart = prefix.utf8.count + opening.utf8.count
        return Fixture(ext: "xml", content: beforeNote + note + "</note>\n</config>\n", anchor: anchor,
            baseline: [
                Finding(type: .credential, line: 2, customRuleName: nil,
                        bytes: valueStart..<(valueStart + value.utf8.count)),
                Finding(type: .xmlCredential, line: 2, customRuleName: nil,
                        bytes: prefix.utf8.count..<(prefix.utf8.count + element.utf8.count))
            ],
            customFinding: Finding(type: .credential, line: 3, customRuleName: "source-context",
                                   bytes: beforeNote.utf8.count..<(beforeNote.utf8.count + note.utf8.count)))
    }

    // WO-718@v2: byte offsets avoid platform-dependent String.Index storage in assertion diagnostics.
    private func locations(_ matches: [DetectedMatch], in content: String) -> Set<Finding> {
        Set(matches.map { match in
            Finding(type: match.type, line: match.line, customRuleName: match.customRuleName,
                bytes: content.utf8.distance(from: content.utf8.startIndex, to: match.range.lowerBound)..<content.utf8.distance(
                    from: content.utf8.startIndex, to: match.range.upperBound))
        })
    }
}
