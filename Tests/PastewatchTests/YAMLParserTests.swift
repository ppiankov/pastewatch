import XCTest
@testable import PastewatchCore

final class YAMLParserTests: XCTestCase {
    let parser = YAMLValueParser()

    // WO-716@v2: inline comments and surrounding quotes are syntax rather than scalar bytes.
    func testQuotedScalarsDropInlineComments() {
        let value = ["sample", "scalar"].joined(separator: "-")
        for quote in ["\"", "'"] {
            for whitespace in [" ", "\t"] {
                let values = parser.parseValues(from: "field: " + quote + value + quote + whitespace + "# note\n")
                XCTAssertEqual(values.count, 1)
                XCTAssertTrue(values.first?.value == value)
            }
        }
    }

    // WO-716@v2: escaped quote delimiters and hashes inside quotes remain part of the source scalar.
    func testQuotedEscapesDoNotEndScalarsEarly() {
        let doubleQuoted = "sample" + "\\\"" + " # retained"
        let singleQuoted = "sample" + "''" + " # retained"
        for (quote, value) in [("\"", doubleQuoted), ("'", singleQuoted)] {
            let values = parser.parseValues(from: "field: " + quote + value + quote + " # outside\n")
            XCTAssertEqual(values.count, 1)
            XCTAssertTrue(values.first?.value == value)
        }
    }

    // WO-716@v2: only a whitespace-delimited hash starts a plain scalar's inline comment.
    func testUnquotedCommentsRequirePrecedingWhitespace() {
        for whitespace in [" ", "\t"] {
            let values = parser.parseValues(from: "field: sample" + whitespace + "# outside\n")
            XCTAssertEqual(values.count, 1)
            XCTAssertTrue(values.first?.value == "sample")
        }
        let values = parser.parseValues(from: "field: a#b\n")
        XCTAssertEqual(values.count, 1)
        XCTAssertTrue(values.first?.value == "a#b")
    }

    // WO-716@v2: parsed credential targeting must exclude quotes and comments without changing source mapping.
    func testKeyAwareCredentialRangeContainsOnlyScalarBytes() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            let key = "pass" + "word"
            let base = ["Q7mN", "4rZ9", "T2xV", "8bD5"].joined()
            let config = TestConfigHelper.configWithAmbiguousAdvisories([.credential])
            for (quote, suffix) in [("\"", ""), ("'", ""), ("\"", "\\\" # inside"), ("'", "'' # inside"), ("", "")] {
                let value = base + suffix
                let content = "name: sample\n" + key + ": " + quote + value + quote + "  # outside\n"
                let matches = try DirectoryScanner.scanFileContentOrThrow(
                    content: content, ext: "yaml", relativePath: "fixture.yaml", config: config
                ).filter { $0.type == .credential }
                XCTAssertEqual(matches.count, 1)
                guard let match = matches.first else { continue }
                XCTAssertEqual(match.line, 2)
                XCTAssertEqual(match.effectiveSeverity, .critical)
                XCTAssertTrue(match.value == value)
                XCTAssertTrue(String(content[match.range]) == value)
            }
        }
    }

    func testParsesKeyValuePairs() {
        let content = "host: db.internal.net\nport: 5432\n"
        let values = parser.parseValues(from: content)
        XCTAssertEqual(values.count, 2)
        XCTAssertEqual(values[0].value, "db.internal.net")
        XCTAssertEqual(values[0].key, "host")
        XCTAssertEqual(values[0].line, 1)
    }

    func testSkipsComments() {
        let content = "# comment\nkey: value\n"
        let values = parser.parseValues(from: content)
        XCTAssertEqual(values.count, 1)
    }

    func testHandlesQuotedValues() {
        let content = "name: \"quoted value\"\nother: 'single'\n"
        let values = parser.parseValues(from: content)
        XCTAssertEqual(values.count, 2)
        XCTAssertEqual(values[0].value, "quoted value")
        XCTAssertEqual(values[1].value, "single")
    }

    func testSkipsDocumentMarkers() {
        let content = "---\nkey: value\n...\n"
        let values = parser.parseValues(from: content)
        XCTAssertEqual(values.count, 1)
    }

    func testHandlesListItems() {
        let content = "hosts:\n  - name: host1.corp.net\n  - name: host2.corp.net\n"
        let values = parser.parseValues(from: content)
        let hostValues = values.filter { $0.key == "name" }
        XCTAssertEqual(hostValues.count, 2)
    }

    func testSkipsBlockMappingKeys() {
        let content = "database:\n  host: db.corp.net\n"
        let values = parser.parseValues(from: content)
        XCTAssertEqual(values.count, 1)
        XCTAssertEqual(values[0].value, "db.corp.net")
    }
}
