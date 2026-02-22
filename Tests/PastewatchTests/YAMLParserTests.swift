import XCTest
@testable import PastewatchCore

final class YAMLParserTests: XCTestCase {
    let parser = YAMLValueParser()

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
