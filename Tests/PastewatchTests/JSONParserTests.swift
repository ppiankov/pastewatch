import XCTest
@testable import PastewatchCore

final class JSONParserTests: XCTestCase {
    let parser = JSONValueParser()

    func testExtractsStringValues() {
        let content = "{\"name\": \"test\", \"url\": \"https://example.com\"}"
        let values = parser.parseValues(from: content)
        XCTAssertEqual(values.count, 2)
        let valueStrings = values.map { $0.value }
        XCTAssertTrue(valueStrings.contains("test"))
        XCTAssertTrue(valueStrings.contains("https://example.com"))
    }

    func testExtractsNestedValues() {
        let content = "{\"db\": {\"host\": \"internal.corp.net\", \"port\": 5432}}"
        let values = parser.parseValues(from: content)
        // Should extract "internal.corp.net" but not 5432 (integer)
        XCTAssertEqual(values.count, 1)
        XCTAssertEqual(values[0].value, "internal.corp.net")
        XCTAssertEqual(values[0].key, "host")
    }

    func testExtractsArrayValues() {
        let content = "{\"hosts\": [\"db1.corp.net\", \"db2.corp.net\"]}"
        let values = parser.parseValues(from: content)
        XCTAssertEqual(values.count, 2)
    }

    func testHandlesInvalidJSON() {
        let content = "not valid json {"
        let values = parser.parseValues(from: content)
        XCTAssertEqual(values.count, 0)
    }

    func testSkipsNumericValues() {
        let content = "{\"count\": 42, \"active\": true, \"name\": \"test\"}"
        let values = parser.parseValues(from: content)
        XCTAssertEqual(values.count, 1)
        XCTAssertEqual(values[0].value, "test")
    }
}
