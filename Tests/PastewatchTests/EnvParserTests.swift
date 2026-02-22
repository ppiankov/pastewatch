import XCTest
@testable import PastewatchCore

final class EnvParserTests: XCTestCase {
    let parser = EnvParser()

    func testParsesKeyValuePairs() {
        let content = "DB_HOST=localhost\nDB_PORT=5432\n"
        let values = parser.parseValues(from: content)
        XCTAssertEqual(values.count, 2)
        XCTAssertEqual(values[0].value, "localhost")
        XCTAssertEqual(values[0].key, "DB_HOST")
        XCTAssertEqual(values[0].line, 1)
        XCTAssertEqual(values[1].line, 2)
    }

    func testSkipsComments() {
        let content = "# This is a comment\nKEY=value\n"
        let values = parser.parseValues(from: content)
        XCTAssertEqual(values.count, 1)
        XCTAssertEqual(values[0].key, "KEY")
    }

    func testHandlesQuotedValues() {
        let content = "SECRET=\"my secret value\"\nOTHER='single quoted'\n"
        let values = parser.parseValues(from: content)
        XCTAssertEqual(values.count, 2)
        XCTAssertEqual(values[0].value, "my secret value")
        XCTAssertEqual(values[1].value, "single quoted")
    }

    func testSkipsEmptyLines() {
        let content = "\n\nKEY=value\n\n"
        let values = parser.parseValues(from: content)
        XCTAssertEqual(values.count, 1)
    }

    func testSkipsEmptyValues() {
        let content = "EMPTY=\nNONEMPTY=hello\n"
        let values = parser.parseValues(from: content)
        XCTAssertEqual(values.count, 1)
        XCTAssertEqual(values[0].key, "NONEMPTY")
    }
}
