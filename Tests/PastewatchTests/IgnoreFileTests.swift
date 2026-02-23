import XCTest
@testable import PastewatchCore

final class IgnoreFileTests: XCTestCase {

    func testFileGlobPattern() {
        let ignore = IgnoreFile(patterns: ["*.log"])
        XCTAssertTrue(ignore.shouldIgnore("debug.log"))
        XCTAssertTrue(ignore.shouldIgnore("path/to/error.log"))
        XCTAssertFalse(ignore.shouldIgnore("config.yml"))
    }

    func testDirectoryPattern() {
        let ignore = IgnoreFile(patterns: ["fixtures/"])
        XCTAssertTrue(ignore.shouldIgnore("fixtures/data.json"))
        XCTAssertTrue(ignore.shouldIgnore("test/fixtures/sample.env"))
        XCTAssertFalse(ignore.shouldIgnore("src/main.swift"))
    }

    func testPathPattern() {
        let ignore = IgnoreFile(patterns: ["test-data/*"])
        XCTAssertTrue(ignore.shouldIgnore("test-data/sample.env"))
        XCTAssertFalse(ignore.shouldIgnore("src/test-data.swift"))
    }

    func testCommentsAndEmptyLinesSkipped() {
        let content = "# comment\n\n*.log\n  \n# another\nfixtures/"
        let patterns = content
            .components(separatedBy: .newlines)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty && !$0.hasPrefix("#") }
        let ignore = IgnoreFile(patterns: patterns)
        XCTAssertEqual(ignore.patterns.count, 2)
        XCTAssertEqual(ignore.patterns[0], "*.log")
        XCTAssertEqual(ignore.patterns[1], "fixtures/")
    }

    func testLoadFromMissingDirectory() {
        let result = IgnoreFile.load(from: "/nonexistent/path")
        XCTAssertNil(result)
    }
}
