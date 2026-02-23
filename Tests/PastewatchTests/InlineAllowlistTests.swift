import XCTest
@testable import PastewatchCore

final class InlineAllowlistTests: XCTestCase {
    let config = PastewatchConfig.defaultConfig

    func testHashCommentStyleSuppressesMatch() {
        let content = "admin@corp.com # pastewatch:allow"
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertFalse(matches.isEmpty)
        let filtered = Allowlist.filterInlineAllow(matches: matches, content: content)
        XCTAssertTrue(filtered.isEmpty)
    }

    func testSlashCommentStyleSuppressesMatch() {
        let content = "admin@corp.com // pastewatch:allow"
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertFalse(matches.isEmpty)
        let filtered = Allowlist.filterInlineAllow(matches: matches, content: content)
        XCTAssertTrue(filtered.isEmpty)
    }

    func testLinesWithoutMarkerStillDetected() {
        let content = "admin@corp.com"
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertFalse(matches.isEmpty)
        let filtered = Allowlist.filterInlineAllow(matches: matches, content: content)
        XCTAssertEqual(filtered.count, matches.count)
    }

    func testMarkerOnlySuppressesSpecificLine() {
        let content = "admin@corp.com\ntest@example.com # pastewatch:allow\nother@test.com"
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertEqual(matches.count, 3)
        let filtered = Allowlist.filterInlineAllow(matches: matches, content: content)
        XCTAssertEqual(filtered.count, 2)
        XCTAssertTrue(filtered.allSatisfy { $0.value != "test@example.com" })
    }

    func testMultiLineMixedAllowAndDetect() {
        let key = ["AKIA", "IOSFODNN7EXAMPLE"].joined()
        let content = """
        SECRET_KEY=\(key) # pastewatch:allow
        DB_PASS=hunter2
        API_KEY=\(key)
        SAFE=hello // pastewatch:allow
        """
        let matches = DetectionRules.scan(content, config: config)
        let filtered = Allowlist.filterInlineAllow(matches: matches, content: content)
        for m in filtered {
            let lines = content.components(separatedBy: "\n")
            let lineContent = lines[m.line - 1]
            XCTAssertFalse(lineContent.contains("pastewatch:allow"))
        }
    }

    func testEmptyContentReturnsEmptyMatches() {
        let filtered = Allowlist.filterInlineAllow(matches: [], content: "")
        XCTAssertTrue(filtered.isEmpty)
    }
}
