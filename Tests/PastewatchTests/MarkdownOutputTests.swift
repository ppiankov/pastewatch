import XCTest
@testable import PastewatchCore

final class MarkdownOutputTests: XCTestCase {
    func testSingleFileMarkdownHeader() {
        let match = DetectedMatch(
            type: .email, value: "test@corp.com",
            range: "test@corp.com".startIndex..<"test@corp.com".endIndex,
            line: 1
        )
        let output = MarkdownFormatter.formatSingle(matches: [match], filePath: nil, obfuscated: nil)
        XCTAssertTrue(output.hasPrefix("## Pastewatch Scan Results"))
        XCTAssertTrue(output.contains("1 finding(s) detected"))
    }

    func testSingleFileMarkdownTable() {
        let match = DetectedMatch(
            type: .email, value: "admin@corp.com",
            range: "admin@corp.com".startIndex..<"admin@corp.com".endIndex,
            line: 5
        )
        let output = MarkdownFormatter.formatSingle(matches: [match], filePath: "test.env", obfuscated: nil)
        XCTAssertTrue(output.contains("| high | Email | 5 |"))
    }

    func testDirectoryMarkdownGroupsByFile() {
        let match1 = DetectedMatch(
            type: .email, value: "a@b.com",
            range: "a@b.com".startIndex..<"a@b.com".endIndex,
            line: 1, filePath: "file1.txt"
        )
        let match2 = DetectedMatch(
            type: .ipAddress, value: "10.0.0.1",
            range: "10.0.0.1".startIndex..<"10.0.0.1".endIndex,
            line: 3, filePath: "file2.txt"
        )
        let results = [
            FileScanResult(filePath: "file1.txt", matches: [match1], content: ""),
            FileScanResult(filePath: "file2.txt", matches: [match2], content: "")
        ]
        let output = MarkdownFormatter.formatDirectory(results: results)
        XCTAssertTrue(output.contains("### file1.txt"))
        XCTAssertTrue(output.contains("### file2.txt"))
        XCTAssertTrue(output.contains("2 finding(s) in 2 file(s)"))
    }

    func testMarkdownEscapesBacktickValues() {
        let match = DetectedMatch(
            type: .credential, value: "password=secret",
            range: "password=secret".startIndex..<"password=secret".endIndex,
            line: 1
        )
        let output = MarkdownFormatter.formatSingle(matches: [match], filePath: nil, obfuscated: nil)
        XCTAssertTrue(output.contains("`password=secret`"))
    }
}
