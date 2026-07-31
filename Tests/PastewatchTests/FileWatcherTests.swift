import Foundation
import XCTest
@testable import PastewatchCore

final class FileWatcherTests: XCTestCase {
    // WO-602@v2: watcher diagnostics identify malformed evidence without its bytes.
    func testInvalidTextDiagnosticsAreStableAndValueFree() throws {
        let timestamp = "2026-07-30T01:00:00Z"
        let path = "config.txt"

        let text = FileWatcher.invalidTextMessage(
            relativePath: path,
            timestamp: timestamp
        )
        XCTAssertTrue(text.contains(path))
        XCTAssertTrue(text.contains("input is not valid UTF-8"))

        let json = try XCTUnwrap(FileWatcher.invalidTextJSON(
            relativePath: path,
            timestamp: timestamp
        ))
        let object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: String]
        )
        XCTAssertEqual(object["file"], path)
        XCTAssertEqual(object["error"], "scan_input_invalid_text")
        XCTAssertEqual(object["message"], "input is not valid UTF-8")
        XCTAssertEqual(object["timestamp"], timestamp)
    }
}
