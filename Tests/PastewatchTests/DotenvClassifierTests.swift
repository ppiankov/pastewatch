import XCTest
@testable import PastewatchCore

final class DotenvClassifierTests: XCTestCase {
    func testCurrentDotenvFilenameContract() {
        for fileName in [".env", "config.env", "service.production.env"] {
            XCTAssertTrue(DotenvClassifier.isDotenvFile(fileName), fileName)
        }

        for fileName in [".env.local", ".env.example", "config.ENV", "env", "config.env.backup"] {
            XCTAssertFalse(DotenvClassifier.isDotenvFile(fileName), fileName)
        }
    }
}
