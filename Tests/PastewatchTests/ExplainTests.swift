import XCTest
@testable import PastewatchCore

final class ExplainTests: XCTestCase {
    func testAllTypesHaveExplanations() {
        for type in SensitiveDataType.allCases {
            XCTAssertFalse(type.explanation.isEmpty, "\(type.rawValue) missing explanation")
        }
    }

    func testAllTypesHaveExamples() {
        for type in SensitiveDataType.allCases {
            XCTAssertFalse(type.examples.isEmpty, "\(type.rawValue) missing examples")
        }
    }

    func testExplanationIsDescriptive() {
        // Explanations should be meaningful, not just the raw value
        for type in SensitiveDataType.allCases {
            XCTAssertGreaterThan(type.explanation.count, type.rawValue.count,
                                 "\(type.rawValue) explanation too short")
        }
    }

    func testExamplesAreNonEmpty() {
        for type in SensitiveDataType.allCases {
            for example in type.examples {
                XCTAssertFalse(example.isEmpty, "\(type.rawValue) has empty example")
            }
        }
    }
}
