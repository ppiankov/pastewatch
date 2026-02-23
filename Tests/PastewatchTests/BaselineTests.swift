import XCTest
@testable import PastewatchCore

final class BaselineTests: XCTestCase {

    var testDir: String!

    override func setUp() {
        super.setUp()
        testDir = NSTemporaryDirectory() + "pastewatch-baseline-test-\(UUID().uuidString)"
        try? FileManager.default.createDirectory(atPath: testDir, withIntermediateDirectories: true)
    }

    override func tearDown() {
        try? FileManager.default.removeItem(atPath: testDir)
        super.tearDown()
    }

    // MARK: - BaselineEntry

    func testFingerprintIsDeterministic() {
        let match = makeMatch(type: .email, value: "test@example.com")
        let entry1 = BaselineEntry.from(match: match, filePath: "file.txt")
        let entry2 = BaselineEntry.from(match: match, filePath: "file.txt")
        XCTAssertEqual(entry1.fingerprint, entry2.fingerprint)
    }

    func testDifferentValuesDifferentFingerprints() {
        let match1 = makeMatch(type: .email, value: "a@example.com")
        let match2 = makeMatch(type: .email, value: "b@example.com")
        let entry1 = BaselineEntry.from(match: match1, filePath: "file.txt")
        let entry2 = BaselineEntry.from(match: match2, filePath: "file.txt")
        XCTAssertNotEqual(entry1.fingerprint, entry2.fingerprint)
    }

    func testDifferentTypesDifferentFingerprints() {
        let match1 = makeMatch(type: .email, value: "test@example.com")
        let match2 = makeMatch(type: .hostname, value: "test@example.com")
        let entry1 = BaselineEntry.from(match: match1, filePath: "file.txt")
        let entry2 = BaselineEntry.from(match: match2, filePath: "file.txt")
        XCTAssertNotEqual(entry1.fingerprint, entry2.fingerprint)
    }

    func testFingerprintIsHexString() {
        let match = makeMatch(type: .email, value: "test@example.com")
        let entry = BaselineEntry.from(match: match, filePath: "file.txt")
        XCTAssertEqual(entry.fingerprint.count, 64)
        XCTAssertTrue(entry.fingerprint.allSatisfy { $0.isHexDigit })
    }

    // MARK: - BaselineFile round-trip

    func testBaselineFileSaveAndLoad() throws {
        let entries = [
            BaselineEntry(fingerprint: "abc123", filePath: "a.txt"),
            BaselineEntry(fingerprint: "def456", filePath: "b.txt")
        ]
        let baseline = BaselineFile(entries: entries)
        let path = testDir + "/baseline.json"
        try baseline.save(to: path)

        let loaded = try BaselineFile.load(from: path)
        XCTAssertEqual(loaded.version, "1")
        XCTAssertEqual(loaded.entries.count, 2)
        XCTAssertEqual(loaded.entries[0].fingerprint, "abc123")
        XCTAssertEqual(loaded.entries[1].filePath, "b.txt")
    }

    func testBaselineFileLoadFailsForMissingFile() {
        XCTAssertThrowsError(try BaselineFile.load(from: "/nonexistent/baseline.json"))
    }

    // MARK: - Filtering

    func testFilterNewRemovesBaselineMatches() {
        let match1 = makeMatch(type: .email, value: "known@example.com")
        let match2 = makeMatch(type: .email, value: "new@example.com")

        let entry = BaselineEntry.from(match: match1, filePath: "file.txt")
        let baseline = BaselineFile(entries: [entry])

        let newMatches = baseline.filterNew(matches: [match1, match2], filePath: "file.txt")
        XCTAssertEqual(newMatches.count, 1)
        XCTAssertEqual(newMatches[0].value, "new@example.com")
    }

    func testFilterNewReturnsAllWhenBaselineEmpty() {
        let match = makeMatch(type: .email, value: "test@example.com")
        let baseline = BaselineFile(entries: [])
        let newMatches = baseline.filterNew(matches: [match], filePath: "file.txt")
        XCTAssertEqual(newMatches.count, 1)
    }

    func testFilterNewResultsRemovesBaselineFiles() {
        let match1 = makeMatch(type: .email, value: "known@example.com")
        let match2 = makeMatch(type: .email, value: "new@example.com")

        let entry = BaselineEntry.from(match: match1, filePath: "a.txt")
        let baseline = BaselineFile(entries: [entry])

        let results = [
            FileScanResult(filePath: "a.txt", matches: [match1], content: ""),
            FileScanResult(filePath: "b.txt", matches: [match2], content: "")
        ]

        let filtered = baseline.filterNewResults(results: results)
        XCTAssertEqual(filtered.count, 1)
        XCTAssertEqual(filtered[0].filePath, "b.txt")
    }

    // MARK: - Helpers

    private func makeMatch(type: SensitiveDataType, value: String) -> DetectedMatch {
        DetectedMatch(
            type: type,
            value: value,
            range: value.startIndex..<value.endIndex
        )
    }
}
