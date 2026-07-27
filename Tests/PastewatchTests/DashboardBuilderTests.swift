import XCTest
@testable import PastewatchCore

final class DashboardBuilderTests: XCTestCase {
    // WO-556@v2: historical dashboard artifacts retain a truthful list-size floor.
    func testLegacyJSONDerivesHotFilesTotal() throws {
        let json = """
        {
          "generatedAt":"2025-01-01T00:00:00Z",
          "sessions":1,
          "period":{"earliest":null,"latest":null},
          "summary":{
            "filesRead":0,"filesWritten":0,"secretsRedacted":0,
            "placeholdersResolved":0,"unresolvedPlaceholders":0,
            "outputChecks":0,"outputChecksDirty":0,"scans":0,"scanFindings":0
          },
          "topTypes":[],
          "hotFiles":[],
          "verdict":"Clean"
        }
        """
        let dashboard = try JSONDecoder().decode(Dashboard.self, from: Data(json.utf8))
        XCTAssertEqual(dashboard.hotFilesTotal, dashboard.hotFiles.count)
    }
}
