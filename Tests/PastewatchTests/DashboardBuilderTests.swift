import XCTest
@testable import PastewatchCore
@testable import PastewatchCLI

final class DashboardBuilderTests: XCTestCase {
    // WO-556@v2, WO-583@v2: historical artifacts retain truthful list-size floors.
    func testLegacyJSONDerivesListTotals() throws {
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
          "topTypes":[
            {"type":"AWS Key","count":2,"severity":"critical"},
            {"type":"JWT","count":1,"severity":"critical"}
          ],
          "hotFiles":[],
          "verdict":"Clean"
        }
        """
        let dashboard = try JSONDecoder().decode(Dashboard.self, from: Data(json.utf8))
        XCTAssertEqual(dashboard.topTypesTotal, dashboard.topTypes.count)
        XCTAssertEqual(dashboard.hotFilesTotal, dashboard.hotFiles.count)
    }

    // WO-583@v2: JSON exposes the complete type count without truncating the list.
    func testDashboardJSONIncludesTopTypesTotal() throws {
        let dashboard = makeDashboard(typeCount: 11)
        let data = try JSONEncoder().encode(dashboard)
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])

        XCTAssertEqual(json["topTypesTotal"] as? Int, 11)
        XCTAssertEqual((json["topTypes"] as? [[String: Any]])?.count, 11)
    }

    // WO-583@v2: text and Markdown share an explicit, truthful truncation label.
    func testTopTypesTruncationSuffixAtRenderBoundary() {
        XCTAssertEqual(DashboardCommand.topTypesTruncationSuffix(for: makeDashboard(typeCount: 0)), "")
        XCTAssertEqual(DashboardCommand.topTypesTruncationSuffix(for: makeDashboard(typeCount: 10)), "")
        XCTAssertEqual(
            DashboardCommand.topTypesTruncationSuffix(for: makeDashboard(typeCount: 11)),
            " (showing 10 of 11)"
        )
    }

    // WO-583@v2: construct dashboards with totals above and below the render limit.
    private func makeDashboard(typeCount: Int) -> Dashboard {
        let topTypes = (0..<typeCount).map {
            TypeCount(type: "Type \($0)", count: typeCount - $0, severity: "high")
        }
        return Dashboard(
            generatedAt: "2025-01-01T00:00:00Z",
            sessions: 1,
            period: DashboardPeriod(earliest: nil, latest: nil),
            summary: SessionSummary(
                filesRead: 0,
                filesWritten: 0,
                secretsRedacted: 0,
                placeholdersResolved: 0,
                unresolvedPlaceholders: 0,
                outputChecks: 0,
                outputChecksDirty: 0,
                scans: 0,
                scanFindings: 0
            ),
            topTypes: topTypes,
            hotFiles: [],
            verdict: "Clean"
        )
    }
}
