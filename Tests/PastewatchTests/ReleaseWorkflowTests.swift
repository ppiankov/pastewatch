import Foundation
import XCTest

final class ReleaseWorkflowTests: XCTestCase {
    // WO-520@v2: automated tagging must produce one release event, not push plus dispatch.
    func testAutoTagUsesBuiltInTokenAndOneExplicitDispatch() throws {
        let workflow = try source(".github/workflows/ci.yml")

        XCTAssertTrue(workflow.contains("GH_TOKEN: ${{ github.token }}"))
        XCTAssertFalse(workflow.contains("GH_TOKEN: ${{ secrets.HOMEBREW_TAP_TOKEN }}"))
        XCTAssertEqual(occurrences(of: "gh workflow run release.yml", in: workflow), 1)
        XCTAssertTrue(workflow.contains("if: steps.tag.outputs.pushed == 'true'"))
    }

    // WO-520@v2: both operator entry points remain, with duplicate attempts serialized by tag.
    func testReleaseTriggersAndConcurrencyAreTagScoped() throws {
        let workflow = try source(".github/workflows/release.yml")

        XCTAssertTrue(workflow.contains("push:\n    tags:"))
        XCTAssertTrue(workflow.contains("workflow_dispatch:"))
        XCTAssertTrue(workflow.contains("group: release-${{ github.event_name == 'workflow_dispatch' && inputs.tag || github.ref_name }}"))
        XCTAssertTrue(workflow.contains("cancel-in-progress: false"))
    }

    // WO-520@v2: one run publishes assets before deriving and writing formula checksums.
    func testReleasePublishesAssetsBeforeFormulaUpdate() throws {
        let workflow = try source(".github/workflows/release.yml")
        let releaseIndex = try XCTUnwrap(workflow.range(of: "- name: Create Release")?.lowerBound)
        let formulaIndex = try XCTUnwrap(workflow.range(of: "- name: Update Homebrew formula")?.lowerBound)

        XCTAssertLessThan(releaseIndex, formulaIndex)
        XCTAssertTrue(workflow[formulaIndex...].contains("shasum -a 256 release/pastewatch-cli"))
        XCTAssertTrue(workflow[formulaIndex...].contains("--method PUT"))
    }

    // WO-520@v2: source-contract tests read workflow files from the package root.
    private func source(_ relativePath: String) throws -> String {
        let root = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
        return try String(contentsOf: root.appendingPathComponent(relativePath), encoding: .utf8)
    }

    // WO-520@v2: dispatch count is an exact contract, not a loose contains check.
    private func occurrences(of needle: String, in value: String) -> Int {
        value.components(separatedBy: needle).count - 1
    }
}
