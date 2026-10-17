import XCTest
@testable import PastewatchCLI

// WO-696@v2: doctor and startup consume the same stubbed discovery contract.
final class DoctorWireOwnerTests: XCTestCase {
    // WO-696@v2: conflicts are reported only when a running pastewatch proxy supplies wire context.
    func testDoctorListsDiscoveryAndFlagsConfiguredUpstream() throws {
        try ProxyChainGuardTests.withDiscoveryStub { path in
            let discover = { WireProxyDiscovery.discover(searchPath: path, timeout: 10) }
            let checks = Doctor().checkWireOwners(
                discover: discover,
                proxyCommands: { ["pastewatch-cli proxy --upstream http://127.0.0.1:8181"] },
                environment: ["ANTHROPIC_BASE_URL": "http://127.0.0.1:8181"]
            )
            XCTAssertEqual(checks.count, 1)
            XCTAssertEqual(checks.first?.status, "warn")
            XCTAssertTrue(checks.first?.detail.contains("fixture-owner") == true)
            XCTAssertTrue(checks.first?.detail.contains("configured agent upstream") == true)
            let unchained = Doctor().checkWireOwners(discover: discover, proxyCommands: { [] }, environment: [:])
            XCTAssertEqual(unchained.first?.status, "info")
            XCTAssertTrue(unchained.first?.detail.contains("fixture-owner") == true)
        }
    }
}
