import XCTest
@testable import PastewatchCLI

// WO-696@v3: doctor and startup consume the same stubbed discovery contract.
final class DoctorWireOwnerTests: XCTestCase {
    // WO-702@v1: both supported argument forms must match a complete flag rather than its prefix.
    func testFlagExtractionFormsAndTokenBoundaries() {
        struct Fixture {
            let command: String
            let flag: String
            let expected: String?
        }
        let fixtures = [
            Fixture(command: "proxy --port 9000", flag: "--port", expected: "9000"),
            Fixture(command: "proxy --port=9000", flag: "--port", expected: "9000"),
            Fixture(command: "proxy --upstream http://127.0.0.1:8181", flag: "--upstream",
                    expected: "http://127.0.0.1:8181"),
            Fixture(command: "proxy --upstream=http://127.0.0.1:8181", flag: "--upstream",
                    expected: "http://127.0.0.1:8181"),
            Fixture(command: "proxy --portal 1", flag: "--port", expected: nil),
            Fixture(command: "proxy", flag: "--port", expected: nil)
        ]
        for fixture in fixtures {
            XCTAssertEqual(Doctor().extractFlag(fixture.command, flag: fixture.flag), fixture.expected, fixture.command)
        }
    }

    // WO-702@v1: an equals-form upstream must still warn about the same discovered wire owner.
    func testDoctorFlagsEqualsFormUpstream() {
        let checks = Doctor().checkWireOwners(
            discover: { [WireProxyRecord(alive: true, listenAddr: "127.0.0.1:8181", proxyID: "fixture-owner")] },
            proxyCommands: { ["pastewatch-cli proxy --upstream=http://127.0.0.1:8181"] },
            environment: [:]
        )
        XCTAssertEqual(checks.first?.status, "warn")
        XCTAssertTrue(checks.first?.detail.contains("fixture-owner") == true)
    }

    // WO-696@v3: conflicts are reported only when a running pastewatch proxy supplies wire context.
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
