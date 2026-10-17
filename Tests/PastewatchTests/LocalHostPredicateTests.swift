import XCTest
@testable import PastewatchCore
@testable import PastewatchCLI

// WO-704@v1: every consumer must agree on literal identity while retaining its destination or listen role.
final class LocalHostPredicateTests: XCTestCase {
    // WO-704@v1: mapped abbreviated IPv4 retains the same classification as its IPv4 suffix.
    private let loopbacks = [
        "127.0.0.1", "127.0.0.2", "127.1", "0177.0.0.1", "::1", "[::1]",
        "::ffff:127.0.0.1", "localhost", "LOCALHOST", "::ffff:127.1"
    ]
    // WO-704@v1: empty and mapped-zero listeners are wildcards, never loopback destinations.
    private let wildcards = ["0.0.0.0", "::", "::ffff:0.0.0.0", ""]
    private let remoteHosts = ["10.0.0.5", "192.168.1.2", "fd00::1", "203.0.113.1", "api.example.com"]

    // WO-704@v1: pure recognition keeps wildcard aliases distinct and never accepts nearby non-loopback literals.
    func testNamedPredicatesClassifyTheCompleteTable() {
        for host in loopbacks + wildcards + remoteHosts {
            XCTAssertEqual(isLoopbackDestination(host), loopbacks.contains(host), host)
            XCTAssertEqual(isWildcardListenAddress(host), wildcards.contains(host), host)
        }
        for host in ["", "0", "[::]", "0:0:0:0:0:0:0:0"] {
            XCTAssertFalse(isLoopbackDestination(host), host)
            XCTAssertTrue(isWildcardListenAddress(host), host)
        }
        for host in ["08.0.0.1", "127.0.0.1.example.com", "::1:8443", "%", "127.0.0.1\u{0}example.com"] {
            XCTAssertFalse(isLoopbackDestination(host))
            XCTAssertFalse(isWildcardListenAddress(host))
        }
    }

    // WO-704@v1: unspecified listeners alias only loopback upstreams at their own port.
    func testDiscoveryWildcardListenersDoNotAliasRemoteDestinations() throws {
        for listen in [":9000", "0.0.0.0:9000", "[::]:9000"] {
            let record = WireProxyRecord(alive: true, listenAddr: listen, proxyID: "fixture")
            for host in loopbacks + remoteHosts {
                XCTAssertEqual(WireProxyDiscovery.matches(record, upstream: try endpoint(host)),
                               loopbacks.contains(host), host)
            }
            XCTAssertFalse(WireProxyDiscovery.matches(record, upstream: try XCTUnwrap(URL(string: "http://127.1:9001"))))
        }
    }

    // WO-704@v1: the same table exercises launch cleanup, discovery aliases, outbound Via and diagnostic coverage.
    func testEveryConsumerUsesLoopbackAndWildcardRoles() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            for host in loopbacks + wildcards + remoteHosts {
                let url = try endpoint(host)
                let loopback = loopbacks.contains(host)
                let launch = Launch.isLocalAnthropicBaseURLHost(host)
                let discovery = WireProxyDiscovery.matches(
                    WireProxyRecord(alive: true, listenAddr: "127.0.0.1:9000", proxyID: "fixture"), upstream: url
                )
                let via = ProxyServer.isLoopbackUpstream(url)
                let doctor = Doctor().observedWireAgents(
                    environment: ["ANTHROPIC_BASE_URL": url.absoluteString],
                    proxyCommands: { ["pastewatch-cli proxy --port 9000"] }
                ).contains("claude-code")
                print("host=\(host) launch=\(launch) discovery=\(discovery) via=\(via) doctor=\(doctor)")
                // WO-704@v1: an empty listen host is meaningful to discovery but not to Launch's URL-host decision.
                XCTAssertEqual(launch, !host.isEmpty && (loopback || wildcards.contains(host)), "launch: \(host)")
                XCTAssertEqual(discovery, loopback, "discovery: \(host)")
                XCTAssertEqual(via, loopback, "Via: \(host)")
                XCTAssertEqual(doctor, loopback, "doctor: \(host)")
            }
        }
    }

    // WO-704@v1: preserve the three pre-consolidation Launch verdicts missed by the original table.
    func testLaunchPreservesMappedIPv4AndEmptyHostVerdicts() {
        XCTAssertTrue(Launch.isLocalAnthropicBaseURLHost("::ffff:0.0.0.0"))
        XCTAssertTrue(Launch.isLocalAnthropicBaseURLHost("::ffff:127.1"))
        XCTAssertFalse(Launch.isLocalAnthropicBaseURLHost(""))
    }

    // WO-704@v1: URL brackets are presentation only and no table row requires a DNS lookup.
    private func endpoint(_ host: String) throws -> URL {
        let authority = host.contains(":") && !host.hasPrefix("[") ? "[\(host)]" : host
        return try XCTUnwrap(URL(string: "http://\(authority):9000"))
    }
}
