import XCTest
@testable import PastewatchCore
@testable import PastewatchCLI
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

// WO-696@v3: wire ownership must not change request bytes or contact an upstream in tests.
final class ProxyChainGuardTests: XCTestCase {
    // WO-696@v3: a socket pair proves the real HTTP refusal without opening a network listener.
    func testHeaderGateReturns508BeforeBodyProcessing() throws {
        for token in ["pastewatch", "neurorouter", "PaStEwAtCh"] {
            var sockets = [Int32](repeating: -1, count: 2)
            #if canImport(Darwin)
            let kind = SOCK_STREAM
            #else
            let kind = Int32(SOCK_STREAM.rawValue)
            #endif
            guard socketpair(AF_UNIX, kind, 0, &sockets) == 0 else { throw POSIXError(.EIO) }
            let peer = FileHandle(fileDescriptor: sockets[0], closeOnDealloc: true)
            let serverSide = FileHandle(fileDescriptor: sockets[1], closeOnDealloc: true)
            defer { try? peer.close(); try? serverSide.close() }
            let body = "{ \"messages\" : [] }"
            let request = "POST /v1/messages HTTP/1.1\r\nHost: example\r\nVia: 1.1 " + token +
                "\r\nContent-Length: \(body.utf8.count)\r\n\r\n" + body
            try peer.write(contentsOf: Data(request.utf8))
            let server = ProxyServer(port: 0, quietLog: true)
            XCTAssertNil(server.readUnchainedHTTPRequest(from: sockets[1]))
            shutdown(sockets[1], Int32(SHUT_WR))
            let response = try XCTUnwrap(String(data: peer.readDataToEndOfFile(), encoding: .utf8))
            XCTAssertTrue(response.hasPrefix("HTTP/1.1 508 Loop Detected\r\n"))
            XCTAssertTrue(response.contains("one wire proxy per session"))
            XCTAssertFalse(response.contains(body))
        }
    }

    // WO-696@v3: the published discovery fields are synthetic and never require a running proxy.
    static let discoveryJSON = "[{\"alive\":true,\"listen_addr\":\"127.0.0.1:8181\",\"proxy_id\":\"fixture-owner\"}]"

    // WO-696@v3: executable fixtures validate argv and return operator-format data without network access.
    static func withDiscoveryStub(
        output: String = discoveryJSON, exitCode: Int = 0, hangs: Bool = false,
        body: (String) throws -> Void
    ) throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let directory = root.appendingPathComponent("bin", isDirectory: true)
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            let script = directory.appendingPathComponent("nr")
            let escaped = output.replacingOccurrences(of: "'", with: "'\\''")
            let content = "#!/bin/sh\n[ \"$*\" = 'proxies --json --output-mode operator' ] || exit 97\n" +
                (hangs ? "exec /bin/sleep 10\n" : "printf '%s\\n' '" + escaped + "'\nexit \(exitCode)\n")
            try content.write(to: script, atomically: true, encoding: .utf8)
            try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: script.path)
            try body(directory.path)
        }
    }

    // WO-696@v3: exact received-by tokens refuse chaining; similarly named hosts and comments do not.
    func testInboundWireOwnerTokensRefuseWithoutInspectingBody() {
        for token in ["pastewatch", "neurorouter", "NeUrOrOuTeR", "PASTEWATCH"] {
            let refusal = ProxyServer.wireChainRefusal(headers: [("vIa", "1.0 example, 1.1 " + token)])
            XCTAssertTrue(refusal?.contains("one wire proxy") == true)
            XCTAssertTrue(refusal?.contains("directly to the provider") == true)
        }
        for hop in ["1.1 pastewatch-other", "1.1 not-neurorouter", "1.1 example (pastewatch)"] {
            XCTAssertNil(ProxyServer.wireChainRefusal(headers: [("Via", hop)]))
        }
    }

    // WO-696@v3: only exclusively loopback resolution may announce the wire-hop identity.
    func testResolvedHostsRequireExclusivelyLoopbackAddresses() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            let url = try XCTUnwrap(URL(string: "http://gateway.example:8181"))
            let cases: [([String], Bool)] = [
                (["127.0.0.1"], true), (["127.0.0.1", "::1", "::ffff:127.23.45.67"], true),
                (["10.1.2.3", "fd00::1"], false), (["127.0.0.1", "10.1.2.3"], false),
                (["127.0.0.1", "203.0.113.1"], false), (["203.0.113.1"], false), ([], false)
            ]
            let body = "{ \"messages\" : [], \"system\" : \"unchanged\" }"
            for (addresses, expected) in cases {
                let server = ProxyServer(upstream: url, quietLog: true)
                var resolvedHosts: [String] = []
                server.resolveLoopbackUpstream { host in
                    resolvedHosts.append(host)
                    return addresses
                }
                for _ in 0..<2 {
                    let headers = try XCTUnwrap(server.buildForwardHeaders(from: [], bodyLength: body.utf8.count))
                    XCTAssertEqual(headers.contains { $0.0.lowercased() == "via" }, expected)
                    XCTAssertTrue(Data(server.scanAndRedactBody(body).body.utf8).elementsEqual(Data(body.utf8)))
                }
                XCTAssertEqual(resolvedHosts, ["gateway.example"])
            }
            XCTAssertTrue(ProxyServer.isLoopbackUpstream(try XCTUnwrap(URL(string: "http://[::ffff:127.0.0.1]"))))
        }
    }

    // WO-696@v3: successful discovery refuses only a live record at the configured endpoint.
    func testDiscoveryMatchingUpstreamRefusesStartup() throws {
        try Self.withDiscoveryStub { path in
            let records = WireProxyDiscovery.discover(searchPath: path, timeout: 10)
            XCTAssertEqual(records.count, 1)
            let upstream = try XCTUnwrap(URL(string: "http://127.0.0.1:8181/api"))
            XCTAssertTrue(WireProxyDiscovery.refusal(upstream: upstream, records: records)?.contains("fixture-owner") == true)
            XCTAssertThrowsError(try requireSingleWireOwner(upstream: upstream, discover: { records }))
            XCTAssertNoThrow(try requireSingleWireOwner(
                upstream: XCTUnwrap(URL(string: "http://127.0.0.1:8182")), discover: { records }
            ))
        }
    }

    // WO-696@v3: literal loopback aliases and wildcard listeners identify the same local endpoint.
    func testDiscoveryNormalizesLoopbackAndWildcardEndpoints() throws {
        let listeners = ["localhost:8181", "127.0.0.1:8181", "127.23.45.67:8181", "[::1]:8181",
                         "0.0.0.0:8181", "[::]:8181", ":8181"]
        for listener in listeners {
            let record = WireProxyRecord(alive: true, listenAddr: listener, proxyID: "fixture-owner")
            for host in ["localhost", "LOCALHOST", "127.0.0.1", "127.98.76.54", "[::1]"] {
                let upstream = try XCTUnwrap(URL(string: "http://" + host + ":8181/api"))
                XCTAssertTrue(WireProxyDiscovery.matches(record, upstream: upstream), listener + " / " + host)
                XCTAssertFalse(WireProxyDiscovery.matches(record, upstream:
                    try XCTUnwrap(URL(string: "http://" + host + ":8182"))))
            }
            XCTAssertFalse(WireProxyDiscovery.matches(record, upstream:
                try XCTUnwrap(URL(string: "http://203.0.113.1:8181"))))
        }
        let dead = WireProxyRecord(alive: false, listenAddr: ":8181", proxyID: "fixture-owner")
        XCTAssertFalse(WireProxyDiscovery.matches(dead, upstream: try XCTUnwrap(URL(string: "http://localhost:8181"))))
        let privateHost = WireProxyRecord(alive: true, listenAddr: "10.1.2.3:8181", proxyID: "fixture-owner")
        XCTAssertTrue(WireProxyDiscovery.matches(privateHost, upstream: try XCTUnwrap(URL(string: "http://10.1.2.3:8181"))))
        XCTAssertFalse(WireProxyDiscovery.matches(privateHost, upstream: try XCTUnwrap(URL(string: "http://10.1.2.4:8181"))))
    }

    // WO-696@v3: non-success exit codes never acquire meaning from matching JSON or human wording.
    func testUnavailableUnsupportedMalformedAndTimedOutDiscoveryProceed() throws {
        for code in [1, 3, 7] {
            try Self.withDiscoveryStub(exitCode: code) { path in
                XCTAssertTrue(WireProxyDiscovery.discover(searchPath: path, timeout: 10).isEmpty)
            }
        }
        for output in ["unsupported capability", "not-json", "{}",
                       Self.discoveryJSON.replacingOccurrences(of: "true", with: "false")] {
            try Self.withDiscoveryStub(output: output) { path in
                XCTAssertTrue(WireProxyDiscovery.discover(searchPath: path, timeout: 10).isEmpty)
            }
        }
        try Self.withDiscoveryStub(hangs: true) { path in
            XCTAssertTrue(WireProxyDiscovery.discover(searchPath: path, timeout: 0.05).isEmpty)
        }
    }

    // WO-696@v3: discovery shares the cwd-hijack controls already enforced for curl.
    func testSharedPathLookupIgnoresEmptyAndRelativeEntries() {
        var checked: [String] = []
        let result = PathExecutable.resolve(name: "nr", searchPath: ":relative:/absolute::") { path in
            checked.append(path)
            return !path.hasPrefix("/absolute/")
        }
        XCTAssertNil(result)
        XCTAssertEqual(checked, ["/absolute/nr"])
        XCTAssertEqual(PathExecutable.resolve(name: "nr", searchPath: ":relative:/absolute:",
                                             isExecutable: { _ in true }), "/absolute/nr")
    }

    // WO-696@v3: loopback hops append their identity without fingerprinting private or public gateways.
    func testViaIsAppendedOnlyForLoopbackUpstreamsWithoutChangingBody() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            let body = "{ \"messages\" : [], \"system\":\"unchanged\" }"
            for host in ["127.0.0.1", "127.23.45.67", "[::1]", "[::ffff:127.0.0.1]", "localhost"] {
                let server = ProxyServer(upstream: try XCTUnwrap(URL(string: "http://" + host + ":8181")))
                let headers = try XCTUnwrap(server.buildForwardHeaders(from: [("Via", "1.0 example")], bodyLength: body.utf8.count))
                XCTAssertEqual(headers.filter { $0.0.lowercased() == "via" }.map { $0.1 }, ["1.0 example", "1.1 pastewatch"], host)
                XCTAssertTrue(server.scanAndRedactBody(body).body == body)
            }
            for host in ["10.2.3.4", "172.16.0.1", "192.168.1.2", "169.254.1.2", "[fe80::1]", "[fd00::1]",
                         "[::ffff:10.1.2.3]", "203.0.113.2", "172.32.0.1", "[2001:db8::1]", "api.example.com"] {
                let server = ProxyServer(upstream: try XCTUnwrap(URL(string: "https://" + host)))
                XCTAssertFalse(try XCTUnwrap(server.buildForwardHeaders(from: [], bodyLength: body.utf8.count))
                    .contains { $0.0.lowercased() == "via" })
                XCTAssertTrue(server.scanAndRedactBody(body).body == body)
            }
        }
    }

    // WO-696@v3: a private gateway remains usable without a discovery match or a product-identifying header.
    func testCorporateGatewayKeepsBodyWithoutWireIdentity() throws {
        try Self.withDiscoveryStub { path in
            let upstream = try XCTUnwrap(URL(string: "http://10.1.2.3:8181"))
            let records = WireProxyDiscovery.discover(searchPath: path, timeout: 10)
            XCTAssertEqual(records.count, 1)
            XCTAssertNoThrow(try requireSingleWireOwner(upstream: upstream, discover: { records }))
            var sockets = [Int32](repeating: -1, count: 2)
            #if canImport(Darwin)
            let kind = SOCK_STREAM
            #else
            let kind = Int32(SOCK_STREAM.rawValue)
            #endif
            guard socketpair(AF_UNIX, kind, 0, &sockets) == 0 else { throw POSIXError(.EIO) }
            let peer = FileHandle(fileDescriptor: sockets[0], closeOnDealloc: true)
            let serverSide = FileHandle(fileDescriptor: sockets[1], closeOnDealloc: true)
            defer { try? peer.close(); try? serverSide.close() }
            let body = "{ \"system\" : \"unchanged\", \"messages\" : [] }"
            let request = "POST /v1/messages HTTP/1.1\r\nHost: gateway.example\r\nContent-Length: \(body.utf8.count)\r\n\r\n" + body
            try peer.write(contentsOf: Data(request.utf8))
            let server = ProxyServer(upstream: upstream, quietLog: true)
            let admitted = try XCTUnwrap(server.readUnchainedHTTPRequest(from: sockets[1]))
            XCTAssertTrue(admitted.bodyData.elementsEqual(Data(body.utf8)))
            let headers = try XCTUnwrap(server.buildForwardHeaders(from: admitted.headers, bodyLength: admitted.bodyData.count))
            XCTAssertFalse(headers.contains { $0.0.lowercased() == "via" })
            XCTAssertTrue(Data(server.scanAndRedactBody(body).body.utf8).elementsEqual(admitted.bodyData))
        }
    }
}
