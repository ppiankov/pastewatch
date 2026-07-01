import XCTest
@testable import PastewatchCore

/// WO-143: --ca-cert / --insecure govern only the proxy's upstream TLS handshake.
/// These tests cover flag plumbing into ProxyServer and the curl argument assembly;
/// the live TLS handshake (URLSession delegate / curl -k) is verified manually.
final class ProxyTLSTests: XCTestCase {

    // MARK: - ProxyServer flag plumbing

    func testDefaultsNoTLSOverrides() {
        let s = ProxyServer(port: 0)
        XCTAssertNil(s.caCertPath)
        XCTAssertFalse(s.insecureTLS)
    }

    func testCaCertPathStored() {
        let s = ProxyServer(port: 0, caCertPath: "/tmp/corp-ca.pem")
        XCTAssertEqual(s.caCertPath, "/tmp/corp-ca.pem")
        XCTAssertFalse(s.insecureTLS)
    }

    func testInsecureStored() {
        let s = ProxyServer(port: 0, insecureTLS: true)
        XCTAssertTrue(s.insecureTLS)
        XCTAssertNil(s.caCertPath)
    }

    // MARK: - curl TLS argument assembly

    func testCurlArgsDefaultEmpty() {
        XCTAssertEqual(CurlHTTPClient.tlsArgs(caCertPath: nil, insecure: false), [])
    }

    func testCurlArgsCaCert() {
        XCTAssertEqual(
            CurlHTTPClient.tlsArgs(caCertPath: "/tmp/corp-ca.pem", insecure: false),
            ["--cacert", "/tmp/corp-ca.pem"]
        )
    }

    func testCurlArgsInsecure() {
        XCTAssertEqual(CurlHTTPClient.tlsArgs(caCertPath: nil, insecure: true), ["-k"])
    }

    func testCurlArgsInsecureWinsOverCaCert() {
        // When both are set, insecure takes precedence and --cacert is not emitted.
        XCTAssertEqual(
            CurlHTTPClient.tlsArgs(caCertPath: "/tmp/corp-ca.pem", insecure: true),
            ["-k"]
        )
    }
}
