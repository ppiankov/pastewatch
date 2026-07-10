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

    #if canImport(Darwin)
    func testSSEStreamRelayForwardsTaskChallengeToTLSHandler() {
        var forwarded = false
        var completedDisposition: URLSession.AuthChallengeDisposition?
        let relay = SSEStreamRelay(
            clientSocket: -1,
            sendFlags: 0,
            redactionMode: .perSSEEvent,
            config: PastewatchConfig.defaultConfig,
            severity: .high,
            idleTimeoutSeconds: 1,
            tlsChallengeHandler: { _, challenge, completionHandler in
                forwarded = true
                XCTAssertEqual(challenge.protectionSpace.host, "example.test")
                completionHandler(.performDefaultHandling, nil)
            }
        )
        let session = URLSession(configuration: .ephemeral)
        defer { session.invalidateAndCancel() }
        let task = session.dataTask(with: URL(string: "https://example.test/stream")!)
        let protectionSpace = URLProtectionSpace(
            host: "example.test",
            port: 443,
            protocol: "https",
            realm: nil,
            authenticationMethod: NSURLAuthenticationMethodServerTrust
        )
        let challenge = URLAuthenticationChallenge(
            protectionSpace: protectionSpace,
            proposedCredential: nil,
            previousFailureCount: 0,
            failureResponse: nil,
            error: nil,
            sender: ProxyTLSChallengeSender()
        )

        relay.urlSession(session, task: task, didReceive: challenge) { disposition, _ in
            completedDisposition = disposition
        }

        XCTAssertTrue(forwarded)
        XCTAssertEqual(completedDisposition, .performDefaultHandling)
    }
    #endif
}

#if canImport(Darwin)
private final class ProxyTLSChallengeSender: NSObject, URLAuthenticationChallengeSender {
    func use(_ credential: URLCredential, for challenge: URLAuthenticationChallenge) {}
    func continueWithoutCredential(for challenge: URLAuthenticationChallenge) {}
    func cancel(_ challenge: URLAuthenticationChallenge) {}
}
#endif
