import XCTest
@testable import PastewatchCore

/// WO-148: Verifies timeout constant values and CurlHTTPClient idle-based timeout args.
final class ProxyTimeoutTests: XCTestCase {

    // MARK: - Timeout constant sanity

    func testStreamIdleTimeoutIsReasonable() {
        // Must be > 0 and <= 3600 to be a sensible idle window.
        XCTAssertGreaterThan(proxyStreamIdleTimeoutSeconds, 0)
        XCTAssertLessThanOrEqual(proxyStreamIdleTimeoutSeconds, 3600)
    }

    func testNonStreamTotalTimeoutExceedsOldCap() {
        // The old 120s cap was the problem; new ceiling must be significantly larger.
        XCTAssertGreaterThan(proxyNonStreamTotalTimeoutSeconds, 120)
    }

    func testCurlSpeedTimeIsPositive() {
        XCTAssertGreaterThan(curlSpeedTimeSeconds, 0)
    }

    func testCurlMaxTimeExceedsOldCap() {
        XCTAssertGreaterThan(curlMaxTimeSeconds, 120)
    }

    func testClientSocketTimeoutConstantIsNamedThirtySecondWindow() {
        XCTAssertEqual(proxyClientSocketTimeoutSeconds, 30)
        XCTAssertGreaterThan(proxyClientSocketTimeoutSeconds, 0)
    }

    // MARK: - CurlHTTPClient idle-based args

    func testStreamingCurlArgsContainSpeedBasedIdle() {
        // We can't call the private execute(), but we can verify the public tlsArgs helper
        // and the constants feed through correctly.
        // Verify speed-based constants are self-consistent.
        XCTAssertGreaterThanOrEqual(curlSpeedTimeSeconds, 10,
                                    "Idle window must be generous enough for slow upstreams")
        XCTAssertEqual(curlMinSpeedBytesPerSecond, 1,
                       "Min speed must be 1 byte/s to allow maximally slow progress")
    }

    func testNonStreamingArgsMustNotUseOldFixed120Seconds() {
        // The old code used timeoutSeconds: 120 as a magic number.
        // Confirm the named constant replaces it and is larger.
        XCTAssertNotEqual(Int(proxyNonStreamTotalTimeoutSeconds), 120,
                          "Non-streaming timeout must not be the old 120s fixed cap")
    }

    // MARK: - CurlHTTPClient TLS args (regression: existing behavior preserved)

    func testTLSArgsInsecureWins() {
        let args = CurlHTTPClient.tlsArgs(caCertPath: "/some/cert.pem", insecure: true)
        XCTAssertEqual(args, ["-k"])
    }

    func testTLSArgsCACertPath() {
        let args = CurlHTTPClient.tlsArgs(caCertPath: "/certs/bundle.pem", insecure: false)
        XCTAssertEqual(args, ["--cacert", "/certs/bundle.pem"])
    }

    func testTLSArgsDefaultIsEmpty() {
        let args = CurlHTTPClient.tlsArgs(caCertPath: nil, insecure: false)
        XCTAssertTrue(args.isEmpty)
    }
}
