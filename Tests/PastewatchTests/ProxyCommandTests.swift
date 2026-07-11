@testable import PastewatchCLI
import XCTest

final class ProxyCommandTests: XCTestCase {
    func testProxyShutdownExitCodeDistinguishesStartupInterrupt() {
        // WO-375: SIGINT before listen succeeds must not look like a clean shutdown.
        XCTAssertEqual(proxyShutdownExitCode(didStart: false), proxyInterruptedExitCode)
        XCTAssertNotEqual(proxyShutdownExitCode(didStart: false), 0)
    }

    func testProxyShutdownExitCodeKeepsCleanPostStartShutdownZero() {
        // WO-375: preserve the existing clean shutdown signal after listen succeeds.
        XCTAssertEqual(proxyShutdownExitCode(didStart: true), 0)
    }
}
