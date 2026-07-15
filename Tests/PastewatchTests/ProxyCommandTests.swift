@testable import PastewatchCLI
@testable import PastewatchCore
import XCTest
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

final class ProxyCommandTests: XCTestCase {
    // WO-473: the shared command gate rejects mixed valid/invalid rules before listen.
    func testProxyCustomRuleStartupGateRejectsWholeSet() {
        var config = PastewatchConfig.defaultConfig
        config.customRules = [
            CustomRuleConfig(name: "Valid", pattern: "SAFE-[0-9]+"),
            CustomRuleConfig(name: "Invalid", pattern: "[broken")
        ]

        XCTAssertThrowsError(try compileProxyCustomRules(config))
    }

    func testDirectProxyServerRejectsInvalidRuleBeforeListen() {
        let invalidPattern = "[" + "broken"
        var config = PastewatchConfig.defaultConfig
        config.customRules = [CustomRuleConfig(name: "Invalid", pattern: invalidPattern)]
        let server = ProxyServer(port: 0, config: config)

        XCTAssertThrowsError(try server.start()) { error in
            XCTAssertTrue(error.localizedDescription.contains("Invalid"))
            XCTAssertFalse(error.localizedDescription.contains(invalidPattern))
        }
    }

    // WO-275: quiet launch and normal peer disconnects are silent; unexpected
    // socket failures remain visible in explicit non-quiet proxy mode.
    func testSocketDeliveryFailureLoggingPolicy() {
        XCTAssertFalse(ProxyServer.shouldLogSocketDeliveryFailure(errorCode: EPIPE, quiet: false))
        XCTAssertFalse(ProxyServer.shouldLogSocketDeliveryFailure(errorCode: ECONNRESET, quiet: false))
        XCTAssertFalse(ProxyServer.shouldLogSocketDeliveryFailure(errorCode: EIO, quiet: true))
        XCTAssertTrue(ProxyServer.shouldLogSocketDeliveryFailure(errorCode: EBADF, quiet: false))
        XCTAssertTrue(ProxyServer.shouldLogSocketDeliveryFailure(errorCode: EIO, quiet: false))
    }

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
