import XCTest
@testable import PastewatchCLI
@testable import PastewatchCore

final class InitCommandTests: XCTestCase {
    // WO-532: verify the default template does not opt in ambiguous classes.
    func testDefaultTemplateKeepsAmbiguousObfuscationOff() throws {
        let config = try decode(Init.defaultTemplate())

        XCTAssertTrue(config.obfuscate.isEmpty)
        XCTAssertFalse(config.isTypeEnabled(.email))
        XCTAssertFalse(config.isTypeEnabled(.hostname))
    }

    // WO-532: verify the banking template entries authorize their detectors.
    func testBankingTemplateSamplesAreBehaviorallyEffective() throws {
        let config = try decode(Init.bankingTemplate())
        let email = ["operator", "@", "YOURBANK.com"].joined()
        let host = ["api", ".internal.YOURBANK.com"].joined()

        XCTAssertTrue(config.isTypeEnabled(.email))
        XCTAssertTrue(config.isTypeEnabled(.hostname))
        XCTAssertTrue(
            DetectionRules.scan(email, config: config)
                .contains { $0.mutationAuthorizationSources.contains(.configuredObfuscate) }
        )
        XCTAssertTrue(
            DetectionRules.scan(host, config: config)
                .contains { $0.mutationAuthorizationSources.contains(.configuredObfuscate) }
        )
    }

    // WO-532: decode generated templates through the public config model.
    private func decode(_ json: String) throws -> PastewatchConfig {
        try JSONDecoder().decode(PastewatchConfig.self, from: Data(json.utf8))
    }
}
