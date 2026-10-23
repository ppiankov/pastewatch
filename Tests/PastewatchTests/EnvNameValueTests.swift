import XCTest
@testable import PastewatchCore

// WO-708@v3: reference-name exclusions must preserve literal credentials and existing DSN authority bytes.
final class EnvNameValueTests: XCTestCase {
    // WO-708@v3: each source spelling shares the value gate rather than a language-specific exception.
    func testEnvironmentNamesAreNotCredentialsAcrossSourceSpellings() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            let config = TestConfigHelper.configWithAmbiguousAdvisories([.credential])
            let name = "SERVICE_" + "ACCESS_KEY"
            let literal = "fixture_" + "value9"
            let keys = ["Secret", "APIKey", "Token", "Password"].map { "EnvService" + $0 }
            let prefixes = ["const ", "let ", "", "export const ", "export "]
            for (spelling, prefix) in prefixes.enumerated() {
                for key in keys {
                    let source = prefix + key + " = \"" + name + "\""
                    let matches = DetectionRules.scan(source, config: config).filter { $0.type == .credential }
                    XCTAssertEqual(matches.count, 0, "source spelling \(spelling): Credential count")
                    let control = prefix + key + " = \"" + literal + "\""
                    let controls = DetectionRules.scan(control, config: config).filter { $0.type == .credential }
                    XCTAssertEqual(controls.count, 1, "literal spelling \(spelling): Credential count")
                    XCTAssertTrue(controls.allSatisfy { $0.effectiveSeverity == .critical })
                }
            }
        }
    }

    // WO-708@v3: the reference grammar is bounded ASCII, not an exemption for arbitrary uppercase values.
    func testEnvironmentNameGrammarHasClosedBoundaries() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            let names = ["SERVICE_" + "KEY2", "A_" + String(repeating: "Z", count: 126)]
            for name in names {
                for quote in ["", "\"", "'"] {
                    XCTAssertFalse(DetectionRules.isValidCredentialValue(quote + name + quote), "env-name verdict")
                }
            }
            let literals = ["Service_" + "KEY2", "2SERVICE_" + "KEY", "SERVICE." + "KEY2",
                            "SÉRVICE_" + "KEY", "A_" + String(repeating: "Z", count: 127)]
            for literal in literals {
                XCTAssertTrue(DetectionRules.isValidCredentialValue("\"" + literal + "\""), "literal verdict")
            }
        }
    }

    // WO-708@v3: shell regex punctuation cannot supply a bare database scheme's missing authority.
    func testBareDatabaseSchemesBeforeBackslashAndPipeAreNotConnections() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            let config = TestConfigHelper.configWithAmbiguousAdvisories([.dbConnectionString])
            for scheme in ["post" + "gres", "my" + "sql", "mongo" + "db"] {
                for suffix in ["\\|DATABASE_URL", "|DATABASE_URL", "\\", "|"] {
                    let content = "grep -v -i 'reference|" + scheme + "://" + suffix + "' fixture.txt"
                    let matches = DetectionRules.scan(content, config: config)
                        .filter { $0.type == .dbConnectionString }
                    XCTAssertEqual(matches.count, 0, "bare scheme: DB Connection count")
                }
            }
        }
    }

    // WO-708@v3: preserving colon as an authority byte retains intrinsic empty-username DSNs.
    func testDatabaseAuthoritiesKeepNormalAndEmptyUsernamePasswords() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            let config = TestConfigHelper.configWithAmbiguousAdvisories([.dbConnectionString])
            let password = "fixture_" + "value9"
            for scheme in ["post" + "gres", "my" + "sql", "mongo" + "db"] {
                for user in ["fixture-user", ""] {
                    let content = scheme + "://" + user + ":" + password + "@db.internal/catalog"
                    let matches = DetectionRules.scan(content, config: config)
                        .filter { $0.type == .dbConnectionString }
                    XCTAssertEqual(matches.count, 1, "authority: DB Connection count")
                    XCTAssertTrue(matches.allSatisfy { $0.effectiveSeverity == .critical })
                    XCTAssertTrue(matches.allSatisfy { $0.mutationAuthorizationSources.contains(.intrinsicFormat) })
                }
            }
        }
    }
}
