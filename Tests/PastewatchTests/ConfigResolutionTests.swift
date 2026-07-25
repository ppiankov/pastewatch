import XCTest
@testable import PastewatchCore

final class ConfigResolutionTests: XCTestCase {

    func testDefaultConfigHasAllTypesEnabled() {
        let config = PastewatchConfig.defaultConfig
        // WO-529: Default config only enables intrinsic detectors, not ambiguous classes.
        // Ambiguous classes (email, host, IP, filePath, phone, dbConnectionString,
        // jdbcUrl, genericApiKey, credential, uuid, xmlUsername, xmlHostname, highEntropyString)
        // are opt-in via the obfuscate config.
        let intrinsicCount = SensitiveDataType.allCases.filter { !$0.isAmbiguousClass }.count
        XCTAssertEqual(config.enabledTypes.count, intrinsicCount)
        XCTAssertFalse(config.isTypeEnabled(.highEntropyString))
        // Verify ambiguous types are NOT enabled by default
        XCTAssertFalse(config.isTypeEnabled(.email))
        XCTAssertFalse(config.isTypeEnabled(.hostname))
        XCTAssertFalse(config.isTypeEnabled(.ipAddress))
        XCTAssertTrue(config.enabled)
    }

    func testDefaultConfigHasEmptyAllowlist() {
        let config = PastewatchConfig.defaultConfig
        XCTAssertTrue(config.allowedValues.isEmpty)
    }

    func testDefaultConfigHasEmptyCustomRules() {
        let config = PastewatchConfig.defaultConfig
        XCTAssertTrue(config.customRules.isEmpty)
        XCTAssertTrue(config.sharedPatternFiles.isEmpty)
        // WO-521: per-redaction operator notices are deliberately opt-in.
        XCTAssertFalse(config.operatorRedactionNotices)
    }

    func testConfigRoundTrip() throws {
        // WO-521: use a mutable fixture to enable the opt-in field explicitly.
        var config = PastewatchConfig(
            enabled: true,
            enabledTypes: ["Email", "Phone"],
            showNotifications: false,
            soundEnabled: false,
            allowedValues: ["test@example.com"],
            customRules: [CustomRuleConfig(name: "Test", pattern: "TEST-[0-9]+")]
        )
        // WO-521: the opt-in setting survives config encoding.
        config.operatorRedactionNotices = true

        let encoder = JSONEncoder()
        let data = try encoder.encode(config)
        let decoded = try JSONDecoder().decode(PastewatchConfig.self, from: data)

        XCTAssertEqual(decoded.enabled, config.enabled)
        // Auto-enable adds new types on decode, so original types must be present
        for t in config.enabledTypes {
            XCTAssertTrue(decoded.enabledTypes.contains(t), "Missing originally enabled type: \(t)")
        }
        XCTAssertTrue(decoded.enabledTypes.contains("Workledger Key"),
                       "New types should be auto-enabled on decode")
        XCTAssertEqual(decoded.allowedValues, config.allowedValues)
        XCTAssertEqual(decoded.customRules.count, config.customRules.count)
        // WO-521: decoding preserves an explicitly enabled operator notice.
        XCTAssertTrue(decoded.operatorRedactionNotices)
    }

    func testBackwardCompatibleDecoding() throws {
        // Config without allowedValues and customRules (v0.2.0 format)
        let json = """
        {
            "enabled": true,
            "enabledTypes": ["Email"],
            "showNotifications": true,
            "soundEnabled": false
        }
        """
        let data = Data(json.utf8)
        let config = try JSONDecoder().decode(PastewatchConfig.self, from: data)

        XCTAssertTrue(config.allowedValues.isEmpty)
        XCTAssertTrue(config.customRules.isEmpty)
        XCTAssertTrue(config.sharedPatternFiles.isEmpty)
        // WO-521: old configs remain silent by default.
        XCTAssertFalse(config.operatorRedactionNotices)
    }

    func testResolveReturnsDefaultWhenNoConfigFiles() {
        // In test environment, CWD typically won't have .pastewatch.json
        // and ~/.config/pastewatch/config.json may or may not exist
        let config = PastewatchConfig.resolve()
        XCTAssertTrue(config.enabled)
        XCTAssertFalse(config.enabledTypes.isEmpty)
    }

    func testResolveFindsProjectConfig() throws {
        let cwd = FileManager.default.currentDirectoryPath
        let projectPath = cwd + "/.pastewatch.json"

        // Create a project config with only Email enabled
        let config = PastewatchConfig(
            enabled: true,
            enabledTypes: ["Email"],
            showNotifications: false,
            soundEnabled: false
        )
        let encoder = JSONEncoder()
        let data = try encoder.encode(config)
        try data.write(to: URL(fileURLWithPath: projectPath))

        defer {
            try? FileManager.default.removeItem(atPath: projectPath)
        }

        let resolved = PastewatchConfig.resolve()
        XCTAssertTrue(resolved.enabledTypes.contains("Email"), "Original type must be present")
        XCTAssertTrue(resolved.enabledTypes.contains("Workledger Key"),
                       "New types should be auto-enabled from project config")
    }

    func testIsTypeEnabled() {
        let config = PastewatchConfig(
            enabled: true,
            enabledTypes: ["Email", "Phone"],
            showNotifications: false,
            soundEnabled: false
        )
        XCTAssertTrue(config.isTypeEnabled(.email))
        XCTAssertTrue(config.isTypeEnabled(.phone))
        XCTAssertFalse(config.isTypeEnabled(.ipAddress))
    }

    // WO-529@v3: verify configured entries activate only their matching ambiguous detectors.
    func testObfuscateEntryActivatesOnlyItsDetectorAndRoundTrips() throws {
        var config = PastewatchConfig.defaultConfig
        config.obfuscate = [
            ObfuscateEntry(type: "email", pattern: "@example.com"),
            ObfuscateEntry(type: "host", pattern: ".example.com"),
        ]

        let decoded = try JSONDecoder().decode(
            PastewatchConfig.self,
            from: JSONEncoder().encode(config)
        )

        XCTAssertTrue(decoded.isTypeEnabled(.email))
        XCTAssertTrue(decoded.isTypeEnabled(.hostname))
        XCTAssertFalse(decoded.isTypeEnabled(.ipAddress))
        XCTAssertEqual(decoded.obfuscate, config.obfuscate)
    }

    func testValidateRejectsMalformedObfuscateEntriesWithoutEchoingPatterns() throws {
        // WO-541: every invalid shape fails closed with indexed, value-free diagnostics.
        let cases = [
            ObfuscateEntry(type: "unknown", pattern: "@example.com"),
            ObfuscateEntry(type: "email", pattern: ""),
            ObfuscateEntry(type: "email", pattern: ".example.com"),
            ObfuscateEntry(type: "email", pattern: "@"),
            ObfuscateEntry(type: "host", pattern: "@example.com"),
            ObfuscateEntry(type: "host", pattern: "."),
        ]

        for entry in cases {
            let configURL = try writeConfig(obfuscate: [entry])
            defer { try? FileManager.default.removeItem(at: configURL) }

            let result = ConfigValidator.validate(path: configURL.path)

            XCTAssertFalse(result.isValid, "accepted \(entry.type)")
            XCTAssertTrue(result.errors.contains { $0.contains("obfuscate[0]") })
            XCTAssertFalse(result.errors.contains { $0.contains(entry.pattern) && !entry.pattern.isEmpty })
        }
    }

    // WO-541: verify every documented exact and domain-scoped shape validates.
    func testValidateAcceptsEverySupportedObfuscateShape() throws {
        let entries = [
            ObfuscateEntry(type: "email", pattern: "operator@example.com"),
            ObfuscateEntry(type: "email", pattern: "@example.com"),
            ObfuscateEntry(type: "host", pattern: "gateway.example.com"),
            ObfuscateEntry(type: "host", pattern: ".example.com"),
        ]
        let configURL = try writeConfig(obfuscate: entries)
        defer { try? FileManager.default.removeItem(at: configURL) }

        XCTAssertTrue(ConfigValidator.validate(path: configURL.path).isValid)
    }

    func testValidateRejectsMissingSharedPatternFile() throws {
        let missingURL = temporaryJSONURL(prefix: "pastewatch-missing-shared")
        let configURL = try writeConfig(sharedPatternFiles: [missingURL.path])
        defer { try? FileManager.default.removeItem(at: configURL) }

        let result = ConfigValidator.validate(path: configURL.path)

        XCTAssertFalse(result.isValid)
        XCTAssertTrue(result.errors.contains { $0.contains(missingURL.path) && $0.contains("could not read") })
    }

    func testValidateRejectsMalformedSharedPatternFile() throws {
        let artifactURL = temporaryJSONURL(prefix: "pastewatch-malformed-shared")
        try "{".write(to: artifactURL, atomically: true, encoding: .utf8)
        let configURL = try writeConfig(sharedPatternFiles: [artifactURL.path])
        defer {
            try? FileManager.default.removeItem(at: artifactURL)
            try? FileManager.default.removeItem(at: configURL)
        }

        let result = ConfigValidator.validate(path: configURL.path)

        XCTAssertFalse(result.isValid)
        XCTAssertTrue(result.errors.contains { $0.contains(artifactURL.path) && $0.contains("invalid JSON") })
    }

    func testValidateRejectsUnsupportedSharedPatternEnvelope() throws {
        let artifactURL = temporaryJSONURL(prefix: "pastewatch-unsupported-shared")
        try #"{"unexpected_patterns":[]}"#.write(to: artifactURL, atomically: true, encoding: .utf8)
        let configURL = try writeConfig(sharedPatternFiles: [artifactURL.path])
        defer {
            try? FileManager.default.removeItem(at: artifactURL)
            try? FileManager.default.removeItem(at: configURL)
        }

        let result = ConfigValidator.validate(path: configURL.path)

        XCTAssertFalse(result.isValid)
        XCTAssertTrue(result.errors.contains { $0.contains(artifactURL.path) && $0.contains("unsupported") })
    }

    func testValidateRejectsEmptySharedPatternManifest() throws {
        let artifactURL = temporaryJSONURL(prefix: "pastewatch-empty-shared")
        let manifest = SharedSecretPatternManifest(patterns: [])
        try JSONEncoder().encode(manifest).write(to: artifactURL)
        let configURL = try writeConfig(sharedPatternFiles: [artifactURL.path])
        defer {
            try? FileManager.default.removeItem(at: artifactURL)
            try? FileManager.default.removeItem(at: configURL)
        }

        let result = ConfigValidator.validate(path: configURL.path)

        XCTAssertFalse(result.isValid)
        XCTAssertTrue(result.errors.contains { $0.contains(artifactURL.path) && $0.contains("no shared patterns") })
    }

    func testValidateRejectsInvalidSharedPatternRegex() throws {
        let artifactURL = temporaryJSONURL(prefix: "pastewatch-invalid-regex-shared")
        let patterns = [
            SharedSecretPatternConfig(name: "broken_shared", type: "github_token", regex: "(", policy: "redact")
        ]
        try JSONEncoder().encode(patterns).write(to: artifactURL)
        let configURL = try writeConfig(sharedPatternFiles: [artifactURL.path])
        defer {
            try? FileManager.default.removeItem(at: artifactURL)
            try? FileManager.default.removeItem(at: configURL)
        }

        let result = ConfigValidator.validate(path: configURL.path)

        XCTAssertFalse(result.isValid)
        XCTAssertTrue(result.errors.contains { $0.contains(artifactURL.path) && $0.contains("invalid regex") })
    }

    func testValidateRejectsInvalidSharedPatternPolicy() throws {
        let artifactURL = temporaryJSONURL(prefix: "pastewatch-invalid-policy-shared")
        let patterns = [
            SharedSecretPatternConfig(
                name: "bad_policy_shared",
                type: "github_token",
                regex: #"PW-POLICY-[A-F0-9]{12}"#,
                policy: "quarantine"
            )
        ]
        try JSONEncoder().encode(patterns).write(to: artifactURL)
        let configURL = try writeConfig(sharedPatternFiles: [artifactURL.path])
        defer {
            try? FileManager.default.removeItem(at: artifactURL)
            try? FileManager.default.removeItem(at: configURL)
        }

        let result = ConfigValidator.validate(path: configURL.path)

        XCTAssertFalse(result.isValid)
        XCTAssertTrue(result.errors.contains { $0.contains(artifactURL.path) && $0.contains("invalid policy") })
    }

    private func writeConfig(sharedPatternFiles: [String]) throws -> URL {
        var config = PastewatchConfig.defaultConfig
        config.sharedPatternFiles = sharedPatternFiles
        let url = temporaryJSONURL(prefix: "pastewatch-config")
        try JSONEncoder().encode(config).write(to: url)
        return url
    }

    // WO-541: build isolated obfuscate configs for fail-closed validation tests.
    private func writeConfig(obfuscate: [ObfuscateEntry]) throws -> URL {
        var config = PastewatchConfig.defaultConfig
        config.obfuscate = obfuscate
        let url = temporaryJSONURL(prefix: "pastewatch-obfuscate-config")
        try JSONEncoder().encode(config).write(to: url)
        return url
    }

    private func temporaryJSONURL(prefix: String) -> URL {
        URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("\(prefix)-\(UUID().uuidString).json")
    }
}
