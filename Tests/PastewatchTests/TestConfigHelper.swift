import Foundation
@testable import PastewatchCore

/// WO-529: Test helper for creating configs with obfuscate entries.
/// Ambiguous classes (email, host, IP, etc.) are opt-in via the obfuscate config.
enum TestConfigHelper {
    /// Creates a config with email obfuscation enabled for common test domains.
    static func configWithEmailObfuscation() -> PastewatchConfig {
        var config = PastewatchConfig.defaultConfig
        if !config.enabledTypes.contains(SensitiveDataType.email.rawValue) {
            config.enabledTypes.append(SensitiveDataType.email.rawValue)
        }
        config.obfuscate = [
            ObfuscateEntry(type: "email", pattern: "@corp.com"),
            ObfuscateEntry(type: "email", pattern: "@example.com"),
            ObfuscateEntry(type: "email", pattern: "@test.com"),
            ObfuscateEntry(type: "email", pattern: "@company.com"),
            ObfuscateEntry(type: "email", pattern: "@safe.com")
        ]
        return config
    }

    /// Creates a config with host obfuscation enabled for common test domains.
    static func configWithHostObfuscation() -> PastewatchConfig {
        var config = PastewatchConfig.defaultConfig
        if !config.enabledTypes.contains(SensitiveDataType.hostname.rawValue) {
            config.enabledTypes.append(SensitiveDataType.hostname.rawValue)
        }
        config.obfuscate = [
            ObfuscateEntry(type: "host", pattern: ".internal"),
            ObfuscateEntry(type: "host", pattern: ".local"),
            ObfuscateEntry(type: "host", pattern: ".corp"),
            ObfuscateEntry(type: "host", pattern: "nas.local"),
            ObfuscateEntry(type: "host", pattern: "printer.lan")
        ]
        return config
    }

    /// Creates a config with all ambiguous types enabled and obfuscation for common test values.
    static func configWithAllAmbiguousObfuscation() -> PastewatchConfig {
        var config = PastewatchConfig.defaultConfig
        // Enable all ambiguous types
        let ambiguousTypes: [SensitiveDataType] = [
            .email, .phone, .ipAddress, .filePath, .hostname,
            .dbConnectionString, .jdbcUrl, .genericApiKey, .credential, .uuid
        ]
        for type in ambiguousTypes where !config.enabledTypes.contains(type.rawValue) {
            config.enabledTypes.append(type.rawValue)
        }
        config.obfuscate = [
            // Email patterns
            ObfuscateEntry(type: "email", pattern: "@corp.com"),
            ObfuscateEntry(type: "email", pattern: "@example.com"),
            ObfuscateEntry(type: "email", pattern: "@test.com"),
            ObfuscateEntry(type: "email", pattern: "@company.com"),
            ObfuscateEntry(type: "email", pattern: "@safe.com"),
            // Host patterns
            ObfuscateEntry(type: "host", pattern: ".internal"),
            ObfuscateEntry(type: "host", pattern: ".local"),
            ObfuscateEntry(type: "host", pattern: ".corp"),
            ObfuscateEntry(type: "host", pattern: "nas.local"),
            ObfuscateEntry(type: "host", pattern: "printer.lan")
        ]
        return config
    }
}
