import Foundation
@testable import PastewatchCore

/// WO-529@v3: Test helper for creating configs with obfuscate entries.
/// Ambiguous classes (email, host, IP, etc.) are opt-in via the obfuscate config.
enum TestConfigHelper {
    // WO-634: fail before config I/O if a fixture could reach operator policy.
    enum IsolationError: Error {
        case globalConfigNotIsolated
        case cannotChangeDirectory
    }

    // WO-634: use a scoped fixture, not HOME, and restore CWD even on thrown errors.
    static func withIsolatedGlobalConfig<T>(_ body: (URL) throws -> T) throws -> T {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("pastewatch-config-isolation-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let path = root.appendingPathComponent("global.json")
        // WO-634: the lock spans the fixture scope, including CWD restoration on throws.
        return try PastewatchConfig.withTestGlobalConfigPath(path) {
            guard PastewatchConfig.configPath == path else {
                throw IsolationError.globalConfigNotIsolated
            }
            let cwd = FileManager.default.currentDirectoryPath
            guard FileManager.default.changeCurrentDirectoryPath(root.path) else {
                throw IsolationError.cannotChangeDirectory
            }
            defer { _ = FileManager.default.changeCurrentDirectoryPath(cwd) }
            return try body(root)
        }
    }

    // WO-634: subprocesses must select fixture policy before user-config fallback.
    static func ensureProjectConfig(in directory: URL) throws {
        let path = directory.appendingPathComponent(".pastewatch.json")
        if !FileManager.default.fileExists(atPath: path.path) {
            try JSONEncoder().encode(PastewatchConfig.defaultConfig).write(to: path)
        }
    }

    // WO-634: subprocess-only fixtures get their own CWD, never a shared /tmp config.
    static func makeProjectDirectory() throws -> URL {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("pastewatch-project-config-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        try ensureProjectConfig(in: root)
        return root
    }

    /// WO-542: legacy advisory fixtures must opt ambiguous detectors in without authorizing mutation.
    static func configWithAmbiguousAdvisories(
        _ types: [SensitiveDataType]
    ) -> PastewatchConfig {
        var config = PastewatchConfig.defaultConfig
        for type in types where !config.enabledTypes.contains(type.rawValue) {
            config.enabledTypes.append(type.rawValue)
        }
        return config
    }

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
