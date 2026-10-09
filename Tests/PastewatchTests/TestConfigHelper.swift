import Foundation
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif
@testable import PastewatchCore

/// WO-529@v3: Test helper for creating configs with obfuscate entries.
/// Ambiguous classes (email, host, IP, etc.) are opt-in via the obfuscate config.
enum TestConfigHelper {
    // WO-634: fail before config I/O if a fixture could reach operator policy.
    enum IsolationError: Error {
        case globalConfigNotIsolated
        case cannotChangeDirectory
    }

    // WO-672@v1: DEBUG subprocesses share the scoped global fixture, not operator policy.
    // WO-634: use a scoped fixture, not HOME, and restore CWD even on thrown errors.
    static func withIsolatedGlobalConfig<T>(_ body: (URL) throws -> T) throws -> T {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("pastewatch-config-isolation-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let path = root.appendingPathComponent("global.json")
        // WO-672@v1: system policy is fixture-owned too, including subprocesses.
        let systemPath = root.appendingPathComponent("system.json")
        // WO-634: the lock spans the fixture scope, including CWD restoration on throws.
        return try PastewatchConfig.withTestGlobalConfigPath(path) {
            // WO-672@v1: administrator-path injection uses the same scoped DEBUG boundary.
            try PastewatchConfig.withTestSystemConfigPath(systemPath) {
                // WO-672@v1: restore both environment channels on nesting and errors.
                let key = PastewatchConfig.testGlobalConfigEnvironmentKey
                let previous = ProcessInfo.processInfo.environment[key]
                let systemKey = PastewatchConfig.testSystemConfigEnvironmentKey
                let previousSystem = ProcessInfo.processInfo.environment[systemKey]
                setenv(key, path.path, 1)
                setenv(systemKey, systemPath.path, 1)
                defer {
                    if let previous { setenv(key, previous, 1) } else { unsetenv(key) }
                    if let previousSystem { setenv(systemKey, previousSystem, 1) } else { unsetenv(systemKey) }
                }
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
    }

    // WO-672@v1: a project file no longer replaces global policy, so isolate both tiers.
    // WO-634: subprocesses select private fixture policy rather than operator files.
    static func ensureProjectConfig(in directory: URL) throws {
        let path = directory.appendingPathComponent(".pastewatch.json")
        if !FileManager.default.fileExists(atPath: path.path) {
            try JSONEncoder().encode(PastewatchConfig.defaultConfig).write(to: path)
        }
        // WO-672@v1: an existing scoped user fixture is preserved; otherwise use an empty valid config.
        let current = PastewatchConfig.configPath
        let global = current.deletingLastPathComponent().standardizedFileURL == directory.standardizedFileURL ?
            current : directory.appendingPathComponent(".pastewatch-test-global.json")
        if !FileManager.default.fileExists(atPath: global.path) {
            try JSONEncoder().encode(PastewatchConfig.defaultConfig).write(to: global)
        }
        setenv(PastewatchConfig.testGlobalConfigEnvironmentKey, global.path, 1)
        // WO-672@v1: absent system fixtures preserve the authoritative-user test case.
        let currentSystem = URL(fileURLWithPath: PastewatchConfig.systemConfigPath)
        let system = currentSystem.deletingLastPathComponent().standardizedFileURL == directory.standardizedFileURL ?
            currentSystem : directory.appendingPathComponent(".pastewatch-test-system.json")
        setenv(PastewatchConfig.testSystemConfigEnvironmentKey, system.path, 1)
    }

    // WO-672@v1: custom child environments cannot discard the DEBUG isolation channel.
    static func subprocessEnvironment(_ overrides: [String: String] = [:]) -> [String: String] {
        let key = PastewatchConfig.testGlobalConfigEnvironmentKey
        let isolatedPath = ProcessInfo.processInfo.environment[key] ??
            FileManager.default.temporaryDirectory.appendingPathComponent("pastewatch-absent-global-\(UUID().uuidString).json").path
        var environment = overrides
        environment[key] = overrides[key] ?? isolatedPath
        // WO-672@v1: custom child environments cannot accidentally load administrator policy.
        let systemKey = PastewatchConfig.testSystemConfigEnvironmentKey
        environment[systemKey] = overrides[systemKey] ?? ProcessInfo.processInfo.environment[systemKey] ??
            FileManager.default.temporaryDirectory.appendingPathComponent("pastewatch-absent-system-\(UUID().uuidString).json").path
        return environment
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
