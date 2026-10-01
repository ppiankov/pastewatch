import XCTest
@testable import PastewatchCore

// WO-634: verify isolation before any read, including in the unfixed canary.
final class ConfigIsolationTests: XCTestCase {
    // WO-634: refuse the real global path before exercising either config loader.
    func testIsolatedGlobalConfigCanary() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let path = PastewatchConfig.configPath.standardizedFileURL.path
            let home = FileManager.default.homeDirectoryForCurrentUser.standardizedFileURL.path
            XCTAssertFalse(path.hasPrefix(home + "/"))
            XCTAssertEqual(path, root.appendingPathComponent("global.json").standardizedFileURL.path)
            try assertDefaults(PastewatchConfig.load())
            try assertDefaults(PastewatchConfig.resolve())
            let resolved = try ConfigValidator.resolveValidated()
            XCTAssertEqual(resolved.source, .defaults)
            try assertDefaults(resolved.config)
        }
    }

    // WO-634: exercise load, validated resolution, and save using only fixture-owned files.
    func testInjectedGlobalConfigIsUsedAndProjectStillTakesPrecedence() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            var config = PastewatchConfig.defaultConfig
            config.enabledTypes.append(SensitiveDataType.dbConnectionString.rawValue)
            try config.save()
            XCTAssertTrue(PastewatchConfig.load().isTypeEnabled(.dbConnectionString))
            XCTAssertTrue(PastewatchConfig.resolve().isTypeEnabled(.dbConnectionString))
            let resolved = try ConfigValidator.resolveValidated()
            XCTAssertEqual(resolved.source, .user)
            XCTAssertEqual(resolved.path, PastewatchConfig.configPath.path)
            XCTAssertTrue(resolved.config.isTypeEnabled(.dbConnectionString))
            XCTAssertTrue(ConfigValidator.validate().isValid)

            try TestConfigHelper.ensureProjectConfig(in: root)
            try assertDefaults(PastewatchConfig.resolve())
            XCTAssertEqual(try ConfigValidator.resolveValidated().source, .project)
        }
    }

    // WO-634: nesting and throwing cannot leak a fixture path into subsequent tests.
    func testIsolationRestoresPathAndDirectoryAfterThrow() throws {
        let originalPath = PastewatchConfig.configPath
        let originalDirectory = FileManager.default.currentDirectoryPath
        enum FixtureFailure: Error { case expected }
        XCTAssertThrowsError(try TestConfigHelper.withIsolatedGlobalConfig { _ in
            let outerPath = PastewatchConfig.configPath
            let outerDirectory = FileManager.default.currentDirectoryPath
            XCTAssertThrowsError(try TestConfigHelper.withIsolatedGlobalConfig { _ in
                XCTAssertNotEqual(PastewatchConfig.configPath, outerPath)
                throw FixtureFailure.expected
            }) { XCTAssertTrue($0 is FixtureFailure) }
            XCTAssertEqual(PastewatchConfig.configPath, outerPath)
            XCTAssertEqual(FileManager.default.currentDirectoryPath, outerDirectory)
            throw FixtureFailure.expected
        }) { XCTAssertTrue($0 is FixtureFailure) }
        XCTAssertEqual(PastewatchConfig.configPath, originalPath)
        XCTAssertEqual(FileManager.default.currentDirectoryPath, originalDirectory)
    }

    // WO-634: compile the actual config source without DEBUG; the probe never opens config files.
    func testReleaseConfigPathIgnoresEnvironmentOverrides() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("pastewatch-release-config-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let main = root.appendingPathComponent("main.swift")
        try "import Foundation\nprint(PastewatchConfig.configPath.path)\n".write(
            to: main, atomically: true, encoding: .utf8
        )
        let repository = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let binary = root.appendingPathComponent("config-path-probe")
        let environment = ProcessInfo.processInfo.environment
        _ = try runProcess(
            URL(fileURLWithPath: "/usr/bin/env"),
            arguments: [
                "swiftc", "-O", "-module-cache-path", root.appendingPathComponent("cache").path,
                repository.appendingPathComponent("Sources/PastewatchCore/Types.swift").path,
                main.path, "-o", binary.path,
            ], environment: environment
        )
        let baseline = try runProcess(binary, environment: environment)
        let expected = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".config/pastewatch/config.json").path + "\n"
        XCTAssertEqual(baseline, Data(expected.utf8))

        var redirected = environment
        let variables = Set(environment.keys.filter { $0.hasPrefix("PASTEWATCH_") }).union([
            "HOME", "XDG_CONFIG_HOME", "PASTEWATCH_CONFIG", "PASTEWATCH_CONFIG_PATH",
            "PASTEWATCH_HOME", "PASTEWATCH_GLOBAL_CONFIG_PATH",
        ])
        for variable in variables { redirected[variable] = root.path }
        XCTAssertEqual(try runProcess(binary, environment: redirected), baseline)
    }

    // WO-634: child diagnostics never expose inherited configuration or matched content.
    private func runProcess(
        _ executable: URL, arguments: [String] = [], environment: [String: String]
    ) throws -> Data {
        let process = Process()
        process.executableURL = executable
        process.arguments = arguments
        process.environment = environment
        let output = Pipe()
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        try process.run()
        let data = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            XCTFail("Config-path probe exited \(process.terminationStatus)")
            throw TestConfigHelper.IsolationError.globalConfigNotIsolated
        }
        return data
    }

    // WO-634: compare every setting without exposing config contents in a failure.
    private func assertDefaults(_ config: PastewatchConfig) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        XCTAssertTrue(try encoder.encode(config) == encoder.encode(PastewatchConfig.defaultConfig))
        XCTAssertFalse(config.isTypeEnabled(.dbConnectionString))
        XCTAssertFalse(config.isTypeEnabled(.credential))
    }
}
