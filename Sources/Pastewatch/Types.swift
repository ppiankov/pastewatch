import Foundation

/// Detected sensitive data types.
/// Each type has deterministic detection rules — no ML, no guessing.
enum SensitiveDataType: String, CaseIterable {
    case email = "Email"
    case phone = "Phone"
    case ipAddress = "IP"
    case awsKey = "AWS Key"
    case genericApiKey = "API Key"
    case uuid = "UUID"
    case dbConnectionString = "DB Connection"
    case sshPrivateKey = "SSH Key"
    case jwtToken = "JWT"
    case creditCard = "Card"
}

/// A single detected match in the clipboard content.
struct DetectedMatch: Identifiable, Equatable {
    let id = UUID()
    let type: SensitiveDataType
    let value: String
    let range: Range<String.Index>

    static func == (lhs: DetectedMatch, rhs: DetectedMatch) -> Bool {
        lhs.id == rhs.id
    }
}

/// Result of scanning clipboard content.
struct ScanResult {
    let originalContent: String
    let matches: [DetectedMatch]
    let obfuscatedContent: String
    let timestamp: Date

    var hasMatches: Bool { !matches.isEmpty }

    /// Summary for notification display.
    var summary: String {
        guard hasMatches else { return "" }

        let grouped = Dictionary(grouping: matches, by: { $0.type })
        let parts = grouped.map { type, items in
            "\(type.rawValue) (\(items.count))"
        }
        return parts.joined(separator: ", ")
    }
}

/// Application state.
enum AppState: Equatable {
    case idle
    case monitoring
    case paused
}

/// Configuration for Pastewatch.
/// Loaded from ~/.config/pastewatch/config.json if present.
struct PastewatchConfig: Codable {
    var enabled: Bool
    var enabledTypes: [String]
    var showNotifications: Bool
    var soundEnabled: Bool

    static let defaultConfig = PastewatchConfig(
        enabled: true,
        enabledTypes: SensitiveDataType.allCases.map { $0.rawValue },
        showNotifications: true,
        soundEnabled: false
    )

    static let configPath: URL = {
        let home = FileManager.default.homeDirectoryForCurrentUser
        return home.appendingPathComponent(".config/pastewatch/config.json")
    }()

    static func load() -> PastewatchConfig {
        guard FileManager.default.fileExists(atPath: configPath.path) else {
            return defaultConfig
        }

        do {
            let data = try Data(contentsOf: configPath)
            return try JSONDecoder().decode(PastewatchConfig.self, from: data)
        } catch {
            return defaultConfig
        }
    }

    func save() throws {
        let directory = PastewatchConfig.configPath.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let data = try JSONEncoder().encode(self)
        try data.write(to: PastewatchConfig.configPath)
    }

    func isTypeEnabled(_ type: SensitiveDataType) -> Bool {
        enabledTypes.contains(type.rawValue)
    }
}
