import Foundation

/// Detected sensitive data types.
/// Each type has deterministic detection rules — no ML, no guessing.
public enum SensitiveDataType: String, CaseIterable, Codable {
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
    case filePath = "File Path"
    case hostname = "Hostname"
    case credential = "Credential"
}

/// A single detected match in the clipboard content.
public struct DetectedMatch: Identifiable, Equatable {
    public let id = UUID()
    public let type: SensitiveDataType
    public let value: String
    public let range: Range<String.Index>

    public init(type: SensitiveDataType, value: String, range: Range<String.Index>) {
        self.type = type
        self.value = value
        self.range = range
    }

    public static func == (lhs: DetectedMatch, rhs: DetectedMatch) -> Bool {
        lhs.id == rhs.id
    }
}

/// Result of scanning clipboard content.
public struct ScanResult {
    public let originalContent: String
    public let matches: [DetectedMatch]
    public let obfuscatedContent: String
    public let timestamp: Date

    public init(originalContent: String, matches: [DetectedMatch], obfuscatedContent: String, timestamp: Date) {
        self.originalContent = originalContent
        self.matches = matches
        self.obfuscatedContent = obfuscatedContent
        self.timestamp = timestamp
    }

    public var hasMatches: Bool { !matches.isEmpty }

    /// Summary for notification display.
    public var summary: String {
        guard hasMatches else { return "" }

        let grouped = Dictionary(grouping: matches, by: { $0.type })
        let parts = grouped.map { type, items in
            "\(type.rawValue) (\(items.count))"
        }
        return parts.joined(separator: ", ")
    }
}

/// Application state.
public enum AppState: Equatable {
    case idle
    case monitoring
    case paused
}

/// Configuration for Pastewatch.
/// Loaded from ~/.config/pastewatch/config.json if present.
public struct PastewatchConfig: Codable {
    public var enabled: Bool
    public var enabledTypes: [String]
    public var showNotifications: Bool
    public var soundEnabled: Bool

    public init(enabled: Bool, enabledTypes: [String], showNotifications: Bool, soundEnabled: Bool) {
        self.enabled = enabled
        self.enabledTypes = enabledTypes
        self.showNotifications = showNotifications
        self.soundEnabled = soundEnabled
    }

    public static let defaultConfig = PastewatchConfig(
        enabled: true,
        enabledTypes: SensitiveDataType.allCases.map { $0.rawValue },
        showNotifications: true,
        soundEnabled: false
    )

    public static let configPath: URL = {
        let home = FileManager.default.homeDirectoryForCurrentUser
        return home.appendingPathComponent(".config/pastewatch/config.json")
    }()

    public static func load() -> PastewatchConfig {
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

    public func save() throws {
        let directory = PastewatchConfig.configPath.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let data = try JSONEncoder().encode(self)
        try data.write(to: PastewatchConfig.configPath)
    }

    public func isTypeEnabled(_ type: SensitiveDataType) -> Bool {
        enabledTypes.contains(type.rawValue)
    }
}
