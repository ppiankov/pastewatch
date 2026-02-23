import Foundation

/// Severity level for detected findings.
public enum Severity: String, Codable, CaseIterable, Comparable {
    case critical
    case high
    case medium
    case low

    private var rank: Int {
        switch self {
        case .critical: return 4
        case .high: return 3
        case .medium: return 2
        case .low: return 1
        }
    }

    public static func < (lhs: Severity, rhs: Severity) -> Bool {
        lhs.rank < rhs.rank
    }

    /// Map to SARIF result level.
    public var sarifLevel: String {
        switch self {
        case .critical, .high: return "error"
        case .medium: return "warning"
        case .low: return "note"
        }
    }
}

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
    case slackWebhook = "Slack Webhook"
    case discordWebhook = "Discord Webhook"
    case azureConnectionString = "Azure Connection"
    case gcpServiceAccount = "GCP Service Account"

    /// Severity of this detection type.
    public var severity: Severity {
        switch self {
        case .awsKey, .genericApiKey, .sshPrivateKey, .dbConnectionString,
             .jwtToken, .creditCard, .credential,
             .slackWebhook, .discordWebhook, .azureConnectionString, .gcpServiceAccount:
            return .critical
        case .email, .phone:
            return .high
        case .ipAddress, .filePath, .hostname:
            return .medium
        case .uuid:
            return .low
        }
    }
}

/// A single detected match in the clipboard content.
public struct DetectedMatch: Identifiable, Equatable {
    public let id = UUID()
    public let type: SensitiveDataType
    public let value: String
    public let range: Range<String.Index>
    public let line: Int
    public let filePath: String?
    public let customRuleName: String?

    public init(
        type: SensitiveDataType,
        value: String,
        range: Range<String.Index>,
        line: Int = 1,
        filePath: String? = nil,
        customRuleName: String? = nil
    ) {
        self.type = type
        self.value = value
        self.range = range
        self.line = line
        self.filePath = filePath
        self.customRuleName = customRuleName
    }

    /// Display name for output (custom rule name or type rawValue).
    public var displayName: String {
        customRuleName ?? type.rawValue
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

/// Custom rule definition for user-defined patterns.
public struct CustomRuleConfig: Codable {
    public let name: String
    public let pattern: String

    public init(name: String, pattern: String) {
        self.name = name
        self.pattern = pattern
    }
}

/// Configuration for Pastewatch.
/// Loaded from ~/.config/pastewatch/config.json if present.
public struct PastewatchConfig: Codable {
    public var enabled: Bool
    public var enabledTypes: [String]
    public var showNotifications: Bool
    public var soundEnabled: Bool
    public var allowedValues: [String]
    public var customRules: [CustomRuleConfig]

    public init(
        enabled: Bool,
        enabledTypes: [String],
        showNotifications: Bool,
        soundEnabled: Bool,
        allowedValues: [String] = [],
        customRules: [CustomRuleConfig] = []
    ) {
        self.enabled = enabled
        self.enabledTypes = enabledTypes
        self.showNotifications = showNotifications
        self.soundEnabled = soundEnabled
        self.allowedValues = allowedValues
        self.customRules = customRules
    }

    // Backward-compatible decoding: missing fields get defaults
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        enabled = try container.decode(Bool.self, forKey: .enabled)
        enabledTypes = try container.decode([String].self, forKey: .enabledTypes)
        showNotifications = try container.decode(Bool.self, forKey: .showNotifications)
        soundEnabled = try container.decode(Bool.self, forKey: .soundEnabled)
        allowedValues = try container.decodeIfPresent([String].self, forKey: .allowedValues) ?? []
        customRules = try container.decodeIfPresent([CustomRuleConfig].self, forKey: .customRules) ?? []
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

    /// Resolve config with cascade: CWD .pastewatch.json -> ~/.config/pastewatch/config.json -> defaults.
    public static func resolve() -> PastewatchConfig {
        let cwd = FileManager.default.currentDirectoryPath
        let projectPath = cwd + "/.pastewatch.json"
        if FileManager.default.fileExists(atPath: projectPath),
           let data = try? Data(contentsOf: URL(fileURLWithPath: projectPath)),
           let config = try? JSONDecoder().decode(PastewatchConfig.self, from: data) {
            return config
        }
        return load()
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
