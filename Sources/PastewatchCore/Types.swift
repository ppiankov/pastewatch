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
    case openaiKey = "OpenAI Key"
    case anthropicKey = "Anthropic Key"
    case huggingfaceToken = "Hugging Face Token"
    case groqKey = "Groq Key"
    case npmToken = "npm Token"
    case pypiToken = "PyPI Token"
    case rubygemsToken = "RubyGems Token"
    case gitlabToken = "GitLab Token"
    case telegramBotToken = "Telegram Bot Token"
    case sendgridKey = "SendGrid Key"
    case shopifyToken = "Shopify Token"
    case digitaloceanToken = "DigitalOcean Token"
    case perplexityKey = "Perplexity Key"
    case jdbcUrl = "JDBC URL"
    case xmlCredential = "XML Credential"
    case xmlUsername = "XML Username"
    case xmlHostname = "XML Hostname"
    case highEntropyString = "High Entropy"

    /// Severity of this detection type.
    public var severity: Severity {
        switch self {
        case .awsKey, .genericApiKey, .sshPrivateKey, .dbConnectionString,
             .jwtToken, .creditCard, .credential,
             .slackWebhook, .discordWebhook, .azureConnectionString, .gcpServiceAccount,
             .openaiKey, .anthropicKey, .huggingfaceToken, .groqKey,
             .npmToken, .pypiToken, .rubygemsToken,
             .gitlabToken, .telegramBotToken, .sendgridKey, .shopifyToken, .digitaloceanToken,
             .perplexityKey, .jdbcUrl, .xmlCredential:
            return .critical
        case .email, .phone, .xmlUsername:
            return .high
        case .ipAddress, .filePath, .hostname, .xmlHostname:
            return .medium
        case .uuid, .highEntropyString:
            return .low
        }
    }

    /// Human-readable explanation of what this type detects.
    public var explanation: String {
        switch self {
        case .email: return "Email addresses (user@domain.tld)"
        case .phone: return "Phone numbers in international or US format"
        case .ipAddress: return "Private and public IPv4 addresses (excludes localhost)"
        case .awsKey: return "AWS access key IDs starting with AKIA"
        case .genericApiKey: return "API keys and tokens (GitHub, Stripe, generic secret_ prefixes)"
        case .uuid: return "UUIDs (version 1-5 format)"
        case .dbConnectionString: return "Database connection strings (postgres://, mysql://, mongodb://)"
        case .sshPrivateKey: return "SSH/PGP private key headers (BEGIN RSA/DSA/EC/OPENSSH PRIVATE KEY)"
        case .jwtToken: return "JSON Web Tokens (three base64url-encoded segments)"
        case .creditCard: return "Credit card numbers (Visa, Mastercard, Amex) with Luhn validation"
        case .filePath: return "Sensitive file paths (/etc/*, /home/*/.ssh/*, etc.)"
        case .hostname: return "Internal hostnames and non-public domains"
        case .credential: return "Key-value credential patterns (password=, secret:, auth=)"
        case .slackWebhook: return "Slack incoming webhook URLs"
        case .discordWebhook: return "Discord webhook URLs"
        case .azureConnectionString: return "Azure Storage connection strings with AccountKey"
        case .gcpServiceAccount: return "GCP service account JSON key files"
        case .openaiKey: return "OpenAI API keys (sk-proj-, sk-svcacct- prefixes)"
        case .anthropicKey: return "Anthropic API keys (sk-ant-api03-, sk-ant-admin01-, sk-ant-oat01- prefixes)"
        case .huggingfaceToken: return "Hugging Face access tokens (hf_ prefix)"
        case .groqKey: return "Groq API keys (gsk_ prefix)"
        case .npmToken: return "npm access tokens (npm_ prefix)"
        case .pypiToken: return "PyPI API tokens (pypi- prefix)"
        case .rubygemsToken: return "RubyGems API keys (rubygems_ prefix)"
        case .gitlabToken: return "GitLab personal access tokens (glpat- prefix)"
        case .telegramBotToken: return "Telegram bot tokens (numeric ID + AA hash)"
        case .sendgridKey: return "SendGrid API keys (SG. prefix with base64 segments)"
        case .shopifyToken: return "Shopify access tokens (shpat_, shpca_, shppa_ prefixes)"
        case .digitaloceanToken: return "DigitalOcean tokens (dop_v1_, doo_v1_ prefixes)"
        case .perplexityKey: return "Perplexity AI API keys (pplx- prefix)"
        case .jdbcUrl: return "JDBC connection URLs (jdbc:oracle, jdbc:db2, jdbc:mysql, jdbc:postgresql, jdbc:sqlserver)"
        case .xmlCredential: return "Credentials in XML tags (password, secret, access_key)"
        case .xmlUsername: return "Usernames in XML tags (user, name within users context)"
        case .xmlHostname: return "Hostnames in XML tags (host, hostname, replica)"
        case .highEntropyString: return "High-entropy strings that may be secrets (Shannon entropy > 4.0, mixed character classes)"
        }
    }

    /// Example strings that would be detected by this type.
    public var examples: [String] {
        switch self {
        case .email: return ["user@company.com", "admin@internal.corp.net"]
        case .phone: return ["+14155551234", "(555) 123-4567"]
        case .ipAddress: return ["192.168.1.100", "10.0.0.50"]
        case .awsKey: return ["AKIA<20-character key ID>"]
        case .genericApiKey: return ["ghp_<36-character token>", "sk_live_<key>"]
        case .uuid: return ["550e8400-e29b-41d4-a716-446655440000"]
        case .dbConnectionString: return ["postgres://... (connection URI)", "mongodb://... (connection URI)"]
        case .sshPrivateKey: return ["-----BEGIN <type> PRIVATE KEY-----"]
        case .jwtToken: return ["<header>.<payload>.<signature> (base64url)"]
        case .creditCard: return ["4111 1111 1111 1111", "5500 0000 0000 0004"]
        case .filePath: return ["/etc/nginx/nginx.conf", "/home/deploy/.ssh/id_rsa"]
        case .hostname: return ["db-primary.internal.corp.net", "api.staging.company.io"]
        case .credential: return ["password=<value>", "secret: <value>"]
        case .slackWebhook: return ["https://hooks.slack.com/services/T.../B.../xxx"]
        case .discordWebhook: return ["https://discord.com/api/webhooks/<id>/<token>"]
        case .azureConnectionString: return ["DefaultEndpointsProtocol=https;AccountName=<name>;AccountKey=<key>"]
        case .gcpServiceAccount: return ["{\"type\": \"service_account\", \"project_id\": \"<id>\"}"]
        case .openaiKey: return ["sk-proj-<project key>", "sk-svcacct-<service account key>"]
        case .anthropicKey: return ["sk-ant-api03-<API key>", "sk-ant-admin01-<admin key>"]
        case .huggingfaceToken: return ["hf_<access token>"]
        case .groqKey: return ["gsk_<API key>"]
        case .npmToken: return ["npm_<access token>"]
        case .pypiToken: return ["pypi-<API token>"]
        case .rubygemsToken: return ["rubygems_<API key>"]
        case .gitlabToken: return ["glpat-<personal access token>"]
        case .telegramBotToken: return ["123456789:AA<33-character hash>"]
        case .sendgridKey: return ["SG.<base64>.<base64>"]
        case .shopifyToken: return ["shpat_<access token>", "shpca_<token>", "shppa_<token>"]
        case .digitaloceanToken: return ["dop_v1_<64-hex-chars>", "doo_v1_<64-hex-chars>"]
        case .perplexityKey: return ["pplx-<48-alphanumeric-chars>"]
        case .jdbcUrl: return ["jdbc:oracle:thin:@host:1521:SID", "jdbc:postgresql://host:5432/db"]
        case .xmlCredential: return ["<password>secret123</password>", "<secret_access_key>KEY</secret_access_key>"]
        case .xmlUsername: return ["<user>admin</user>", "<name>deploy</name>"]
        case .xmlHostname: return ["<host>db-primary.internal.corp.net</host>"]
        case .highEntropyString: return ["xK9mP2qL8nR5vT1wY6hJ3dF0s (20+ chars, mixed case/digits)"]
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
    public let customSeverity: Severity?

    public init(
        type: SensitiveDataType,
        value: String,
        range: Range<String.Index>,
        line: Int = 1,
        filePath: String? = nil,
        customRuleName: String? = nil,
        customSeverity: Severity? = nil
    ) {
        self.type = type
        self.value = value
        self.range = range
        self.line = line
        self.filePath = filePath
        self.customRuleName = customRuleName
        self.customSeverity = customSeverity
    }

    /// Effective severity: custom override if set, otherwise type default.
    public var effectiveSeverity: Severity {
        customSeverity ?? type.severity
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
    public let severity: String?

    public init(name: String, pattern: String, severity: String? = nil) {
        self.name = name
        self.pattern = pattern
        self.severity = severity
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
    public var safeHosts: [String]
    public var sensitiveHosts: [String]
    public var allowedPatterns: [String]
    public var sensitiveIPPrefixes: [String]
    public var mcpMinSeverity: String
    public var xmlSensitiveTags: [String]
    public var placeholderPrefix: String?

    public init(
        enabled: Bool,
        enabledTypes: [String],
        showNotifications: Bool,
        soundEnabled: Bool,
        allowedValues: [String] = [],
        customRules: [CustomRuleConfig] = [],
        safeHosts: [String] = [],
        sensitiveHosts: [String] = [],
        allowedPatterns: [String] = [],
        sensitiveIPPrefixes: [String] = [],
        mcpMinSeverity: String = "high",
        xmlSensitiveTags: [String] = [],
        placeholderPrefix: String? = nil
    ) {
        self.enabled = enabled
        self.enabledTypes = enabledTypes
        self.showNotifications = showNotifications
        self.soundEnabled = soundEnabled
        self.allowedValues = allowedValues
        self.customRules = customRules
        self.safeHosts = safeHosts
        self.sensitiveHosts = sensitiveHosts
        self.allowedPatterns = allowedPatterns
        self.sensitiveIPPrefixes = sensitiveIPPrefixes
        self.mcpMinSeverity = mcpMinSeverity
        self.xmlSensitiveTags = xmlSensitiveTags
        self.placeholderPrefix = placeholderPrefix
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
        safeHosts = try container.decodeIfPresent([String].self, forKey: .safeHosts) ?? []
        sensitiveHosts = try container.decodeIfPresent([String].self, forKey: .sensitiveHosts) ?? []
        allowedPatterns = try container.decodeIfPresent([String].self, forKey: .allowedPatterns) ?? []
        sensitiveIPPrefixes = try container.decodeIfPresent([String].self, forKey: .sensitiveIPPrefixes) ?? []
        mcpMinSeverity = try container.decodeIfPresent(String.self, forKey: .mcpMinSeverity) ?? "high"
        xmlSensitiveTags = try container.decodeIfPresent([String].self, forKey: .xmlSensitiveTags) ?? []
        placeholderPrefix = try container.decodeIfPresent(String.self, forKey: .placeholderPrefix)
    }

    public static let defaultConfig = PastewatchConfig(
        enabled: true,
        enabledTypes: SensitiveDataType.allCases.filter { $0 != .highEntropyString }.map { $0.rawValue },
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
