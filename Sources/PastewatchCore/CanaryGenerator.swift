import Foundation

// MARK: - Types

public struct CanaryToken: Codable {
    public let type: String
    public let value: String

    public init(type: String, value: String) {
        self.type = type
        self.value = value
    }
}

public struct CanaryManifest: Codable {
    public let generatedAt: String
    public let prefix: String
    public let canaries: [CanaryToken]

    public init(generatedAt: String, prefix: String, canaries: [CanaryToken]) {
        self.generatedAt = generatedAt
        self.prefix = prefix
        self.canaries = canaries
    }
}

public struct CanaryVerifyResult {
    public let type: String
    public let value: String
    public let detected: Bool
    public let detectedAs: String?
}

public struct CanaryLeakResult {
    public let type: String
    public let value: String
    public let found: Bool
}

// MARK: - Generator

public enum CanaryGenerator {

    /// Generate canary tokens for all critical types.
    public static func generate(prefix: String = "canary") -> CanaryManifest {
        let df = ISO8601DateFormatter()
        df.formatOptions = [.withInternetDateTime]
        let now = df.string(from: Date())

        let canaries = [
            generateAWSKey(prefix: prefix),
            generateGitHubToken(prefix: prefix),
            generateOpenAIKey(prefix: prefix),
            generateAnthropicKey(prefix: prefix),
            generateDBURL(prefix: prefix),
            generateStripeKey(prefix: prefix),
            generateGenericAPIKey(prefix: prefix)
        ]

        return CanaryManifest(generatedAt: now, prefix: prefix, canaries: canaries)
    }

    /// Verify all canaries in manifest are detected by DetectionRules.
    /// WO-529: Use a config with ambiguous types enabled for canary verification.
    public static func verify(manifest: CanaryManifest) -> [CanaryVerifyResult] {
        var config = PastewatchConfig.defaultConfig
        // Enable ambiguous types used by canaries
        let canaryTypes: [SensitiveDataType] = [.genericApiKey, .dbConnectionString]
        for type in canaryTypes {
            if !config.enabledTypes.contains(type.rawValue) {
                config.enabledTypes.append(type.rawValue)
            }
        }
        return manifest.canaries.map { token in
            let matches = DetectionRules.scan(token.value, config: config)
            let firstMatch = matches.first
            return CanaryVerifyResult(
                type: token.type,
                value: token.value,
                detected: !matches.isEmpty,
                detectedAs: firstMatch?.type.rawValue
            )
        }
    }

    /// Search log content for canary values.
    public static func checkLog(
        manifest: CanaryManifest,
        logContent: String
    ) -> [CanaryLeakResult] {
        manifest.canaries.map { token in
            CanaryLeakResult(
                type: token.type,
                value: token.value,
                found: logContent.contains(token.value)
            )
        }
    }

    // MARK: - Per-type Generators

    /// AWS Key: AKIA + 16 uppercase alphanumeric chars.
    /// Prefix is uppercased and truncated to fit within the 16-char suffix.
    static func generateAWSKey(prefix: String) -> CanaryToken {
        let upper = prefix.uppercased().filter { $0.isLetter || $0.isNumber }
        let truncated = String(upper.prefix(10))
        let remaining = 16 - truncated.count
        let value = "AKIA" + truncated + randomUpperAlphanumeric(count: remaining)
        return CanaryToken(type: "AWS Key", value: value)
    }

    /// GitHub Token: ghp_ + 36 alphanumeric chars.
    static func generateGitHubToken(prefix: String) -> CanaryToken {
        let safe = prefix.filter { $0.isLetter || $0.isNumber }
        let truncated = String(safe.prefix(20))
        let remaining = 36 - truncated.count
        let value = "ghp_" + truncated + randomAlphanumeric(count: remaining)
        return CanaryToken(type: "GitHub Token", value: value)
    }

    /// OpenAI Key: sk-proj- + 20+ alphanumeric/dash/underscore chars.
    static func generateOpenAIKey(prefix: String) -> CanaryToken {
        let safe = prefix.filter { $0.isLetter || $0.isNumber }
        let truncated = String(safe.prefix(10))
        let remaining = 24 - truncated.count
        let value = "sk-proj-" + truncated + randomAlphanumeric(count: remaining)
        return CanaryToken(type: "OpenAI Key", value: value)
    }

    /// Anthropic Key: sk-ant-api03- + 20+ alphanumeric/dash/underscore chars.
    static func generateAnthropicKey(prefix: String) -> CanaryToken {
        let safe = prefix.filter { $0.isLetter || $0.isNumber }
        let truncated = String(safe.prefix(10))
        let remaining = 24 - truncated.count
        let value = "sk-ant-api03-" + truncated + randomAlphanumeric(count: remaining)
        return CanaryToken(type: "Anthropic Key", value: value)
    }

    /// DB Connection String: protocol://prefix_user:prefix_pw_RANDOM@host:port/prefix_db
    static func generateDBURL(prefix: String) -> CanaryToken {
        let safe = prefix.filter { $0.isLetter || $0.isNumber }
        let pw = randomAlphanumeric(count: 12)
        let proto = ["postgres", "://"].joined()
        let value = "\(proto)\(safe)_user:\(safe)_pw_\(pw)@canary.internal:5432/\(safe)_db"
        return CanaryToken(type: "DB Connection", value: value)
    }

    /// Stripe Key: sk_test_ + 24+ alphanumeric chars.
    static func generateStripeKey(prefix: String) -> CanaryToken {
        let safe = prefix.filter { $0.isLetter || $0.isNumber }
        let truncated = String(safe.prefix(10))
        let remaining = 24 - truncated.count
        let value = "sk_test_" + truncated + randomAlphanumeric(count: remaining)
        return CanaryToken(type: "Stripe Key", value: value)
    }

    /// Generic API Key: token_ + 20+ alphanumeric chars.
    static func generateGenericAPIKey(prefix: String) -> CanaryToken {
        let safe = prefix.filter { $0.isLetter || $0.isNumber }
        let truncated = String(safe.prefix(10))
        let remaining = 20 - truncated.count
        let value = "token_" + truncated + randomAlphanumeric(count: remaining)
        return CanaryToken(type: "API Key", value: value)
    }

    // MARK: - Random Helpers

    private static let alphanumericChars = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
    private static let upperAlphanumericChars = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

    static func randomAlphanumeric(count: Int) -> String {
        String((0..<count).map { _ in alphanumericChars.randomElement()! })
    }

    static func randomUpperAlphanumeric(count: Int) -> String {
        String((0..<count).map { _ in upperAlphanumericChars.randomElement()! })
    }
}
