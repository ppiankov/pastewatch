import Foundation

/// WO-124: NR-compatible generated secret-pattern artifact entry.
public struct SharedSecretPatternConfig: Codable {
    public let name: String
    public let type: String?
    public let regex: String
    public let policy: String?

    public init(name: String, type: String? = nil, regex: String, policy: String? = nil) {
        self.name = name
        self.type = type
        self.regex = regex
        self.policy = policy
    }
}

/// WO-124: cross-language manifest emitted from NR's canonical SecretPatternConfig source.
public struct SharedSecretPatternManifest: Codable {
    public let manifestVersion: String?
    public let source: String?
    public let generatedFrom: String?
    public let patterns: [SharedSecretPatternConfig]

    public init(
        manifestVersion: String? = nil,
        source: String? = nil,
        generatedFrom: String? = nil,
        patterns: [SharedSecretPatternConfig]
    ) {
        self.manifestVersion = manifestVersion
        self.source = source
        self.generatedFrom = generatedFrom
        self.patterns = patterns
    }

    enum CodingKeys: String, CodingKey {
        case manifestVersion = "manifest_version"
        case source
        case generatedFrom = "generated_from"
        case patterns
    }
}

/// WO-126: configured shared pattern load diagnostics for fail-closed callers.
public struct SharedSecretPatternLoadError: Error, Equatable, LocalizedError {
    public let path: String
    public let message: String

    public var errorDescription: String? {
        "\(path): \(message)"
    }
}

/// WO-126: rules plus diagnostics so MCP can refuse configured-but-broken coverage.
public struct SharedSecretPatternLoadResult {
    public let rules: [CustomRule]
    public let errors: [SharedSecretPatternLoadError]

    public var isValid: Bool {
        errors.isEmpty
    }
}

/// WO-124: loads generated shared secret-pattern artifacts for file IO redaction.
public enum SharedSecretPatternSource {
    private static let sharedTypeMap: [String: SensitiveDataType] = [
        // WO-127: NR secret categories that should use API-key placeholders.
        "access_token": .genericApiKey,
        "api_key": .genericApiKey,
        "dashscope_key": .dashscopeKey, // WO-145: NR manifest category for sk-ws keys.
        "github_oauth_token": .genericApiKey,
        "github_token": .genericApiKey,
        "oauth_token": .genericApiKey,
        "token": .genericApiKey
    ]

    public static func fileIORuleSet(for config: PastewatchConfig) -> SharedSecretPatternLoadResult {
        var rules = CustomRule.compileValid(config.customRules)
        var errors: [SharedSecretPatternLoadError] = []

        for path in config.sharedPatternFiles {
            do {
                rules.append(contentsOf: try loadConfiguredRules(from: path))
            } catch let error as SharedSecretPatternLoadError {
                errors.append(error)
            } catch {
                errors.append(SharedSecretPatternLoadError(path: path, message: error.localizedDescription))
            }
        }

        return SharedSecretPatternLoadResult(rules: rules, errors: errors)
    }

    public static func fileIORules(for config: PastewatchConfig) -> [CustomRule] {
        fileIORuleSet(for: config).rules
    }

    public static func loadRules(from path: String) -> [CustomRule] {
        (try? loadConfiguredRules(from: path)) ?? []
    }

    public static func validationErrors(for config: PastewatchConfig) -> [String] {
        fileIORuleSet(for: config).errors.map { "sharedPatternFiles: \($0.localizedDescription)" }
    }

    private static func loadConfiguredRules(from path: String) throws -> [CustomRule] {
        let url = URL(fileURLWithPath: expandTilde(path))
        let data: Data
        do {
            data = try Data(contentsOf: url)
        } catch {
            throw SharedSecretPatternLoadError(path: path, message: "could not read shared pattern file")
        }

        if let configs = try? JSONDecoder().decode([SharedSecretPatternConfig].self, from: data) {
            return try compile(configs, path: path)
        }
        if let manifest = try? JSONDecoder().decode(SharedSecretPatternManifest.self, from: data) {
            return try compile(manifest.patterns, path: path)
        }
        if let legacyEnvelope = try? JSONDecoder().decode(SharedSecretPatternLegacyEnvelope.self, from: data) {
            return try compile(legacyEnvelope.patterns, path: path)
        }
        if (try? JSONSerialization.jsonObject(with: data)) != nil {
            throw SharedSecretPatternLoadError(path: path, message: "unsupported shared pattern envelope")
        }
        throw SharedSecretPatternLoadError(path: path, message: "invalid JSON")
    }

    private static func compile(_ configs: [SharedSecretPatternConfig], path: String) throws -> [CustomRule] {
        guard !configs.isEmpty else {
            throw SharedSecretPatternLoadError(path: path, message: "no shared patterns found")
        }

        return try configs.map { config in
            guard !config.name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                throw SharedSecretPatternLoadError(path: path, message: "shared pattern name is empty")
            }
            guard !config.regex.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                throw SharedSecretPatternLoadError(path: path, message: "shared pattern '\(config.name)' regex is empty")
            }

            let regex: NSRegularExpression
            do {
                regex = try NSRegularExpression(pattern: config.regex)
            } catch {
                throw SharedSecretPatternLoadError(
                    path: path,
                    message: "shared pattern '\(config.name)' has invalid regex"
                )
            }

            return CustomRule(
                name: config.name,
                regex: regex,
                severity: try severity(for: config.policy, path: path, name: config.name),
                type: detectionType(for: config.type)
            )
        }
    }

    private static func severity(for policy: String?, path: String, name: String) throws -> Severity {
        guard let policy, !policy.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            return .high
        }

        switch policy.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
        case "block":
            return .critical
        case "redact":
            return .high
        case "warn":
            return .medium
        default:
            throw SharedSecretPatternLoadError(path: path, message: "shared pattern '\(name)' has invalid policy")
        }
    }

    private static func detectionType(for type: String?) -> SensitiveDataType {
        guard let type else {
            return .credential
        }

        let normalized = normalizeType(type)
        if let sharedType = sharedTypeMap[normalized] {
            return sharedType
        }
        if let builtinType = SensitiveDataType.allCases.first(where: { normalizeType($0.rawValue) == normalized }) {
            return builtinType
        }
        return .credential
    }

    private static func normalizeType(_ value: String) -> String {
        value.lowercased()
            .replacingOccurrences(of: "-", with: "_")
            .replacingOccurrences(of: " ", with: "_")
    }

    private static func expandTilde(_ path: String) -> String {
        guard path == "~" || path.hasPrefix("~/") else {
            return path
        }
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        if path == "~" {
            return home
        }
        return home + path.dropFirst()
    }
}

private struct SharedSecretPatternLegacyEnvelope: Decodable {
    let patterns: [SharedSecretPatternConfig]

    enum CodingKeys: String, CodingKey {
        case patterns
        case customPatterns = "custom_patterns"
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        if let patterns = try container.decodeIfPresent([SharedSecretPatternConfig].self, forKey: .patterns) {
            self.patterns = patterns
        } else if let patterns = try container.decodeIfPresent(
            [SharedSecretPatternConfig].self,
            forKey: .customPatterns
        ) {
            self.patterns = patterns
        } else {
            throw DecodingError.keyNotFound(
                CodingKeys.patterns,
                DecodingError.Context(codingPath: decoder.codingPath, debugDescription: "missing patterns")
            )
        }
    }
}
