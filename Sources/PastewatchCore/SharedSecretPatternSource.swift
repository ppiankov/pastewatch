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

/// WO-124: loads generated shared secret-pattern artifacts for file IO redaction.
public enum SharedSecretPatternSource {
    public static func fileIORules(for config: PastewatchConfig) -> [CustomRule] {
        var rules = CustomRule.compileValid(config.customRules)
        for path in config.sharedPatternFiles {
            rules.append(contentsOf: loadRules(from: path))
        }
        return rules
    }

    public static func loadRules(from path: String) -> [CustomRule] {
        let url = URL(fileURLWithPath: expandTilde(path))
        guard let data = try? Data(contentsOf: url) else {
            return []
        }

        if let configs = try? JSONDecoder().decode([SharedSecretPatternConfig].self, from: data) {
            return compile(configs)
        }
        if let manifest = try? JSONDecoder().decode(SharedSecretPatternManifest.self, from: data) {
            return compile(manifest.patterns)
        }
        if let legacyEnvelope = try? JSONDecoder().decode(SharedSecretPatternLegacyEnvelope.self, from: data) {
            return compile(legacyEnvelope.patterns)
        }
        return []
    }

    private static func compile(_ configs: [SharedSecretPatternConfig]) -> [CustomRule] {
        let ruleConfigs = configs.map { config in
            CustomRuleConfig(
                name: config.name,
                pattern: config.regex,
                severity: severity(for: config.policy)
            )
        }
        return CustomRule.compileValid(ruleConfigs)
    }

    private static func severity(for policy: String?) -> String? {
        switch policy?.lowercased() {
        case "block", "redact", "warn":
            return "high"
        default:
            return nil
        }
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
        patterns = try container.decodeIfPresent([SharedSecretPatternConfig].self, forKey: .patterns)
            ?? container.decodeIfPresent([SharedSecretPatternConfig].self, forKey: .customPatterns)
            ?? []
    }
}
