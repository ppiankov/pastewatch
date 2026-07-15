import Foundation

/// A compiled custom detection rule.
public struct CustomRule {
    public let name: String
    public let regex: NSRegularExpression
    public let severity: Severity
    public let type: SensitiveDataType // WO-127: shared manifest category for placeholders/reporting

    public init(
        name: String,
        regex: NSRegularExpression,
        severity: Severity = .high,
        type: SensitiveDataType = .credential
    ) {
        self.name = name
        self.regex = regex
        self.severity = severity
        self.type = type
    }

    /// Load custom rules from a JSON file.
    public static func load(from path: String) throws -> [CustomRule] {
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        let configs = try JSONDecoder().decode([CustomRuleConfig].self, from: data)
        return try compile(configs)
    }

    /// Compile CustomRuleConfig array into CustomRule array.
    public static func compile(_ configs: [CustomRuleConfig]) throws -> [CustomRule] {
        try configs.map { config in
            do {
                let regex = try NSRegularExpression(pattern: config.pattern)
                let severity: Severity
                if let sevStr = config.severity, let sev = Severity(rawValue: sevStr) {
                    severity = sev
                } else {
                    severity = .high
                }
                return CustomRule(name: config.name, regex: regex, severity: severity)
            } catch {
                throw CustomRuleError.invalidPattern(name: config.name, pattern: config.pattern)
            }
        }
    }

    /// WO-473: proxy startup treats every configured rule as a protection
    /// contract. Invalid names, severities, or patterns reject the whole set.
    public static func compileForProxyStartup(_ configs: [CustomRuleConfig]) throws -> [CustomRule] {
        for (index, config) in configs.enumerated() {
            guard !config.name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                throw CustomRuleError.emptyName(index: index)
            }
            guard !config.pattern.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                throw CustomRuleError.emptyPattern(name: config.name)
            }
            if let severity = config.severity, Severity(rawValue: severity) == nil {
                throw CustomRuleError.invalidSeverity(name: config.name, severity: severity)
            }
        }
        return try compile(configs)
    }

    /// WO-124: compile configs when invalid generated entries should degrade to the valid subset.
    public static func compileValid(_ configs: [CustomRuleConfig]) -> [CustomRule] {
        configs.compactMap { config in
            guard let regex = try? NSRegularExpression(pattern: config.pattern) else {
                return nil
            }
            let severity = config.severity.flatMap(Severity.init(rawValue:)) ?? .high
            return CustomRule(name: config.name, regex: regex, severity: severity)
        }
    }
}

/// Errors for custom rule loading.
public enum CustomRuleError: Error, LocalizedError {
    case invalidPattern(name: String, pattern: String)
    case emptyName(index: Int) // WO-473: unnamed startup contracts are invalid.
    case emptyPattern(name: String) // WO-473: an empty regex would match every position.
    case invalidSeverity(name: String, severity: String) // WO-473: no silent severity fallback at startup.

    public var errorDescription: String? {
        switch self {
        case .invalidPattern(let name, _):
            return "invalid regex in custom rule '\(name)'"
        case .emptyName(let index):
            return "custom rule at index \(index) has an empty name"
        case .emptyPattern(let name):
            return "custom rule '\(name)' has an empty pattern"
        case .invalidSeverity(let name, let severity):
            return "invalid severity '\(severity)' in custom rule '\(name)'"
        }
    }
}
