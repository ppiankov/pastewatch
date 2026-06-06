import Foundation

/// A compiled custom detection rule.
public struct CustomRule {
    public let name: String
    public let regex: NSRegularExpression
    public let severity: Severity

    public init(name: String, regex: NSRegularExpression, severity: Severity = .high) {
        self.name = name
        self.regex = regex
        self.severity = severity
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

    public var errorDescription: String? {
        switch self {
        case .invalidPattern(let name, let pattern):
            return "invalid regex in custom rule '\(name)': \(pattern)"
        }
    }
}
