import Foundation

/// A compiled custom detection rule.
public struct CustomRule {
    public let name: String
    public let regex: NSRegularExpression

    public init(name: String, regex: NSRegularExpression) {
        self.name = name
        self.regex = regex
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
                return CustomRule(name: config.name, regex: regex)
            } catch {
                throw CustomRuleError.invalidPattern(name: config.name, pattern: config.pattern)
            }
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
