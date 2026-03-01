import Foundation

public struct ConfigValidationResult {
    public let errors: [String]
    public var isValid: Bool { errors.isEmpty }
}

public enum ConfigValidator {
    /// Validate a config file at the given path, or the resolved config if nil.
    public static func validate(path: String? = nil) -> ConfigValidationResult {
        let loaded = loadConfigData(path: path)
        guard let (data, configPath) = loaded.value else {
            return ConfigValidationResult(errors: loaded.errors)
        }

        var errors: [String] = []

        // Validate JSON syntax
        let config: PastewatchConfig
        do {
            config = try JSONDecoder().decode(PastewatchConfig.self, from: data)
        } catch {
            return ConfigValidationResult(errors: ["\(configPath): invalid JSON: \(error.localizedDescription)"])
        }

        // Validate enabledTypes
        let validTypeNames = Set(SensitiveDataType.allCases.map { $0.rawValue })
        for typeName in config.enabledTypes where !validTypeNames.contains(typeName) {
            errors.append("unknown type in enabledTypes: '\(typeName)'")
        }

        // Validate custom rules
        for (i, rule) in config.customRules.enumerated() {
            validateRule(rule, index: i, errors: &errors)
        }

        // Validate safeHosts / sensitiveHosts
        for (i, host) in config.safeHosts.enumerated()
            where host.trimmingCharacters(in: .whitespaces).isEmpty {
            errors.append("safeHosts[\(i)]: empty value")
        }
        for (i, host) in config.sensitiveHosts.enumerated()
            where host.trimmingCharacters(in: .whitespaces).isEmpty {
            errors.append("sensitiveHosts[\(i)]: empty value")
        }
        let safeSet = Set(config.safeHosts.map { $0.lowercased() })
        let sensitiveSet = Set(config.sensitiveHosts.map { $0.lowercased() })
        let overlap = safeSet.intersection(sensitiveSet)
        for host in overlap.sorted() {
            errors.append("'\(host)' appears in both safeHosts and sensitiveHosts (sensitiveHosts takes precedence)")
        }

        // Validate sensitiveIPPrefixes
        for (i, prefix) in config.sensitiveIPPrefixes.enumerated() {
            let trimmed = prefix.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty {
                errors.append("sensitiveIPPrefixes[\(i)]: empty value")
            } else if !trimmed.allSatisfy({ $0.isNumber || $0 == "." }) {
                errors.append("sensitiveIPPrefixes[\(i)]: must contain only digits and dots")
            }
        }

        // Validate allowedPatterns
        for (i, pattern) in config.allowedPatterns.enumerated() {
            if pattern.trimmingCharacters(in: .whitespaces).isEmpty {
                errors.append("allowedPatterns[\(i)]: empty pattern")
            } else {
                do {
                    _ = try NSRegularExpression(pattern: pattern)
                } catch {
                    errors.append("allowedPatterns[\(i)]: invalid regex: \(error.localizedDescription)")
                }
            }
        }

        return ConfigValidationResult(errors: errors)
    }

    private static func validateRule(_ rule: CustomRuleConfig, index i: Int, errors: inout [String]) {
        if rule.name.isEmpty {
            errors.append("customRules[\(i)]: name is empty")
        }
        if rule.pattern.isEmpty {
            errors.append("customRules[\(i)]: pattern is empty")
        } else {
            do {
                _ = try NSRegularExpression(pattern: rule.pattern)
            } catch {
                errors.append("customRules[\(i)] '\(rule.name)': invalid regex: \(error.localizedDescription)")
            }
        }
        if let sev = rule.severity, Severity(rawValue: sev) == nil {
            errors.append("customRules[\(i)] '\(rule.name)': invalid severity '\(sev)' (use: critical, high, medium, low)")
        }
    }

    private static func loadConfigData(path: String?) -> (value: (Data, String)?, errors: [String]) {
        if let path = path {
            guard FileManager.default.fileExists(atPath: path) else {
                return (nil, ["file not found: \(path)"])
            }
            guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else {
                return (nil, ["could not read: \(path)"])
            }
            return ((data, path), [])
        }

        let cwd = FileManager.default.currentDirectoryPath
        let projectPath = cwd + "/.pastewatch.json"
        if FileManager.default.fileExists(atPath: projectPath) {
            guard let data = try? Data(contentsOf: URL(fileURLWithPath: projectPath)) else {
                return (nil, ["could not read: \(projectPath)"])
            }
            return ((data, projectPath), [])
        }

        if FileManager.default.fileExists(atPath: PastewatchConfig.configPath.path) {
            guard let data = try? Data(contentsOf: PastewatchConfig.configPath) else {
                return (nil, ["could not read: \(PastewatchConfig.configPath.path)"])
            }
            return ((data, PastewatchConfig.configPath.path), [])
        }

        // No config file found — using defaults is valid
        return (nil, [])
    }
}
