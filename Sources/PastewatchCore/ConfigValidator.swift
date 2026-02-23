import Foundation

public struct ConfigValidationResult {
    public let errors: [String]
    public var isValid: Bool { errors.isEmpty }
}

public enum ConfigValidator {
    /// Validate a config file at the given path, or the resolved config if nil.
    public static func validate(path: String? = nil) -> ConfigValidationResult {
        var errors: [String] = []

        let data: Data
        let configPath: String

        if let path = path {
            configPath = path
            guard FileManager.default.fileExists(atPath: path) else {
                return ConfigValidationResult(errors: ["file not found: \(path)"])
            }
            guard let d = try? Data(contentsOf: URL(fileURLWithPath: path)) else {
                return ConfigValidationResult(errors: ["could not read: \(path)"])
            }
            data = d
        } else {
            // Try CWD .pastewatch.json first, then ~/.config/pastewatch/config.json
            let cwd = FileManager.default.currentDirectoryPath
            let projectPath = cwd + "/.pastewatch.json"
            if FileManager.default.fileExists(atPath: projectPath) {
                configPath = projectPath
                guard let d = try? Data(contentsOf: URL(fileURLWithPath: projectPath)) else {
                    return ConfigValidationResult(errors: ["could not read: \(projectPath)"])
                }
                data = d
            } else if FileManager.default.fileExists(atPath: PastewatchConfig.configPath.path) {
                configPath = PastewatchConfig.configPath.path
                guard let d = try? Data(contentsOf: PastewatchConfig.configPath) else {
                    return ConfigValidationResult(errors: ["could not read: \(PastewatchConfig.configPath.path)"])
                }
                data = d
            } else {
                // No config file found — using defaults is valid
                return ConfigValidationResult(errors: [])
            }
        }

        // Validate JSON syntax
        let config: PastewatchConfig
        do {
            config = try JSONDecoder().decode(PastewatchConfig.self, from: data)
        } catch {
            errors.append("\(configPath): invalid JSON: \(error.localizedDescription)")
            return ConfigValidationResult(errors: errors)
        }

        // Validate enabledTypes
        let validTypeNames = Set(SensitiveDataType.allCases.map { $0.rawValue })
        for typeName in config.enabledTypes {
            if !validTypeNames.contains(typeName) {
                errors.append("unknown type in enabledTypes: '\(typeName)'")
            }
        }

        // Validate custom rules
        for (i, rule) in config.customRules.enumerated() {
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
            if let sev = rule.severity {
                if Severity(rawValue: sev) == nil {
                    errors.append("customRules[\(i)] '\(rule.name)': invalid severity '\(sev)' (use: critical, high, medium, low)")
                }
            }
        }

        return ConfigValidationResult(errors: errors)
    }
}
