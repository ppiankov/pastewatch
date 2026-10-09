import Foundation

// WO-672@v1: keep the legacy type API attached to the shared strict resolution implementation.
extension PastewatchConfig {
    // WO-672@v1: all configuration resolution uses the same validated, tightening-only merge.
    public static func resolve() -> PastewatchConfig {
        (try? ConfigValidator.resolveValidated().config) ?? defaultConfig
    }
}

public struct ConfigValidationResult {
    public let errors: [String]
    public var isValid: Bool { errors.isEmpty }
}

// WO-574@v4: identify the exact precedence source that governed enforcement.
public enum PastewatchConfigSource: Equatable {
    case system
    case project
    case user
    case defaults
}

// WO-574@v4: carry validated config and source evidence as one atomic result.
public struct ResolvedPastewatchConfig {
    public let config: PastewatchConfig
    public let source: PastewatchConfigSource
    public let path: String?
    // WO-672@v1: diagnostics use the same validated tier contributions as enforcement.
    let contributions: [ConfigContribution]
}

// WO-672@v1: private policy values never enter diagnostic serialization.
struct ConfigContribution {
    let source: PastewatchConfigSource
    let path: String
    let config: PastewatchConfig
}

// WO-574@v4: enforcement diagnostics disclose the failing path, never config values.
public struct PastewatchConfigResolutionError: Error, Equatable, LocalizedError {
    public enum Kind: Equatable {
        case unreadable
        case invalid
    }

    public let path: String
    public let kind: Kind

    public var errorDescription: String? {
        let reason = kind == .unreadable ? "could not be read" : "is invalid"
        return "configuration at \(path) \(reason); run pastewatch-cli config check --file \(path)"
    }
}

public enum ConfigValidator {
    // WO-672@v1: validating effective policy must validate every participating tier.
    // WO-574@v4: all enforcement commands share this strict config boundary.
    /// Validate a config file at the given path, or the resolved config if nil.
    public static func validate(path: String? = nil) -> ConfigValidationResult {
        // WO-672@v1: explicit-file checks retain their detailed validation behavior.
        if path == nil {
            do {
                _ = try resolveValidated()
                return ConfigValidationResult(errors: [])
            } catch {
                return ConfigValidationResult(errors: [error.localizedDescription])
            }
        }
        let loaded = loadConfigData(path: path)
        guard let (data, configPath) = loaded.value else {
            return ConfigValidationResult(errors: loaded.errors)
        }

        let decoded = decodeAndValidate(data: data, configPath: configPath)
        return ConfigValidationResult(errors: decoded.errors)
    }

    // WO-672@v1: operator policy survives project contributions at the strict resolver boundary.
    // WO-636@v2: diagnostics and enforcement share candidate discovery.
    // WO-574@v4: present invalid config is an enforcement failure, not a fallback signal.
    public static func resolveValidated(
        fileManager: FileManager = .default,
        currentDirectory: String = FileManager.default.currentDirectoryPath,
        systemConfigPath: String = PastewatchConfig.systemConfigPath,
        userConfigPath: String = PastewatchConfig.configPath.path
    ) throws -> ResolvedPastewatchConfig {
        // WO-636@v2: reuse candidate discovery without changing strict resolution semantics.
        let candidates = configurationCandidates(
            currentDirectory: currentDirectory, systemConfigPath: systemConfigPath, userConfigPath: userConfigPath
        )

        // WO-672@v1: present invalid policy at any tier fails closed rather than disappearing.
        var contributions: [ConfigContribution] = []
        for (source, path) in candidates where pathExistsIncludingDanglingSymlink(path, fileManager: fileManager) {
            let data: Data
            do {
                data = try Data(contentsOf: URL(fileURLWithPath: path))
            } catch {
                throw PastewatchConfigResolutionError(path: path, kind: .unreadable)
            }
            let decoded = decodeAndValidate(data: data, configPath: path)
            guard let config = decoded.config, decoded.errors.isEmpty else {
                throw PastewatchConfigResolutionError(path: path, kind: .invalid)
            }
            contributions.append(ConfigContribution(source: source, path: path, config: config))
        }
        return ResolvedPastewatchConfig(config: merge(contributions), source: contributions.first?.source ?? .defaults,
                                       path: contributions.first?.path, contributions: contributions)
    }

    // WO-672@v1: arrays only accumulate protection; operator scalar choices remain authoritative.
    private static func merge(_ contributions: [ConfigContribution]) -> PastewatchConfig {
        let operatorPolicy = contributions.first { $0.source == .system } ??
            contributions.first { $0.source == .user }
        var result = operatorPolicy?.config ?? .defaultConfig
        let baseSource = operatorPolicy.map { tierName($0.source) } ?? "defaults"
        let fields = ["enabled", "enabledTypes", "customRules", "obfuscate", "protectedPaths", "sharedPatternFiles",
                      "allowedValues", "allowedPatterns", "mcpMinSeverity", "documentationPolicy", "safeHosts",
                      "sensitiveHosts", "sensitiveIPPrefixes", "xmlSensitiveTags", "placeholderPrefix",
                      "responseStreamingRedactionMode", "operatorRedactionNotices"]
        result.fieldSources = Dictionary(uniqueKeysWithValues: fields.map { ($0, [baseSource]) })
        result.allowedValues = []
        result.allowedValueSources = [:]
        // WO-672@v1: project patterns cannot extend the operator's suppression policy.
        result.allowedPatterns = []
        result.allowedPatternSources = [:]
        for contribution in contributions {
            // WO-672@v1: system policy makes both lower tiers tighten-only.
            let tightenOnly = contribution.source == .project ||
                (operatorPolicy?.source == .system && contribution.source == .user)
            mergeRestrictions(contribution, tightenOnly: tightenOnly, into: &result)
            let source = tierName(contribution.source)
            // WO-672@v1: subordinate user entries retain their tier but lose intrinsic exemption authority.
            let entrySource: AllowlistSource
            switch contribution.source {
            case .system: entrySource = .system
            case .user: entrySource = tightenOnly ? .restrictedUser : .user
            default: entrySource = .project
            }
            for value in contribution.config.allowedValues {
                if !result.allowedValues.contains(value) { result.allowedValues.append(value) }
                result.allowedValueSources[value, default: []].insert(entrySource)
            }
            if !contribution.config.allowedValues.isEmpty { record("allowedValues", source: source, in: &result) }
            // WO-672@v1: only the authoritative operator tier contributes suppression patterns.
            if !tightenOnly {
                appendUnique(contribution.config.allowedPatterns, to: &result.allowedPatterns)
                for pattern in contribution.config.allowedPatterns {
                    result.allowedPatternSources[pattern, default: []].insert(entrySource)
                }
                if !contribution.config.allowedPatterns.isEmpty { record("allowedPatterns", source: source, in: &result) }
            }
        }
        return result
    }

    // WO-672@v1: subordinate policy accumulates protection and may only increase advisory visibility.
    private static func mergeRestrictions(_ contribution: ConfigContribution, tightenOnly: Bool,
                                          into result: inout PastewatchConfig) {
        let config = contribution.config
        let source = tierName(contribution.source)
        let arrays: [(String, WritableKeyPath<PastewatchConfig, [String]>)] = [
            ("enabledTypes", \.enabledTypes), ("protectedPaths", \.protectedPaths),
            ("sharedPatternFiles", \.sharedPatternFiles), ("sensitiveHosts", \.sensitiveHosts),
            ("sensitiveIPPrefixes", \.sensitiveIPPrefixes), ("xmlSensitiveTags", \.xmlSensitiveTags),
        ]
        for (field, keyPath) in arrays where !config[keyPath: keyPath].isEmpty {
            appendUnique(config[keyPath: keyPath], to: &result[keyPath: keyPath])
            record(field, source: source, in: &result)
        }
        appendUnique(config.obfuscate, to: &result.obfuscate)
        if !config.obfuscate.isEmpty { record("obfuscate", source: source, in: &result) }
        for rule in config.customRules {
            if let index = result.customRules.firstIndex(where: { $0.name == rule.name && $0.pattern == rule.pattern }) {
                let existingSeverity = Severity(rawValue: result.customRules[index].severity ?? "high") ?? .high
                let addedSeverity = Severity(rawValue: rule.severity ?? "high") ?? .high
                if addedSeverity > existingSeverity {
                    result.customRules[index] = CustomRuleConfig(name: rule.name, pattern: rule.pattern,
                                                                severity: addedSeverity.rawValue)
                }
            } else {
                result.customRules.append(rule)
            }
            record("customRules", source: source, in: &result)
        }
        // WO-672@v1: user scalar choices are subordinate whenever system policy exists.
        if tightenOnly {
            // WO-672@v1: a project may add placeholder formatting but cannot replace an operator prefix.
            if result.placeholderPrefix == nil, let prefix = config.placeholderPrefix {
                result.placeholderPrefix = prefix
                record("placeholderPrefix", source: source, in: &result)
            }
            // WO-672@v1: project notices may add visibility, never disable operator notices.
            if config.operatorRedactionNotices {
                result.operatorRedactionNotices = true
                record("operatorRedactionNotices", source: source, in: &result)
            }
            let existing = Severity(rawValue: result.mcpMinSeverity) ?? .high
            let added = Severity(rawValue: config.mcpMinSeverity) ?? .high
            // WO-672@v1: a lower threshold exposes more advisories without granting mutation authority.
            if added < existing {
                result.mcpMinSeverity = added.rawValue
                record("mcpMinSeverity", source: source, in: &result)
            }
            if config.documentationPolicy == .enforce {
                result.documentationPolicy = .enforce
                record("documentationPolicy", source: source, in: &result)
            }
        }
    }

    // WO-672@v1: deterministic union preserves rule and pattern order across tiers.
    private static func appendUnique<T: Equatable>(_ values: [T], to result: inout [T]) {
        for value in values where !result.contains(value) { result.append(value) }
    }

    // WO-672@v1: field attribution exposes tier names only, never policy values.
    private static func record(_ field: String, source: String, in config: inout PastewatchConfig) {
        if config.fieldSources[field] == ["defaults"] { config.fieldSources[field] = [] }
        if config.fieldSources[field]?.contains(source) != true { config.fieldSources[field, default: []].append(source) }
    }

    // WO-672@v1: stable labels make merged policy attribution usable by diagnostics.
    private static func tierName(_ source: PastewatchConfigSource) -> String {
        switch source {
        case .system: return "system"
        case .user: return "user"
        case .project: return "project"
        case .defaults: return "defaults"
        }
    }

    // WO-636@v2: the read-only walkthrough uses the enforcement resolver's exact order.
    static func configurationCandidates(
        currentDirectory: String, systemConfigPath: String, userConfigPath: String
    ) -> [(PastewatchConfigSource, String)] {
        [(.system, systemConfigPath), (.project, currentDirectory + "/.pastewatch.json"), (.user, userConfigPath)]
    }

    // WO-636@v2: diagnostic presence checks must recognize the same dangling policy symlinks.
    // WO-574@v4: a dangling active-config symlink is present policy, not absence.
    static func pathExistsIncludingDanglingSymlink(
        _ path: String,
        fileManager: FileManager
    ) -> Bool {
        if fileManager.fileExists(atPath: path) {
            return true
        }
        return (try? fileManager.destinationOfSymbolicLink(atPath: path)) != nil
    }

    // WO-636@v2: shadowed-config diagnostics share decoding and validation, not a second parser.
    static func decodeAndValidate(
        data: Data,
        configPath: String
    ) -> (config: PastewatchConfig?, errors: [String]) {
        var errors: [String] = []

        // WO-574@v4: inspect soft-defaulted wire fields before decoding erases invalid input.
        if let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           let rawMode = object["responseStreamingRedactionMode"] as? String,
           StreamingRedactionMode(rawValue: rawMode) == nil {
            errors.append("responseStreamingRedactionMode: unknown value")
        }

        // Validate JSON syntax
        let config: PastewatchConfig
        do {
            config = try JSONDecoder().decode(PastewatchConfig.self, from: data)
        } catch {
            return (nil, ["\(configPath): invalid JSON: \(error.localizedDescription)"])
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

        // WO-541: invalid opt-in entries must fail closed instead of silently no-oping.
        for (index, entry) in config.obfuscate.enumerated() {
            validateObfuscateEntry(entry, index: index, errors: &errors)
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

        // Validate mcpMinSeverity
        if Severity(rawValue: config.mcpMinSeverity) == nil {
            errors.append("mcpMinSeverity: invalid severity '\(config.mcpMinSeverity)' (use: \(Severity.allCases.map(\.rawValue).joined(separator: ", ")))")
        }

        // WO-126: configured shared pattern files must not silently disable redaction coverage.
        errors.append(contentsOf: SharedSecretPatternSource.validationErrors(for: config))

        return (config, errors)
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
            errors.append("customRules[\(i)] '\(rule.name)': invalid severity '\(sev)' (use: \(Severity.allCases.map(\.rawValue).joined(separator: ", ")))")
        }
    }

    // WO-541: diagnostics identify only the entry index and shape error, never its value.
    private static func validateObfuscateEntry(
        _ entry: ObfuscateEntry,
        index: Int,
        errors: inout [String]
    ) {
        guard let type = entry.entryType else {
            errors.append("obfuscate[\(index)]: unknown type (use: email, host)")
            return
        }
        let pattern = entry.pattern.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !pattern.isEmpty else {
            errors.append("obfuscate[\(index)]: pattern is empty")
            return
        }
        guard !pattern.contains(where: \.isWhitespace) else {
            errors.append("obfuscate[\(index)]: pattern must not contain whitespace")
            return
        }

        switch type {
        case .email:
            if pattern.hasPrefix(".") {
                errors.append("obfuscate[\(index)]: email pattern must be an address or start with @")
            } else if pattern.hasPrefix("@") {
                if !isValidDomain(String(pattern.dropFirst())) {
                    errors.append("obfuscate[\(index)]: email domain pattern is malformed")
                }
            } else if !isValidExactEmail(pattern) {
                errors.append("obfuscate[\(index)]: exact email pattern is malformed")
            }
        case .host:
            if pattern.hasPrefix("@") {
                errors.append("obfuscate[\(index)]: host pattern must be a hostname or start with .")
            } else {
                let domain = pattern.hasPrefix(".") ? String(pattern.dropFirst()) : pattern
                if !isValidDomain(domain) {
                    errors.append("obfuscate[\(index)]: host pattern is malformed")
                }
            }
        }
    }

    private static func isValidExactEmail(_ value: String) -> Bool {
        let components = value.split(separator: "@", omittingEmptySubsequences: false)
        guard components.count == 2, !components[0].isEmpty else { return false }
        return isValidDomain(String(components[1]))
    }

    private static func isValidDomain(_ value: String) -> Bool {
        guard !value.isEmpty, !value.hasPrefix("."), !value.hasSuffix("."),
              value.contains(".") else {
            return false
        }
        return value.split(separator: ".", omittingEmptySubsequences: false).allSatisfy { label in
            guard !label.isEmpty, label.first != "-", label.last != "-" else { return false }
            return label.allSatisfy { $0.isLetter || $0.isNumber || $0 == "-" }
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
