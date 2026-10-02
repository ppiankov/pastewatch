#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import Foundation

// WO-636@v2: diagnostic fingerprints never retain the value they describe.
public struct DiagnosticValueSummary: Encodable {
    public let lengthBytes: Int
    public let maskedShape: String
    public let sha256Prefix: String

    // WO-636@v2: cap printable metadata and use the same digest on both platforms.
    public init(_ value: String) {
        lengthBytes = value.utf8.count
        maskedShape = String(value.unicodeScalars.prefix(64).map { scalar -> Character in
            if CharacterSet.letters.contains(scalar) { return "x" }
            if CharacterSet.decimalDigits.contains(scalar) { return "9" }
            if CharacterSet.controlCharacters.contains(scalar) { return "?" }
            return Character(String(scalar))
        })
        sha256Prefix = SHA256.hash(data: Data(value.utf8)).prefix(4)
            .map { String(format: "%02x", $0) }.joined()
    }
}

// WO-636@v2: the serializable report contains metadata only, never the backing config.
public struct ConfigExplanation: Encodable {
    // WO-636@v2: candidate contributions expose losses caused by first-wins resolution.
    public struct Candidate: Encodable {
        public let source: String
        public let path: String
        public let exists: Bool
        public let parseOK: Bool
        public let validationErrors: Int
        public let disposition: String
        public let customRules: Int
        public let enabledTypes: Int
        public let allowlistEntries: Int
        public let sharedPatternFiles: Int
    }

    // WO-636@v2: per-rule metadata separates compilation, thresholds and authorization.
    public struct Rule: Encodable {
        public let name: String
        public let pattern: DiagnosticValueSummary
        public let compileStatus: String
        public let severity: String
        public let severityDefaulted: Bool
        public let duplicateName: Bool
        public let guardHook: String
        public let scan: String
        public let mcp: String
        public let proxy: String
    }

    // WO-636@v2: distinguish intrinsic defaults from explicitly enabled ambiguous detectors.
    public struct Detector: Encodable {
        public let type: String
        public let classification: String
        public let enabled: Bool
        public let enabledByDefault: Bool
    }

    // WO-636@v2: failed shared coverage must be visible without disclosing loader messages.
    public struct SharedPatterns: Encodable {
        public let path: String
        public let status: String
        public let patternCount: Int
    }

    // WO-636@v2: private inspection state may contain policy; it is never encoded.
    private struct Inspection {
        let exists: Bool
        let config: PastewatchConfig?
        let errors: Int
    }

    // WO-636@v2: check may consume validated policy but cannot accidentally encode it.
    public enum ExplanationError: Error {
        case invalidActiveConfiguration
    }

    public let resolution: [Candidate]
    public let source: String
    public let path: String?
    public let valid: Bool
    public let warnings: [String]
    public let detectors: [Detector]
    public let customRules: [Rule]
    public let sharedPatterns: [SharedPatterns]
    public let allowedValues: [DiagnosticValueSummary]
    public let allowedPatterns: [DiagnosticValueSummary]
    public let possibleSuppression: [String]
    public let documentationPolicy: String
    public let mcpMinSeverity: String
    public let summary: String
    private let effectiveConfig: PastewatchConfig?

    // WO-636@v2: the full policy is deliberately excluded from every JSON serialization.
    private enum CodingKeys: String, CodingKey {
        case resolution, source, path, valid, warnings, detectors, customRules, sharedPatterns
        case allowedValues, allowedPatterns, possibleSuppression, documentationPolicy, mcpMinSeverity, summary
    }

    // WO-636@v2: explicit paths support isolated tests; production uses the normal strict resolver.
    public init(
        currentDirectory: String = FileManager.default.currentDirectoryPath,
        systemConfigPath: String = PastewatchConfig.systemConfigPath,
        userConfigPath: String = PastewatchConfig.configPath.path
    ) {
        let resolved = try? ConfigValidator.resolveValidated(
            currentDirectory: currentDirectory, systemConfigPath: systemConfigPath, userConfigPath: userConfigPath
        )
        let candidates = ConfigValidator.configurationCandidates(
            currentDirectory: currentDirectory, systemConfigPath: systemConfigPath, userConfigPath: userConfigPath
        )
        let inspections = candidates.map { candidate in
            Self.inspect(path: candidate.1, resolved: resolved)
        }
        let winner = inspections.firstIndex { $0.exists }
        let config = resolved?.config ?? winner.flatMap { inspections[$0].config } ?? .defaultConfig
        effectiveConfig = resolved?.config
        valid = resolved != nil
        source = winner.map { Self.sourceName(candidates[$0].0) } ?? "defaults"
        path = winner.map { Self.safeLabel(candidates[$0].1, config: config) }
        resolution = candidates.enumerated().map { index, candidate in
            let inspected = inspections[index]
            let contribution = inspected.config
            return Candidate(
                source: Self.sourceName(candidate.0), path: Self.safeLabel(candidate.1, config: config),
                exists: inspected.exists, parseOK: contribution != nil, validationErrors: inspected.errors,
                disposition: !inspected.exists ? "absent" : (index == winner ? "WINNER" : "SHADOWED"),
                customRules: contribution?.customRules.count ?? 0,
                enabledTypes: contribution?.enabledTypes.count ?? 0,
                allowlistEntries: (contribution?.allowedValues.count ?? 0) + (contribution?.allowedPatterns.count ?? 0),
                sharedPatternFiles: contribution?.sharedPatternFiles.count ?? 0
            )
        }
        // WO-636@v2: compare private contributions without exposing allowlist or manifest contents.
        warnings = Self.shadowWarnings(resolution, inspections: inspections, winner: winner, valid: valid)
        detectors = SensitiveDataType.allCases.map {
            Detector(type: $0.rawValue, classification: $0.isAmbiguousClass ? "ambiguous opt-in" : "intrinsic",
                     enabled: config.isTypeEnabled($0), enabledByDefault: PastewatchConfig.defaultConfig.isTypeEnabled($0))
        }
        customRules = Self.explainRules(config, valid: valid)
        sharedPatterns = Self.explainSharedPatterns(config)
        allowedValues = config.allowedValues.map(DiagnosticValueSummary.init)
        allowedPatterns = config.allowedPatterns.map(DiagnosticValueSummary.init)
        possibleSuppression = Self.suppressionWarnings(config)
        documentationPolicy = config.documentationPolicy.rawValue
        mcpMinSeverity = Self.safeLabel(config.mcpMinSeverity, config: config)
        let blocking = customRules.filter { $0.guardHook == "blocks" }.count
        let dropped = customRules.filter { $0.compileStatus != "ok" }.count
        summary = "\(blocking) of \(customRules.count) custom rules can block on the guard hook; " +
            "\(dropped) dropped (invalid rules); \(customRules.filter { $0.guardHook == "reports only" }.count) below threshold" +
            (valid ? "" : "; active configuration invalid: enforcement fails closed")
    }

    // WO-636@v2: consumers must not turn a diagnostic fallback into active default policy.
    public func validatedConfiguration() throws -> PastewatchConfig {
        guard let effectiveConfig else { throw ExplanationError.invalidActiveConfiguration }
        return effectiveConfig
    }

    // WO-636@v2: one metadata-only encoder serves CLI and leak regression tests.
    public func jsonData() throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return try encoder.encode(self)
    }

    // WO-636@v2: render only the report, never compiler diagnostics or raw policy values.
    public func text() -> String {
        var lines = ["Resolution (first-wins, no merge):"]
        lines += resolution.map {
            "  \($0.source): \($0.path) [\($0.disposition)] exists=\($0.exists) parseOK=\($0.parseOK) " +
                "errors=\($0.validationErrors); \($0.customRules) customRules, \($0.enabledTypes) enabledTypes, " +
                "\($0.allowlistEntries) allowlist entries, \($0.sharedPatternFiles) sharedPatternFiles"
        }
        lines += warnings.map { "[WARN] \($0)" }
        lines += ["Config in use: \(source)\(path.map { ": \($0)" } ?? ""); \(customRules.filter { $0.compileStatus == "ok" }.count) custom rules compiled",
                  "documentationPolicy: \(documentationPolicy); mcpMinSeverity: \(mcpMinSeverity)", "Detectors:"]
        lines += detectors.map { "  \($0.type): \($0.classification), enabled=\($0.enabled), default=\($0.enabledByDefault)" }
        lines += ["Custom rules (when matched and not allowlisted):"]
        lines += customRules.map {
            "  \($0.name): \($0.compileStatus), \($0.severityDefaulted ? "default -> " : "")\($0.severity); " +
                "guard=\($0.guardHook), scan=\($0.scan), MCP=\($0.mcp), proxy=\($0.proxy); " +
                "pattern length=\($0.pattern.lengthBytes) shape=\($0.pattern.maskedShape) sha256=\($0.pattern.sha256Prefix)" +
                ($0.duplicateName ? " [WARN duplicate name]" : "")
        }
        lines += ["Shared pattern files:"] + sharedPatterns.map { "  \($0.path): \($0.status), \($0.patternCount) patterns" }
        lines += ["Allowlists: \(allowedValues.count) allowedValues, \(allowedPatterns.count) allowedPatterns"]
        lines += possibleSuppression.map { "[WARN] possible allowedPattern suppression: \($0) (rule-name probe only)" }
        lines.append(summary)
        return lines.joined(separator: "\n")
    }

    // WO-636@v2: error text from parsers can contain policy; retain only structural diagnostics.
    private static func inspect(path: String, resolved: ResolvedPastewatchConfig?) -> Inspection {
        let exists = ConfigValidator.pathExistsIncludingDanglingSymlink(path, fileManager: .default)
        guard exists else { return Inspection(exists: false, config: nil, errors: 0) }
        if resolved?.path == path { return Inspection(exists: true, config: resolved?.config, errors: 0) }
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else {
            return Inspection(exists: true, config: nil, errors: 1)
        }
        let decoded = ConfigValidator.decodeAndValidate(data: data, configPath: path)
        return Inspection(exists: true, config: decoded.config, errors: decoded.errors.count)
    }

    // WO-636@v2: stable source labels avoid depending on enum debug descriptions.
    private static func sourceName(_ source: PastewatchConfigSource) -> String {
        switch source {
        case .system: return "system (admin)"
        case .project: return "project"
        case .user: return "user"
        case .defaults: return "defaults"
        }
    }

    // WO-636@v2: metadata labels must not echo an exact secret embedded in another config field.
    private static func safeLabel(_ value: String, config: PastewatchConfig) -> String {
        let secrets = config.customRules.map(\.pattern) + config.allowedValues + config.allowedPatterns
        if secrets.contains(where: { !$0.isEmpty && value.contains($0) }) {
            return "[redacted label sha256=\(DiagnosticValueSummary(value).sha256Prefix)]"
        }
        return value
    }

    // WO-636@v2: warn about concrete lost counts and provide a source-specific remedy.
    private static func shadowWarnings(
        _ candidates: [Candidate], inspections: [Inspection], winner: Int?, valid: Bool
    ) -> [String] {
        var result = valid ? [] : ["Active configuration is invalid; enforcement fails closed."]
        guard let winner else { return result }
        let selected = candidates[winner]
        // WO-636@v2: first-wins can discard opt-ins and policy even without custom rules.
        let selectedConfig = inspections[winner].config
        for (index, candidate) in candidates.enumerated() where candidate.disposition == "SHADOWED" {
            guard let shadowed = inspections[index].config else { continue }
            let lostTypes = SensitiveDataType.allCases.filter {
                shadowed.isTypeEnabled($0) && selectedConfig?.isTypeEnabled($0) != true
            }.map(\.rawValue).sorted()
            let lostAllowlist = shadowed.allowedValues.filter { selectedConfig?.allowedValues.contains($0) != true }.count +
                shadowed.allowedPatterns.filter { selectedConfig?.allowedPatterns.contains($0) != true }.count
            let lostShared = shadowed.sharedPatternFiles.filter { selectedConfig?.sharedPatternFiles.contains($0) != true }.count
            guard candidate.customRules > 0 || !lostTypes.isEmpty || lostAllowlist > 0 || lostShared > 0 else { continue }
            result.append("\(selected.source) WINS; \(candidate.source) SHADOWED, losing \(candidate.customRules) customRules " +
                          "and \(lostTypes.count) detector types [\(lostTypes.joined(separator: ", "))], " +
                          "\(lostAllowlist) allowlist entries, \(lostShared) sharedPatternFiles. Fix: move the rules into \(selected.path)" +
                          (selected.source == "project" ? " or remove/rename that project config." : " with the configuration owner's approval."))
        }
        return result
    }

    // WO-636@v2: compile with the runtime compiler and ask shared policy about each rule's severity.
    private static func explainRules(_ config: PastewatchConfig, valid: Bool) -> [Rule] {
        let names = Dictionary(grouping: config.customRules, by: \.name)
        return config.customRules.map { rule in
            let compiled = try? CustomRule.compile([rule]).first
            let severity = compiled?.severity ?? .defaultCustomRuleSeverity
            let value = "diagnostic"
            let match = DetectedMatch(type: .credential, value: value, range: value.startIndex..<value.endIndex,
                                      line: 1, customRuleName: rule.name, customSeverity: severity)
            let guardDecision = GuardDecision.evaluate(matches: [match], content: value, config: .defaultConfig,
                                                       contentTrust: .agentControlled, minimumSeverity: .defaultGuardThreshold,
                                                       filePath: nil)
            let mcp = partitionMutationMatches([match], site: .mcpRead,
                                               minAdvisorySeverity: Severity(rawValue: config.mcpMinSeverity) ?? .defaultGuardThreshold)
            let proxy = partitionMutationMatches([match], site: .proxyUserText, minAdvisorySeverity: .defaultGuardThreshold)
            return Rule(name: safeLabel(rule.name, config: config), pattern: DiagnosticValueSummary(rule.pattern),
                        compileStatus: compiled == nil ? "error: invalid regex" : "ok", severity: severity.rawValue,
                        severityDefaulted: rule.severity == nil, duplicateName: (names[rule.name]?.count ?? 0) > 1,
                        guardHook: !valid ? "fail closed" : (guardDecision.actionableMatches.isEmpty ? "reports only" : "blocks"),
                        scan: valid ? "blocks (exit 6)" : "fail closed",
                        mcp: !valid ? "fail closed" : (mcp.authorized.isEmpty ? "reports only" : "placeholder (two-way)"),
                        proxy: !valid ? "fail closed" : (proxy.authorized.isEmpty ? "reports only" : "redacted (one-way)"))
        }
    }

    // WO-636@v2: shared coverage diagnostics use the same mandatory loader as file IO.
    private static func explainSharedPatterns(_ config: PastewatchConfig) -> [SharedPatterns] {
        config.sharedPatternFiles.map { path in
            var isolated = config
            isolated.customRules = []
            isolated.sharedPatternFiles = [path]
            let loaded = SharedSecretPatternSource.fileIORuleSet(for: isolated)
            let status = loaded.isValid ? "loaded" : (FileManager.default.fileExists(atPath: path) ? "error" : "missing/error")
            return SharedPatterns(path: safeLabel(path, config: config), status: status, patternCount: loaded.rules.count)
        }
    }

    // WO-636@v2: reuse anchored allowlist matching; this is a probe, not proof of regex overlap.
    private static func suppressionWarnings(_ config: PastewatchConfig) -> [String] {
        var patternsOnly = config
        patternsOnly.allowedValues = []
        let allowlist = Allowlist.fromConfig(patternsOnly)
        return CustomRule.compileValid(config.customRules).compactMap { rule in
            let range = NSRange(rule.name.startIndex..., in: rule.name)
            guard rule.regex.firstMatch(in: rule.name, range: range) != nil else { return nil }
            let match = DetectedMatch(type: rule.type, value: rule.name, range: rule.name.startIndex..<rule.name.endIndex,
                                      line: 1, customRuleName: rule.name, customSeverity: rule.severity)
            return allowlist.filter([match]).isEmpty ? safeLabel(rule.name, config: config) : nil
        }
    }
}
