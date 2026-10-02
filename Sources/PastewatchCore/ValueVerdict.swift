import Foundation

// WO-637: retain only diagnostic metadata; neither input nor policy values can be encoded.
public struct ValueVerdict: Encodable {
    // WO-637: describe each surface independently rather than inferring it from severity.
    public struct Finding: Encodable {
        public let type: String
        public let classification: String
        public let ruleName: String?
        public let severity: String
        public let line: Int
        public let value: DiagnosticValueSummary
        public let mutationAuthorized: Bool
        public let mutationReasons: [String]
        public let guardVerdict: String
        public let guardSeverity: String?
        public let scanExitCode: Int32
        public let mcp: String
        public let placeholderShape: String?
        public let proxy: String
        public let allowlistSuppression: [String]
    }

    // WO-637: transient decisions contain matches and never enter the report's stored state.
    private struct Decisions {
        let guardHook: GuardDecision
        let scan: GuardDecision
        let mcp: MCPReadDecision
        let proxy: MutationOutcome
        let proxyRefused: Bool
    }

    public let configSource: String
    public let configPath: String?
    public let customRulesLoaded: Int
    public let documentationPolicy: String
    public let mcpMinSeverity: String
    public let findings: [Finding]
    public let scanExitCode: Int32
    public let mcpRoundTripVerified: Bool
    public let mcpDirection = "two-way: placeholders restored locally on write"
    public let proxyDirection = "one-way: outbound redaction, never restored"

    // WO-637: reuse strict config resolution, file parsing and the production surface decisions.
    public init(content: String, filePath: String?, explanation: ConfigExplanation) throws {
        let config = try explanation.validatedConfiguration()
        let matches = try Self.scan(content: content, filePath: filePath, config: config)
        let decisions = try Self.decisions(content: content, filePath: filePath, config: config, matches: matches)
        let proxyMatches = decisions.proxy.mutated + decisions.proxy.advisory + decisions.proxy.advisoryBelowThreshold
        var allMatches = matches
        for match in proxyMatches where !Self.contains(match, in: allMatches) {
            allMatches.append(match)
        }
        let protectedValues = [content] + allMatches.map(\.value) + config.customRules.map(\.pattern)
            + config.allowedValues + config.allowedPatterns
        configSource = explanation.source
        configPath = explanation.path.map { Self.safeLabel($0, protectedValues: protectedValues) }
        customRulesLoaded = explanation.customRules.filter { $0.compileStatus == "ok" }.count
        documentationPolicy = explanation.documentationPolicy
        mcpMinSeverity = explanation.mcpMinSeverity
        let localNames = Set(config.customRules.map(\.name))
        let sharedNames = Set(SharedSecretPatternSource.fileIORuleSet(for: config).rules.map(\.name))
            .subtracting(localNames)
        findings = allMatches.sorted { $0.range.lowerBound < $1.range.lowerBound }.map {
            Self.finding($0, decisions: decisions, content: content, config: config,
                         sharedNames: sharedNames, protectedValues: protectedValues, filePath: filePath)
        }
        scanExitCode = decisions.scan.actionableMatches.isEmpty ? ScanExitContract.clean : ScanExitContract.findingsDetected
        let store = RedactionStore(placeholderPrefix: config.placeholderPrefix)
        let mappingPath = filePath ?? "stdin"
        let (redacted, _) = store.redact(content: content, matches: decisions.mcp.authorized, filePath: mappingPath)
        mcpRoundTripVerified = store.resolve(content: redacted, filePath: mappingPath).content == content
    }

    // WO-637: JSON contains the same metadata as text, with no backing input or config.
    public func jsonData() throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return try encoder.encode(self)
    }

    // WO-637: findings expose coarse character classes, never a value shape or hash.
    public func text() -> String {
        var lines = ["Config in use: \(configPath ?? configSource); \(customRulesLoaded) custom rules loaded",
                     "documentationPolicy=\(documentationPolicy); MCP minimum severity=\(mcpMinSeverity)",
                     "MCP: \(mcpDirection)", "Proxy: \(proxyDirection) (input as outbound user text)"]
        if findings.isEmpty { lines.append("No match.") }
        for finding in findings {
            lines.append("\(finding.type) line=\(finding.line) class=\(finding.classification) severity=\(finding.severity)" +
                         (finding.ruleName.map { " rule=\($0)" } ?? ""))
            // WO-637: type and rule name identify the finding without a brute-force oracle.
            lines.append("  lengthBytes=\(finding.value.lengthBytes) characterClasses=[\(finding.value.characterClasses.joined(separator: ", "))]")
            lines.append("  mutation=\(finding.mutationAuthorized ? "authorized" : "advisory-only")" +
                         " reason=\(finding.mutationReasons.joined(separator: ", "))")
            lines.append("  guard=\(finding.guardVerdict)" + (finding.guardSeverity.map { " (\($0))" } ?? "") +
                         "; scan exit=\(finding.scanExitCode); MCP=\(finding.mcp)" +
                         (finding.placeholderShape.map { " \($0)" } ?? "") + "; proxy=\(finding.proxy)")
            lines.append("  allowlist suppression=\(finding.allowlistSuppression.isEmpty ? "none" : finding.allowlistSuppression.joined(separator: ", "))")
        }
        lines.append("Scan exit code: \(scanExitCode)")
        return lines.joined(separator: "\n")
    }

    // WO-637: file checks use MCP/scan's structured parser; stdin remains untrusted plain text.
    private static func scan(content: String, filePath: String?, config: PastewatchConfig) throws -> [DetectedMatch] {
        guard let filePath else { return try DetectionRules.scanFileIOOrThrow(content, config: config) }
        let url = URL(fileURLWithPath: filePath)
        let ext = DotenvClassifier.isDotenvFile(url.lastPathComponent) ? "env" : url.pathExtension.lowercased()
        return try DirectoryScanner.scanFileContentOrThrow(content: content, ext: ext, relativePath: filePath, config: config)
    }

    // WO-637: invoke the real MCP policy and proxy redactor, including fail-closed request handling.
    private static func decisions(
        content: String, filePath: String?, config: PastewatchConfig, matches: [DetectedMatch]
    ) throws -> Decisions {
        let trust: GuardContentTrust = filePath == nil ? .agentControlled : .trustedFile
        let guardHook = GuardDecision.evaluate(matches: matches, content: content, config: config,
                                              contentTrust: trust, minimumSeverity: .defaultGuardThreshold, filePath: filePath)
        let scan = GuardDecision.evaluate(matches: matches, content: content, config: config,
                                         contentTrust: trust, minimumSeverity: nil, filePath: filePath)
        let mcp = MCPReadDecision.evaluate(matches: matches, content: content, config: config,
                                          minimumSeverity: Severity(rawValue: config.mcpMinSeverity) ?? .defaultGuardThreshold,
                                          filePath: filePath)
        let proxy = ProxyServer(config: config, quietLog: true)
        let outbound = proxy.outboundTextDecision(content, site: .proxyUserText)
        let body = try JSONSerialization.data(withJSONObject: ["messages": [["role": "user", "content": content]]])
        guard let bodyText = String(data: body, encoding: .utf8) else { throw CocoaError(.fileReadInapplicableStringEncoding) }
        let request = proxy.scanAndRedactBody(bodyText)
        return Decisions(guardHook: guardHook, scan: scan, mcp: mcp, proxy: outbound,
                         proxyRefused: request.serializationFailed || request.blockingAdvisory != nil)
    }

    // WO-637: membership in production outcomes determines verdicts, not a second policy implementation.
    // swiftlint:disable:next function_parameter_count
    private static func finding(
        _ match: DetectedMatch, decisions: Decisions, content: String, config: PastewatchConfig,
        sharedNames: Set<String>, protectedValues: [String], filePath: String?
    ) -> Finding {
        let effectiveMatch = decisions.scan.reportableMatches.first { sameMatch(match, $0) } ?? match
        let partition = partitionMutationMatches([effectiveMatch], site: .cliScan, minAdvisorySeverity: .low)
        let guardMatch = decisions.guardHook.reportableMatches.first { sameMatch(match, $0) }
        let mcpMutates = contains(match, in: decisions.mcp.authorized)
        let mcpAdvisory = contains(match, in: decisions.mcp.reportedAdvisories)
        let proxyMutates = contains(match, in: decisions.proxy.mutated)
        let placeholder = config.placeholderPrefix == nil
            ? Obfuscator.makeMCPPlaceholder(type: match.type, number: 1).replacingOccurrences(of: "_1__", with: "_n__")
            : "<configured-prefix>nnn"
        return Finding(
            type: match.type.rawValue, classification: classification(match, sharedNames: sharedNames),
            ruleName: match.customRuleName.map { safeLabel($0, protectedValues: protectedValues) },
            severity: match.effectiveSeverity.rawValue, line: match.line, value: DiagnosticValueSummary(match.value),
            mutationAuthorized: !partition.authorized.isEmpty, mutationReasons: mutationReasons(effectiveMatch, partition: partition),
            guardVerdict: contains(match, in: decisions.guardHook.actionableMatches) ? "blocks" : (guardMatch == nil ? "not reported" : "reports"),
            guardSeverity: guardMatch?.effectiveSeverity.rawValue,
            scanExitCode: contains(match, in: decisions.scan.actionableMatches) ? ScanExitContract.findingsDetected : ScanExitContract.clean,
            mcp: mcpMutates ? "placeholder, restored on write" : (mcpAdvisory ? "advisory, unchanged" : "unchanged, not reported"),
            placeholderShape: mcpMutates ? placeholder : nil,
            proxy: decisions.proxyRefused ? "refused, not forwarded" : (proxyMutates ? "redacted outbound" : "forwarded unchanged"),
            allowlistSuppression: suppressions(match, content: content, config: config, filePath: filePath)
        )
    }

    // WO-637: merged detector provenance, not class names, explains mutation authorization.
    private static func mutationReasons(_ match: DetectedMatch, partition: MutationPartition) -> [String] {
        guard !partition.authorized.isEmpty else {
            return match.advisory.map { ["not authorized: \($0)"] } ?? ["not authorized"]
        }
        return match.mutationAuthorizationSources.map { String(describing: $0) }.sorted()
    }

    // WO-637: distinguish shared rules without exposing their source patterns or files.
    private static func classification(_ match: DetectedMatch, sharedNames: Set<String>) -> String {
        if let name = match.customRuleName { return sharedNames.contains(name) ? "shared pattern" : "custom rule" }
        if match.mutationAuthorizationSources.contains(.exactKnownSecret) { return "exact known secret" }
        if match.mutationAuthorizationSources.contains(.intrinsicFormat) { return "intrinsic" }
        return "ambiguous opt-in"
    }

    // WO-637: use the actual allowlist filters and identify lists, never their entries.
    private static func suppressions(
        _ match: DetectedMatch, content: String, config: PastewatchConfig, filePath: String?
    ) -> [String] {
        let allowlist = Allowlist.fromConfig(config)
        var result: [String] = []
        if Allowlist(values: allowlist.values).filter([match]).isEmpty { result.append("allowedValues") }
        if Allowlist(patterns: allowlist.patterns).filter([match]).isEmpty { result.append("allowedPatterns") }
        if filePath != nil && Allowlist.filterInlineAllow(matches: [match], content: content).isEmpty {
            result.append("inline allow")
        }
        return result
    }

    // WO-637: GuardDecision may copy a match to lower doc severity, changing its UUID.
    private static func sameMatch(_ left: DetectedMatch, _ right: DetectedMatch) -> Bool {
        left.range == right.range && left.type == right.type && left.customRuleName == right.customRuleName
    }

    // WO-637: compare source spans so policy copies still refer to the same finding.
    private static func contains(_ match: DetectedMatch, in matches: [DetectedMatch]) -> Bool {
        matches.contains { sameMatch(match, $0) }
    }

    // WO-637: names and filenames are user-controlled and may themselves contain checked secrets.
    private static func safeLabel(_ value: String, protectedValues: [String]) -> String {
        guard !protectedValues.contains(where: { !$0.isEmpty && value.contains($0) }) else { return "[masked]" }
        return String(value.unicodeScalars.prefix(160).map {
            CharacterSet.controlCharacters.contains($0) ? "?" : Character(String($0))
        })
    }
}
