import Foundation

/// WO-502: inline comments are authoritative only in operator-controlled files.
public enum GuardContentTrust {
    case agentControlled
    case trustedFile
}

/// WO-502: one post-scan policy keeps guard surfaces from drifting.
public struct GuardDecision {
    public let reportableMatches: [DetectedMatch]
    public let actionableMatches: [DetectedMatch]

    // WO-672@v1: agent mutation cannot create or change its own policy files.
    public static let operatorOwnedFileMessage = "operator-owned file: edit it yourself"

    // WO-672@v1: ownership checks apply before nonexistent-file and empty-content shortcuts.
    public static func isOperatorOwnedPath(_ path: String) -> Bool {
        // WO-672@v1: policy names remain operator-owned under filesystem-equivalent spelling.
        let name = URL(fileURLWithPath: path).lastPathComponent.precomposedStringWithCanonicalMapping.lowercased()
        return [".pastewatch.json", ".pastewatch-allow"].contains(name)
    }

    // WO-635: classify by the supplied path only, never by content or directory names.
    private static let documentationExtensions: Set<String> = ["md", "mdx", "markdown", "rst", "adoc"]

    // WO-670@v1: every file decision shares target-root allow-file loading; rootless decisions load none.
    // WO-635: one decision owns documentation classification and protects independently authorized secrets.
    public static func evaluate(
        matches: [DetectedMatch],
        content: String,
        config: PastewatchConfig,
        contentTrust: GuardContentTrust,
        minimumSeverity: Severity?,
        // WO-670@v1: non-git multi-file scans supply their explicit root, not an inferred ancestor.
        filePath: String? = nil,
        scanRoot: String? = nil
    ) -> GuardDecision {
        let nonTestMatches = matches.filter {
            !DetectionRules.isTestCredential($0.value)
        }
        let inlineFiltered: [DetectedMatch]
        switch contentTrust {
        case .agentControlled:
            inlineFiltered = nonTestMatches
        case .trustedFile:
            inlineFiltered = Allowlist.filterInlineAllow(
                matches: nonTestMatches,
                content: content
            )
        }
        // WO-635: no path is non-documentation; authorized intrinsic/exact/custom evidence never downgrades.
        let isDocumentation = filePath.map {
            documentationExtensions.contains(URL(fileURLWithPath: $0).pathExtension.lowercased())
        } ?? false
        // WO-672@v1: allow-file accounting sees the same effective custom rules as the guard.
        let allowlist = Allowlist.fromConfig(config).merged(with:
            Allowlist.projectFile(for: filePath, scanRoot: scanRoot, config: config).allowlist)
        let reportable = allowlist.filter(inlineFiltered).map { match in
            guard config.documentationPolicy == .advisory, isDocumentation,
                  match.type.isAmbiguousClass,
                  match.mutationAuthorizationSources.isDisjoint(with: [.intrinsicFormat, .exactKnownSecret, .customRule]),
                  match.customRuleName == nil, match.advisory == nil else { return match }
            return DetectedMatch(
                type: match.type, value: match.value, range: match.range,
                line: match.line, filePath: match.filePath,
                customRuleName: match.customRuleName, customSeverity: .medium,
                advisory: .documentationPolicy,
                mutationAuthorizationSources: match.mutationAuthorizationSources,
                obfuscateRuleIdentifier: match.obfuscateRuleIdentifier
            )
        }
        // WO-635: a reporting warning never becomes actionable even at a low block threshold.
        let actionable = reportable.filter { match in
            match.advisory != .documentationPolicy &&
                (minimumSeverity.map { match.effectiveSeverity >= $0 } ?? true)
        }
        return GuardDecision(
            reportableMatches: reportable,
            actionableMatches: actionable
        )
    }
}
