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

    public static func evaluate(
        matches: [DetectedMatch],
        content: String,
        config: PastewatchConfig,
        contentTrust: GuardContentTrust,
        minimumSeverity: Severity?
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
        let reportable = Allowlist.fromConfig(config).filter(inlineFiltered)
        let actionable: [DetectedMatch]
        if let minimumSeverity {
            actionable = reportable.filter { $0.effectiveSeverity >= minimumSeverity }
        } else {
            actionable = reportable
        }
        return GuardDecision(
            reportableMatches: reportable,
            actionableMatches: actionable
        )
    }
}
