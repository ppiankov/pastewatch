import Foundation

/// WO-454: semantic location of a mutation decision; no caller receives a permissive default.
public enum MutationSite: CaseIterable {
    case clipboard
    case cliScan
    case mcpRead
    case proxySystem
    case proxyToolDescription
    case proxyInputSchema
    case proxyToolInputExample
    case proxyUserText
    case proxyAssistantText
    case proxyToolUseInput
    case proxyToolResult
    case proxyStopSequence
    case proxyResponse
}

/// WO-454: exhaustive accounting prevents advisory matches from disappearing.
public struct MutationPartition {
    public let authorized: [DetectedMatch]
    public let advisory: [DetectedMatch]
    public let advisoryBelowThreshold: [DetectedMatch]
}

/// WO-454: the only normal production result for text mutation.
public struct MutationOutcome {
    public let text: String
    public let mutated: [DetectedMatch]
    public let advisory: [DetectedMatch]
    public let advisoryBelowThreshold: [DetectedMatch]
}

/// WO-454: evidence authorizes mutation; site and severity only classify reporting.
public func partitionMutationMatches(
    _ matches: [DetectedMatch],
    site: MutationSite,
    minAdvisorySeverity: Severity
) -> MutationPartition {
    _ = site
    var authorized: [DetectedMatch] = []
    var advisory: [DetectedMatch] = []
    var belowThreshold: [DetectedMatch] = []

    for match in matches {
        if match.advisory == nil && !match.mutationAuthorizationSources.isEmpty {
            authorized.append(match)
        } else if match.effectiveSeverity >= minAdvisorySeverity {
            advisory.append(match)
        } else {
            belowThreshold.append(match)
        }
    }

    assert(authorized.count + advisory.count + belowThreshold.count == matches.count)
    return MutationPartition(
        authorized: authorized,
        advisory: advisory,
        advisoryBelowThreshold: belowThreshold
    )
}

/// WO-454: every normal mutation call passes through this evidence gate.
public func applyAuthorizedMutations(
    to text: String,
    matches: [DetectedMatch],
    site: MutationSite,
    minAdvisorySeverity: Severity
) -> MutationOutcome {
    let partition = partitionMutationMatches(
        matches,
        site: site,
        minAdvisorySeverity: minAdvisorySeverity
    )
    return MutationOutcome(
        text: Obfuscator.obfuscate(text, matches: partition.authorized),
        mutated: partition.authorized,
        advisory: partition.advisory,
        advisoryBelowThreshold: partition.advisoryBelowThreshold
    )
}
