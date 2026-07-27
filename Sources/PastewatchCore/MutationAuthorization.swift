import Foundation

/// WO-454/WO-488: exhaustive site classification keeps every caller explicit.
/// Authorization is deliberately evidence-based and uniform across these sites.
public enum MutationSite: CaseIterable {
    case clipboard
    case cliScan
    case mcpRead
    // WO-549@v2: MCP write restoration is an explicit data mutation site.
    case mcpWrite
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

/// WO-454/WO-488: evidence authorizes mutation; the required site label classifies
/// callers for exhaustive tests but cannot silently widen or narrow authorization.
public func partitionMutationMatches(
    _ matches: [DetectedMatch],
    site _: MutationSite,
    minAdvisorySeverity: Severity
) -> MutationPartition {
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
