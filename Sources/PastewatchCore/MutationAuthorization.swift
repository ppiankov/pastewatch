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

// WO-639: only text-rewriting primitives consume targeting; invalid metadata over-redacts the whole match.
func authorizedMutationRange(for match: DetectedMatch, in text: String) -> Range<String.Index> {
    guard let span = match.mutationSubrange, !span.isEmpty,
          match.range.lowerBound >= text.startIndex, match.range.upperBound <= text.endIndex,
          match.range.lowerBound <= span.lowerBound, span.upperBound <= match.range.upperBound,
          match.type == .dbConnectionString,
          text[match.range].utf8.elementsEqual(match.value.utf8),
          let lower = String.Index(span.lowerBound, within: text),
          let upper = String.Index(span.upperBound, within: text) else { return match.range }
    return lower..<upper
}

// WO-645@v1: share the obfuscator writer while preserving whole-match authorization identities.
// WO-639: rewrite optional subranges without changing the match identities reported to callers.
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
        // WO-645@v1: targeting is supplied to the single placeholder-numbering and replacement path.
        text: Obfuscator.obfuscate(text, matches: partition.authorized, replacementRange: {
            authorizedMutationRange(for: $0, in: text)
        }),
        mutated: partition.authorized,
        advisory: partition.advisory,
        advisoryBelowThreshold: partition.advisoryBelowThreshold
    )
}
