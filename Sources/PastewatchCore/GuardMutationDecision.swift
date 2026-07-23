import Foundation

/// WO-526@v3: classify a proposed file mutation without exposing matched values.
public enum GuardMutationBlockReason: String, Equatable {
    case invalidInput
    case touchesExistingFinding
    case changesFindingSet
}

/// WO-526@v3: Edit and Write hooks share one change-aware allow/block result.
public enum GuardMutationDecision: Equatable {
    case allow
    case block(GuardMutationBlockReason)
}

/// WO-526@v3: compare actionable findings before and after a proposed mutation.
public enum GuardMutationEvaluator {
    // WO-526@v3: Edit authorization accounts for every replaced range.
    // swiftlint:disable:next function_parameter_count
    public static func evaluateEdit(
        currentContent: String,
        oldString: String,
        newString: String,
        replaceAll: Bool,
        filePath: String,
        config: PastewatchConfig,
        minimumSeverity: Severity
    ) throws -> GuardMutationDecision {
        guard !oldString.isEmpty else { return .block(.invalidInput) }

        let replacementRanges = ranges(of: oldString, in: currentContent)
        guard !replacementRanges.isEmpty else { return .block(.invalidInput) }
        guard replaceAll || replacementRanges.count == 1 else {
            return .block(.invalidInput)
        }

        let currentMatches = try actionableMatches(
            in: currentContent,
            filePath: filePath,
            config: config,
            minimumSeverity: minimumSeverity
        )
        let appliedRanges = replaceAll ? replacementRanges : [replacementRanges[0]]
        if currentMatches.contains(where: { match in
            appliedRanges.contains(where: { $0.overlaps(match.range) })
        }) {
            return .block(.touchesExistingFinding)
        }

        let proposedContent: String
        if replaceAll {
            proposedContent = currentContent.replacingOccurrences(of: oldString, with: newString)
        } else {
            var result = currentContent
            result.replaceSubrange(replacementRanges[0], with: newString)
            proposedContent = result
        }

        return try compareFindingSets(
            currentMatches: currentMatches,
            proposedContent: proposedContent,
            filePath: filePath,
            config: config,
            minimumSeverity: minimumSeverity
        )
    }

    // WO-526@v3: Write authorization preserves the actionable finding multiset.
    public static func evaluateWrite(
        currentContent: String,
        proposedContent: String,
        filePath: String,
        config: PastewatchConfig,
        minimumSeverity: Severity
    ) throws -> GuardMutationDecision {
        let currentMatches = try actionableMatches(
            in: currentContent,
            filePath: filePath,
            config: config,
            minimumSeverity: minimumSeverity
        )
        return try compareFindingSets(
            currentMatches: currentMatches,
            proposedContent: proposedContent,
            filePath: filePath,
            config: config,
            minimumSeverity: minimumSeverity
        )
    }

    // WO-526@v3: one comparison path prevents Edit and Write policy drift.
    private static func compareFindingSets(
        currentMatches: [DetectedMatch],
        proposedContent: String,
        filePath: String,
        config: PastewatchConfig,
        minimumSeverity: Severity
    ) throws -> GuardMutationDecision {
        let proposedMatches = try actionableMatches(
            in: proposedContent,
            filePath: filePath,
            config: config,
            minimumSeverity: minimumSeverity
        )
        return findingCounts(currentMatches) == findingCounts(proposedMatches)
            ? .allow
            : .block(.changesFindingSet)
    }

    // WO-526@v3: mutations use the same format and allowlist policy as file guards.
    private static func actionableMatches(
        in content: String,
        filePath: String,
        config: PastewatchConfig,
        minimumSeverity: Severity
    ) throws -> [DetectedMatch] {
        guard !content.isEmpty else { return [] }
        let fileName = URL(fileURLWithPath: filePath).lastPathComponent
        let ext = DotenvClassifier.isDotenvFile(fileName)
            ? "env"
            : URL(fileURLWithPath: filePath).pathExtension.lowercased()
        let matches = try DirectoryScanner.scanFileContentOrThrow(
            content: content,
            ext: ext,
            relativePath: filePath,
            config: config
        )
        // WO-527@v2: neither snapshot may self-authorize findings with inline directives.
        return GuardDecision.evaluate(
            matches: matches,
            content: content,
            config: config,
            contentTrust: .agentControlled,
            minimumSeverity: minimumSeverity
        ).actionableMatches
    }

    // WO-526@v3: multiplicity prevents duplicate findings from collapsing into a set.
    private static func findingCounts(_ matches: [DetectedMatch]) -> [FindingIdentity: Int] {
        Dictionary(grouping: matches.map(FindingIdentity.init), by: { $0 })
            .mapValues(\.count)
    }

    // WO-526@v3: enumerate non-overlapping replacements exactly as Edit applies them.
    private static func ranges(of needle: String, in content: String) -> [Range<String.Index>] {
        var result: [Range<String.Index>] = []
        var searchStart = content.startIndex
        while searchStart < content.endIndex,
              let range = content.range(of: needle, range: searchStart..<content.endIndex) {
            result.append(range)
            searchStart = range.upperBound
        }
        return result
    }

    private struct FindingIdentity: Hashable {
        let type: SensitiveDataType
        let value: String

        // WO-526@v3: identity excludes locations so harmless line shifts remain allowed.
        init(_ match: DetectedMatch) {
            type = match.type
            value = match.value
        }
    }
}
