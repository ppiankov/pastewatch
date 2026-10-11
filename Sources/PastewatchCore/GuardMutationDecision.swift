import Foundation

/// WO-526@v3: classify a proposed file mutation without exposing matched values.
public enum GuardMutationBlockReason: String, Equatable {
    // WO-672@v1: operator-owned policy cannot be changed by an agent-controlled mutation.
    case operatorOwnedFile
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
    // WO-676@v4: expose selected findings to CLI diagnostics without a separate scan or policy side effect.
    // WO-672@v1: refuse operator-owned paths before evaluating existing or proposed content.
    // WO-526@v3: Edit authorization accounts for every replaced range.
    // swiftlint:disable:next function_parameter_count
    public static func evaluateEdit(
        currentContent: String,
        oldString: String,
        newString: String,
        replaceAll: Bool,
        filePath: String,
        config: PastewatchConfig,
        minimumSeverity: Severity,
        onFindings: ((String, [DetectedMatch]) -> Void)? = nil
    ) throws -> GuardMutationDecision {
        // WO-672@v1: ownership does not depend on whether the target exists or contains findings.
        if GuardDecision.isOperatorOwnedPath(filePath) { return .block(.operatorOwnedFile) }
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
            // WO-676@v4: diagnostic observers cannot alter the selected matches.
            minimumSeverity: minimumSeverity, onFindings: onFindings
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

        // WO-676@v4: reuse the proposed snapshot's scan for the diagnostic and decision.
        let proposedMatches = try actionableMatches(
            in: proposedContent,
            filePath: filePath,
            config: config,
            minimumSeverity: minimumSeverity, onFindings: onFindings
        )
        return compareFindingSets(currentMatches: currentMatches, proposedMatches: proposedMatches)
    }

    // WO-676@v4: callers may observe findings without introducing policy or output in Core.
    // WO-672@v1: ownership protects clean creation as well as modifications.
    // WO-526@v3: Write authorization preserves the actionable finding multiset.
    public static func evaluateWrite(
        currentContent: String,
        proposedContent: String,
        filePath: String,
        config: PastewatchConfig,
        minimumSeverity: Severity,
        onFindings: ((String, [DetectedMatch]) -> Void)? = nil
    ) throws -> GuardMutationDecision {
        // WO-672@v1: check ownership before any content-based admission.
        if GuardDecision.isOperatorOwnedPath(filePath) { return .block(.operatorOwnedFile) }
        let currentMatches = try actionableMatches(
            in: currentContent,
            filePath: filePath,
            config: config,
            // WO-676@v4: diagnostics consume the same current findings used by authorization.
            minimumSeverity: minimumSeverity, onFindings: onFindings
        )
        // WO-676@v4: diagnostics consume the proposed snapshot's single scan.
        let proposedMatches = try actionableMatches(
            in: proposedContent,
            filePath: filePath,
            config: config,
            minimumSeverity: minimumSeverity, onFindings: onFindings
        )
        return compareFindingSets(currentMatches: currentMatches, proposedMatches: proposedMatches)
    }

    // WO-676@v4: comparison consumes scanned snapshots without diagnostic plumbing.
    // WO-526@v3: one comparison path prevents Edit and Write policy drift.
    private static func compareFindingSets(
        currentMatches: [DetectedMatch],
        proposedMatches: [DetectedMatch]
    ) -> GuardMutationDecision {
        findingCounts(currentMatches) == findingCounts(proposedMatches)
            ? .allow
            : .block(.changesFindingSet)
    }

    // WO-676@v4: diagnostic observation never changes the marker-free mutation decision.
    // WO-526@v3: mutations use the same format and allowlist policy as file guards.
    private static func actionableMatches(
        in content: String,
        filePath: String,
        config: PastewatchConfig,
        minimumSeverity: Severity,
        onFindings: ((String, [DetectedMatch]) -> Void)?
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
        // WO-676@v4: neither snapshot may self-authorize an inline exemption.
        let actionable = GuardDecision.evaluate(
            matches: matches,
            content: content,
            config: config,
            minimumSeverity: minimumSeverity,
            // WO-635: both mutation snapshots share the target file's documentation policy.
            filePath: filePath
        ).actionableMatches
        // WO-676@v4: Core returns findings only; the CLI owns all migration text and I/O.
        onFindings?(content, actionable)
        return actionable
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
