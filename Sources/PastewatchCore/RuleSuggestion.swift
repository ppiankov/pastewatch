import Foundation

// WO-711@v1: suggestions promote operator-selected advisories without changing recognition or mutation policy.
public struct RuleSuggestion: Encodable {
    public let rule: CustomRuleConfig
    public let placement: [String]
    public let warnings: [String]

    // WO-711@v1: derivation uses a local source view rather than changing DetectedMatch's authority or range.
    private struct Candidate {
        let line: String
        let range: Range<String.Index>
    }

    // WO-711@v1: the proposed value span remains separate from both the finding and the emitted rule.
    private struct ValueSpan {
        let range: Range<String.Index>
        let quote: Character?
    }

    // WO-711@v1: literal source context supplies a fixed-length anchor that cannot contain the selected value.
    private struct Anchor {
        let key: String
        let text: String
    }

    // WO-711@v1: select only findings that the actual trusted-file read policy would leave unmasked.
    public static func generate(
        content: String, config: PastewatchConfig, filePath: String?, line: Int,
        exact: Bool = false, name: String? = nil
    ) throws -> RuleSuggestion {
        if let name, name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            throw RuleSuggestionError.cannotDerive
        }
        let candidate = try candidate(content: content, config: config, filePath: filePath, line: line)
        let span = try valueSpan(in: candidate)
        let anchor = anchor(in: candidate.line, before: span.range.lowerBound, quote: span.quote)
        let value = String(candidate.line[span.range])
        let pattern: String
        if exact {
            pattern = NSRegularExpression.escapedPattern(for: value)
        } else {
            guard let anchor else { throw RuleSuggestionError.cannotDerive }
            let ext = filePath.map { URL(fileURLWithPath: $0).pathExtension.lowercased() }
            pattern = "(?<=" + NSRegularExpression.escapedPattern(for: anchor.text) + ")" +
                valuePattern(quote: span.quote, properties: ext == "properties")
        }
        let rule = CustomRuleConfig(name: name ?? "suggested-" + sanitizedKey(anchor?.key ?? "advisory"),
                                    pattern: pattern, severity: Severity.defaultCustomRuleSeverity.rawValue)
        do {
            try verify(rule, candidate: candidate, span: span, config: config)
        } catch {
            throw RuleSuggestionError.cannotDerive
        }
        let result = RuleSuggestion(rule: rule, placement: [
            "User config: ~/.config/pastewatch/config.json; administrator policy remains authoritative when present.",
            "Project config: .pastewatch.json at the git toplevel. Run from that root; added customRules tighten protection without replacing operator rules."
        ], warnings: exact ? [
            "WARNING: this rule stores the secret value in plaintext in config and stops matching after rotation."
        ] : [])
        guard !rule.name.contains(value), !result.placement.contains(where: { $0.contains(value) }),
              !result.warnings.contains(where: { $0.contains(value) }), exact || !rule.pattern.contains(value) else {
            throw RuleSuggestionError.cannotDerive
        }
        return result
    }

    // WO-711@v1: JSON encodes only the proposed entry, placement guidance and explicit literal-mode warnings.
    public func jsonData() throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(self)
    }

    // WO-711@v1: text remains a pasteable JSON entry followed by configuration guidance, never a config write.
    public func text() throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        guard let entry = String(data: try encoder.encode(rule), encoding: .utf8) else {
            throw RuleSuggestionError.cannotDerive
        }
        return (warnings + [entry, "Add the entry to customRules in:"] + placement.map { "- " + $0 } +
                ["This command never edits configuration."]).joined(separator: "\n")
    }

    // WO-711@v1: reuse normal scanning and authorization; a custom or intrinsic finding is already protected.
    private static func candidate(
        content: String, config: PastewatchConfig, filePath: String?, line: Int
    ) throws -> Candidate {
        guard line > 0 else { throw RuleSuggestionError.cannotDerive }
        let matches: [DetectedMatch]
        if let filePath {
            let url = URL(fileURLWithPath: filePath)
            let ext = DotenvClassifier.isDotenvFile(url.lastPathComponent) ? "env" : url.pathExtension.lowercased()
            matches = try DirectoryScanner.scanFileContentOrThrow(content: content, ext: ext,
                                                                  relativePath: filePath, config: config)
        } else {
            matches = try DetectionRules.scanFileIOOrThrow(content, config: config)
        }
        let decision = GuardDecision.evaluate(matches: matches, content: content, config: config,
                                              minimumSeverity: nil, filePath: filePath)
        let partition = partitionMutationMatches(decision.reportableMatches, site: .mcpRead, minAdvisorySeverity: .low)
        let advisories = partition.advisory.filter { $0.line == line }
        guard let first = advisories.first else {
            if partition.authorized.contains(where: { $0.line == line }) { throw RuleSuggestionError.alreadyMasked }
            throw RuleSuggestionError.noAdvisoryFinding
        }
        guard advisories.allSatisfy({ $0.range == first.range }) else { throw RuleSuggestionError.cannotDerive }
        let start = content[..<first.range.lowerBound].lastIndex(of: "\n").map { content.index(after: $0) }
            ?? content.startIndex
        let end = content[first.range.lowerBound...].firstIndex(of: "\n") ?? content.endIndex
        guard first.range.lowerBound >= start, first.range.upperBound <= end else { throw RuleSuggestionError.cannotDerive }
        let sourceLine = String(content[start..<end])
        let sourceRange = NSRange(start..<end, in: content)
        let matchRange = NSRange(first.range, in: content)
        guard let range = Range(NSRange(location: matchRange.location - sourceRange.location,
                                        length: matchRange.length), in: sourceLine) else {
            throw RuleSuggestionError.cannotDerive
        }
        return Candidate(line: sourceLine, range: range)
    }

    // WO-711@v1: remove only bounded assignment/quote/comment syntax from the original advisory span.
    private static func valueSpan(in candidate: Candidate) throws -> ValueSpan {
        let line = candidate.line
        var range = candidate.range
        let previous = line[..<range.lowerBound].last
        let adjacentQuote: Character? = previous == "\"" || previous == "'" ? previous : nil
        let hasSourceAnchor = anchor(in: line, before: range.lowerBound, quote: adjacentQuote) != nil
        if !hasSourceAnchor,
           let prefix = line[range].range(of: #"^[A-Za-z_][A-Za-z0-9_.-]*[ \t]*[=:][ \t]*"#,
                                         options: .regularExpression) {
            range = prefix.upperBound..<range.upperBound
        }
        guard !range.isEmpty else { throw RuleSuggestionError.cannotDerive }
        let quote: Character?
        if line[range.lowerBound] == "\"" || line[range.lowerBound] == "'" {
            quote = line[range.lowerBound]
            let closing = try closingQuote(in: line, range: range)
            range = line.index(after: range.lowerBound)..<closing
        } else if range.lowerBound > line.startIndex, range.upperBound < line.endIndex,
                  let previous = line[..<range.lowerBound].last, previous == "\"" || previous == "'",
                  line[range.upperBound] == previous {
            quote = previous
        } else {
            quote = nil
            range = unquotedRange(range, in: line)
        }
        guard !range.isEmpty, !line[range].contains(where: { $0.isNewline }) else {
            throw RuleSuggestionError.cannotDerive
        }
        return ValueSpan(range: range, quote: quote)
    }

    // WO-711@v1: quote termination follows only the pinned escape rules and never crosses the finding's source line.
    private static func closingQuote(in line: String, range: Range<String.Index>) throws -> String.Index {
        let quote = line[range.lowerBound]
        var index = line.index(after: range.lowerBound)
        while index < range.upperBound {
            let next = line.index(after: index)
            if quote == "\"", line[index] == "\\" {
                guard next < range.upperBound else { throw RuleSuggestionError.cannotDerive }
                index = line.index(after: next)
                continue
            }
            if line[index] == quote {
                if quote == "'", next < range.upperBound, line[next] == "'" {
                    index = line.index(after: next)
                    continue
                }
                return index
            }
            index = next
        }
        throw RuleSuggestionError.cannotDerive
    }

    // WO-711@v1: escaped hashes remain value bytes, while unescaped whitespace-hash starts an inline comment.
    private static func unquotedRange(_ range: Range<String.Index>, in line: String) -> Range<String.Index> {
        var end = range.upperBound
        var index = range.lowerBound
        while index < range.upperBound {
            let next = line.index(after: index)
            if line[index] == "\\", next < range.upperBound {
                index = line.index(after: next)
                continue
            }
            if line[index] == "#", index > line.startIndex,
               [" ", "\t"].contains(line[line.index(before: index)]) {
                end = index
                break
            }
            index = next
        }
        while end > range.lowerBound, line[line.index(before: end)].isWhitespace { end = line.index(before: end) }
        return range.lowerBound..<end
    }

    // WO-711@v1: full source keys, including prefixes outside a raw keyword match, define the literal assignment anchor.
    private static func anchor(in line: String, before index: String.Index, quote: Character?) -> Anchor? {
        let prefix = String(line[..<index])
        guard let regex = try? NSRegularExpression(
            pattern: #"(?:^|[^A-Za-z0-9_.-])([A-Za-z_][A-Za-z0-9_.-]*)([ \t]*[=:][ \t]*)(["']?)$"#
        ), let match = regex.firstMatch(in: prefix, range: NSRange(prefix.startIndex..., in: prefix)),
           let keyRange = Range(match.range(at: 1), in: prefix),
           let quoteRange = Range(match.range(at: 3), in: prefix),
           String(prefix[quoteRange]) == (quote.map(String.init) ?? "") else { return nil }
        return Anchor(key: String(prefix[keyRange]), text: String(prefix[keyRange.lowerBound...]))
    }

    // WO-711@v1: fixed source anchors use bounded ICU lookbehind; format-specific classes preserve surrounding syntax.
    private static func valuePattern(quote: Character?, properties: Bool) -> String {
        if let quote {
            let escaped = NSRegularExpression.escapedPattern(for: String(quote))
            return "[^" + escaped + "\\r\\n]+(?=" + escaped + ")"
        }
        return properties ? "[^\\r\\n]*[^\\s\\r\\n]" : "[^\\s#\\r\\n]+"
    }

    // WO-711@v1: neither a wider span nor a second occurrence may reach the operator as an apparently safe suggestion.
    private static func verify(
        _ rule: CustomRuleConfig, candidate: Candidate, span: ValueSpan, config: PastewatchConfig
    ) throws {
        let compiled = try CustomRule.compile([rule])
        let matches = try DetectionRules.scanFileIOOrThrow(candidate.line, config: config, customRules: compiled)
        guard matches.count == 1, let match = matches.first,
              match.customRuleName == rule.name,
              NSRange(match.range, in: candidate.line) == NSRange(span.range, in: candidate.line),
              match.value.utf8.elementsEqual(candidate.line[span.range].utf8) else {
            throw RuleSuggestionError.cannotDerive
        }
    }

    // WO-711@v1: rule identifiers depend only on the source key, not the selected value or a fingerprint of it.
    private static func sanitizedKey(_ key: String) -> String {
        let sanitized = key.lowercased().replacingOccurrences(of: "[^a-z0-9]+", with: "-", options: .regularExpression)
            .trimmingCharacters(in: CharacterSet(charactersIn: "-"))
        return sanitized.isEmpty ? "advisory" : sanitized
    }
}

// WO-711@v1: errors carry no source content, matched value, pattern, length or fingerprint.
public enum RuleSuggestionError: Error {
    case noAdvisoryFinding
    case alreadyMasked
    case cannotDerive
}
