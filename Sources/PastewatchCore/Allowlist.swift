import Foundation

/// Manages allowed values that should be excluded from scan results.
public struct Allowlist {
    public let values: Set<String>
    public let patterns: [NSRegularExpression]
    // WO-672@v1: exact exemptions retain the source that granted them.
    public let valueSources: [String: Set<AllowlistSource>]
    public let patternSources: [Set<AllowlistSource>]

    // WO-672@v1: unannotated caller-supplied entries have no operator authority.
    public init(values: Set<String> = [], patterns: [NSRegularExpression] = [], source: AllowlistSource = .remedy) {
        self.values = values
        self.patterns = patterns
        // WO-672@v1: source metadata is not supplied by the allowlist file contents.
        valueSources = Dictionary(uniqueKeysWithValues: values.map { ($0, [source]) })
        patternSources = Array(repeating: [source], count: patterns.count)
    }

    // WO-672@v1: combining tiers must not lose operator exact-value authority.
    private init(values: Set<String>, patterns: [NSRegularExpression], valueSources: [String: Set<AllowlistSource>],
                 patternSources: [Set<AllowlistSource>]) {
        self.values = values
        self.patterns = patterns
        self.valueSources = valueSources
        self.patternSources = patternSources
    }

    /// Load allowlist from a file (one value per line, # comments).
    public static func load(from path: String) throws -> Allowlist {
        let content = try String(contentsOfFile: path, encoding: .utf8)
        let values = content
            .components(separatedBy: .newlines)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty && !$0.hasPrefix("#") }
        return Allowlist(values: Set(values))
    }

    // WO-672@v1: union source evidence as well as values when multiple tiers share an entry.
    /// Merge multiple allowlists.
    public func merged(with other: Allowlist) -> Allowlist {
        var sources = valueSources
        for (value, tiers) in other.valueSources { sources[value, default: []].formUnion(tiers) }
        return Allowlist(values: values.union(other.values), patterns: patterns + other.patterns, valueSources: sources,
                        patternSources: patternSources + other.patternSources)
    }

    // WO-672@v1: only the validated resolver or user loader may attach operator authority.
    /// Merge with config's allowedValues and allowedPatterns.
    public static func fromConfig(_ config: PastewatchConfig) -> Allowlist {
        // WO-672@v1: source metadata travels with each successfully compiled pattern.
        let compiled = config.allowedPatterns.compactMap { pattern -> (NSRegularExpression, Set<AllowlistSource>)? in
            guard let regex = try? NSRegularExpression(pattern: "^(\(pattern))$") else { return nil }
            return (regex, config.allowedPatternSources[pattern] ?? [.project])
        }
        // WO-672@v1: directly constructed or decoded policy defaults to project-tier exemptions.
        let sources = Dictionary(uniqueKeysWithValues: Set(config.allowedValues).map {
            ($0, config.allowedValueSources[$0] ?? [.project])
        })
        return Allowlist(values: Set(config.allowedValues), patterns: compiled.map { $0.0 }, valueSources: sources,
                        patternSources: compiled.map { $0.1 })
    }

    // WO-672@v1: shared authorization governs filtering before any surface can lose evidence.
    /// Filter matches, removing only source-authorized exact values or patterns.
    public func filter(_ matches: [DetectedMatch]) -> [DetectedMatch] {
        matches.filter { match in
            // WO-672@v1: pattern suppression never grants intrinsic-format authority.
            if valueSources[match.value]?.contains(where: {
                permitsAllowlistSuppression(of: match, source: $0, exactValue: true)
            }) == true { return false }
            for (pattern, sources) in zip(patterns, patternSources) where sources.contains(where: {
                permitsAllowlistSuppression(of: match, source: $0, exactValue: false)
            }) {
                let range = NSRange(match.value.startIndex..., in: match.value)
                if pattern.firstMatch(in: match.value, range: range) != nil { return false }
            }
            return true
        }
    }

    /// Check if a value is allowed (should be skipped).
    public func contains(_ value: String) -> Bool {
        values.contains(value)
    }

    /// WO-554@v3: only documented line or trailing comment forms can authorize a value.
    /// Requiring whitespace before the delimiter prevents URL fragments and operators
    /// from becoming accidental authorization markers.
    private static let inlineAllowPattern = try? NSRegularExpression(
        pattern: #"(?:^|\s)(?:#|//)\s*pastewatch:allow(?=\s|$)"#
    )

    // WO-672@v1: inline directives cannot hide intrinsic evidence from guards or mutation.
    /// Filter advisory matches on lines containing a pastewatch:allow directive.
    public static func filterInlineAllow(matches: [DetectedMatch], content: String) -> [DetectedMatch] {
        guard !matches.isEmpty, let inlineAllowPattern else { return matches }
        let lines = content.components(separatedBy: "\n")
        return matches.filter { match in
            // WO-672@v1: the directive's source is always unprivileged, even in trusted files.
            guard permitsAllowlistSuppression(of: match, source: .inlineDirective, exactValue: false) else { return true }
            let lineIndex = match.line - 1
            guard lineIndex >= 0, lineIndex < lines.count else { return true }
            let line = lines[lineIndex]
            let range = NSRange(line.startIndex..<line.endIndex, in: line)
            return inlineAllowPattern.firstMatch(in: line, range: range) == nil
        }
    }
}
