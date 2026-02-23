import Foundation

/// Manages allowed values that should be excluded from scan results.
public struct Allowlist {
    public let values: Set<String>

    public init(values: Set<String> = []) {
        self.values = values
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

    /// Merge multiple allowlists.
    public func merged(with other: Allowlist) -> Allowlist {
        Allowlist(values: values.union(other.values))
    }

    /// Merge with config's allowedValues.
    public static func fromConfig(_ config: PastewatchConfig) -> Allowlist {
        Allowlist(values: Set(config.allowedValues))
    }

    /// Filter matches, removing any whose value is in the allowlist.
    public func filter(_ matches: [DetectedMatch]) -> [DetectedMatch] {
        matches.filter { !values.contains($0.value) }
    }

    /// Check if a value is allowed (should be skipped).
    public func contains(_ value: String) -> Bool {
        values.contains(value)
    }

    /// Filter out matches on lines that contain a pastewatch:allow comment.
    public static func filterInlineAllow(matches: [DetectedMatch], content: String) -> [DetectedMatch] {
        guard !matches.isEmpty else { return [] }
        let lines = content.components(separatedBy: "\n")
        return matches.filter { match in
            let lineIndex = match.line - 1
            guard lineIndex >= 0, lineIndex < lines.count else { return true }
            return !lines[lineIndex].contains("pastewatch:allow")
        }
    }
}
