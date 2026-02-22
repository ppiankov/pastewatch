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
}
