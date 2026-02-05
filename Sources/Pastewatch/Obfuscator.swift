import Foundation

/// Obfuscates detected sensitive data with stable placeholders.
///
/// Design principles:
/// - Placeholders are deterministic within a single paste operation
/// - Mapping exists only in memory
/// - No persistence, no recovery mechanism
/// - After paste, the system returns to rest
struct Obfuscator {

    /// Obfuscate all matches in the content.
    /// Returns the obfuscated content with matches replaced by placeholders.
    static func obfuscate(_ content: String, matches: [DetectedMatch]) -> String {
        guard !matches.isEmpty else { return content }

        // Sort matches by range start position (descending) to replace from end
        // This preserves indices during replacement
        let sortedMatches = matches.sorted { $0.range.lowerBound > $1.range.lowerBound }

        // Track placeholder counters per type
        var typeCounters: [SensitiveDataType: Int] = [:]

        // First pass: assign numbers to matches in order of appearance
        var matchNumbers: [UUID: Int] = [:]
        for match in matches.sorted(by: { $0.range.lowerBound < $1.range.lowerBound }) {
            let count = (typeCounters[match.type] ?? 0) + 1
            typeCounters[match.type] = count
            matchNumbers[match.id] = count
        }

        // Second pass: replace from end to preserve indices
        var result = content
        for match in sortedMatches {
            let number = matchNumbers[match.id] ?? 1
            let placeholder = makePlaceholder(type: match.type, number: number)
            result.replaceSubrange(match.range, with: placeholder)
        }

        return result
    }

    /// Create a placeholder string for a given type and occurrence number.
    private static func makePlaceholder(type: SensitiveDataType, number: Int) -> String {
        let typeName = type.rawValue.uppercased().replacingOccurrences(of: " ", with: "_")
        return "<\(typeName)_\(number)>"
    }
}
