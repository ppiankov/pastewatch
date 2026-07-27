import Foundation

/// Obfuscates detected sensitive data with stable placeholders.
///
/// Design principles:
/// - Placeholders are deterministic within a single paste operation
/// - Mapping exists only in memory
/// - No persistence, no recovery mechanism
/// - After paste, the system returns to rest
public struct Obfuscator {

    /// WO-454: explicit display-hygiene exception for commands echoed to diagnostics.
    public static func redactForDisplay(_ content: String, matches: [DetectedMatch]) -> String {
        obfuscate(content, matches: matches)
    }

    // WO-478: advisory scanner outcomes cannot authorize content replacement.
    /// Obfuscate all matches in the content.
    /// Returns the obfuscated content with matches replaced by placeholders.
    public static func obfuscate(_ content: String, matches: [DetectedMatch]) -> String {
        // WO-478: advisory diagnostics reserve ranges for reporting but never
        // authorize replacement, even when a caller passes the full scan result.
        let matches = matches.filter { $0.advisory == nil }
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
    /// Used by GUI clipboard obfuscation and CLI output.
    public static func makePlaceholder(type: SensitiveDataType, number: Int) -> String {
        let typeName = type.rawValue.uppercased().replacingOccurrences(of: " ", with: "_")
        return "<\(typeName)_\(number)>"
    }

    /// Create an MCP-safe placeholder that never collides with real content.
    /// Format: __PW_TYPE_N__ — ASCII-safe, grep-friendly, proxy-compatible.
    /// Used by MCP redacted read/write tools.
    public static func makeMCPPlaceholder(type: SensitiveDataType, number: Int) -> String {
        let typeName = type.rawValue.uppercased().replacingOccurrences(of: " ", with: "_")
        return "__PW_\(typeName)_\(number)__"
    }

    /// Create a custom-prefix placeholder.
    /// Format: {prefix}{zero-padded number} — no braces, no special chars.
    public static func makeCustomPlaceholder(prefix: String, number: Int) -> String {
        return "\(prefix)\(String(format: "%03d", number))"
    }

    /// Regex pattern matching MCP placeholders for resolution.
    public static let mcpPlaceholderPattern = "__PW_[A-Z][A-Z0-9_]*_\\d+__"
    /// WO-557@v2: POSIX ERE form used by generated shell hooks.
    public static let mcpPlaceholderPOSIXERE = "__PW_[A-Z][A-Z0-9_]*_[0-9]+__"

    /// Build a regex pattern matching custom-prefix placeholders.
    public static func customPlaceholderPattern(prefix: String) -> String {
        return NSRegularExpression.escapedPattern(for: prefix) + "\\d{3,}"
    }
}
