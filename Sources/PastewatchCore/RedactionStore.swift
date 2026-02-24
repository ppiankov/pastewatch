import Foundation

/// In-memory store for placeholder↔original mappings used by MCP redacted read/write.
///
/// Design:
/// - Mapping lives only in server process memory — dies on exit, never persisted
/// - Keyed by file path — same file re-read returns same placeholders
/// - Deobfuscation happens locally on-device — secrets never leave the machine
/// - Uses __PW{TYPE_N}__ format — never collides with real content
public final class RedactionStore {
    // swiftlint:disable:next force_try
    private static let placeholderRegex = try! NSRegularExpression(pattern: Obfuscator.mcpPlaceholderPattern)

    /// Forward mapping: placeholder → original value, per file.
    private var mappings: [String: [String: String]] = [:]

    /// Reverse mapping: original value → placeholder, per file (for idempotent re-reads).
    private var reverseMappings: [String: [String: String]] = [:]

    /// Type counters per file for placeholder numbering.
    private var typeCounters: [String: [SensitiveDataType: Int]] = [:]

    public init() {}

    /// Redact sensitive values in content, storing the mapping for later resolution.
    /// Returns the redacted content and a manifest of redactions.
    public func redact(content: String, matches: [DetectedMatch], filePath: String) -> (String, [RedactionEntry]) {
        guard !matches.isEmpty else {
            return (content, [])
        }

        // Sort by position (ascending) for consistent placeholder assignment
        let sorted = matches.sorted { $0.range.lowerBound < $1.range.lowerBound }

        var entries: [RedactionEntry] = []
        var placeholdersByMatch: [(DetectedMatch, String)] = []

        for match in sorted {
            let original = match.value
            let reverse = reverseMappings[filePath] ?? [:]

            let placeholder: String
            if let existing = reverse[original] {
                // Same value seen before in this file — reuse placeholder
                placeholder = existing
            } else {
                var counters = typeCounters[filePath] ?? [:]
                let count = (counters[match.type] ?? 0) + 1
                counters[match.type] = count
                typeCounters[filePath] = counters

                placeholder = Obfuscator.makeMCPPlaceholder(type: match.type, number: count)

                var forward = mappings[filePath] ?? [:]
                forward[placeholder] = original
                mappings[filePath] = forward

                var rev = reverseMappings[filePath] ?? [:]
                rev[original] = placeholder
                reverseMappings[filePath] = rev
            }

            placeholdersByMatch.append((match, placeholder))

            entries.append(RedactionEntry(
                type: match.displayName,
                severity: match.effectiveSeverity.rawValue,
                line: match.line,
                placeholder: placeholder
            ))
        }

        // Replace from end to preserve indices
        var result = content
        for (match, placeholder) in placeholdersByMatch.reversed() {
            result.replaceSubrange(match.range, with: placeholder)
        }

        return (result, entries)
    }

    /// Resolve placeholders in content using mappings for a specific file.
    public func resolve(content: String, filePath: String) -> ResolveResult {
        return resolveWithMappings(content: content, filePaths: [filePath])
    }

    /// Resolve placeholders in content using mappings across all files.
    public func resolveAll(content: String) -> ResolveResult {
        return resolveWithMappings(content: content, filePaths: Array(mappings.keys))
    }

    /// Clear all mappings.
    public func clear() {
        mappings.removeAll()
        reverseMappings.removeAll()
        typeCounters.removeAll()
    }

    /// Check if any mappings exist for a file.
    public func hasMappings(for filePath: String) -> Bool {
        mappings[filePath] != nil && !(mappings[filePath]?.isEmpty ?? true)
    }

    private func resolveWithMappings(content: String, filePaths: [String]) -> ResolveResult {
        // Build combined mapping from specified files
        var combined: [String: String] = [:]
        for path in filePaths {
            if let fileMap = mappings[path] {
                for (placeholder, original) in fileMap {
                    combined[placeholder] = original
                }
            }
        }

        var result = content
        var resolvedCount = 0
        var unresolvedPlaceholders: [String] = []

        // Find all MCP placeholder patterns: __PW{TYPE_N}__
        let nsContent = result as NSString
        let allMatches = Self.placeholderRegex.matches(in: result, range: NSRange(location: 0, length: nsContent.length))

        // Process in reverse order to preserve indices
        for match in allMatches.reversed() {
            let placeholder = nsContent.substring(with: match.range)
            if let original = combined[placeholder] {
                let startIndex = result.index(result.startIndex, offsetBy: match.range.location)
                let endIndex = result.index(startIndex, offsetBy: match.range.length)
                result.replaceSubrange(startIndex..<endIndex, with: original)
                resolvedCount += 1
            } else {
                unresolvedPlaceholders.append(placeholder)
            }
        }

        return ResolveResult(
            content: result,
            resolved: resolvedCount,
            unresolved: unresolvedPlaceholders.count,
            unresolvedPlaceholders: unresolvedPlaceholders.reversed()  // restore original order
        )
    }
}

/// A single redaction entry in the manifest.
public struct RedactionEntry {
    public let type: String
    public let severity: String
    public let line: Int
    public let placeholder: String
}

/// Result of resolving placeholders back to original values.
public struct ResolveResult {
    public let content: String
    public let resolved: Int
    public let unresolved: Int
    public let unresolvedPlaceholders: [String]
}
