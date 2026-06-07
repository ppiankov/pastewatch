import Foundation

/// In-memory store for placeholder↔original mappings used by MCP redacted read/write.
///
/// Design:
/// - Mapping lives only in server process memory — dies on exit, never persisted
/// - Same value always maps to same placeholder across all files in a session
/// - Deobfuscation happens locally on-device — secrets never leave the machine
/// - Default format: __PW_TYPE_N__ — never collides with real content
/// - Custom prefix format: {prefix}{NNN} — LLM-proxy compatible, no braces
public final class RedactionStore {
    // swiftlint:disable:next force_try
    private static let structuredRegex = try! NSRegularExpression(pattern: Obfuscator.mcpPlaceholderPattern)

    /// Optional custom prefix for LLM-proxy compatibility.
    private let customPrefix: String?

    /// Compiled regex for custom-prefix placeholders (nil when using structured format).
    private let customRegex: NSRegularExpression?

    /// Global sequential counter for custom-prefix placeholders.
    private var globalCounter: Int = 0

    /// Forward mapping: placeholder → original value, per file.
    private var mappings: [String: [String: String]] = [:]

    /// Global reverse mapping: original value → placeholder (cross-file consistency).
    private var globalReverse: [String: String] = [:]

    /// Global type counters for placeholder numbering (structured format only).
    private var globalTypeCounters: [SensitiveDataType: Int] = [:]

    public init(placeholderPrefix: String? = nil) {
        self.customPrefix = placeholderPrefix
        if let prefix = placeholderPrefix {
            // swiftlint:disable:next force_try
            self.customRegex = try! NSRegularExpression(pattern: Obfuscator.customPlaceholderPattern(prefix: prefix))
        } else {
            self.customRegex = nil
        }
    }

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

            let placeholder: String
            if let existing = globalReverse[original] {
                // Same value seen before in any file — reuse placeholder
                placeholder = existing
            } else if let prefix = customPrefix {
                globalCounter += 1
                placeholder = Obfuscator.makeCustomPlaceholder(prefix: prefix, number: globalCounter)
                globalReverse[original] = placeholder
            } else {
                let count = (globalTypeCounters[match.type] ?? 0) + 1
                globalTypeCounters[match.type] = count
                placeholder = Obfuscator.makeMCPPlaceholder(type: match.type, number: count)
                globalReverse[original] = placeholder
            }

            // Always store in per-file forward mapping for resolution
            var forward = mappings[filePath] ?? [:]
            forward[placeholder] = original
            mappings[filePath] = forward

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
        globalReverse.removeAll()
        globalTypeCounters.removeAll()
        globalCounter = 0
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

        let regex = customRegex ?? Self.structuredRegex
        let nsContent = result as NSString
        let allMatches = regex.matches(in: result, range: NSRange(location: 0, length: nsContent.length))

        // Process in reverse order to preserve indices.
        // WO-132: match.range is a UTF-16 NSRange; convert it with Range(_:in:)
        // rather than offsetting String.Index by Character count, which drifts
        // after astral-plane characters (emoji / surrogate pairs) and corrupts
        // the surrounding bytes on resolve.
        for match in allMatches.reversed() {
            let placeholder = nsContent.substring(with: match.range)
            if let original = combined[placeholder] {
                guard let swiftRange = Range(match.range, in: result) else {
                    unresolvedPlaceholders.append(placeholder)
                    continue
                }
                result.replaceSubrange(swiftRange, with: original)
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
