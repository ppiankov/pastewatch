import Foundation

// MARK: - Report Types

/// Aggregated report from an MCP audit log session.
public struct SessionReport: Codable {
    public let generatedAt: String
    public let auditLogPath: String
    public let periodStart: String?
    public let periodEnd: String?
    public let summary: SessionSummary
    public let secretsByType: [TypeCount]
    public let filesAccessed: [FileAccess]
    public let verdict: String
    // WO-531: Obfuscation coverage stats
    public let obfuscationCoverage: ObfuscationCoverage?
}

/// WO-531: Obfuscation coverage derived from structured proxy receipts.
public struct ObfuscationCoverage: Codable {
    public let tier1Intrinsic: [ObfuscationCoverageCount]
    public let tier2OptIn: [ObfuscationCoverageCount]
    public let advisory: [ObfuscationCoverageCount]
    public let seenButNotConfigured: [DomainSuggestion]
}

/// WO-540: Renderable aggregate retaining the receipt's authorization and surface evidence.
public struct ObfuscationCoverageCount: Codable {
    public let tier: ObfuscationCoverageTier
    public let type: String
    public let ruleIdentifier: String?
    public let source: ObfuscationCoverageSource
    public let count: Int
}

/// WO-531: Suggestion for obfuscate config entry (grouped by domain, redacted specifics).
public struct DomainSuggestion: Codable {
    public let type: String  // "email" or "host"
    public let domain: String  // Redacted domain (e.g., "@corp.com" or ".internal")
    public let count: Int
    public let suggestedEntry: String  // Suggested obfuscate config entry
}

/// Summary counters for a session.
public struct SessionSummary: Codable {
    public let filesRead: Int
    public let filesWritten: Int
    public let secretsRedacted: Int
    public let placeholdersResolved: Int
    public let unresolvedPlaceholders: Int
    public let outputChecks: Int
    public let outputChecksDirty: Int
    public let scans: Int
    public let scanFindings: Int
}

/// Count of a detection type found during the session.
public struct TypeCount: Codable {
    public let type: String
    public let count: Int
    public let severity: String
}

/// Per-file access summary.
public struct FileAccess: Codable {
    public let file: String
    public let reads: Int
    public let writes: Int
    public let secretsRedacted: Int
}

// MARK: - Internal Aggregation Types

struct WriteFileStats {
    var writes: Int = 0
    var resolved: Int = 0
    var unresolved: Int = 0
}

// MARK: - Builder

/// Parses MCP audit log content and builds a SessionReport.
public enum SessionReportBuilder {

    /// Build a session report from audit log content.
    public static func build(
        content: String,
        logPath: String,
        since: Date? = nil
    ) -> SessionReport {
        let df = ISO8601DateFormatter()
        df.formatOptions = [.withInternetDateTime]
        let now = df.string(from: Date())

        let lines = content.components(separatedBy: "\n").filter { !$0.isEmpty }

        // Parse lines into entries
        var timestamps: [String] = []
        var readFiles: [String: (reads: Int, secrets: Int)] = [:]
        var writeFiles: [String: WriteFileStats] = [:]
        var typeCounts: [String: Int] = [:]
        var totalRedacted = 0
        var totalResolved = 0
        var totalUnresolved = 0
        var outputChecks = 0
        var outputChecksDirty = 0
        var scans = 0
        var scanFindings = 0
        var coverageEvents: [ObfuscationCoverageEvent] = [] // WO-540: parse receipts independently of legacy logs.

        for line in lines {
            // Extract timestamp (ISO8601 = 20 chars min, up to first space after)
            guard let spaceIdx = line.firstIndex(of: " "),
                  spaceIdx > line.startIndex else { continue }

            // WO-540: proxy audit lines bracket timestamps while MCP lines do not.
            let tsStr = String(line[line.startIndex..<spaceIdx])
                .trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
            let rest = String(line[line.index(after: spaceIdx)...])
                .trimmingCharacters(in: .whitespaces)

            // Filter by --since
            if let since = since, let ts = df.date(from: tsStr), ts < since {
                continue
            }

            timestamps.append(tsStr)

            if rest.hasPrefix("PROXY COVERAGE ") {
                parseCoverageLine(rest, events: &coverageEvents)
            } else if rest.hasPrefix("READ") {
                parseReadLine(rest, readFiles: &readFiles, typeCounts: &typeCounts,
                              totalRedacted: &totalRedacted)
            } else if rest.hasPrefix("WRITE") {
                parseWriteLine(rest, writeFiles: &writeFiles,
                               totalResolved: &totalResolved,
                               totalUnresolved: &totalUnresolved)
            } else if rest.hasPrefix("CHECK") {
                outputChecks += 1
                if rest.contains("clean=false") {
                    outputChecksDirty += 1
                }
            } else if rest.hasPrefix("SCAN") {
                scans += 1
                if let n = extractInt(from: rest, key: "findings") {
                    scanFindings += n
                }
            }
        }

        // Build per-file access list
        var allFiles = Set<String>()
        for key in readFiles.keys { allFiles.insert(key) }
        for key in writeFiles.keys { allFiles.insert(key) }

        let filesAccessed = allFiles.sorted().map { file -> FileAccess in
            let r = readFiles[file]
            let w = writeFiles[file]
            return FileAccess(
                file: file,
                reads: r?.reads ?? 0,
                writes: w?.writes ?? 0,
                secretsRedacted: r?.secrets ?? 0
            )
        }

        // Build type counts with severity
        let secretsByType = typeCounts.keys.sorted().map { type -> TypeCount in
            let sev = SensitiveDataType(rawValue: type)?.severity.rawValue ?? "unknown"
            return TypeCount(type: type, count: typeCounts[type] ?? 0, severity: sev)
        }

        // Verdict
        let verdict: String
        if totalUnresolved > 0 {
            verdict = "WARNING: \(totalUnresolved) unresolved placeholder(s) — secrets may have leaked."
        } else if outputChecksDirty > 0 {
            verdict = "WARNING: \(outputChecksDirty) output check(s) found secrets in agent output."
        } else {
            verdict = "Zero secrets leaked to cloud API during this session."
        }

        let summary = SessionSummary(
            filesRead: readFiles.count,
            filesWritten: writeFiles.count,
            secretsRedacted: totalRedacted,
            placeholdersResolved: totalResolved,
            unresolvedPlaceholders: totalUnresolved,
            outputChecks: outputChecks,
            outputChecksDirty: outputChecksDirty,
            scans: scans,
            scanFindings: scanFindings
        )

        let obfuscationCoverage = computeObfuscationCoverage(events: coverageEvents)

        return SessionReport(
            generatedAt: now,
            auditLogPath: logPath,
            periodStart: timestamps.first,
            periodEnd: timestamps.last,
            summary: summary,
            secretsByType: secretsByType,
            filesAccessed: filesAccessed,
            verdict: verdict,
            obfuscationCoverage: obfuscationCoverage
        )
    }

    // MARK: - WO-531: Obfuscation Coverage

    /// WO-540: Internal aggregate keys prevent unrelated sources or rules from being conflated.
    private struct CoverageKey: Hashable {
        let tier: ObfuscationCoverageTier
        let type: String
        let ruleIdentifier: String?
        let source: ObfuscationCoverageSource
    }

    /// WO-531: Internal struct for tracking privacy-safe domain counts.
    private struct DomainCount {
        let type: String
        let domain: String
        var count: Int
    }

    /// WO-540: Aggregate only structured coverage receipts; legacy type logs lack authorization evidence.
    private static func computeObfuscationCoverage(
        events: [ObfuscationCoverageEvent]
    ) -> ObfuscationCoverage? {
        guard !events.isEmpty else { return nil }

        var coverageCounts: [CoverageKey: Int] = [:]
        var domainCounts: [String: DomainCount] = [:]

        for event in events {
            if event.tier == .observed, let domain = event.domainBucket {
                let suggestionType = event.type == SensitiveDataType.email.rawValue ? "email" : "host"
                let key = "\(suggestionType)|\(domain)"
                var existing = domainCounts[key] ?? DomainCount(
                    type: suggestionType,
                    domain: domain,
                    count: 0
                )
                existing.count += event.count
                domainCounts[key] = existing
                continue
            }

            let key = CoverageKey(
                tier: event.tier,
                type: event.type,
                ruleIdentifier: event.ruleIdentifier,
                source: event.source
            )
            coverageCounts[key, default: 0] += event.count
        }

        let counts = coverageCounts.map { key, count in
            ObfuscationCoverageCount(
                tier: key.tier,
                type: key.type,
                ruleIdentifier: key.ruleIdentifier,
                source: key.source,
                count: count
            )
        }
        let suggestions = domainCounts.values.map { entry in
            DomainSuggestion(
                type: entry.type,
                domain: entry.domain,
                count: entry.count,
                suggestedEntry: entry.type == "email"
                    ? "{\"type\":\"email\",\"pattern\":\"\(entry.domain)\"}"
                    : "{\"type\":\"host\",\"pattern\":\"\(entry.domain)\"}"
            )
        }

        return ObfuscationCoverage(
            tier1Intrinsic: sortedCoverageCounts(counts.filter { $0.tier == .intrinsic }),
            tier2OptIn: sortedCoverageCounts(counts.filter { $0.tier == .configured }),
            advisory: sortedCoverageCounts(counts.filter { $0.tier == .advisory }),
            seenButNotConfigured: suggestions.sorted {
                ($0.count, $0.type, $0.domain) > ($1.count, $1.type, $1.domain)
            }
        )
    }

    private static func sortedCoverageCounts(
        _ counts: [ObfuscationCoverageCount]
    ) -> [ObfuscationCoverageCount] {
        counts.sorted {
            ($0.count, $0.type, $0.source.rawValue, $0.ruleIdentifier ?? "") >
                ($1.count, $1.type, $1.source.rawValue, $1.ruleIdentifier ?? "")
        }
    }

    /// WO-540: Malformed receipts are ignored without contaminating legacy report counters.
    private static func parseCoverageLine(
        _ line: String,
        events: inout [ObfuscationCoverageEvent]
    ) {
        let prefix = "PROXY COVERAGE "
        guard line.hasPrefix(prefix),
              let data = String(line.dropFirst(prefix.count)).data(using: .utf8),
              let event = try? JSONDecoder().decode(ObfuscationCoverageEvent.self, from: data) else {
            return
        }
        events.append(event)
    }

    // MARK: - Line Parsers

    private static func parseReadLine(
        _ line: String,
        readFiles: inout [String: (reads: Int, secrets: Int)],
        typeCounts: inout [String: Int],
        totalRedacted: inout Int
    ) {
        // Format: "READ  <path>  redacted=N [Type1, Type2]" or "READ  <path>  clean"
        let parts = line.replacingOccurrences(of: "READ", with: "")
            .trimmingCharacters(in: .whitespaces)

        // Extract path (up to first double-space or "redacted=" or "clean")
        let path = extractPath(from: parts)
        guard !path.isEmpty else { return }

        var existing = readFiles[path] ?? (reads: 0, secrets: 0)
        existing.reads += 1

        if let n = extractInt(from: parts, key: "redacted") {
            existing.secrets += n
            totalRedacted += n

            // Extract types from [Type1, Type2]
            if let bracketStart = parts.firstIndex(of: "["),
               let bracketEnd = parts.firstIndex(of: "]") {
                let typeStr = parts[parts.index(after: bracketStart)..<bracketEnd]
                let types = typeStr.components(separatedBy: ", ")
                for type in types where !type.isEmpty {
                    typeCounts[type, default: 0] += 1
                }
            }
        }

        readFiles[path] = existing
    }

    private static func parseWriteLine(
        _ line: String,
        writeFiles: inout [String: WriteFileStats],
        totalResolved: inout Int,
        totalUnresolved: inout Int
    ) {
        // Format: "WRITE <path>  resolved=N unresolved=M"
        let parts = line.replacingOccurrences(of: "WRITE", with: "")
            .trimmingCharacters(in: .whitespaces)

        let path = extractPath(from: parts)
        guard !path.isEmpty else { return }

        var existing = writeFiles[path] ?? WriteFileStats()
        existing.writes += 1

        if let n = extractInt(from: parts, key: "resolved") {
            existing.resolved += n
            totalResolved += n
        }
        if let n = extractInt(from: parts, key: "unresolved") {
            existing.unresolved += n
            totalUnresolved += n
        }

        writeFiles[path] = existing
    }

    // MARK: - Helpers

    /// Extract path from log detail (everything before key=value pairs).
    private static func extractPath(from detail: String) -> String {
        // Path ends at first key=value pattern or bracket
        let tokens = detail.components(separatedBy: "  ").filter { !$0.isEmpty }
        guard let first = tokens.first else { return "" }
        // Skip inline markers
        if first == "(inline)" { return "(inline)" }
        return first
    }

    /// Extract integer value for a key=N pattern.
    static func extractInt(from text: String, key: String) -> Int? {
        let pattern = key + "="
        guard let range = text.range(of: pattern) else { return nil }
        let after = text[range.upperBound...]
        let numStr = after.prefix(while: { $0.isNumber })
        return Int(numStr)
    }

    // MARK: - Formatters

    /// Format report as human-readable text.
    public static func formatText(_ report: SessionReport) -> String {
        var lines: [String] = []
        lines.append("Agent Session Report")
        lines.append("Generated: \(report.generatedAt)")
        lines.append("Audit log: \(report.auditLogPath)")
        if let start = report.periodStart, let end = report.periodEnd {
            lines.append("Period: \(start) — \(end)")
        }
        lines.append("")

        let s = report.summary
        lines.append("Summary")
        lines.append("  Files read via MCP:      \(s.filesRead)")
        lines.append("  Files written via MCP:   \(s.filesWritten)")
        lines.append("  Secrets redacted (read): \(s.secretsRedacted)")
        lines.append("  Placeholders resolved:   \(s.placeholdersResolved)")
        lines.append("  Unresolved placeholders: \(s.unresolvedPlaceholders)")
        lines.append("  Output checks:           \(s.outputChecks)")
        lines.append("  Output checks (dirty):   \(s.outputChecksDirty)")
        lines.append("  Scans:                   \(s.scans)")
        lines.append("  Scan findings:           \(s.scanFindings)")
        lines.append("")

        if !report.secretsByType.isEmpty {
            lines.append("Secrets by type")
            for tc in report.secretsByType {
                let padType = tc.type.padding(toLength: 22, withPad: " ", startingAt: 0)
                lines.append("  \(padType) \(tc.count)  (\(tc.severity))")
            }
            lines.append("")
        }

        if !report.filesAccessed.isEmpty {
            lines.append("Files accessed")
            for fa in report.filesAccessed {
                lines.append("  \(fa.file)  reads=\(fa.reads) writes=\(fa.writes) redacted=\(fa.secretsRedacted)")
            }
            lines.append("")
        }

        // WO-531: Obfuscation coverage stats
        if let coverage = report.obfuscationCoverage {
            lines.append("Obfuscation Coverage")
            if !coverage.tier1Intrinsic.isEmpty {
                lines.append("  Tier-1 (intrinsic, always-on):")
                for tc in coverage.tier1Intrinsic {
                    let padType = tc.type.padding(toLength: 20, withPad: " ", startingAt: 0)
                    lines.append("    \(padType) \(tc.count)  source=\(tc.source.rawValue)")
                }
            }
            if !coverage.tier2OptIn.isEmpty {
                lines.append("  Tier-2 (opt-in obfuscate):")
                for tc in coverage.tier2OptIn {
                    let padType = tc.type.padding(toLength: 20, withPad: " ", startingAt: 0)
                    let rule = tc.ruleIdentifier ?? "unknown"
                    lines.append("    \(padType) \(tc.count)  source=\(tc.source.rawValue) rule=\(rule)")
                }
            }
            if !coverage.advisory.isEmpty {
                lines.append("  Advisory (reported, unchanged):")
                for item in coverage.advisory {
                    let padType = item.type.padding(toLength: 20, withPad: " ", startingAt: 0)
                    lines.append("    \(padType) \(item.count)  source=\(item.source.rawValue)")
                }
            }
            if !coverage.seenButNotConfigured.isEmpty {
                lines.append("  Seen but not configured (suggestions):")
                for suggestion in coverage.seenButNotConfigured {
                    lines.append("    \(suggestion.type): \(suggestion.count) seen — add \(suggestion.suggestedEntry)")
                }
            }
            lines.append("")
        }

        lines.append("Verdict: \(report.verdict)")
        lines.append("")
        return lines.joined(separator: "\n")
    }

    /// Format report as JSON.
    public static func formatJSON(_ report: SessionReport) -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        guard let data = try? encoder.encode(report),
              let str = String(data: data, encoding: .utf8) else {
            return "{}"
        }
        return str + "\n"
    }

    /// Format report as markdown.
    public static func formatMarkdown(_ report: SessionReport) -> String {
        var lines: [String] = []
        lines.append("# Agent Session Report")
        lines.append("")
        lines.append("Generated: \(report.generatedAt)")
        lines.append("Audit log: `\(report.auditLogPath)`")
        if let start = report.periodStart, let end = report.periodEnd {
            lines.append("Period: \(start) — \(end)")
        }
        lines.append("")

        let s = report.summary
        lines.append("## Summary")
        lines.append("")
        lines.append("| Metric | Count |")
        lines.append("|--------|-------|")
        lines.append("| Files read via MCP | \(s.filesRead) |")
        lines.append("| Files written via MCP | \(s.filesWritten) |")
        lines.append("| Secrets redacted (read) | \(s.secretsRedacted) |")
        lines.append("| Placeholders resolved (write) | \(s.placeholdersResolved) |")
        lines.append("| Unresolved placeholders | \(s.unresolvedPlaceholders) |")
        lines.append("| Output checks | \(s.outputChecks) |")
        lines.append("| Output checks (dirty) | \(s.outputChecksDirty) |")
        lines.append("| Scans | \(s.scans) |")
        lines.append("| Scan findings | \(s.scanFindings) |")
        lines.append("")

        if !report.secretsByType.isEmpty {
            lines.append("## Secrets by Type")
            lines.append("")
            lines.append("| Type | Count | Severity |")
            lines.append("|------|-------|----------|")
            for tc in report.secretsByType {
                lines.append("| \(tc.type) | \(tc.count) | \(tc.severity) |")
            }
            lines.append("")
        }

        if !report.filesAccessed.isEmpty {
            lines.append("## Files Accessed")
            lines.append("")
            lines.append("| File | Reads | Writes | Secrets Redacted |")
            lines.append("|------|-------|--------|-----------------|")
            for fa in report.filesAccessed {
                lines.append("| \(fa.file) | \(fa.reads) | \(fa.writes) | \(fa.secretsRedacted) |")
            }
            lines.append("")
        }

        if let coverage = report.obfuscationCoverage {
            lines.append("## Obfuscation Coverage")
            lines.append("")
            lines.append("| Tier | Type | Source | Rule | Count |")
            lines.append("|------|------|--------|------|-------|")
            for item in coverage.tier1Intrinsic + coverage.tier2OptIn + coverage.advisory {
                lines.append(
                    "| \(item.tier.rawValue) | \(item.type) | \(item.source.rawValue) | " +
                        "\(item.ruleIdentifier ?? "-") | \(item.count) |"
                )
            }
            for suggestion in coverage.seenButNotConfigured {
                lines.append(
                    "| observed | \(suggestion.type) | suggestion | " +
                        "`\(suggestion.suggestedEntry)` | \(suggestion.count) |"
                )
            }
            lines.append("")
        }

        lines.append("## Verdict")
        lines.append("")
        lines.append(report.verdict)
        lines.append("")
        return lines.joined(separator: "\n")
    }
}
