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
        var writeFiles: [String: (writes: Int, resolved: Int, unresolved: Int)] = [:]
        var typeCounts: [String: Int] = [:]
        var totalRedacted = 0
        var totalResolved = 0
        var totalUnresolved = 0
        var outputChecks = 0
        var outputChecksDirty = 0
        var scans = 0
        var scanFindings = 0

        for line in lines {
            // Extract timestamp (ISO8601 = 20 chars min, up to first space after)
            guard let spaceIdx = line.firstIndex(of: " "),
                  spaceIdx > line.startIndex else { continue }

            let tsStr = String(line[line.startIndex..<spaceIdx])
            let rest = String(line[line.index(after: spaceIdx)...])
                .trimmingCharacters(in: .whitespaces)

            // Filter by --since
            if let since = since, let ts = df.date(from: tsStr), ts < since {
                continue
            }

            timestamps.append(tsStr)

            if rest.hasPrefix("READ") {
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

        return SessionReport(
            generatedAt: now,
            auditLogPath: logPath,
            periodStart: timestamps.first,
            periodEnd: timestamps.last,
            summary: summary,
            secretsByType: secretsByType,
            filesAccessed: filesAccessed,
            verdict: verdict
        )
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
        writeFiles: inout [String: (writes: Int, resolved: Int, unresolved: Int)],
        totalResolved: inout Int,
        totalUnresolved: inout Int
    ) {
        // Format: "WRITE <path>  resolved=N unresolved=M"
        let parts = line.replacingOccurrences(of: "WRITE", with: "")
            .trimmingCharacters(in: .whitespaces)

        let path = extractPath(from: parts)
        guard !path.isEmpty else { return }

        var existing = writeFiles[path] ?? (writes: 0, resolved: 0, unresolved: 0)
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

        lines.append("## Verdict")
        lines.append("")
        lines.append(report.verdict)
        lines.append("")
        return lines.joined(separator: "\n")
    }
}
