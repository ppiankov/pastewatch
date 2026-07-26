import Foundation

// MARK: - Data structures

public struct InventoryEntry: Codable, Equatable {
    public let filePath: String
    public let type: String
    public let severity: String
    public let count: Int
    public let lines: [Int]

    public init(filePath: String, type: String, severity: String, count: Int, lines: [Int]) {
        self.filePath = filePath
        self.type = type
        self.severity = severity
        self.count = count
        self.lines = lines
    }
}

public struct SeverityBreakdown: Codable {
    public let critical: Int
    public let high: Int
    public let medium: Int
    public let low: Int

    public init(critical: Int, high: Int, medium: Int, low: Int) {
        self.critical = critical
        self.high = high
        self.medium = medium
        self.low = low
    }
}

public struct HotSpot: Codable {
    public let filePath: String
    public let findingCount: Int
    public let types: [String]

    public init(filePath: String, findingCount: Int, types: [String]) {
        self.filePath = filePath
        self.findingCount = findingCount
        self.types = types
    }
}

public struct TypeGroup: Codable {
    public let type: String
    public let severity: String
    public let count: Int
    public let files: [String]

    public init(type: String, severity: String, count: Int, files: [String]) {
        self.type = type
        self.severity = severity
        self.count = count
        self.files = files
    }
}

public struct InventoryDelta: Codable {
    public let added: [InventoryEntry]
    public let removed: [InventoryEntry]
    public let totalBefore: Int
    public let totalAfter: Int
    public let summary: String

    public init(added: [InventoryEntry], removed: [InventoryEntry],
                totalBefore: Int, totalAfter: Int, summary: String) {
        self.added = added
        self.removed = removed
        self.totalBefore = totalBefore
        self.totalAfter = totalAfter
        self.summary = summary
    }
}

public struct InventoryReport: Codable {
    public let version: String
    public let generatedAt: String
    public let directory: String
    public let totalFindings: Int
    public let filesAffected: Int
    public let severityBreakdown: SeverityBreakdown
    public let entries: [InventoryEntry]
    public let hotSpots: [HotSpot]
    /// WO-556: total hot-spot files before the top-10 cap. When > hotSpots.count, the list was truncated.
    public let hotSpotsTotal: Int
    public let typeGroups: [TypeGroup]

    public init(version: String, generatedAt: String, directory: String,
                totalFindings: Int, filesAffected: Int,
                severityBreakdown: SeverityBreakdown,
                entries: [InventoryEntry], hotSpots: [HotSpot],
                typeGroups: [TypeGroup], hotSpotsTotal: Int = 0) {
        self.version = version
        self.generatedAt = generatedAt
        self.directory = directory
        self.totalFindings = totalFindings
        self.filesAffected = filesAffected
        self.severityBreakdown = severityBreakdown
        self.entries = entries
        self.hotSpots = hotSpots
        self.hotSpotsTotal = hotSpotsTotal
        self.typeGroups = typeGroups
    }
}

private struct EntryAccumulator {
    let type: String
    let severity: String
    var lines: [Int]
}

// MARK: - Build

public extension InventoryReport {

    static func build(from results: [FileScanResult], directory: String) -> InventoryReport {
        let allMatches = results.flatMap { fr in
            fr.matches.map { (fr.filePath, $0) }
        }

        // Entries: group by (filePath, type)
        var entryMap: [String: EntryAccumulator] = [:]
        for (path, match) in allMatches {
            let key = "\(path)|\(match.displayName)"
            if var existing = entryMap[key] {
                existing.lines.append(match.line)
                entryMap[key] = existing
            } else {
                entryMap[key] = EntryAccumulator(
                    type: match.displayName,
                    severity: match.effectiveSeverity.rawValue,
                    lines: [match.line]
                )
            }
        }

        var entries: [InventoryEntry] = []
        for (key, value) in entryMap {
            let path = String(key.prefix(while: { $0 != "|" }))
            entries.append(InventoryEntry(
                filePath: path, type: value.type,
                severity: value.severity, count: value.lines.count,
                lines: value.lines.sorted()
            ))
        }
        entries.sort { $0.filePath < $1.filePath || ($0.filePath == $1.filePath && $0.type < $1.type) }

        // Severity breakdown
        var crit = 0, high = 0, med = 0, low = 0
        for (_, match) in allMatches {
            switch match.effectiveSeverity {
            case .critical: crit += 1
            case .high: high += 1
            case .medium: med += 1
            case .low: low += 1
            }
        }

        // Hot spots: files sorted by match count
        let byFile = Dictionary(grouping: allMatches, by: { $0.0 })
        var hotSpots = byFile.map { (path, matches) in
            HotSpot(
                filePath: path,
                findingCount: matches.count,
                types: Array(Set(matches.map { $0.1.displayName })).sorted()
            )
        }
        hotSpots.sort { $0.findingCount > $1.findingCount }
        let hotSpotsTotal = hotSpots.count
        if hotSpots.count > 10 { hotSpots = Array(hotSpots.prefix(10)) }

        // Type groups
        let byType = Dictionary(grouping: allMatches, by: { $0.1.displayName })
        var typeGroups = byType.map { (type, matches) in
            TypeGroup(
                type: type,
                severity: matches.first?.1.effectiveSeverity.rawValue ?? "low",
                count: matches.count,
                files: Array(Set(matches.map { $0.0 })).sorted()
            )
        }
        typeGroups.sort { $0.count > $1.count }

        let formatter = ISO8601DateFormatter()
        let timestamp = formatter.string(from: Date())

        return InventoryReport(
            version: "1",
            generatedAt: timestamp,
            directory: directory,
            totalFindings: allMatches.count,
            filesAffected: byFile.count,
            severityBreakdown: SeverityBreakdown(critical: crit, high: high, medium: med, low: low),
            entries: entries,
            hotSpots: hotSpots,
            typeGroups: typeGroups,
            hotSpotsTotal: hotSpotsTotal
        )
    }

    static func load(from path: String) throws -> InventoryReport {
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        return try JSONDecoder().decode(InventoryReport.self, from: data)
    }
}

// MARK: - Compare

public extension InventoryReport {

    static func compare(current: InventoryReport, previous: InventoryReport) -> InventoryDelta {
        let currentKeys = Set(current.entries.map { "\($0.filePath)|\($0.type)" })
        let previousKeys = Set(previous.entries.map { "\($0.filePath)|\($0.type)" })

        let addedKeys = currentKeys.subtracting(previousKeys)
        let removedKeys = previousKeys.subtracting(currentKeys)

        let added = current.entries.filter { addedKeys.contains("\($0.filePath)|\($0.type)") }
        let removed = previous.entries.filter { removedKeys.contains("\($0.filePath)|\($0.type)") }

        let delta = current.totalFindings - previous.totalFindings
        let sign = delta >= 0 ? "+" : ""
        let summary = "\(sign)\(addedKeys.count) added, -\(removedKeys.count) removed (\(current.totalFindings) total, was \(previous.totalFindings))"

        return InventoryDelta(
            added: added.sorted { $0.filePath < $1.filePath },
            removed: removed.sorted { $0.filePath < $1.filePath },
            totalBefore: previous.totalFindings,
            totalAfter: current.totalFindings,
            summary: summary
        )
    }
}

// MARK: - Formatters

public enum InventoryFormatter {

    public static func formatText(_ report: InventoryReport) -> String {
        var lines: [String] = []
        lines.append("Secret Inventory Report")
        lines.append("=======================")
        lines.append("Directory: \(report.directory)")
        lines.append("Generated: \(report.generatedAt)")
        lines.append("")
        lines.append("Total findings: \(report.totalFindings)")
        lines.append("Files affected: \(report.filesAffected)")
        lines.append("")
        lines.append("Severity breakdown:")
        lines.append("  critical:  \(report.severityBreakdown.critical)")
        lines.append("  high:      \(report.severityBreakdown.high)")
        lines.append("  medium:    \(report.severityBreakdown.medium)")
        lines.append("  low:       \(report.severityBreakdown.low)")

        if !report.hotSpots.isEmpty {
            lines.append("")
            lines.append("Hot spots:")
            for hs in report.hotSpots {
                let types = hs.types.joined(separator: ", ")
                lines.append("  \(hs.filePath)  \(hs.findingCount) findings (\(types))")
            }
        }

        if !report.typeGroups.isEmpty {
            lines.append("")
            lines.append("Findings by type:")
            for tg in report.typeGroups {
                lines.append("  \(tg.type) (\(tg.severity))  \(tg.count) in \(tg.files.count) file(s)")
            }
        }

        return lines.joined(separator: "\n") + "\n"
    }

    public static func formatJSON(_ report: InventoryReport) -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        guard let data = try? encoder.encode(report),
              let str = String(data: data, encoding: .utf8) else {
            return "{}"
        }
        return str
    }

    public static func formatMarkdown(_ report: InventoryReport) -> String {
        var lines: [String] = []
        lines.append("## Secret Inventory Report")
        lines.append("")
        lines.append("**Directory:** `\(report.directory)`")
        lines.append("**Generated:** \(report.generatedAt)")
        lines.append("**Total findings:** \(report.totalFindings) | **Files affected:** \(report.filesAffected)")
        lines.append("")
        lines.append("### Severity Breakdown")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        lines.append("| critical | \(report.severityBreakdown.critical) |")
        lines.append("| high | \(report.severityBreakdown.high) |")
        lines.append("| medium | \(report.severityBreakdown.medium) |")
        lines.append("| low | \(report.severityBreakdown.low) |")

        if !report.hotSpots.isEmpty {
            lines.append("")
            lines.append("### Hot Spots")
            lines.append("")
            lines.append("| File | Findings | Types |")
            lines.append("|------|----------|-------|")
            for hs in report.hotSpots {
                lines.append("| \(hs.filePath) | \(hs.findingCount) | \(hs.types.joined(separator: ", ")) |")
            }
        }

        if !report.typeGroups.isEmpty {
            lines.append("")
            lines.append("### Findings by Type")
            lines.append("")
            lines.append("| Type | Severity | Count | Files |")
            lines.append("|------|----------|-------|-------|")
            for tg in report.typeGroups {
                lines.append("| \(tg.type) | \(tg.severity) | \(tg.count) | \(tg.files.joined(separator: ", ")) |")
            }
        }

        if !report.entries.isEmpty {
            lines.append("")
            lines.append("### All Findings")
            lines.append("")
            lines.append("| File | Type | Severity | Count | Lines |")
            lines.append("|------|------|----------|-------|-------|")
            for entry in report.entries {
                let lineStr = entry.lines.map(String.init).joined(separator: ", ")
                lines.append("| \(entry.filePath) | \(entry.type) | \(entry.severity) | \(entry.count) | \(lineStr) |")
            }
        }

        return lines.joined(separator: "\n") + "\n"
    }

    public static func formatCSV(_ report: InventoryReport) -> String {
        var lines: [String] = []
        lines.append("file,type,severity,count,lines")
        for entry in report.entries {
            let lineStr = entry.lines.map(String.init).joined(separator: ";")
            lines.append("\(entry.filePath),\(entry.type),\(entry.severity),\(entry.count),\"\(lineStr)\"")
        }
        return lines.joined(separator: "\n") + "\n"
    }

    public static func formatDeltaText(_ delta: InventoryDelta) -> String {
        var lines: [String] = []
        lines.append("")
        lines.append("Changes")
        lines.append("-------")
        lines.append(delta.summary)

        if !delta.added.isEmpty {
            lines.append("")
            lines.append("New findings:")
            for entry in delta.added {
                lines.append("  + \(entry.filePath): \(entry.type) (\(entry.count))")
            }
        }

        if !delta.removed.isEmpty {
            lines.append("")
            lines.append("Resolved findings:")
            for entry in delta.removed {
                lines.append("  - \(entry.filePath): \(entry.type) (\(entry.count))")
            }
        }

        return lines.joined(separator: "\n") + "\n"
    }

    public static func formatDeltaMarkdown(_ delta: InventoryDelta) -> String {
        var lines: [String] = []
        lines.append("")
        lines.append("### Changes")
        lines.append("")
        lines.append(delta.summary)

        if !delta.added.isEmpty {
            lines.append("")
            lines.append("**New findings:**")
            lines.append("")
            lines.append("| File | Type | Count |")
            lines.append("|------|------|-------|")
            for entry in delta.added {
                lines.append("| \(entry.filePath) | \(entry.type) | \(entry.count) |")
            }
        }

        if !delta.removed.isEmpty {
            lines.append("")
            lines.append("**Resolved findings:**")
            lines.append("")
            lines.append("| File | Type | Count |")
            lines.append("|------|------|-------|")
            for entry in delta.removed {
                lines.append("| \(entry.filePath) | \(entry.type) | \(entry.count) |")
            }
        }

        return lines.joined(separator: "\n") + "\n"
    }
}
