import Foundation

// MARK: - Dashboard Types

/// Aggregate dashboard across multiple audit log sessions.
public struct Dashboard: Codable {
    public let generatedAt: String
    public let sessions: Int
    public let period: DashboardPeriod
    public let summary: SessionSummary
    public let topTypes: [TypeCount]
    public let hotFiles: [FileAccess]
    /// WO-556@v2: total hot files before the top-10 cap. When > hotFiles.count, the list was truncated.
    public let hotFilesTotal: Int
    public let verdict: String

    public init(generatedAt: String, sessions: Int, period: DashboardPeriod,
                summary: SessionSummary, topTypes: [TypeCount], hotFiles: [FileAccess],
                hotFilesTotal: Int? = nil, verdict: String) {
        self.generatedAt = generatedAt
        self.sessions = sessions
        self.period = period
        self.summary = summary
        self.topTypes = topTypes
        self.hotFiles = hotFiles
        self.hotFilesTotal = hotFilesTotal ?? hotFiles.count
        self.verdict = verdict
    }

    // WO-556@v2: historical dashboard JSON derives a truthful lower bound instead of zero.
    private enum CodingKeys: String, CodingKey {
        case generatedAt, sessions, period, summary, topTypes, hotFiles, hotFilesTotal, verdict
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        generatedAt = try c.decode(String.self, forKey: .generatedAt)
        sessions = try c.decode(Int.self, forKey: .sessions)
        period = try c.decode(DashboardPeriod.self, forKey: .period)
        summary = try c.decode(SessionSummary.self, forKey: .summary)
        topTypes = try c.decode([TypeCount].self, forKey: .topTypes)
        hotFiles = try c.decode([FileAccess].self, forKey: .hotFiles)
        hotFilesTotal = try c.decodeIfPresent(Int.self, forKey: .hotFilesTotal)
            ?? hotFiles.count
        verdict = try c.decode(String.self, forKey: .verdict)
    }
}

/// Time range covered by the dashboard.
public struct DashboardPeriod: Codable {
    public let earliest: String?
    public let latest: String?
}

// MARK: - Builder

/// Aggregates multiple audit logs into a single dashboard.
public enum DashboardBuilder {

    /// Build dashboard from all audit log files in a directory.
    public static func build(logDirectory: String, since: Date? = nil) -> Dashboard {
        let fm = FileManager.default
        let df = ISO8601DateFormatter()
        df.formatOptions = [.withInternetDateTime]
        let now = df.string(from: Date())

        // Find all audit log files
        let logFiles = findAuditLogs(in: logDirectory, fm: fm)

        guard !logFiles.isEmpty else {
            return Dashboard(
                generatedAt: now, sessions: 0,
                period: DashboardPeriod(earliest: nil, latest: nil),
                summary: emptySummary(),
                topTypes: [], hotFiles: [], verdict: "No audit logs found"
            )
        }

        // Build individual reports
        var reports: [SessionReport] = []
        for path in logFiles {
            guard let content = try? String(contentsOfFile: path, encoding: .utf8),
                  !content.isEmpty else { continue }
            let report = SessionReportBuilder.build(content: content, logPath: path, since: since)
            reports.append(report)
        }

        guard !reports.isEmpty else {
            // WO-556@v2: empty dashboards still carry an explicit complete hot-file total.
            return Dashboard(
                generatedAt: now, sessions: 0,
                period: DashboardPeriod(earliest: nil, latest: nil),
                summary: emptySummary(),
                topTypes: [], hotFiles: [], hotFilesTotal: 0,
                verdict: "No audit log entries found"
            )
        }

        // Aggregate summaries
        let summary = aggregateSummaries(reports)
        let topTypes = aggregateTypes(reports)
        // WO-556@v2: retain the complete count before limiting rendered hot files.
        let allHotFiles = aggregateFiles(reports)
        let hotFilesTotal = allHotFiles.count
        let hotFiles = Array(allHotFiles.prefix(10))
        let period = aggregatePeriod(reports)
        let verdict = computeVerdict(summary)

        return Dashboard(
            generatedAt: now,
            sessions: reports.count,
            period: period,
            summary: summary,
            topTypes: topTypes,
            hotFiles: hotFiles,
            // WO-556@v2: expose truncation without changing the existing limited list.
            hotFilesTotal: hotFilesTotal,
            verdict: verdict
        )
    }

    // MARK: - Private

    private static func findAuditLogs(in directory: String, fm: FileManager) -> [String] {
        guard let entries = try? fm.contentsOfDirectory(atPath: directory) else { return [] }
        return entries
            .filter { $0.hasPrefix("pastewatch-audit") && $0.hasSuffix(".log") }
            .map { (directory as NSString).appendingPathComponent($0) }
            .sorted()
    }

    private static func emptySummary() -> SessionSummary {
        SessionSummary(
            filesRead: 0, filesWritten: 0, secretsRedacted: 0,
            placeholdersResolved: 0, unresolvedPlaceholders: 0,
            outputChecks: 0, outputChecksDirty: 0, scans: 0, scanFindings: 0
        )
    }

    private static func aggregateSummaries(_ reports: [SessionReport]) -> SessionSummary {
        var fr = 0, fw = 0, sr = 0, pr = 0, up = 0, oc = 0, ocd = 0, sc = 0, sf = 0
        for r in reports {
            fr += r.summary.filesRead
            fw += r.summary.filesWritten
            sr += r.summary.secretsRedacted
            pr += r.summary.placeholdersResolved
            up += r.summary.unresolvedPlaceholders
            oc += r.summary.outputChecks
            ocd += r.summary.outputChecksDirty
            sc += r.summary.scans
            sf += r.summary.scanFindings
        }
        return SessionSummary(
            filesRead: fr, filesWritten: fw, secretsRedacted: sr,
            placeholdersResolved: pr, unresolvedPlaceholders: up,
            outputChecks: oc, outputChecksDirty: ocd, scans: sc, scanFindings: sf
        )
    }

    private static func aggregateTypes(_ reports: [SessionReport]) -> [TypeCount] {
        var counts: [String: (count: Int, severity: String)] = [:]
        for r in reports {
            for tc in r.secretsByType {
                let existing = counts[tc.type] ?? (count: 0, severity: tc.severity)
                counts[tc.type] = (count: existing.count + tc.count, severity: existing.severity)
            }
        }
        return counts
            .map { TypeCount(type: $0.key, count: $0.value.count, severity: $0.value.severity) }
            .sorted { $0.count > $1.count }
    }

    private struct FileStats {
        var reads: Int = 0
        var writes: Int = 0
        var secrets: Int = 0
    }

    private static func aggregateFiles(_ reports: [SessionReport]) -> [FileAccess] {
        var files: [String: FileStats] = [:]
        for r in reports {
            for fa in r.filesAccessed {
                var existing = files[fa.file] ?? FileStats()
                existing.reads += fa.reads
                existing.writes += fa.writes
                existing.secrets += fa.secretsRedacted
                files[fa.file] = existing
            }
        }
        return files
            .map { FileAccess(file: $0.key, reads: $0.value.reads, writes: $0.value.writes, secretsRedacted: $0.value.secrets) }
            .sorted { $0.secretsRedacted > $1.secretsRedacted }
    }

    private static func aggregatePeriod(_ reports: [SessionReport]) -> DashboardPeriod {
        let starts = reports.compactMap { $0.periodStart }
        let ends = reports.compactMap { $0.periodEnd }
        return DashboardPeriod(
            earliest: starts.min(),
            latest: ends.max()
        )
    }

    private static func computeVerdict(_ summary: SessionSummary) -> String {
        if summary.unresolvedPlaceholders > 0 || summary.outputChecksDirty > 0 {
            return "WARNING: \(summary.unresolvedPlaceholders) unresolved placeholder(s), \(summary.outputChecksDirty) dirty check(s)"
        }
        if summary.secretsRedacted == 0 && summary.filesRead == 0 {
            return "No MCP activity recorded"
        }
        return "Zero secrets leaked — \(summary.secretsRedacted) redacted across \(summary.filesRead) file read(s)"
    }
}
