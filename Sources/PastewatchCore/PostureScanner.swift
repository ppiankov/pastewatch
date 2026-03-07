import Foundation

// MARK: - Data structures

public struct RepositorySummary: Codable {
    public let name: String
    public let totalFindings: Int
    public let filesAffected: Int
    public let severityBreakdown: SeverityBreakdown
    public let typeGroups: [TypeGroup]
    public let hotSpots: [HotSpot]

    public init(name: String, totalFindings: Int, filesAffected: Int,
                severityBreakdown: SeverityBreakdown,
                typeGroups: [TypeGroup], hotSpots: [HotSpot]) {
        self.name = name
        self.totalFindings = totalFindings
        self.filesAffected = filesAffected
        self.severityBreakdown = severityBreakdown
        self.typeGroups = typeGroups
        self.hotSpots = hotSpots
    }
}

public struct PostureReport: Codable {
    public let version: String
    public let generatedAt: String
    public let organization: String
    public let totalRepos: Int
    public let reposScanned: Int
    public let totalFindings: Int
    public let severityBreakdown: SeverityBreakdown
    public let repositories: [RepositorySummary]

    public init(version: String, generatedAt: String, organization: String,
                totalRepos: Int, reposScanned: Int, totalFindings: Int,
                severityBreakdown: SeverityBreakdown,
                repositories: [RepositorySummary]) {
        self.version = version
        self.generatedAt = generatedAt
        self.organization = organization
        self.totalRepos = totalRepos
        self.reposScanned = reposScanned
        self.totalFindings = totalFindings
        self.severityBreakdown = severityBreakdown
        self.repositories = repositories
    }
}

public struct PostureDelta: Codable {
    public let newFindings: [String]
    public let resolvedFindings: [String]
    public let totalBefore: Int
    public let totalAfter: Int
    public let summary: String

    public init(newFindings: [String], resolvedFindings: [String],
                totalBefore: Int, totalAfter: Int, summary: String) {
        self.newFindings = newFindings
        self.resolvedFindings = resolvedFindings
        self.totalBefore = totalBefore
        self.totalAfter = totalAfter
        self.summary = summary
    }
}

// MARK: - Scanner

public enum PostureScanner {

    public static func runCommand(_ executable: String, _ arguments: [String]) throws -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = [executable] + arguments
        let pipe = Pipe()
        let errPipe = Pipe()
        process.standardOutput = pipe
        process.standardError = errPipe
        try process.run()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
            let errMsg = String(data: errData, encoding: .utf8) ?? "unknown error"
            throw PostureError.commandFailed(executable, errMsg.trimmingCharacters(in: .whitespacesAndNewlines))
        }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        return String(data: data, encoding: .utf8) ?? ""
    }

    public static func enumerateRepos(org: String) throws -> [String] {
        let output = try runCommand("gh", ["repo", "list", org,
                                           "--no-archived", "--source",
                                           "--limit", "500",
                                           "--json", "name", "-q", ".[].name"])
        return output.split(separator: "\n")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
    }

    public static func cloneRepo(org: String, name: String, into baseDir: String) throws -> String {
        let dest = (baseDir as NSString).appendingPathComponent(name)
        _ = try runCommand("gh", ["repo", "clone", "\(org)/\(name)", dest, "--", "--depth", "1", "--quiet"])
        return dest
    }

    public static func scanRepo(at path: String, name: String, config: PastewatchConfig) throws -> RepositorySummary {
        let ignoreFile = IgnoreFile.load(from: path)
        let results = try DirectoryScanner.scan(
            directory: path, config: config,
            ignoreFile: ignoreFile, extraIgnorePatterns: []
        )
        let report = InventoryReport.build(from: results, directory: path)
        return RepositorySummary(
            name: name,
            totalFindings: report.totalFindings,
            filesAffected: report.filesAffected,
            severityBreakdown: report.severityBreakdown,
            typeGroups: report.typeGroups,
            hotSpots: report.hotSpots
        )
    }

    public static func aggregate(
        org: String, summaries: [RepositorySummary], totalRepos: Int
    ) -> PostureReport {
        var crit = 0, high = 0, med = 0, low = 0
        var totalFindings = 0
        for s in summaries {
            crit += s.severityBreakdown.critical
            high += s.severityBreakdown.high
            med += s.severityBreakdown.medium
            low += s.severityBreakdown.low
            totalFindings += s.totalFindings
        }

        let sorted = summaries.sorted { $0.totalFindings > $1.totalFindings }

        let formatter = ISO8601DateFormatter()
        let timestamp = formatter.string(from: Date())

        return PostureReport(
            version: "1",
            generatedAt: timestamp,
            organization: org,
            totalRepos: totalRepos,
            reposScanned: summaries.count,
            totalFindings: totalFindings,
            severityBreakdown: SeverityBreakdown(critical: crit, high: high, medium: med, low: low),
            repositories: sorted
        )
    }

    public static func compare(current: PostureReport, previous: PostureReport) -> PostureDelta {
        let currentRepos = Set(current.repositories.filter { $0.totalFindings > 0 }.map { $0.name })
        let previousRepos = Set(previous.repositories.filter { $0.totalFindings > 0 }.map { $0.name })

        let newFindings = Array(currentRepos.subtracting(previousRepos)).sorted()
        let resolved = Array(previousRepos.subtracting(currentRepos)).sorted()

        let delta = current.totalFindings - previous.totalFindings
        let sign = delta >= 0 ? "+" : ""
        let summary = "\(sign)\(delta) findings (\(current.totalFindings) total, was \(previous.totalFindings))"

        return PostureDelta(
            newFindings: newFindings,
            resolvedFindings: resolved,
            totalBefore: previous.totalFindings,
            totalAfter: current.totalFindings,
            summary: summary
        )
    }

    public static func load(from path: String) throws -> PostureReport {
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        return try JSONDecoder().decode(PostureReport.self, from: data)
    }
}

public enum PostureError: Error, CustomStringConvertible {
    case commandFailed(String, String)
    case noReposFound(String)

    public var description: String {
        switch self {
        case .commandFailed(let cmd, let msg): return "\(cmd) failed: \(msg)"
        case .noReposFound(let org): return "no repositories found for \(org)"
        }
    }
}

// MARK: - Formatters

public enum PostureFormatter {

    public static func formatText(_ report: PostureReport, findingsOnly: Bool = false) -> String {
        var lines: [String] = []
        lines.append("Posture Report: \(report.organization)")
        lines.append(String(repeating: "=", count: 40))
        lines.append("Generated: \(report.generatedAt)")
        lines.append("Repos scanned: \(report.reposScanned)/\(report.totalRepos)")
        lines.append("Total findings: \(report.totalFindings)")
        lines.append("")
        lines.append("Severity breakdown:")
        lines.append("  critical:  \(report.severityBreakdown.critical)")
        lines.append("  high:      \(report.severityBreakdown.high)")
        lines.append("  medium:    \(report.severityBreakdown.medium)")
        lines.append("  low:       \(report.severityBreakdown.low)")

        let withFindings = report.repositories.filter { $0.totalFindings > 0 }
        let clean = report.repositories.filter { $0.totalFindings == 0 }

        if !withFindings.isEmpty {
            lines.append("")
            lines.append("Repositories with findings:")
            for repo in withFindings {
                let sev = repo.severityBreakdown
                lines.append("  \(repo.name)  \(repo.totalFindings) findings (C:\(sev.critical) H:\(sev.high) M:\(sev.medium) L:\(sev.low))")
            }
        }

        if !findingsOnly && !clean.isEmpty {
            lines.append("")
            lines.append("Clean repositories: \(clean.count)")
            for repo in clean {
                lines.append("  \(repo.name)")
            }
        }

        return lines.joined(separator: "\n") + "\n"
    }

    public static func formatJSON(_ report: PostureReport) -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        guard let data = try? encoder.encode(report),
              let str = String(data: data, encoding: .utf8) else {
            return "{}"
        }
        return str
    }

    public static func formatMarkdown(_ report: PostureReport, findingsOnly: Bool = false) -> String {
        var lines: [String] = []
        lines.append("## Posture Report: \(report.organization)")
        lines.append("")
        lines.append("**Generated:** \(report.generatedAt)")
        lines.append("**Repos scanned:** \(report.reposScanned)/\(report.totalRepos)")
        lines.append("**Total findings:** \(report.totalFindings)")
        lines.append("")
        lines.append("### Severity Breakdown")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        lines.append("| critical | \(report.severityBreakdown.critical) |")
        lines.append("| high | \(report.severityBreakdown.high) |")
        lines.append("| medium | \(report.severityBreakdown.medium) |")
        lines.append("| low | \(report.severityBreakdown.low) |")

        let withFindings = report.repositories.filter { $0.totalFindings > 0 }
        let clean = report.repositories.filter { $0.totalFindings == 0 }

        if !withFindings.isEmpty {
            lines.append("")
            lines.append("### Repositories with Findings")
            lines.append("")
            lines.append("| Repository | Findings | Critical | High | Medium | Low |")
            lines.append("|------------|----------|----------|------|--------|-----|")
            for repo in withFindings {
                let sev = repo.severityBreakdown
                lines.append("| \(repo.name) | \(repo.totalFindings) | \(sev.critical) | \(sev.high) | \(sev.medium) | \(sev.low) |")
            }
        }

        if !findingsOnly && !clean.isEmpty {
            lines.append("")
            lines.append("### Clean Repositories (\(clean.count))")
            lines.append("")
            for repo in clean {
                lines.append("- \(repo.name)")
            }
        }

        return lines.joined(separator: "\n") + "\n"
    }

    public static func formatDeltaText(_ delta: PostureDelta) -> String {
        var lines: [String] = []
        lines.append("")
        lines.append("Changes")
        lines.append("-------")
        lines.append(delta.summary)

        if !delta.newFindings.isEmpty {
            lines.append("")
            lines.append("New repos with findings:")
            for name in delta.newFindings {
                lines.append("  + \(name)")
            }
        }

        if !delta.resolvedFindings.isEmpty {
            lines.append("")
            lines.append("Repos now clean:")
            for name in delta.resolvedFindings {
                lines.append("  - \(name)")
            }
        }

        return lines.joined(separator: "\n") + "\n"
    }

    public static func formatDeltaMarkdown(_ delta: PostureDelta) -> String {
        var lines: [String] = []
        lines.append("")
        lines.append("### Changes")
        lines.append("")
        lines.append(delta.summary)

        if !delta.newFindings.isEmpty {
            lines.append("")
            lines.append("**New repos with findings:**")
            for name in delta.newFindings {
                lines.append("- \(name)")
            }
        }

        if !delta.resolvedFindings.isEmpty {
            lines.append("")
            lines.append("**Repos now clean:**")
            for name in delta.resolvedFindings {
                lines.append("- \(name)")
            }
        }

        return lines.joined(separator: "\n") + "\n"
    }
}
