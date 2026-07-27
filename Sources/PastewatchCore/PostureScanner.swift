import Foundation

// MARK: - Data structures

public struct RepositorySummary: Codable {
    public let name: String
    public let totalFindings: Int
    public let filesAffected: Int
    public let severityBreakdown: SeverityBreakdown
    public let typeGroups: [TypeGroup]
    public let hotSpots: [HotSpot]
    /// WO-556@v2: preserve the pre-truncation inventory count in posture output.
    public let hotSpotsTotal: Int

    public init(name: String, totalFindings: Int, filesAffected: Int,
                severityBreakdown: SeverityBreakdown,
                typeGroups: [TypeGroup], hotSpots: [HotSpot],
                hotSpotsTotal: Int? = nil) {
        self.name = name
        self.totalFindings = totalFindings
        self.filesAffected = filesAffected
        self.severityBreakdown = severityBreakdown
        self.typeGroups = typeGroups
        self.hotSpots = hotSpots
        self.hotSpotsTotal = hotSpotsTotal ?? max(hotSpots.count, filesAffected)
    }

    private enum CodingKeys: String, CodingKey {
        case name, totalFindings, filesAffected, severityBreakdown
        case typeGroups, hotSpots, hotSpotsTotal
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        name = try c.decode(String.self, forKey: .name)
        totalFindings = try c.decode(Int.self, forKey: .totalFindings)
        filesAffected = try c.decode(Int.self, forKey: .filesAffected)
        severityBreakdown = try c.decode(SeverityBreakdown.self, forKey: .severityBreakdown)
        typeGroups = try c.decode([TypeGroup].self, forKey: .typeGroups)
        hotSpots = try c.decode([HotSpot].self, forKey: .hotSpots)
        hotSpotsTotal = try c.decodeIfPresent(Int.self, forKey: .hotSpotsTotal)
            ?? max(hotSpots.count, filesAffected)
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
    /// WO-553@v3: compatibility mirror for reports written before complete pagination.
    public let repoEnumerationCapped: Bool
    /// WO-553@v3: true only when the report can prove repository enumeration completed.
    public let repoEnumerationComplete: Bool

    public init(version: String, generatedAt: String, organization: String,
                totalRepos: Int, reposScanned: Int, totalFindings: Int,
                severityBreakdown: SeverityBreakdown,
                repositories: [RepositorySummary],
                repoEnumerationCapped: Bool = false,
                repoEnumerationComplete: Bool? = nil) {
        self.version = version
        self.generatedAt = generatedAt
        self.organization = organization
        self.totalRepos = totalRepos
        self.reposScanned = reposScanned
        self.totalFindings = totalFindings
        self.severityBreakdown = severityBreakdown
        self.repositories = repositories
        self.repoEnumerationComplete = repoEnumerationComplete ?? !repoEnumerationCapped
        self.repoEnumerationCapped = !self.repoEnumerationComplete
    }

    // WO-553@v3: backward-compatible decode — field is absent in pre-WO-553 JSON.
    private enum CodingKeys: String, CodingKey {
        case version, generatedAt, organization, totalRepos, reposScanned
        case totalFindings, severityBreakdown, repositories
        case repoEnumerationCapped, repoEnumerationComplete
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        version = try c.decode(String.self, forKey: .version)
        generatedAt = try c.decode(String.self, forKey: .generatedAt)
        organization = try c.decode(String.self, forKey: .organization)
        totalRepos = try c.decode(Int.self, forKey: .totalRepos)
        reposScanned = try c.decode(Int.self, forKey: .reposScanned)
        totalFindings = try c.decode(Int.self, forKey: .totalFindings)
        severityBreakdown = try c.decode(SeverityBreakdown.self, forKey: .severityBreakdown)
        repositories = try c.decode([RepositorySummary].self, forKey: .repositories)
        if let complete = try c.decodeIfPresent(Bool.self, forKey: .repoEnumerationComplete) {
            repoEnumerationComplete = complete
        } else if let capped = try c.decodeIfPresent(Bool.self, forKey: .repoEnumerationCapped) {
            repoEnumerationComplete = !capped
        } else {
            // Historical reports cannot prove that enumeration reached the final page.
            repoEnumerationComplete = false
        }
        repoEnumerationCapped = !repoEnumerationComplete
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
    /// WO-553@v3: route pagination through the endpoint matching the account type.
    enum RepositoryOwnerType: String {
        case organization = "Organization"
        case user = "User"

        var endpointComponent: String {
            switch self {
            case .organization: return "orgs"
            case .user: return "users"
            }
        }
    }

    /// WO-553@v3: preserve output-channel separation while draining both pipes.
    private struct CommandOutput {
        let standardOutput: Data
        let standardError: Data
    }
    /// WO-553@v3: execute a command without folding diagnostics into data output.
    public static func runCommand(_ executable: String, _ arguments: [String]) throws -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = [executable] + arguments
        let outputPipe = Pipe()
        let errorPipe = Pipe()
        process.standardOutput = outputPipe
        process.standardError = errorPipe
        try process.run()
        let output = collectCommandOutput(
            process: process,
            outputPipe: outputPipe,
            errorPipe: errorPipe
        )
        guard process.terminationStatus == 0 else {
            let diagnostic = output.standardError.isEmpty
                ? output.standardOutput
                : output.standardError
            let errMsg = String(data: diagnostic, encoding: .utf8) ?? "unknown error"
            throw PostureError.commandFailed(executable, errMsg.trimmingCharacters(in: .whitespacesAndNewlines))
        }
        return String(data: output.standardOutput, encoding: .utf8) ?? ""
    }

    /// WO-553@v3: drain both output channels while the child runs. Keeping stderr
    /// separate prevents successful diagnostics from becoming repository names.
    private static func collectCommandOutput(
        process: Process,
        outputPipe: Pipe,
        errorPipe: Pipe
    ) -> CommandOutput {
        let group = DispatchGroup()
        let lock = NSLock()
        var standardOutput = Data()
        var standardError = Data()

        group.enter()
        DispatchQueue.global(qos: .utility).async {
            let data = outputPipe.fileHandleForReading.readDataToEndOfFile()
            lock.lock()
            standardOutput = data
            lock.unlock()
            group.leave()
        }
        group.enter()
        DispatchQueue.global(qos: .utility).async {
            let data = errorPipe.fileHandleForReading.readDataToEndOfFile()
            lock.lock()
            standardError = data
            lock.unlock()
            group.leave()
        }

        outputPipe.fileHandleForWriting.closeFile()
        errorPipe.fileHandleForWriting.closeFile()
        process.waitUntilExit()
        group.wait()

        lock.lock()
        defer { lock.unlock() }
        return CommandOutput(
            standardOutput: standardOutput,
            standardError: standardError
        )
    }

    /// WO-553@v3: use GitHub API pagination rather than a fixed repository cap.
    static func enumerateReposArguments(org: String) -> [String] {
        enumerateReposArguments(owner: org, ownerType: .organization)
    }

    /// WO-553@v3: build the paginated endpoint after owner-type resolution.
    static func enumerateReposArguments(
        owner: String,
        ownerType: RepositoryOwnerType
    ) -> [String] {
        [
            "api",
            "--paginate",
            "\(ownerType.endpointComponent)/\(owner)/repos?per_page=100",
            "--jq",
            ".[] | select(.archived == false and .fork == false) | .name",
        ]
    }

    /// WO-553@v3: resolve whether the documented owner is a user or organization.
    static func repositoryOwnerTypeArguments(owner: String) -> [String] {
        ["api", "users/\(owner)", "--jq", ".type"]
    }

    public static func enumerateRepos(org: String) throws -> [String] {
        // WO-553@v3: `posture --org` historically accepts either an organization
        // or user account; resolve the API type before choosing the endpoint.
        let typeOutput = try runCommand("gh", repositoryOwnerTypeArguments(owner: org))
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard let ownerType = RepositoryOwnerType(rawValue: typeOutput) else {
            throw PostureError.commandFailed("gh", "unsupported GitHub account type")
        }
        let output = try runCommand(
            "gh",
            enumerateReposArguments(owner: org, ownerType: ownerType)
        )
        return output.split(separator: "\n")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
    }

    /// WO-553@v3: compatibility constant retained for callers compiled against the prior API.
    @available(*, deprecated, message: "Repository enumeration is fully paginated")
    public static let repoEnumerationLimit = 500

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
            hotSpots: report.hotSpots,
            hotSpotsTotal: report.hotSpotsTotal
        )
    }

    public static func aggregate(
        org: String,
        summaries: [RepositorySummary],
        totalRepos: Int,
        repoEnumerationComplete: Bool = true
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
            repositories: sorted,
            repoEnumerationComplete: repoEnumerationComplete
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

    // WO-553@v3: text output distinguishes complete enumeration from partial results.
    public static func formatText(_ report: PostureReport, findingsOnly: Bool = false) -> String {
        var lines: [String] = []
        lines.append("Posture Report: \(report.organization)")
        lines.append(String(repeating: "=", count: 40))
        lines.append("Generated: \(report.generatedAt)")
        if report.repoEnumerationComplete {
            lines.append("Repos scanned: \(report.reposScanned)/\(report.totalRepos)")
        } else {
            lines.append("Repos scanned: \(report.reposScanned) (enumeration incomplete; total unknown)")
        }
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

    // WO-553@v3: Markdown output distinguishes complete enumeration from partial results.
    public static func formatMarkdown(_ report: PostureReport, findingsOnly: Bool = false) -> String {
        var lines: [String] = []
        lines.append("## Posture Report: \(report.organization)")
        lines.append("")
        lines.append("**Generated:** \(report.generatedAt)")
        if report.repoEnumerationComplete {
            lines.append("**Repos scanned:** \(report.reposScanned)/\(report.totalRepos)")
        } else {
            lines.append("**Repos scanned:** \(report.reposScanned) (enumeration incomplete; total unknown)")
        }
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
