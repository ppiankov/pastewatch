import ArgumentParser
import Foundation
import PastewatchCore

struct Posture: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Scan multiple repositories for secret posture across an organization"
    )

    @Option(name: .long, help: "GitHub org or user to enumerate repos from")
    var org: String?

    @Option(name: .long, parsing: .singleValue, help: "Specific repos to scan (org/repo format, can be repeated)")
    var repos: [String] = []

    @Option(name: .long, help: "Output format: text, json, markdown")
    var format: PostureFormat = .text

    @Option(name: .long, help: "Write report to file instead of stdout")
    var output: String?

    @Option(name: .long, help: "Compare with previous posture JSON file")
    var compare: String?

    @Flag(name: .long, help: "Only show repositories with findings")
    var findingsOnly = false

    func run() throws {
        guard org != nil || !repos.isEmpty else {
            FileHandle.standardError.write(Data("error: provide --org or --repos\n".utf8))
            throw ExitCode(rawValue: 2)
        }

        let config = PastewatchConfig.resolve()
        let orgName: String
        var repoNames: [String]

        if !repos.isEmpty {
            // Parse org/repo format
            orgName = repos.first.map { String($0.split(separator: "/").first ?? "") } ?? "multi"
            repoNames = repos.map { String($0.split(separator: "/").last ?? Substring($0)) }
        } else {
            orgName = org!
            FileHandle.standardError.write(Data("Enumerating repos for \(orgName)...\n".utf8))
            repoNames = try PostureScanner.enumerateRepos(org: orgName)
            if repoNames.isEmpty {
                throw PostureError.noReposFound(orgName)
            }
            FileHandle.standardError.write(Data("Found \(repoNames.count) repos\n".utf8))
        }

        let totalRepos = repoNames.count
        let tempDir = NSTemporaryDirectory() + "pastewatch-posture-\(ProcessInfo.processInfo.processIdentifier)"
        try FileManager.default.createDirectory(atPath: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: tempDir) }

        var summaries: [RepositorySummary] = []
        let resolvedOrg = repos.isEmpty ? orgName : repos.first.map { String($0.split(separator: "/").first ?? "") } ?? orgName

        for (index, name) in repoNames.enumerated() {
            let cloneOrg = repos.isEmpty ? orgName : repos[index].split(separator: "/").first.map(String.init) ?? orgName
            FileHandle.standardError.write(Data("[\(index + 1)/\(totalRepos)] Scanning \(name)...\n".utf8))
            do {
                let repoPath = try PostureScanner.cloneRepo(org: cloneOrg, name: name, into: tempDir)
                let summary = try PostureScanner.scanRepo(at: repoPath, name: name, config: config)
                summaries.append(summary)
            } catch {
                FileHandle.standardError.write(Data("  warning: \(name) skipped (\(error))\n".utf8))
                summaries.append(RepositorySummary(
                    name: name, totalFindings: 0, filesAffected: 0,
                    severityBreakdown: SeverityBreakdown(critical: 0, high: 0, medium: 0, low: 0),
                    typeGroups: [], hotSpots: []
                ))
            }
        }

        let report = PostureScanner.aggregate(org: resolvedOrg, summaries: summaries, totalRepos: totalRepos)

        try redirectStdoutIfNeeded()

        let reportOutput: String
        switch format {
        case .text: reportOutput = PostureFormatter.formatText(report, findingsOnly: findingsOnly)
        case .json: reportOutput = PostureFormatter.formatJSON(report)
        case .markdown: reportOutput = PostureFormatter.formatMarkdown(report, findingsOnly: findingsOnly)
        }
        print(reportOutput, terminator: "")

        if let comparePath = compare {
            try runCompare(comparePath: comparePath, report: report)
        }
    }

    private func runCompare(comparePath: String, report: PostureReport) throws {
        guard FileManager.default.fileExists(atPath: comparePath) else {
            FileHandle.standardError.write(Data("error: compare file not found: \(comparePath)\n".utf8))
            throw ExitCode(rawValue: 2)
        }
        let previous: PostureReport
        do {
            previous = try PostureScanner.load(from: comparePath)
        } catch {
            FileHandle.standardError.write(Data("error: invalid posture file: \(comparePath)\n".utf8))
            throw ExitCode(rawValue: 2)
        }
        let delta = PostureScanner.compare(current: report, previous: previous)
        let deltaOutput: String
        switch format {
        case .text: deltaOutput = PostureFormatter.formatDeltaText(delta)
        case .json:
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            if let data = try? encoder.encode(delta),
               let str = String(data: data, encoding: .utf8) {
                deltaOutput = "\n" + str
            } else {
                deltaOutput = ""
            }
        case .markdown: deltaOutput = PostureFormatter.formatDeltaMarkdown(delta)
        }
        if !deltaOutput.isEmpty {
            print(deltaOutput, terminator: "")
        }
    }

    private func redirectStdoutIfNeeded() throws {
        guard let outputPath = output else { return }
        FileManager.default.createFile(atPath: outputPath, contents: nil)
        guard let handle = FileHandle(forWritingAtPath: outputPath) else {
            FileHandle.standardError.write(Data("error: could not write to \(outputPath)\n".utf8))
            throw ExitCode(rawValue: 2)
        }
        dup2(handle.fileDescriptor, STDOUT_FILENO)
        handle.closeFile()
    }
}

enum PostureFormat: String, ExpressibleByArgument {
    case text
    case json
    case markdown
}
