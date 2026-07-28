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

        // WO-574@v4: organization posture cannot be reported under fallback policy.
        let config = try requireValidatedConfig()
        try run(
            config: config,
            cloneRepo: { org, name, baseDir in
                try PostureScanner.cloneRepo(org: org, name: name, into: baseDir)
            },
            scanRepo: { path, name, scanConfig in
                try PostureScanner.scanRepo(at: path, name: name, config: scanConfig)
            },
            emitReport: { report in
                try render(report)
            }
        )
    }

    // WO-591: injected scanning and emission pin the no-partial-report boundary.
    func run(
        config: PastewatchConfig,
        cloneRepo: (_ org: String, _ name: String, _ baseDir: String) throws -> String,
        scanRepo: (_ path: String, _ name: String, _ config: PastewatchConfig) throws -> RepositorySummary,
        emitReport: (PostureReport) throws -> Void
    ) throws {
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
            let repoPath: String
            do {
                repoPath = try cloneRepo(cloneOrg, name, tempDir)
            } catch {
                // WO-575@v2: clone failures are retained as explicit incomplete scans
                // without disclosing arbitrary process error output.
                let errorType = String(describing: type(of: error))
                FileHandle.standardError.write(Data("  warning: \(name) skipped (\(errorType))\n".utf8))
                continue
            }

            do {
                let summary = try scanRepo(repoPath, name, config)
                summaries.append(summary)
            } catch is SharedSecretPatternLoadError {
                // WO-575@v2: detector-configuration failures invalidate the whole posture report.
                FileHandle.standardError.write(
                    Data("error: posture scan stopped because shared patterns could not be loaded\n".utf8)
                )
                throw ExitCode(rawValue: 2)
            } catch {
                // WO-575@v2: an incomplete detector run cannot support any posture report.
                FileHandle.standardError.write(
                    Data("error: posture scan stopped because a repository could not be scanned\n".utf8)
                )
                throw ExitCode(rawValue: 2)
            }
        }

        let report = PostureScanner.aggregate(org: resolvedOrg, summaries: summaries, totalRepos: totalRepos)
        try emitReport(report)
    }

    // WO-591: filesystem/stdout side effects occur only after every repository scan resolves.
    private func render(_ report: PostureReport) throws {
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
