import ArgumentParser
import Foundation
import PastewatchCore

struct DashboardCommand: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "dashboard",
        abstract: "Aggregate view across multiple audit log sessions"
    )

    @Option(name: .long, help: "Directory containing audit log files")
    var dir: String = "/tmp"

    @Option(name: .long, help: "Only include entries since date (ISO format)")
    var since: String?

    @Option(name: .long, help: "Output format: text, json, markdown")
    var format: DashboardFormat = .text

    @Option(name: .long, help: "Write output to file instead of stdout")
    var output: String?

    func run() throws {
        var sinceDate: Date?
        if let since {
            let df = ISO8601DateFormatter()
            df.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
            sinceDate = df.date(from: since)
            if sinceDate == nil {
                let df2 = ISO8601DateFormatter()
                sinceDate = df2.date(from: since)
            }
        }

        let dashboard = DashboardBuilder.build(logDirectory: dir, since: sinceDate)

        if let outputPath = output {
            FileManager.default.createFile(atPath: outputPath, contents: nil)
            guard let handle = FileHandle(forWritingAtPath: outputPath) else {
                FileHandle.standardError.write(Data("error: could not write to \(outputPath)\n".utf8))
                throw ExitCode(rawValue: 2)
            }
            freopen(outputPath, "w", stdout)
            _ = handle
        }

        switch format {
        case .text:
            printText(dashboard)
        case .json:
            printJSON(dashboard)
        case .markdown:
            printMarkdown(dashboard)
        }
    }

    // MARK: - Text

    private func printText(_ d: Dashboard) {
        print("Pastewatch Dashboard")
        print("====================\n")
        print("Sessions:    \(d.sessions)")
        if let earliest = d.period.earliest, let latest = d.period.latest {
            print("Period:      \(earliest) — \(latest)")
        }
        print("")
        print("Files read:           \(d.summary.filesRead)")
        print("Files written:        \(d.summary.filesWritten)")
        print("Secrets redacted:     \(d.summary.secretsRedacted)")
        print("Placeholders resolved:\(d.summary.placeholdersResolved)")
        print("Unresolved:           \(d.summary.unresolvedPlaceholders)")
        print("Scans:                \(d.summary.scans)")
        print("Scan findings:        \(d.summary.scanFindings)")

        if !d.topTypes.isEmpty {
            print("\nTop secret types:")
            for tc in d.topTypes.prefix(10) {
                print("  \(tc.type): \(tc.count) (\(tc.severity))")
            }
        }

        if !d.hotFiles.isEmpty {
            print("\nHot files:")
            for fa in d.hotFiles.prefix(10) {
                print("  \(fa.file): \(fa.reads)R \(fa.writes)W \(fa.secretsRedacted) redacted")
            }
        }

        print("\nVerdict: \(d.verdict)")
    }

    // MARK: - JSON

    private func printJSON(_ d: Dashboard) {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        if let data = try? encoder.encode(d) {
            print(String(data: data, encoding: .utf8)!)
        }
    }

    // MARK: - Markdown

    private func printMarkdown(_ d: Dashboard) {
        print("# Pastewatch Dashboard\n")
        print("**Generated:** \(d.generatedAt)  ")
        print("**Sessions:** \(d.sessions)  ")
        if let earliest = d.period.earliest, let latest = d.period.latest {
            print("**Period:** \(earliest) — \(latest)  ")
        }

        print("\n## Summary\n")
        print("| Metric | Count |")
        print("|--------|-------|")
        print("| Files read | \(d.summary.filesRead) |")
        print("| Files written | \(d.summary.filesWritten) |")
        print("| Secrets redacted | \(d.summary.secretsRedacted) |")
        print("| Placeholders resolved | \(d.summary.placeholdersResolved) |")
        print("| Unresolved | \(d.summary.unresolvedPlaceholders) |")
        print("| Scans | \(d.summary.scans) |")
        print("| Scan findings | \(d.summary.scanFindings) |")

        if !d.topTypes.isEmpty {
            print("\n## Top Secret Types\n")
            print("| Type | Count | Severity |")
            print("|------|-------|----------|")
            for tc in d.topTypes.prefix(10) {
                print("| \(tc.type) | \(tc.count) | \(tc.severity) |")
            }
        }

        if !d.hotFiles.isEmpty {
            print("\n## Hot Files\n")
            print("| File | Reads | Writes | Redacted |")
            print("|------|-------|--------|----------|")
            for fa in d.hotFiles.prefix(10) {
                print("| \(fa.file) | \(fa.reads) | \(fa.writes) | \(fa.secretsRedacted) |")
            }
        }

        print("\n## Verdict\n")
        print("**\(d.verdict)**")
    }
}

enum DashboardFormat: String, ExpressibleByArgument {
    case text, json, markdown
}
