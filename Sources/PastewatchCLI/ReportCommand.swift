import ArgumentParser
import Foundation
import PastewatchCore

struct Report: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Generate session report from MCP audit log"
    )

    @Option(name: .long, help: "Path to MCP audit log file")
    var auditLog: String

    @Option(name: .long, help: "Output format: text, json, markdown (default: text)")
    var format: ReportFormat = .text

    @Option(name: .long, help: "Write report to file instead of stdout")
    var output: String?

    @Option(name: .long, help: "Only entries after this ISO timestamp")
    var since: String?

    func validate() throws {
        guard FileManager.default.fileExists(atPath: auditLog) else {
            throw ValidationError("audit log file not found: \(auditLog)")
        }
        if let since = since {
            let df = ISO8601DateFormatter()
            df.formatOptions = [.withInternetDateTime]
            guard df.date(from: since) != nil else {
                throw ValidationError("invalid ISO timestamp for --since: \(since)")
            }
        }
    }

    func run() throws {
        let content = try String(contentsOfFile: auditLog, encoding: .utf8)

        var sinceDate: Date?
        if let since = since {
            let df = ISO8601DateFormatter()
            df.formatOptions = [.withInternetDateTime]
            sinceDate = df.date(from: since)
        }

        let report = SessionReportBuilder.build(
            content: content,
            logPath: auditLog,
            since: sinceDate
        )

        try redirectStdoutIfNeeded()

        let reportOutput: String
        switch format {
        case .text: reportOutput = SessionReportBuilder.formatText(report)
        case .json: reportOutput = SessionReportBuilder.formatJSON(report)
        case .markdown: reportOutput = SessionReportBuilder.formatMarkdown(report)
        }
        print(reportOutput, terminator: "")
    }

    private func redirectStdoutIfNeeded() throws {
        guard let outputPath = output else { return }
        FileManager.default.createFile(atPath: outputPath, contents: nil)
        guard let handle = FileHandle(forWritingAtPath: outputPath) else {
            FileHandle.standardError.write(
                Data("error: could not write to \(outputPath)\n".utf8)
            )
            throw ExitCode(rawValue: 2)
        }
        dup2(handle.fileDescriptor, STDOUT_FILENO)
        handle.closeFile()
    }
}

enum ReportFormat: String, ExpressibleByArgument {
    case text
    case json
    case markdown
}
