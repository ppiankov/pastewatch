import ArgumentParser
import Foundation
import PastewatchCore

struct Guard: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "guard",
        abstract: "Check if a shell command would access files containing secrets"
    )

    @Argument(help: "Shell command to check")
    var command: String

    @Option(name: .long, help: "Minimum severity to block: critical, high, medium, low")
    var failOnSeverity: Severity = .high

    @Flag(name: .long, help: "Machine-readable JSON output")
    var json = false

    @Flag(name: .long, help: "Exit code only, no output")
    var quiet = false

    func run() throws {
        if ProcessInfo.processInfo.environment["PW_GUARD"] == "0" { return }

        let config = PastewatchConfig.resolve()
        let paths = CommandParser.extractFilePaths(from: command)

        if paths.isEmpty {
            if json {
                printJSON(GuardResult(blocked: false, command: command, files: []))
            }
            return
        }

        var allFileResults: [FileResult] = []
        var shouldBlock = false

        for path in paths {
            guard FileManager.default.fileExists(atPath: path),
                  let content = try? String(contentsOfFile: path, encoding: .utf8) else {
                continue
            }

            let matches = DetectionRules.scan(content, config: config)
            let filtered = matches.filter { $0.effectiveSeverity >= failOnSeverity }

            if !filtered.isEmpty {
                shouldBlock = true
                let bySeverity = Dictionary(grouping: filtered, by: { $0.effectiveSeverity })
                let counts = bySeverity.map { "\($0.value.count) \($0.key.rawValue)" }
                    .sorted()
                allFileResults.append(FileResult(
                    path: path,
                    findings: filtered.count,
                    severityCounts: counts.joined(separator: ", "),
                    types: Set(filtered.map { $0.displayName }).sorted()
                ))
            }
        }

        if shouldBlock {
            if json {
                let result = GuardResult(
                    blocked: true,
                    command: command,
                    files: allFileResults.map {
                        .init(path: $0.path, findings: $0.findings, types: $0.types)
                    }
                )
                printJSON(result)
            } else if !quiet {
                for fr in allFileResults {
                    let msg = "BLOCKED: \(fr.path) contains \(fr.findings) secret(s) (\(fr.severityCounts))\n"
                    FileHandle.standardError.write(Data(msg.utf8))
                }
                FileHandle.standardError.write(Data("Use pastewatch MCP tools for files with secrets.\n".utf8))
            }
            throw ExitCode(rawValue: 1)
        }

        if json {
            printJSON(GuardResult(blocked: false, command: command, files: []))
        }
    }

    private func printJSON(_ result: GuardResult) {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        if let data = try? encoder.encode(result),
           let str = String(data: data, encoding: .utf8) {
            print(str)
        }
    }
}

// MARK: - Output types

private struct FileResult {
    let path: String
    let findings: Int
    let severityCounts: String
    let types: [String]
}

private struct GuardResult: Codable {
    let blocked: Bool
    let command: String
    let files: [GuardFileEntry]

    struct GuardFileEntry: Codable {
        let path: String
        let findings: Int
        let types: [String]
    }
}
