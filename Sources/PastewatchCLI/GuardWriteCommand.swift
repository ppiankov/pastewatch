import ArgumentParser
import Foundation
import PastewatchCore

struct GuardWrite: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "guard-write",
        abstract: "Check if a file contains secrets before allowing Write tool access"
    )

    @Argument(help: "File path to check")
    var filePath: String

    @Option(name: .long, help: "Minimum severity to block: critical, high, medium, low")
    var failOnSeverity: Severity = .high

    func run() throws {
        if ProcessInfo.processInfo.environment["PW_GUARD"] == "0" { return }

        guard FileManager.default.fileExists(atPath: filePath) else { return }

        guard let content = try? String(contentsOfFile: filePath, encoding: .utf8),
              !content.isEmpty else {
            return
        }

        let config = PastewatchConfig.resolve()
        let fileName = URL(fileURLWithPath: filePath).lastPathComponent
        let isEnvFile = fileName == ".env" || fileName.hasSuffix(".env")
        let ext = isEnvFile ? "env" : URL(fileURLWithPath: filePath).pathExtension.lowercased()

        var matches = DirectoryScanner.scanFileContent(
            content: content, ext: ext,
            relativePath: filePath, config: config
        )
        matches = Allowlist.filterInlineAllow(matches: matches, content: content)

        let configAllowlist = Allowlist.fromConfig(config)
        matches = configAllowlist.filter(matches)

        let filtered = matches.filter { $0.effectiveSeverity >= failOnSeverity }
        guard !filtered.isEmpty else { return }

        let bySeverity = Dictionary(grouping: filtered, by: { $0.effectiveSeverity })
        let counts = bySeverity.map { "\($0.value.count) \($0.key.rawValue)" }.sorted()

        let msg = "BLOCKED: \(filePath) contains \(filtered.count) secret(s) (\(counts.joined(separator: ", ")))\n"
        FileHandle.standardError.write(Data(msg.utf8))

        print("You MUST use pastewatch_write_file instead of Write for files containing secrets.")

        throw ExitCode(rawValue: 2)
    }
}
