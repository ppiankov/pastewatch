import ArgumentParser
import Foundation
import PastewatchCore

// WO-561@v3: shared guard logic for read/write — eliminates 95% copy-paste.
enum FileGuard {
    enum Operation {
        case read
        case write

        var toolName: String {
            switch self {
            case .read: return "Read"
            case .write: return "Write"
            }
        }
    }

    /// Throws `ExitCode(2)` on block or shared-pattern error.
    /// Returns normally when the file is clean (no actionable secrets).
    static func check(filePath: String, failOnSeverity: Severity, operation: Operation) throws {
        if ProcessInfo.processInfo.environment["PW_GUARD"] == "0" { return }

        let config = PastewatchConfig.resolve()
        if config.isPathProtected(filePath) {
            let msg = "BLOCKED: \(filePath) is inside a protected directory\n"
            FileHandle.standardError.write(Data(msg.utf8))
            print("You MUST use pastewatch_\(operation == .read ? "read" : "write")_file instead of \(operation.toolName) for files in protected directories.")
            throw ExitCode(rawValue: GuardExitContract.blocked)
        }

        guard FileManager.default.fileExists(atPath: filePath) else { return }

        guard let content = try? String(contentsOfFile: filePath, encoding: .utf8),
              !content.isEmpty else {
            return
        }

        let fileName = URL(fileURLWithPath: filePath).lastPathComponent
        let isEnvFile = DotenvClassifier.isDotenvFile(fileName)
        let ext = isEnvFile ? "env" : URL(fileURLWithPath: filePath).pathExtension.lowercased()

        let matches: [DetectedMatch]
        do {
            matches = try DirectoryScanner.scanFileContentOrThrow(
                content: content, ext: ext,
                relativePath: filePath, config: config
            )
        } catch let error as SharedSecretPatternLoadError {
            let msg = "BLOCKED: shared pattern load failed: \(error.localizedDescription)\n"
            FileHandle.standardError.write(Data(msg.utf8))
            print("Fix shared pattern configuration before using \(operation.toolName).")
            throw ExitCode(rawValue: GuardExitContract.blocked)
        }
        // WO-502: read/write/command/watch use one post-scan decision pipeline.
        let filtered = GuardDecision.evaluate(
            matches: matches,
            content: content,
            config: config,
            contentTrust: .trustedFile,
            minimumSeverity: failOnSeverity
        ).actionableMatches
        guard !filtered.isEmpty else { return }

        let bySeverity = Dictionary(grouping: filtered, by: { $0.effectiveSeverity })
        let counts = bySeverity.map { "\($0.value.count) \($0.key.rawValue)" }.sorted()

        let msg = "BLOCKED: \(filePath) contains \(filtered.count) secret(s) (\(counts.joined(separator: ", ")))\n"
        FileHandle.standardError.write(Data(msg.utf8))

        print("You MUST use pastewatch_\(operation == .read ? "read" : "write")_file instead of \(operation.toolName) for files containing secrets.")

        throw ExitCode(rawValue: GuardExitContract.blocked)
    }
}

// WO-558@v2: GuardRead is governed by the shared blocked-exit contract.
struct GuardRead: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "guard-read",
        abstract: "Check if a file contains secrets before allowing Read tool access"
    )

    @Argument(help: "File path to check")
    var filePath: String

    // WO-559@v2: guard-read uses the named guard threshold by default.
    @Option(name: .long, help: "Minimum severity to block: critical, high, medium, low")
    var failOnSeverity: Severity = .defaultGuardThreshold

    // WO-558@v2: guard-read shares the canonical blocked exit contract.
    func run() throws {
        try FileGuard.check(filePath: filePath, failOnSeverity: failOnSeverity, operation: .read)
    }
}
