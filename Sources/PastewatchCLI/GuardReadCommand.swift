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

    // WO-665@v1: blocked large reads name the bounded MCP continuation arguments.
    // WO-659@v1: Read enforces MCP mutation authorization; Write retains its existing policy.
    /// Throws `ExitCode(2)` on block or shared-pattern error.
    /// Returns normally when the file is clean (no actionable secrets).
    static func check(filePath: String, failOnSeverity: Severity, operation: Operation) throws {
        if ProcessInfo.processInfo.environment["PW_GUARD"] == "0" { return }

        // WO-574@v4: guard decisions cannot use fallback defaults after config corruption.
        let config = try requireValidatedConfig()
        if config.isPathProtected(filePath) {
            let msg = "BLOCKED: \(filePath) is inside a protected directory\n"
            FileHandle.standardError.write(Data(msg.utf8))
            print("You MUST use pastewatch_\(operation == .read ? "read" : "write")_file instead of \(operation.toolName) for files in protected directories.")
            // WO-665@v1: inspect only size metadata when protected paths refuse content access.
            printReadWindowHint(filePath: filePath, operation: operation)
            throw ExitCode(rawValue: GuardExitContract.blocked)
        }

        guard FileManager.default.fileExists(atPath: filePath) else { return }

        // WO-588@v2: existing unscannable files must not bypass read/write guards.
        let data: Data
        do {
            // WO-598@v2: enforce the file cap before guard-read/write allocates bytes.
            data = try DetectionRules.readBoundedFileData(atPath: filePath)
        } catch let error as ScanInputLimitError {
            try blockUnscannableFile(
                filePath: filePath,
                operation: operation,
                reason: error.localizedDescription
            )
        } catch {
            try blockUnscannableFile(
                filePath: filePath,
                operation: operation,
                reason: "could not be read"
            )
        }
        guard let content = String(data: data, encoding: .utf8) else {
            try blockUnscannableFile(
                filePath: filePath,
                operation: operation,
                reason: "is not valid UTF-8"
            )
        }
        guard !content.isEmpty else { return }

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
        } catch let error as ScanInputLimitError {
            // WO-598@v2: overlong decoded input is a guard block, not a generic parse exit.
            try blockUnscannableFile(
                filePath: filePath,
                operation: operation,
                reason: error.localizedDescription
            )
        }
        // WO-502: read/write/command/watch use one post-scan decision pipeline.
        // WO-635: retain reportable advisories while only actionable matches block file access.
        // WO-659@v1: use the MCP decision directly so Read never blocks an advisory-only file.
        let filtered: [DetectedMatch]
        let advisories: [DetectedMatch]
        switch operation {
        case .read:
            let decision = MCPReadDecision.evaluate(
                matches: matches, content: content, config: config,
                minimumSeverity: failOnSeverity, filePath: filePath
            )
            filtered = decision.authorized
            advisories = decision.reportedAdvisories
        case .write:
            // WO-635: path-based documentation policy is shared by read and write guards.
            let decision = GuardDecision.evaluate(
                matches: matches, content: content, config: config,
                contentTrust: .trustedFile, minimumSeverity: failOnSeverity, filePath: filePath
            )
            filtered = decision.actionableMatches
            advisories = decision.reportableMatches.filter { $0.advisory == .documentationPolicy }
        }
        // WO-635: advisory diagnostics expose type and line, never matched values.
        // WO-659@v1: advisory reporting retains the type-and-line wording without exposing values.
        for match in advisories {
            let message = "ADVISORY: \(match.displayName) line \(match.line) count=1\n"
            FileHandle.standardError.write(Data(message.utf8))
        }
        guard !filtered.isEmpty else { return }

        let bySeverity = Dictionary(grouping: filtered, by: { $0.effectiveSeverity })
        let counts = bySeverity.map { "\($0.value.count) \($0.key.rawValue)" }.sorted()

        let msg = "BLOCKED: \(filePath) contains \(filtered.count) secret(s) (\(counts.joined(separator: ", ")))\n"
        FileHandle.standardError.write(Data(msg.utf8))

        print("You MUST use pastewatch_\(operation == .read ? "read" : "write")_file instead of \(operation.toolName) for files containing secrets.")
        // WO-665@v1: the already-read byte count avoids extra I/O on the ordinary block path.
        printReadWindowHint(filePath: filePath, operation: operation, byteCount: data.count)

        throw ExitCode(rawValue: GuardExitContract.blocked)
    }

    // WO-665@v1: large-file guidance uses one shared threshold and never prints file content.
    private static func printReadWindowHint(filePath: String, operation: Operation, byteCount: Int? = nil) {
        guard operation == .read else { return }
        let size = byteCount ?? ((try? FileManager.default.attributesOfItem(atPath: filePath))?[.size] as? NSNumber)?.intValue ?? 0
        guard size > MCPReadDecision.unrangedResponseLimitBytes else { return }
        // WO-665@v1: default line windows use the token-efficient 24 KiB cap; explicit bytes remain available.
        print("For large files, pastewatch_read_file returns whole lines up to 24 KiB; continue at the next start_line named in its response, optionally with line_count. An overlong first line uses Base64 byte_offset/byte_length windows. Windows do not bypass whole-file input limits.")
    }

    // WO-665@v1: oversized refusals name byte arguments without suggesting an input-limit bypass.
    // WO-588@v2: diagnostics identify the failed file without echoing its bytes.
    private static func blockUnscannableFile(
        filePath: String,
        operation: Operation,
        reason: String
    ) throws -> Never {
        let message = "BLOCKED: \(filePath) \(reason)\n"
        FileHandle.standardError.write(Data(message.utf8))
        print("Use pastewatch_\(operation == .read ? "read" : "write")_file only after the file is readable UTF-8.")
        // WO-665@v1: metadata-only size lookup does not inspect an unscannable file's bytes.
        printReadWindowHint(filePath: filePath, operation: operation)
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
