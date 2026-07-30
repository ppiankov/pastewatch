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

    // WO-559@v2: guard policy uses its own named default threshold.
    @Option(name: .long, help: "Minimum severity to block: critical, high, medium, low")
    var failOnSeverity: Severity = .defaultGuardThreshold

    @Flag(name: .long, help: "Machine-readable JSON output")
    var json = false

    @Flag(name: .long, help: "Exit code only, no output")
    var quiet = false

    func run() throws {
        if ProcessInfo.processInfo.environment["PW_GUARD"] == "0" { return }

        // WO-574@v4: command guards cannot fall back from a corrupt active config.
        let config = try requireValidatedConfig()
        let paths = CommandParser.extractFilePaths(from: command)

        var allFileResults: [FileResult] = []
        var allInlineResults: [InlineResult] = []
        var shouldBlock = false

        // WO-550@v2: an invalid shared pattern blocks the command instead of silently
        // evaluating a partial detector set.
        let commandScan = DetectionRules.scanFileIOResult(command, config: config)
        guard !commandScan.hasSharedPatternErrors else {
            if !quiet {
                FileHandle.standardError.write(
                    Data("BLOCKED: configured shared patterns could not be loaded.\n".utf8)
                )
            }
            throw ExitCode(rawValue: GuardExitContract.blocked)
        }
        let commandMatches = commandScan.matches
        // WO-502: one decision pipeline handles examples, allowlists, and severity.
        let commandDecision = GuardDecision.evaluate(
            matches: commandMatches,
            content: command,
            config: config,
            contentTrust: .agentControlled,
            minimumSeverity: failOnSeverity
        )
        // WO-139: JSON redaction covers reportable inline findings even below block threshold.
        let commandDisplayMatches = commandDecision.reportableMatches
        let commandFiltered = commandDecision.actionableMatches
        // WO-138: JSON output must preserve command context without echoing inline credential values.
        let redactedCommand = Obfuscator.redactForDisplay(command, matches: commandDisplayMatches)

        if !commandFiltered.isEmpty {
            shouldBlock = true
            let bySeverity = Dictionary(grouping: commandFiltered, by: { $0.effectiveSeverity })
            let counts = bySeverity.map { "\($0.value.count) \($0.key.rawValue)" }
                .sorted()
            allInlineResults.append(InlineResult(
                findings: commandFiltered.count,
                severityCounts: counts.joined(separator: ", "),
                types: Set(commandFiltered.map { $0.displayName }).sorted()
            ))
        }

        // Scan referenced files
        for path in paths {
            guard FileManager.default.fileExists(atPath: path) else { continue }

            // WO-550@v2: use format-aware scanning for referenced files, matching guard-read behavior.
            let scan = try scanReferencedFile(path: path, config: config)
            let content = scan.content
            let matches = scan.matches
            // WO-502: files REFERENCED by an agent-controlled command are themselves
            // agent-controllable — the agent can write `# pastewatch:allow` into a file it
            // then `cat`s. Treat the referenced content as .agentControlled so inline allow
            // comments cannot self-authorize a secret one layer over. Operator-named files
            // (guard-read/guard-write, FileWatcher) remain .trustedFile.
            let filtered = GuardDecision.evaluate(
                matches: matches,
                content: content,
                config: config,
                contentTrust: .agentControlled,
                minimumSeverity: failOnSeverity
            ).actionableMatches

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
                    command: redactedCommand,
                    files: allFileResults.map {
                        .init(path: $0.path, findings: $0.findings, types: $0.types)
                    },
                    inlineFindings: allInlineResults.map {
                        .init(findings: $0.findings, types: $0.types)
                    }
                )
                printJSON(result)
            } else if !quiet {
                for fr in allFileResults {
                    let msg = "BLOCKED: \(fr.path) contains \(fr.findings) secret(s) (\(fr.severityCounts))\n"
                    FileHandle.standardError.write(Data(msg.utf8))
                }
                for ir in allInlineResults {
                    let msg = "BLOCKED: command contains inline secret(s) (\(ir.severityCounts): \(ir.types.joined(separator: ", ")))\n"
                    FileHandle.standardError.write(Data(msg.utf8))
                }
                FileHandle.standardError.write(Data("Use pastewatch MCP tools for files with secrets.\n".utf8))
            }
            throw ExitCode(rawValue: GuardExitContract.blocked)
        }

        if json {
            printJSON(GuardResult(blocked: false, command: redactedCommand, files: [], inlineFindings: []))
        }
    }

    // WO-601@v2: one fail-closed boundary owns referenced-file decoding and scanning.
    private func scanReferencedFile(
        path: String,
        config: PastewatchConfig
    ) throws -> ReferencedFileScan {
        do {
            // WO-598@v2: reject bounded referenced files before allocating their contents.
            let data = try DetectionRules.readBoundedFileData(atPath: path)
            guard let content = String(data: data, encoding: .utf8) else {
                try blockUnscannableFile(path)
            }
            let refExt = (path as NSString).pathExtension.lowercased()
            let matches = try DirectoryScanner.scanFileContentOrThrow(
                content: content,
                ext: refExt,
                relativePath: path,
                config: config
            )
            return ReferencedFileScan(content: content, matches: matches)
        } catch let error as SharedSecretPatternLoadError {
            if !quiet {
                let message = "BLOCKED: configured shared patterns could not be loaded " +
                    "for \(path): \(error.localizedDescription)\n"
                FileHandle.standardError.write(Data(message.utf8))
            }
            throw ExitCode(rawValue: GuardExitContract.blocked)
        } catch let error as ScanInputLimitError {
            if !quiet {
                let message = "BLOCKED: \(path) \(error.localizedDescription)\n"
                FileHandle.standardError.write(Data(message.utf8))
            }
            throw ExitCode(rawValue: GuardExitContract.blocked)
        } catch let exitCode as ExitCode {
            throw exitCode
        } catch {
            try blockUnscannableFile(path)
        }
    }

    // WO-601@v2: diagnostics identify the evidence boundary without file bytes.
    private func blockUnscannableFile(_ path: String) throws -> Never {
        if !quiet {
            FileHandle.standardError.write(
                Data("BLOCKED: \(path) cannot be scanned safely\n".utf8)
            )
        }
        throw ExitCode(rawValue: GuardExitContract.blocked)
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

private struct InlineResult {
    let findings: Int
    let severityCounts: String
    let types: [String]
}

// WO-601@v2: keep decoded content paired with the matches derived from it.
private struct ReferencedFileScan {
    let content: String
    let matches: [DetectedMatch]
}

private struct GuardResult: Codable {
    let blocked: Bool
    let command: String
    let files: [GuardFileEntry]
    let inlineFindings: [InlineEntry]

    struct GuardFileEntry: Codable {
        let path: String
        let findings: Int
        let types: [String]
    }

    struct InlineEntry: Codable {
        let findings: Int
        let types: [String]
    }
}
