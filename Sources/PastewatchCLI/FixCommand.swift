import ArgumentParser
import Foundation
import PastewatchCore

struct Fix: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Externalize secrets to environment variables"
    )

    @Option(name: .long, help: "Directory to fix")
    var dir: String

    @Flag(name: .long, help: "Show fix plan without applying changes")
    var dryRun = false

    @Option(name: .long, help: "Minimum severity to fix: critical, high, medium, low")
    var minSeverity: Severity = .high

    @Option(name: .long, help: "Path for generated .env file (default: .env)")
    var envFile: String = ".env"

    @Option(name: .long, parsing: .singleValue, help: "Glob pattern to ignore (can be repeated)")
    var ignore: [String] = []

    @Flag(name: .long, help: "Encrypt secrets to vault instead of plaintext .env")
    var encrypt = false

    @Flag(name: .long, help: "Generate encryption key if none exists")
    var initKey = false

    func run() throws {
        guard FileManager.default.fileExists(atPath: dir) else {
            FileHandle.standardError.write(Data("error: directory not found: \(dir)\n".utf8))
            throw ExitCode(rawValue: 2)
        }

        let config = PastewatchConfig.resolve()
        let allowlist = Allowlist.fromConfig(config)

        // Scan directory
        let ignoreFile = IgnoreFile.load(from: dir)
        let fileResults = try DirectoryScanner.scan(
            directory: dir, config: config,
            ignoreFile: ignoreFile, extraIgnorePatterns: ignore
        )

        // Apply allowlist filtering
        var filteredResults: [FileScanResult] = []
        for fr in fileResults {
            let filtered = allowlist.values.isEmpty && allowlist.patterns.isEmpty
                ? fr.matches
                : allowlist.filter(fr.matches)
            if !filtered.isEmpty {
                filteredResults.append(FileScanResult(
                    filePath: fr.filePath, matches: filtered, content: fr.content
                ))
            }
        }

        // Build fix plan
        let plan = Remediation.buildPlan(results: filteredResults, minSeverity: minSeverity)

        if plan.actions.isEmpty {
            FileHandle.standardError.write(Data("No fixable secrets found.\n".utf8))
            return
        }

        // Always print plan
        printPlan(plan)

        // Apply if not dry-run
        if !dryRun {
            if encrypt {
                try applyWithVault(plan: plan)
            } else {
                try Remediation.apply(plan: plan, dirPath: dir, envFilePath: envFile)
                FileHandle.standardError.write(Data("\nApplied \(plan.actions.count) fixes.\n".utf8))

                if !Remediation.gitignoreContainsEnv(dirPath: dir) {
                    FileHandle.standardError.write(
                        Data("warning: \(envFile) not in .gitignore — secrets may be committed\n".utf8)
                    )
                }
            }
        }
    }

    private func applyWithVault(plan: FixPlan) throws {
        let keyPath = (dir as NSString).appendingPathComponent(".pastewatch-key")
        let vaultPath = (dir as NSString).appendingPathComponent(".pastewatch-vault")

        // Resolve or generate key
        let keyHex: String
        if FileManager.default.fileExists(atPath: keyPath) {
            keyHex = try Vault.readKey(from: keyPath)
        } else if initKey {
            keyHex = Vault.generateKey()
            try Vault.writeKey(keyHex, to: keyPath)
            FileHandle.standardError.write(Data("Generated key: \(keyPath)\n".utf8))
        } else {
            FileHandle.standardError.write(
                Data("error: no key file at \(keyPath) — use --init-key to generate\n".utf8)
            )
            throw ExitCode(rawValue: 2)
        }

        // Build new vault entries
        var newVault = try Vault.buildVault(plan: plan, keyHex: keyHex)

        // Merge with existing vault if present
        if FileManager.default.fileExists(atPath: vaultPath) {
            let existing = try Vault.load(from: vaultPath)
            newVault = Vault.merge(existing: existing, new: newVault)
        }

        try Vault.save(newVault, to: vaultPath)

        // Patch source files (same as regular fix, minus .env generation)
        try Remediation.patchFiles(plan: plan, dirPath: dir)

        FileHandle.standardError.write(
            Data("\nEncrypted \(plan.envEntries.count) secrets → \(vaultPath)\n".utf8)
        )

        // Warn about key in gitignore
        let gitignorePath = (dir as NSString).appendingPathComponent(".gitignore")
        if FileManager.default.fileExists(atPath: gitignorePath) {
            let gitignore = (try? String(contentsOfFile: gitignorePath, encoding: .utf8)) ?? ""
            if !gitignore.contains(".pastewatch-key") {
                FileHandle.standardError.write(
                    Data("warning: .pastewatch-key not in .gitignore — key may be committed\n".utf8)
                )
            }
        } else {
            FileHandle.standardError.write(
                Data("warning: no .gitignore found — .pastewatch-key may be committed\n".utf8)
            )
        }
    }

    private func printPlan(_ plan: FixPlan) {
        FileHandle.standardError.write(Data("Fix plan:\n\n".utf8))

        for action in plan.actions {
            let truncated = String(action.secretValue.prefix(16))
            let display = action.secretValue.count > 16 ? "\(truncated)..." : truncated
            let target = action.replacement.isEmpty ? "(moved to \(envFile))" : action.replacement

            let line = "  \(action.filePath):\(action.line)  \(action.type.rawValue) (\(action.severity.rawValue))\n"
            let detail = "    \(display) -> \(target)\n\n"
            FileHandle.standardError.write(Data(line.utf8))
            FileHandle.standardError.write(Data(detail.utf8))
        }

        let envCount = plan.envEntries.count
        FileHandle.standardError.write(Data("  .env file: \(envCount) entries to generate\n".utf8))

        let gitignoreStatus = Remediation.gitignoreContainsEnv(dirPath: dir)
            ? ".env in .gitignore"
            : ".env not in .gitignore (warning)"
        FileHandle.standardError.write(Data("  .gitignore: \(gitignoreStatus)\n\n".utf8))

        let verb = dryRun ? "Run without --dry-run to apply." : ""
        FileHandle.standardError.write(
            Data("\(plan.actions.count) secrets -> \(envCount) env vars. \(verb)\n".utf8)
        )
    }
}
