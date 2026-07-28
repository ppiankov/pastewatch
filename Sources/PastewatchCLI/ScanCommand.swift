import ArgumentParser
import Foundation
import PastewatchCore

struct Scan: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Scan text for sensitive data"
    )

    @Option(name: .long, help: "File to scan (reads from stdin if omitted)")
    var file: String?

    @Option(name: .long, help: "Directory to scan recursively")
    var dir: String?

    @Option(name: .long, help: "Output format: text, json, sarif, markdown")
    var format: OutputFormat = .text

    @Flag(name: .long, help: "Check mode: exit code only, no output modification")
    var check = false

    @Option(name: .long, help: "Path to allowlist file (one value per line)")
    var allowlist: String?

    @Option(name: .long, help: "Path to custom rules JSON file")
    var rules: String?

    @Option(name: .long, help: "Path to baseline file (only report new findings)")
    var baseline: String?

    @Option(name: .long, help: "Filename hint for stdin format-aware parsing")
    var stdinFilename: String?

    @Option(name: .long, help: "Minimum severity for non-zero exit: critical, high, medium, low")
    var failOnSeverity: Severity?

    @Option(name: .long, parsing: .singleValue, help: "Glob pattern to ignore (can be repeated)")
    var ignore: [String] = []

    @Flag(name: .long, help: "Stop at first finding (fast pre-dispatch gate)")
    var bail = false

    @Flag(name: .long, help: "Include gitignored files in exit code (default: warn only)")
    var includeGitignored = false

    @Flag(name: .long, help: "Scan git diff changes (staged by default)")
    var gitDiff = false

    @Flag(name: .long, help: "Include unstaged changes (requires --git-diff)")
    var unstaged = false

    @Flag(name: .long, help: "Scan git commit history for secrets")
    var gitLog = false

    @Option(name: .long, help: "Git revision range (e.g., HEAD~50..HEAD)")
    var range: String?

    @Option(name: .long, help: "Only commits since date (ISO format, requires --git-log)")
    var since: String?

    @Option(name: .long, help: "Scan specific branch (requires --git-log)")
    var branch: String?

    @Option(name: .long, help: "Write report to file instead of stdout")
    var output: String?

    func validate() throws {
        if file != nil && dir != nil {
            throw ValidationError("--file and --dir are mutually exclusive")
        }
        if gitDiff && (file != nil || dir != nil) {
            throw ValidationError("--git-diff is mutually exclusive with --file and --dir")
        }
        if gitLog && (file != nil || dir != nil || gitDiff) {
            throw ValidationError("--git-log is mutually exclusive with --file, --dir, and --git-diff")
        }
        if stdinFilename != nil && (file != nil || dir != nil) {
            throw ValidationError("--stdin-filename is only valid when reading from stdin")
        }
        if unstaged && !gitDiff {
            throw ValidationError("--unstaged requires --git-diff")
        }
        if (range != nil || since != nil || branch != nil) && !gitLog {
            throw ValidationError("--range, --since, and --branch require --git-log")
        }
        if bail && dir == nil && !gitDiff && !gitLog {
            throw ValidationError("--bail is only valid with --dir, --git-diff, or --git-log")
        }
    }

    func run() throws {
        if check && ProcessInfo.processInfo.environment["PW_GUARD"] == "0" { return }

        // WO-574@v4: a present invalid active config must block scanning.
        let config = try requireValidatedConfig()
        let mergedAllowlist: Allowlist
        let customRulesList: [CustomRule]
        let baselineFile: BaselineFile?
        do {
            mergedAllowlist = try loadAllowlist(config: config)
            customRulesList = try loadCustomRules(config: config)
            baselineFile = try loadBaseline()
        } catch let exitCode as ExitCode {
            throw exitCode
        } catch {
            // WO-580@v3: every auxiliary policy read/decode failure uses the operational exit.
            FileHandle.standardError.write(Data("error: scan configuration could not be loaded\n".utf8))
            throw ExitCode(rawValue: ScanExitContract.operationalFailure)
        }

        // Git history scanning mode
        if gitLog {
            try runGitLogScan(config: config, allowlist: mergedAllowlist,
                              customRules: customRulesList, baseline: baselineFile)
            return
        }

        // Git diff scanning mode
        if gitDiff {
            try runGitDiffScan(config: config, allowlist: mergedAllowlist,
                               customRules: customRulesList, baseline: baselineFile)
            return
        }

        // Directory scanning mode
        if let dirPath = dir {
            guard FileManager.default.fileExists(atPath: dirPath) else {
                FileHandle.standardError.write(Data("error: directory not found: \(dirPath)\n".utf8))
                // WO-580@v3: scan setup failures use the stable operational exit.
                throw ExitCode(rawValue: ScanExitContract.operationalFailure)
            }
            try runDirectoryScan(dirPath: dirPath, config: config,
                                 allowlist: mergedAllowlist, customRules: customRulesList,
                                 baseline: baselineFile)
            return
        }

        // Single file or stdin mode
        let input: String
        do {
            input = try readInput()
        } catch let exitCode as ExitCode {
            throw exitCode
        } catch {
            // WO-580@v3: unreadable or invalid UTF-8 input is an operational failure.
            FileHandle.standardError.write(Data("error: input could not be read as UTF-8\n".utf8))
            throw ExitCode(rawValue: ScanExitContract.operationalFailure)
        }

        // WO-131: empty stdin still needs sharedPatternFiles validation before clean success.
        var matches: [DetectedMatch]
        do {
            matches = try scanInput(input, config: config,
                                    allowlist: mergedAllowlist, customRules: customRulesList)
        } catch let error as SharedSecretPatternLoadError {
            // WO-130: single-file and stdin scans fail closed when shared-pattern coverage is unavailable.
            FileHandle.standardError.write(Data("error: shared pattern load failed: \(error.localizedDescription)\n".utf8))
            // WO-580@v3: unavailable scan coverage is an operational failure.
            throw ExitCode(rawValue: ScanExitContract.operationalFailure)
        }
        // WO-577@v3: diagnostics share test/config/inline policy with file guards.
        matches = GuardDecision.evaluate(
            matches: matches,
            content: input,
            config: config,
            // WO-577@v3: a filename selects parsing metadata, not caller trust.
            contentTrust: file != nil ? .trustedFile : .agentControlled,
            minimumSeverity: nil
        ).reportableMatches

        // Apply baseline filtering
        if let bl = baselineFile {
            matches = bl.filterNew(matches: matches, filePath: file ?? "stdin")
        }

        if matches.isEmpty {
            if !check { print(input, terminator: "") }
            return
        }

        try redirectStdoutIfNeeded()

        if check {
            outputCheckMode(matches: matches, filePath: file)
        } else {
            let obfuscated = applyAuthorizedMutations(
                to: input,
                matches: matches,
                site: .cliScan,
                minAdvisorySeverity: .low
            ).text
            outputFindings(matches: matches, filePath: file, obfuscated: obfuscated)
        }
        if shouldFail(matches: matches) {
            // WO-580@v3: preserve the externally consumed findings exit contract.
            throw ExitCode(rawValue: ScanExitContract.findingsDetected)
        }
    }

    private func shouldFail(matches: [DetectedMatch]) -> Bool {
        guard !matches.isEmpty else { return false }
        guard let threshold = failOnSeverity else { return true }
        return matches.contains { $0.effectiveSeverity >= threshold }
    }

    private func redirectStdoutIfNeeded() throws {
        guard let outputPath = output else { return }
        FileManager.default.createFile(atPath: outputPath, contents: nil)
        guard let handle = FileHandle(forWritingAtPath: outputPath) else {
            FileHandle.standardError.write(Data("error: could not write to \(outputPath)\n".utf8))
            // WO-580@v3: output failures use the stable operational exit.
            throw ExitCode(rawValue: ScanExitContract.operationalFailure)
        }
        dup2(handle.fileDescriptor, STDOUT_FILENO)
        handle.closeFile()
    }

    // MARK: - Input loading

    private func loadAllowlist(config: PastewatchConfig) throws -> Allowlist {
        var merged = Allowlist.fromConfig(config)
        if let allowlistPath = allowlist {
            guard FileManager.default.fileExists(atPath: allowlistPath) else {
                FileHandle.standardError.write(Data("error: allowlist file not found: \(allowlistPath)\n".utf8))
                // WO-580@v3: scan configuration failures use the stable operational exit.
                throw ExitCode(rawValue: ScanExitContract.operationalFailure)
            }
            merged = merged.merged(with: try Allowlist.load(from: allowlistPath))
        }
        return merged
    }

    private func loadCustomRules(config: PastewatchConfig) throws -> [CustomRule] {
        var list: [CustomRule] = []
        if !config.customRules.isEmpty {
            list = try CustomRule.compile(config.customRules)
        }
        if let rulesPath = rules {
            guard FileManager.default.fileExists(atPath: rulesPath) else {
                FileHandle.standardError.write(Data("error: rules file not found: \(rulesPath)\n".utf8))
                // WO-580@v3: scan configuration failures use the stable operational exit.
                throw ExitCode(rawValue: ScanExitContract.operationalFailure)
            }
            list.append(contentsOf: try CustomRule.load(from: rulesPath))
        }
        return list
    }

    private func loadBaseline() throws -> BaselineFile? {
        guard let baselinePath = baseline else { return nil }
        guard FileManager.default.fileExists(atPath: baselinePath) else {
            FileHandle.standardError.write(Data("error: baseline file not found: \(baselinePath)\n".utf8))
            // WO-580@v3: scan configuration failures use the stable operational exit.
            throw ExitCode(rawValue: ScanExitContract.operationalFailure)
        }
        return try BaselineFile.load(from: baselinePath)
    }

    private func readInput() throws -> String {
        if let filePath = file {
            guard FileManager.default.fileExists(atPath: filePath) else {
                FileHandle.standardError.write(Data("error: file not found: \(filePath)\n".utf8))
                // WO-580@v3: missing scan input uses the stable operational exit.
                throw ExitCode(rawValue: ScanExitContract.operationalFailure)
            }
            return try String(contentsOfFile: filePath, encoding: .utf8)
        }
        var lines: [String] = []
        while let line = readLine(strippingNewline: false) {
            lines.append(line)
        }
        return lines.joined()
    }

    private func scanInput(
        _ input: String,
        config: PastewatchConfig,
        allowlist: Allowlist,
        customRules: [CustomRule]
    ) throws -> [DetectedMatch] {
        let sourcePath = file ?? stdinFilename

        guard let filePath = sourcePath else {
            // WO-130: plain stdin is the pre-commit hook path, so it must honor sharedPatternFiles.
            let matches = try DetectionRules.scanFileIOOrThrow(
                input,
                config: config,
                customRules: customRules
            )
            return allowlist.filter(matches)
        }

        let ext: String
        if DotenvClassifier.isDotenvFile(URL(fileURLWithPath: filePath).lastPathComponent) {
            ext = "env"
        } else {
            ext = URL(fileURLWithPath: filePath).pathExtension.lowercased()
        }

        // WO-129: single-file and stdin-filename scans must consume sharedPatternFiles.
        let matches = try DirectoryScanner.scanFileContentOrThrow(
            content: input,
            ext: ext,
            relativePath: filePath,
            config: config,
            customRules: customRules
        )
        return allowlist.filter(matches)
    }

    // MARK: - Directory scanning

    private func runDirectoryScan(
        dirPath: String,
        config: PastewatchConfig,
        allowlist: Allowlist,
        customRules: [CustomRule],
        baseline: BaselineFile? = nil
    ) throws {
        let ignoreFile = IgnoreFile.load(from: dirPath)
        let fileResults: [FileScanResult]
        do {
            fileResults = try DirectoryScanner.scan(
                directory: dirPath, config: config,
                ignoreFile: ignoreFile, extraIgnorePatterns: ignore,
                bail: bail
            )
        } catch let error as SharedSecretPatternLoadError {
            // WO-128: git history scans fail closed when shared-pattern coverage is unavailable.
            FileHandle.standardError.write(Data("error: shared pattern load failed: \(error.localizedDescription)\n".utf8))
            // WO-580@v3: unavailable scan coverage is an operational failure.
            throw ExitCode(rawValue: ScanExitContract.operationalFailure)
        }

        // Apply allowlist and custom rules to each file's matches
        var filteredResults: [FileScanResult] = []
        for fr in fileResults {
            var allMatches: [DetectedMatch] = fr.matches

            // Re-scan with allowlist/custom rules if either is provided
            if !allowlist.values.isEmpty || !allowlist.patterns.isEmpty || !customRules.isEmpty {
                allMatches = allowlist.filter(allMatches)
            }

            // WO-577@v3: directory diagnostics use the same trusted-file policy as MCP.
            allMatches = GuardDecision.evaluate(
                matches: allMatches,
                content: fr.content,
                config: config,
                contentTrust: .trustedFile,
                minimumSeverity: nil
            ).reportableMatches

            if !allMatches.isEmpty {
                filteredResults.append(FileScanResult(
                    filePath: fr.filePath,
                    matches: allMatches,
                    content: fr.content,
                    gitignored: fr.gitignored
                ))
            }
        }

        // Apply baseline filtering
        if let bl = baseline {
            filteredResults = bl.filterNewResults(results: filteredResults)
        }

        if filteredResults.isEmpty {
            return
        }

        try redirectStdoutIfNeeded()

        if check {
            outputDirCheckMode(results: filteredResults)
        } else {
            outputDirFindings(results: filteredResults)
        }

        // Only non-gitignored findings count toward exit code (unless --include-gitignored)
        let exitResults = includeGitignored
            ? filteredResults
            : filteredResults.filter { !$0.gitignored }
        let allMatches = exitResults.flatMap { $0.matches }
        if shouldFail(matches: allMatches) {
            // WO-580@v3: preserve the externally consumed findings exit contract.
            throw ExitCode(rawValue: ScanExitContract.findingsDetected)
        }
    }

    // MARK: - Git diff scanning

    private func runGitDiffScan(
        config: PastewatchConfig,
        allowlist: Allowlist,
        customRules: [CustomRule],
        baseline: BaselineFile? = nil
    ) throws {
        let fileResults: [FileScanResult]
        do {
            fileResults = try GitDiffScanner.scan(
                staged: !unstaged, unstaged: unstaged,
                config: config, bail: bail
            )
        } catch let error as GitDiffError {
            FileHandle.standardError.write(Data("error: \(error.description)\n".utf8))
            // WO-580@v3: git scan failures use the stable operational exit.
            throw ExitCode(rawValue: ScanExitContract.operationalFailure)
        } catch let error as SharedSecretPatternLoadError {
            FileHandle.standardError.write(Data("error: shared pattern load failed: \(error.localizedDescription)\n".utf8))
            // WO-580@v3: unavailable scan coverage is an operational failure.
            throw ExitCode(rawValue: ScanExitContract.operationalFailure)
        }

        // Apply allowlist filtering
        var filteredResults: [FileScanResult] = []
        for fr in fileResults {
            var allMatches = fr.matches
            if !allowlist.values.isEmpty || !allowlist.patterns.isEmpty || !customRules.isEmpty {
                allMatches = allowlist.filter(allMatches)
            }
            // WO-577@v3: git-diff diagnostics use the same trusted-file policy as files.
            allMatches = GuardDecision.evaluate(
                matches: allMatches,
                content: fr.content,
                config: config,
                contentTrust: .trustedFile,
                minimumSeverity: nil
            ).reportableMatches

            if !allMatches.isEmpty {
                filteredResults.append(FileScanResult(
                    filePath: fr.filePath,
                    matches: allMatches,
                    content: fr.content,
                    gitignored: fr.gitignored
                ))
            }
        }

        // Apply baseline filtering
        if let bl = baseline {
            filteredResults = bl.filterNewResults(results: filteredResults)
        }

        guard !filteredResults.isEmpty else { return }

        try redirectStdoutIfNeeded()

        if check {
            outputDirCheckMode(results: filteredResults)
        } else {
            outputDirFindings(results: filteredResults)
        }
        let allMatches = filteredResults.flatMap { $0.matches }
        if shouldFail(matches: allMatches) {
            // WO-580@v3: preserve the externally consumed findings exit contract.
            throw ExitCode(rawValue: ScanExitContract.findingsDetected)
        }
    }

    // MARK: - Git log scanning

    private func runGitLogScan(
        config: PastewatchConfig,
        allowlist: Allowlist,
        customRules: [CustomRule],
        baseline: BaselineFile? = nil
    ) throws {
        let result: GitLogScanResult
        do {
            result = try GitHistoryScanner.scan(
                range: range, since: since, branch: branch,
                config: config, bail: bail
            )
        } catch let error as GitDiffError {
            FileHandle.standardError.write(Data("error: \(error.description)\n".utf8))
            // WO-580@v3: git scan failures use the stable operational exit.
            throw ExitCode(rawValue: ScanExitContract.operationalFailure)
        } catch let error as SharedSecretPatternLoadError {
            FileHandle.standardError.write(Data("error: shared pattern load failed: \(error.localizedDescription)\n".utf8))
            // WO-580@v3: unavailable scan coverage is an operational failure.
            throw ExitCode(rawValue: ScanExitContract.operationalFailure)
        }

        // Apply allowlist filtering
        var filteredFindings: [CommitFinding] = []
        for cf in result.findings {
            var allMatches = cf.matches
            if !allowlist.values.isEmpty || !allowlist.patterns.isEmpty || !customRules.isEmpty {
                allMatches = allowlist.filter(allMatches)
            }
            // WO-577@v3: history scanners already apply trusted inline allow; this
            // decision adds test-credential parity without reclassifying content.
            allMatches = GuardDecision.evaluate(
                matches: allMatches,
                content: "",
                config: config,
                contentTrust: .agentControlled,
                minimumSeverity: nil
            ).reportableMatches
            if !allMatches.isEmpty {
                filteredFindings.append(CommitFinding(
                    commitHash: cf.commitHash, author: cf.author,
                    date: cf.date, filePath: cf.filePath, matches: allMatches
                ))
            }
        }

        // Apply baseline filtering
        if let bl = baseline {
            filteredFindings = filteredFindings.compactMap { cf in
                let filtered = bl.filterNew(matches: cf.matches, filePath: cf.filePath)
                guard !filtered.isEmpty else { return nil }
                return CommitFinding(
                    commitHash: cf.commitHash, author: cf.author,
                    date: cf.date, filePath: cf.filePath, matches: filtered
                )
            }
        }

        guard !filteredFindings.isEmpty else { return }

        try redirectStdoutIfNeeded()

        if check {
            outputGitLogCheckMode(findings: filteredFindings, result: result)
        } else {
            outputGitLogFindings(findings: filteredFindings, result: result)
        }
        let allMatches = filteredFindings.flatMap { $0.matches }
        if shouldFail(matches: allMatches) {
            // WO-580@v3: preserve the externally consumed findings exit contract.
            throw ExitCode(rawValue: ScanExitContract.findingsDetected)
        }
    }

    private func outputGitLogFindings(findings: [CommitFinding], result: GitLogScanResult) {
        switch format {
        case .text:
            outputGitLogText(findings: findings, result: result)
        case .json:
            outputGitLogJSON(findings: findings, result: result)
        case .sarif:
            let pairs = findings.map { ($0.filePath, $0.matches) }
            let data = SarifFormatter.formatMultiFile(fileResults: pairs, version: AppVersion.current)
            print(String(data: data, encoding: .utf8)!)
        case .markdown:
            outputGitLogMarkdown(findings: findings, result: result)
        }
    }

    private func outputGitLogCheckMode(findings: [CommitFinding], result: GitLogScanResult) {
        switch format {
        case .text:
            let totalFindings = findings.flatMap { $0.matches }.count
            let commitCount = Set(findings.map { $0.commitHash }).count
            let msg = "\(totalFindings) finding(s) in \(commitCount) commit(s) (scanned \(result.commitsScanned) commits)\n"
            FileHandle.standardError.write(Data(msg.utf8))
        case .json:
            outputGitLogJSON(findings: findings, result: result)
        case .sarif:
            let pairs = findings.map { ($0.filePath, $0.matches) }
            let data = SarifFormatter.formatMultiFile(fileResults: pairs, version: AppVersion.current)
            print(String(data: data, encoding: .utf8)!)
        case .markdown:
            outputGitLogMarkdown(findings: findings, result: result)
        }
    }

    private func outputGitLogText(findings: [CommitFinding], result: GitLogScanResult) {
        // Group by commit
        let grouped = Dictionary(grouping: findings, by: { $0.commitHash })
        let commitOrder = findings.map { $0.commitHash }.reduce(into: [String]()) {
            if !$0.contains($1) { $0.append($1) }
        }

        for hash in commitOrder {
            guard let commitFindings = grouped[hash] else { continue }
            let first = commitFindings[0]
            let shortHash = String(hash.prefix(7))
            print("commit \(shortHash) (\(first.date), \(first.author))")
            for cf in commitFindings {
                for match in cf.matches {
                    print("  \(cf.filePath):\(match.line)  \(match.displayName)  \(match.value)  (\(match.effectiveSeverity.rawValue))")
                }
            }
            print()
        }

        let totalFindings = findings.flatMap { $0.matches }.count
        let commitCount = commitOrder.count
        print("\(totalFindings) finding(s) in \(commitCount) commit(s) (scanned \(result.commitsScanned) commits, \(result.filesScanned) files)")
    }

    private func outputGitLogJSON(findings: [CommitFinding], result: GitLogScanResult) {
        let output = GitLogOutput(
            commitsScanned: result.commitsScanned,
            filesScanned: result.filesScanned,
            findings: findings.map { cf in
                GitLogFindingOutput(
                    commit: cf.commitHash,
                    author: cf.author,
                    date: cf.date,
                    file: cf.filePath,
                    matches: cf.matches.map {
                        GitLogMatchOutput(
                            type: $0.displayName, line: $0.line,
                            severity: $0.effectiveSeverity.rawValue, value: $0.value
                        )
                    }
                )
            }
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        if let data = try? encoder.encode(output) {
            print(String(data: data, encoding: .utf8)!)
        }
    }

    private func outputGitLogMarkdown(findings: [CommitFinding], result: GitLogScanResult) {
        var lines = [
            "| Commit | File | Line | Type | Severity |",
            "|--------|------|------|------|----------|",
        ]
        for cf in findings {
            let shortHash = String(cf.commitHash.prefix(7))
            for match in cf.matches {
                lines.append("| \(shortHash) | \(cf.filePath) | \(match.line) | \(match.displayName) | \(match.effectiveSeverity.rawValue) |")
            }
        }
        let totalFindings = findings.flatMap { $0.matches }.count
        let commitCount = Set(findings.map { $0.commitHash }).count
        lines.append("")
        lines.append("\(totalFindings) finding(s) in \(commitCount) commit(s) (scanned \(result.commitsScanned) commits)")
        print(lines.joined(separator: "\n"))
    }

    private func gitignorePrefix(_ fr: FileScanResult) -> String {
        fr.gitignored ? "[gitignored] " : ""
    }

    private func outputDirCheckMode(results: [FileScanResult]) {
        switch format {
        case .text:
            for fr in results {
                let prefix = gitignorePrefix(fr)
                let summary = Dictionary(grouping: fr.matches, by: { $0.type })
                    .sorted { $0.value.count > $1.value.count }
                    .map { "\($0.key.rawValue): \($0.value.count)" }
                    .joined(separator: ", ")
                FileHandle.standardError.write(Data("\(prefix)\(fr.filePath): \(summary)\n".utf8))
            }
        case .json:
            let output = results.map { fr in
                DirScanFileOutput(
                    file: fr.filePath,
                    findings: fr.matches.map { Finding(type: $0.displayName, value: $0.value, severity: $0.effectiveSeverity.rawValue) },
                    count: fr.matches.count,
                    gitignored: fr.gitignored
                )
            }
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            if let data = try? encoder.encode(output) {
                print(String(data: data, encoding: .utf8)!)
            }
        case .sarif:
            let pairs = results.map { ($0.filePath, $0.matches) }
            let data = SarifFormatter.formatMultiFile(fileResults: pairs, version: AppVersion.current)
            print(String(data: data, encoding: .utf8)!)
        case .markdown:
            print(MarkdownFormatter.formatDirectory(results: results), terminator: "")
        }
    }

    private func outputDirFindings(results: [FileScanResult]) {
        switch format {
        case .text:
            for fr in results {
                let prefix = gitignorePrefix(fr)
                print("--- \(prefix)\(fr.filePath) ---")
                for match in fr.matches {
                    print("  line \(match.line): \(match.displayName): \(match.value)")
                }
            }
        case .json:
            let output = results.map { fr in
                DirScanFileOutput(
                    file: fr.filePath,
                    findings: fr.matches.map { Finding(type: $0.displayName, value: $0.value, severity: $0.effectiveSeverity.rawValue) },
                    count: fr.matches.count,
                    gitignored: fr.gitignored
                )
            }
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            if let data = try? encoder.encode(output) {
                print(String(data: data, encoding: .utf8)!)
            }
        case .sarif:
            let pairs = results.map { ($0.filePath, $0.matches) }
            let data = SarifFormatter.formatMultiFile(fileResults: pairs, version: AppVersion.current)
            print(String(data: data, encoding: .utf8)!)
        case .markdown:
            print(MarkdownFormatter.formatDirectory(results: results), terminator: "")
        }
    }

    // MARK: - Single file/stdin output helpers

    private func outputCheckMode(matches: [DetectedMatch], filePath: String?) {
        switch format {
        case .text:
            let summary = Dictionary(grouping: matches, by: { $0.type })
                .sorted { $0.value.count > $1.value.count }
                .map { "\($0.key.rawValue): \($0.value.count)" }
                .joined(separator: ", ")
            FileHandle.standardError.write(Data("findings: \(summary)\n".utf8))
        case .json:
            let output = ScanOutput(
                findings: matches.map { Finding(type: $0.type.rawValue, value: $0.value, severity: $0.effectiveSeverity.rawValue) },
                count: matches.count,
                obfuscated: nil
            )
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            if let data = try? encoder.encode(output) {
                print(String(data: data, encoding: .utf8)!)
            }
        case .sarif:
            let data = SarifFormatter.format(
                matches: matches, filePath: filePath, version: AppVersion.current
            )
            print(String(data: data, encoding: .utf8)!)
        case .markdown:
            print(MarkdownFormatter.formatSingle(matches: matches, filePath: filePath, obfuscated: nil), terminator: "")
        }
    }

    private func outputFindings(matches: [DetectedMatch], filePath: String?, obfuscated: String) {
        switch format {
        case .text:
            print(obfuscated, terminator: "")
        case .json:
            let output = ScanOutput(
                findings: matches.map { Finding(type: $0.type.rawValue, value: $0.value, severity: $0.effectiveSeverity.rawValue) },
                count: matches.count,
                obfuscated: obfuscated
            )
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            if let data = try? encoder.encode(output) {
                print(String(data: data, encoding: .utf8)!)
            }
        case .sarif:
            let data = SarifFormatter.format(
                matches: matches, filePath: filePath, version: AppVersion.current
            )
            print(String(data: data, encoding: .utf8)!)
        case .markdown:
            print(MarkdownFormatter.formatSingle(matches: matches, filePath: filePath, obfuscated: obfuscated), terminator: "")
        }
    }
}

extension Severity: ExpressibleByArgument {}

enum OutputFormat: String, ExpressibleByArgument {
    case text
    case json
    case sarif
    case markdown
}

struct Finding: Codable {
    let type: String
    let value: String
    let severity: String?
}

struct ScanOutput: Codable {
    let findings: [Finding]
    let count: Int
    let obfuscated: String?
}

struct DirScanFileOutput: Codable {
    let file: String
    let findings: [Finding]
    let count: Int
    let gitignored: Bool
}

struct GitLogOutput: Codable {
    let commitsScanned: Int
    let filesScanned: Int
    let findings: [GitLogFindingOutput]
}

struct GitLogFindingOutput: Codable {
    let commit: String
    let author: String
    let date: String
    let file: String
    let matches: [GitLogMatchOutput]
}

struct GitLogMatchOutput: Codable {
    let type: String
    let line: Int
    let severity: String
    let value: String
}
