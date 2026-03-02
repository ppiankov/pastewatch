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

    @Flag(name: .long, help: "Scan git diff changes (staged by default)")
    var gitDiff = false

    @Flag(name: .long, help: "Include unstaged changes (requires --git-diff)")
    var unstaged = false

    @Option(name: .long, help: "Write report to file instead of stdout")
    var output: String?

    func validate() throws {
        if file != nil && dir != nil {
            throw ValidationError("--file and --dir are mutually exclusive")
        }
        if gitDiff && (file != nil || dir != nil) {
            throw ValidationError("--git-diff is mutually exclusive with --file and --dir")
        }
        if stdinFilename != nil && (file != nil || dir != nil) {
            throw ValidationError("--stdin-filename is only valid when reading from stdin")
        }
        if unstaged && !gitDiff {
            throw ValidationError("--unstaged requires --git-diff")
        }
        if bail && dir == nil && !gitDiff {
            throw ValidationError("--bail is only valid with --dir or --git-diff")
        }
    }

    func run() throws {
        if check && ProcessInfo.processInfo.environment["PW_GUARD"] == "0" { return }

        let config = PastewatchConfig.resolve()
        let mergedAllowlist = try loadAllowlist(config: config)
        let customRulesList = try loadCustomRules(config: config)
        let baselineFile = try loadBaseline()

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
                throw ExitCode(rawValue: 2)
            }
            try runDirectoryScan(dirPath: dirPath, config: config,
                                 allowlist: mergedAllowlist, customRules: customRulesList,
                                 baseline: baselineFile)
            return
        }

        // Single file or stdin mode
        let input = try readInput()
        guard !input.isEmpty else { return }

        var matches = scanInput(input, config: config,
                                allowlist: mergedAllowlist, customRules: customRulesList)
        matches = Allowlist.filterInlineAllow(matches: matches, content: input)

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
            let obfuscated = Obfuscator.obfuscate(input, matches: matches)
            outputFindings(matches: matches, filePath: file, obfuscated: obfuscated)
        }
        if shouldFail(matches: matches) {
            throw ExitCode(rawValue: 6)
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
            throw ExitCode(rawValue: 2)
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
                throw ExitCode(rawValue: 2)
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
                throw ExitCode(rawValue: 2)
            }
            list.append(contentsOf: try CustomRule.load(from: rulesPath))
        }
        return list
    }

    private func loadBaseline() throws -> BaselineFile? {
        guard let baselinePath = baseline else { return nil }
        guard FileManager.default.fileExists(atPath: baselinePath) else {
            FileHandle.standardError.write(Data("error: baseline file not found: \(baselinePath)\n".utf8))
            throw ExitCode(rawValue: 2)
        }
        return try BaselineFile.load(from: baselinePath)
    }

    private func readInput() throws -> String {
        if let filePath = file {
            guard FileManager.default.fileExists(atPath: filePath) else {
                FileHandle.standardError.write(Data("error: file not found: \(filePath)\n".utf8))
                throw ExitCode(rawValue: 2)
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
    ) -> [DetectedMatch] {
        let sourcePath = file ?? stdinFilename

        guard let filePath = sourcePath else {
            return DetectionRules.scan(input, config: config,
                                       allowlist: allowlist, customRules: customRules)
        }

        let ext: String
        if filePath.hasSuffix(".env") || URL(fileURLWithPath: filePath).lastPathComponent == ".env" {
            ext = "env"
        } else {
            ext = URL(fileURLWithPath: filePath).pathExtension.lowercased()
        }

        guard let parser = parserForExtension(ext) else {
            return DetectionRules.scan(input, config: config,
                                       allowlist: allowlist, customRules: customRules)
        }

        let parsedValues = parser.parseValues(from: input)
        var collected: [DetectedMatch] = []
        for pv in parsedValues {
            let valueMatches = DetectionRules.scan(
                pv.value, config: config,
                allowlist: allowlist, customRules: customRules
            )
            for vm in valueMatches {
                collected.append(DetectedMatch(
                    type: vm.type, value: vm.value, range: vm.range,
                    line: pv.line, filePath: file, customRuleName: vm.customRuleName,
                    customSeverity: vm.customSeverity
                ))
            }
        }
        return collected
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
        let fileResults = try DirectoryScanner.scan(
            directory: dirPath, config: config,
            ignoreFile: ignoreFile, extraIgnorePatterns: ignore,
            bail: bail
        )

        // Apply allowlist and custom rules to each file's matches
        var filteredResults: [FileScanResult] = []
        for fr in fileResults {
            var allMatches: [DetectedMatch] = fr.matches

            // Re-scan with allowlist/custom rules if either is provided
            if !allowlist.values.isEmpty || !allowlist.patterns.isEmpty || !customRules.isEmpty {
                allMatches = allowlist.filter(allMatches)
            }

            if !allMatches.isEmpty {
                filteredResults.append(FileScanResult(
                    filePath: fr.filePath, matches: allMatches, content: fr.content
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
        let allMatches = filteredResults.flatMap { $0.matches }
        if shouldFail(matches: allMatches) {
            throw ExitCode(rawValue: 6)
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
            throw ExitCode(rawValue: 2)
        }

        // Apply allowlist filtering
        var filteredResults: [FileScanResult] = []
        for fr in fileResults {
            var allMatches = fr.matches
            if !allowlist.values.isEmpty || !allowlist.patterns.isEmpty || !customRules.isEmpty {
                allMatches = allowlist.filter(allMatches)
            }
            if !allMatches.isEmpty {
                filteredResults.append(FileScanResult(
                    filePath: fr.filePath, matches: allMatches, content: fr.content
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
            throw ExitCode(rawValue: 6)
        }
    }

    private func outputDirCheckMode(results: [FileScanResult]) {
        switch format {
        case .text:
            for fr in results {
                let summary = Dictionary(grouping: fr.matches, by: { $0.type })
                    .sorted { $0.value.count > $1.value.count }
                    .map { "\($0.key.rawValue): \($0.value.count)" }
                    .joined(separator: ", ")
                FileHandle.standardError.write(Data("\(fr.filePath): \(summary)\n".utf8))
            }
        case .json:
            let output = results.map { fr in
                DirScanFileOutput(
                    file: fr.filePath,
                    findings: fr.matches.map { Finding(type: $0.displayName, value: $0.value, severity: $0.effectiveSeverity.rawValue) },
                    count: fr.matches.count
                )
            }
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            if let data = try? encoder.encode(output) {
                print(String(data: data, encoding: .utf8)!)
            }
        case .sarif:
            let pairs = results.map { ($0.filePath, $0.matches) }
            let data = SarifFormatter.formatMultiFile(fileResults: pairs, version: "0.17.3")
            print(String(data: data, encoding: .utf8)!)
        case .markdown:
            print(MarkdownFormatter.formatDirectory(results: results), terminator: "")
        }
    }

    private func outputDirFindings(results: [FileScanResult]) {
        switch format {
        case .text:
            for fr in results {
                print("--- \(fr.filePath) ---")
                for match in fr.matches {
                    print("  line \(match.line): \(match.displayName): \(match.value)")
                }
            }
        case .json:
            let output = results.map { fr in
                DirScanFileOutput(
                    file: fr.filePath,
                    findings: fr.matches.map { Finding(type: $0.displayName, value: $0.value, severity: $0.effectiveSeverity.rawValue) },
                    count: fr.matches.count
                )
            }
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            if let data = try? encoder.encode(output) {
                print(String(data: data, encoding: .utf8)!)
            }
        case .sarif:
            let pairs = results.map { ($0.filePath, $0.matches) }
            let data = SarifFormatter.formatMultiFile(fileResults: pairs, version: "0.17.3")
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
                matches: matches, filePath: filePath, version: "0.17.3"
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
                matches: matches, filePath: filePath, version: "0.17.3"
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
}
