import ArgumentParser
import Foundation
import PastewatchCore

struct Inventory: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Generate a structured inventory of all detected secrets"
    )

    @Option(name: .long, help: "Directory to scan")
    var dir: String

    @Option(name: .long, help: "Output format: text, json, markdown, csv")
    var format: InventoryFormat = .text

    @Option(name: .long, help: "Write report to file instead of stdout")
    var output: String?

    @Option(name: .long, help: "Compare with previous inventory JSON file")
    var compare: String?

    @Option(name: .long, help: "Path to allowlist file (one value per line)")
    var allowlist: String?

    @Option(name: .long, help: "Path to custom rules JSON file")
    var rules: String?

    @Option(name: .long, parsing: .singleValue, help: "Glob pattern to ignore (can be repeated)")
    var ignore: [String] = []

    func run() throws {
        guard FileManager.default.fileExists(atPath: dir) else {
            FileHandle.standardError.write(Data("error: directory not found: \(dir)\n".utf8))
            throw ExitCode(rawValue: 2)
        }

        let config = PastewatchConfig.resolve()
        let mergedAllowlist = try loadAllowlist(config: config)
        let customRulesList = try loadCustomRules(config: config)

        let ignoreFile = IgnoreFile.load(from: dir)
        let fileResults = try DirectoryScanner.scan(
            directory: dir, config: config,
            ignoreFile: ignoreFile, extraIgnorePatterns: ignore
        )

        // Apply allowlist filtering
        var filteredResults: [FileScanResult] = []
        for fr in fileResults {
            var matches = fr.matches
            if !mergedAllowlist.values.isEmpty || !mergedAllowlist.patterns.isEmpty || !customRulesList.isEmpty {
                matches = mergedAllowlist.filter(matches)
            }
            if !matches.isEmpty {
                filteredResults.append(FileScanResult(
                    filePath: fr.filePath, matches: matches, content: fr.content
                ))
            }
        }

        let report = InventoryReport.build(from: filteredResults, directory: dir)

        try redirectStdoutIfNeeded()

        // Output report
        let reportOutput: String
        switch format {
        case .text: reportOutput = InventoryFormatter.formatText(report)
        case .json: reportOutput = InventoryFormatter.formatJSON(report)
        case .markdown: reportOutput = InventoryFormatter.formatMarkdown(report)
        case .csv: reportOutput = InventoryFormatter.formatCSV(report)
        }
        print(reportOutput, terminator: "")

        // Compare mode
        if let comparePath = compare {
            try runCompare(comparePath: comparePath, report: report)
        }
    }

    private func runCompare(comparePath: String, report: InventoryReport) throws {
        guard FileManager.default.fileExists(atPath: comparePath) else {
            FileHandle.standardError.write(Data("error: compare file not found: \(comparePath)\n".utf8))
            throw ExitCode(rawValue: 2)
        }
        let previous: InventoryReport
        do {
            previous = try InventoryReport.load(from: comparePath)
        } catch {
            FileHandle.standardError.write(Data("error: invalid inventory file: \(comparePath)\n".utf8))
            throw ExitCode(rawValue: 2)
        }
        let delta = InventoryReport.compare(current: report, previous: previous)
        let deltaOutput = formatDelta(delta)
        if !deltaOutput.isEmpty {
            print(deltaOutput, terminator: "")
        }
    }

    private func formatDelta(_ delta: InventoryDelta) -> String {
        switch format {
        case .text: return InventoryFormatter.formatDeltaText(delta)
        case .json:
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            if let data = try? encoder.encode(delta),
               let str = String(data: data, encoding: .utf8) {
                return "\n" + str
            }
            return ""
        case .markdown: return InventoryFormatter.formatDeltaMarkdown(delta)
        case .csv: return ""
        }
    }

    // MARK: - Helpers

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
}

enum InventoryFormat: String, ExpressibleByArgument {
    case text
    case json
    case markdown
    case csv
}
