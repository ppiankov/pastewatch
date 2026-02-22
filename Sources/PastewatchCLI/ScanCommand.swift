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

    @Option(name: .long, help: "Output format: text, json, sarif")
    var format: OutputFormat = .text

    @Flag(name: .long, help: "Check mode: exit code only, no output modification")
    var check = false

    @Option(name: .long, help: "Path to allowlist file (one value per line)")
    var allowlist: String?

    @Option(name: .long, help: "Path to custom rules JSON file")
    var rules: String?

    func validate() throws {
        if file != nil && dir != nil {
            throw ValidationError("--file and --dir are mutually exclusive")
        }
    }

    func run() throws {
        let config = PastewatchConfig.defaultConfig

        // Load allowlist
        var mergedAllowlist = Allowlist.fromConfig(config)
        if let allowlistPath = allowlist {
            guard FileManager.default.fileExists(atPath: allowlistPath) else {
                FileHandle.standardError.write(Data("error: allowlist file not found: \(allowlistPath)\n".utf8))
                throw ExitCode(rawValue: 2)
            }
            let fileAllowlist = try Allowlist.load(from: allowlistPath)
            mergedAllowlist = mergedAllowlist.merged(with: fileAllowlist)
        }

        // Load custom rules
        var customRulesList: [CustomRule] = []
        if !config.customRules.isEmpty {
            customRulesList = try CustomRule.compile(config.customRules)
        }
        if let rulesPath = rules {
            guard FileManager.default.fileExists(atPath: rulesPath) else {
                FileHandle.standardError.write(Data("error: rules file not found: \(rulesPath)\n".utf8))
                throw ExitCode(rawValue: 2)
            }
            let fileRules = try CustomRule.load(from: rulesPath)
            customRulesList.append(contentsOf: fileRules)
        }

        // Directory scanning mode
        if let dirPath = dir {
            guard FileManager.default.fileExists(atPath: dirPath) else {
                FileHandle.standardError.write(Data("error: directory not found: \(dirPath)\n".utf8))
                throw ExitCode(rawValue: 2)
            }
            try runDirectoryScan(dirPath: dirPath, config: config,
                                 allowlist: mergedAllowlist, customRules: customRulesList)
            return
        }

        // Single file or stdin mode
        let input: String
        if let filePath = file {
            guard FileManager.default.fileExists(atPath: filePath) else {
                FileHandle.standardError.write(Data("error: file not found: \(filePath)\n".utf8))
                throw ExitCode(rawValue: 2)
            }
            input = try String(contentsOfFile: filePath, encoding: .utf8)
        } else {
            var lines: [String] = []
            while let line = readLine(strippingNewline: false) {
                lines.append(line)
            }
            input = lines.joined()
        }

        guard !input.isEmpty else { return }

        let matches: [DetectedMatch]
        if let filePath = file {
            let ext: String
            if filePath.hasSuffix(".env") || URL(fileURLWithPath: filePath).lastPathComponent == ".env" {
                ext = "env"
            } else {
                ext = URL(fileURLWithPath: filePath).pathExtension.lowercased()
            }

            if let parser = parserForExtension(ext) {
                let parsedValues = parser.parseValues(from: input)
                var collected: [DetectedMatch] = []
                for pv in parsedValues {
                    let valueMatches = DetectionRules.scan(
                        pv.value, config: config,
                        allowlist: mergedAllowlist, customRules: customRulesList
                    )
                    for vm in valueMatches {
                        collected.append(DetectedMatch(
                            type: vm.type,
                            value: vm.value,
                            range: vm.range,
                            line: pv.line,
                            filePath: filePath,
                            customRuleName: vm.customRuleName
                        ))
                    }
                }
                matches = collected
            } else {
                matches = DetectionRules.scan(
                    input, config: config,
                    allowlist: mergedAllowlist, customRules: customRulesList
                )
            }
        } else {
            matches = DetectionRules.scan(
                input, config: config,
                allowlist: mergedAllowlist, customRules: customRulesList
            )
        }

        if matches.isEmpty {
            if !check {
                print(input, terminator: "")
            }
            return
        }

        // Findings detected
        if check {
            outputCheckMode(matches: matches, filePath: file)
        } else {
            let obfuscated = Obfuscator.obfuscate(input, matches: matches)
            outputFindings(matches: matches, filePath: file, obfuscated: obfuscated)
        }
        Darwin.exit(6)
    }

    // MARK: - Directory scanning

    private func runDirectoryScan(
        dirPath: String,
        config: PastewatchConfig,
        allowlist: Allowlist,
        customRules: [CustomRule]
    ) throws {
        let fileResults = try DirectoryScanner.scan(directory: dirPath, config: config)

        // Apply allowlist and custom rules to each file's matches
        var filteredResults: [FileScanResult] = []
        for fr in fileResults {
            var allMatches: [DetectedMatch] = fr.matches

            // Re-scan with allowlist/custom rules if either is provided
            if !allowlist.values.isEmpty || !customRules.isEmpty {
                allMatches = allowlist.filter(allMatches)
            }

            if !allMatches.isEmpty {
                filteredResults.append(FileScanResult(
                    filePath: fr.filePath, matches: allMatches, content: fr.content
                ))
            }
        }

        if filteredResults.isEmpty {
            return
        }

        if check {
            outputDirCheckMode(results: filteredResults)
        } else {
            outputDirFindings(results: filteredResults)
        }
        Darwin.exit(6)
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
                    findings: fr.matches.map { Finding(type: $0.displayName, value: $0.value) },
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
            let data = SarifFormatter.formatMultiFile(fileResults: pairs, version: "0.3.0")
            print(String(data: data, encoding: .utf8)!)
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
                    findings: fr.matches.map { Finding(type: $0.displayName, value: $0.value) },
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
            let data = SarifFormatter.formatMultiFile(fileResults: pairs, version: "0.3.0")
            print(String(data: data, encoding: .utf8)!)
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
                findings: matches.map { Finding(type: $0.type.rawValue, value: $0.value) },
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
                matches: matches, filePath: filePath, version: "0.3.0"
            )
            print(String(data: data, encoding: .utf8)!)
        }
    }

    private func outputFindings(matches: [DetectedMatch], filePath: String?, obfuscated: String) {
        switch format {
        case .text:
            print(obfuscated, terminator: "")
        case .json:
            let output = ScanOutput(
                findings: matches.map { Finding(type: $0.type.rawValue, value: $0.value) },
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
                matches: matches, filePath: filePath, version: "0.3.0"
            )
            print(String(data: data, encoding: .utf8)!)
        }
    }
}

enum OutputFormat: String, ExpressibleByArgument {
    case text
    case json
    case sarif
}

struct Finding: Codable {
    let type: String
    let value: String
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
