import ArgumentParser
import Foundation
import PastewatchCore

struct Scan: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Scan text for sensitive data"
    )

    @Option(name: .long, help: "File to scan (reads from stdin if omitted)")
    var file: String?

    @Option(name: .long, help: "Output format: text, json")
    var format: OutputFormat = .text

    @Flag(name: .long, help: "Check mode: exit code only, no output modification")
    var check = false

    func run() throws {
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

        let config = PastewatchConfig.defaultConfig
        let matches = DetectionRules.scan(input, config: config)

        if matches.isEmpty {
            if !check {
                print(input, terminator: "")
            }
            return
        }

        // Findings detected
        if check {
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
                let data = try encoder.encode(output)
                print(String(data: data, encoding: .utf8)!)
            }
            Darwin.exit(6)
        }

        // Default: output obfuscated text
        let obfuscated = Obfuscator.obfuscate(input, matches: matches)

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
            let data = try encoder.encode(output)
            print(String(data: data, encoding: .utf8)!)
        }
        Darwin.exit(6)
    }
}

enum OutputFormat: String, ExpressibleByArgument {
    case text
    case json
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
