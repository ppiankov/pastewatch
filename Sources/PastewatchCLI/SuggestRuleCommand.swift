import ArgumentParser
import Foundation
import PastewatchCore

// WO-711@v1: value-bearing input arrives only through a file or stdin, never a command argument.
struct SuggestRule: ParsableCommand {
    static let configuration = CommandConfiguration(commandName: "suggest-rule",
        abstract: "Print a custom rule for an advisory finding without editing configuration")

    @Option(name: .long, help: "Read a file with an advisory finding")
    var file: String?

    @Option(name: .long, help: "Select a 1-based source line with --file")
    var line: Int?

    @Flag(name: .long, help: "Read one source line from stdin")
    var stdin = false

    @Flag(name: .long, help: "Include a literal value pattern with a plaintext and rotation warning")
    var exact = false

    @Option(name: .long, help: "Override the suggested rule name")
    var name: String?

    @Option(name: .long, help: "Output format: json or text")
    var format = "text"

    @Argument(parsing: .captureForPassthrough, help: .hidden)
    var rejectedValues: [String] = []

    // WO-711@v1: chunking bounds temporary allocations while only the first input line is consumed for derivation.
    private static let inputChunkBytes = 4 * 1_024

    // WO-711@v1: errors never echo parser arguments, source content, patterns or configuration values.
    mutating func run() throws {
        guard rejectedValues.isEmpty, (file != nil) != stdin,
              file == nil ? line == nil : (line.map { $0 > 0 } ?? false),
              ["json", "text"].contains(format) else {
            throw ValidationError("Use --file with --line, or --stdin; values are never accepted as arguments.")
        }
        do {
            let config = try ConfigValidator.resolveValidated().config
            let content = try readInput()
            let suggestion = try RuleSuggestion.generate(content: content, config: config, filePath: file,
                                                          line: line ?? 1, exact: exact, name: name)
            let output = try format == "json" ? suggestion.jsonData() : Data(suggestion.text().utf8)
            try FileHandle.standardOutput.write(contentsOf: output + Data("\n".utf8))
        } catch let error as RuleSuggestionError {
            let location = "\(file ?? "stdin"):\(line ?? 1)"
            let message: String
            switch error {
            case .noAdvisoryFinding: message = "no advisory finding on \(location)"
            case .alreadyMasked: message = "finding is already masked on \(location); no rule emitted"
            case .cannotDerive: message = "cannot derive a value-only rule for \(location); use --exact"
            }
            FileHandle.standardError.write(Data((message + "\n").utf8))
            throw ExitCode(1)
        } catch {
            FileHandle.standardError.write(Data("suggest-rule could not inspect the input or configuration; no value was printed.\n".utf8))
            throw ExitCode(2)
        }
    }

    // WO-711@v1: file reads retain scanner limits, and stdin never includes a second source line.
    private func readInput() throws -> String {
        let data: Data
        if let file {
            data = try DetectionRules.readBoundedFileData(atPath: file)
        } else {
            data = try readStdinLine()
        }
        guard let content = String(data: data, encoding: .utf8) else { throw CocoaError(.fileReadInapplicableStringEncoding) }
        return content
    }

    // WO-711@v1: the line limit is enforced while reading so an unbounded stream cannot allocate an unbounded input.
    private func readStdinLine() throws -> Data {
        let maximum = ScanInputLimits.current().maximumLineBytes
        var data = Data()
        while let chunk = try FileHandle.standardInput.read(upToCount: Self.inputChunkBytes), !chunk.isEmpty {
            let firstLine = chunk.prefix { $0 != 0x0A && $0 != 0x0D }
            guard firstLine.count <= maximum - data.count else { throw CocoaError(.fileReadTooLarge) }
            data.append(contentsOf: firstLine)
            if firstLine.count < chunk.count { break }
        }
        return data
    }
}
