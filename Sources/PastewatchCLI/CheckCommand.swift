import ArgumentParser
import Foundation
import PastewatchCore
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

// WO-637: diagnostics accept secret-bearing input only through stdin or a file.
struct Check: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Explain detection and guard, scan, MCP and proxy outcomes without showing the input"
    )

    @Option(name: .long, help: "Read a file instead of stdin")
    var file: String?

    @Flag(name: .long, help: "Output metadata as JSON")
    var json = false

    @Argument(parsing: .captureForPassthrough, help: .hidden)
    var rejectedValues: [String] = []

    // WO-637: generic errors never pass parser, path or scanner messages containing input to stderr.
    mutating func run() throws {
        guard rejectedValues.isEmpty else {
            Self.writeError("Refusing positional values: secrets in arguments enter shell history and are visible in ps. Use stdin or --file.")
            throw ExitCode(64)
        }
        try run(explanation: ConfigExplanation())
    }

    // WO-637: tests inject an isolated explanation without any environment-based policy override.
    func run(explanation: ConfigExplanation) throws {
        do {
            _ = try explanation.validatedConfiguration()
            let input = try readInput()
            let report = try ValueVerdict(content: input, filePath: file, explanation: explanation)
            if json {
                FileHandle.standardOutput.write(try report.jsonData())
                FileHandle.standardOutput.write(Data("\n".utf8))
            } else {
                print(report.text())
            }
        } catch {
            Self.writeError("Check could not complete: verify configuration and readable UTF-8 input within scan limits. No value was printed.")
            throw ExitCode(rawValue: ScanExitContract.operationalFailure)
        }
    }

    // WO-637: use the same bounded readers as scanners and never place the input in argv.
    private func readInput() throws -> String {
        let data: Data
        if let file {
            data = try DetectionRules.readBoundedFileData(atPath: file)
        } else if isatty(STDIN_FILENO) == 1 {
            data = try Self.readTerminal()
        } else {
            data = try DetectionRules.readBoundedInputData(from: .standardInput)
        }
        guard let value = String(data: data, encoding: .utf8) else { throw InputError.invalidInput }
        return value
    }

    // WO-637: terminal failures have no input-bearing descriptions.
    private enum InputError: Error {
        case invalidInput
        case terminalUnavailable
        case cancelled
    }

    // WO-637: disable echo before prompting and restore termios on every normal/error return.
    private static func readTerminal() throws -> Data {
        var original = termios()
        guard tcgetattr(STDIN_FILENO, &original) == 0 else { throw InputError.terminalUnavailable }
        var hidden = original
        hidden.c_lflag &= ~tcflag_t(ECHO | ECHONL | ICANON | ISIG)
        withUnsafeMutableBytes(of: &hidden.c_cc) { bytes in
            bytes[Int(VMIN)] = 1
            bytes[Int(VTIME)] = 0
        }
        guard tcsetattr(STDIN_FILENO, TCSANOW, &hidden) == 0 else { throw InputError.terminalUnavailable }
        defer {
            _ = tcsetattr(STDIN_FILENO, TCSANOW, &original)
            FileHandle.standardError.write(Data("\n".utf8))
        }
        FileHandle.standardError.write(Data("Value (hidden): ".utf8))
        return try readTerminalLine(limit: ScanInputLimits.current().maximumFileBytes)
    }

    // WO-637: handle cancellation as input so Ctrl-C cannot terminate before restoring echo.
    private static func readTerminalLine(limit: Int) throws -> Data {
        var data = Data()
        while true {
            var byte: UInt8 = 0
            let count = read(STDIN_FILENO, &byte, 1)
            if count < 0 && errno == EINTR { continue }
            guard count >= 0 else { throw InputError.terminalUnavailable }
            if count == 0 || byte == 4 || byte == 10 || byte == 13 { return data }
            if byte == 3 || byte == 26 { throw InputError.cancelled }
            if byte == 21 { data.removeAll(keepingCapacity: true); continue }
            if byte == 8 || byte == 127 {
                while let removed = data.popLast(), removed & 0xC0 == 0x80 { }
                continue
            }
            guard data.count < limit else { throw InputError.invalidInput }
            data.append(byte)
        }
    }

    // WO-637: keep diagnostics on stderr and never interpolate the rejected input.
    private static func writeError(_ message: String) {
        FileHandle.standardError.write(Data("\(message)\n".utf8))
    }
}
