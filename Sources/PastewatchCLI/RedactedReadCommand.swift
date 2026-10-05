import ArgumentParser
import Foundation
import PastewatchCore

// WO-658@v2: expose the shared redacted read for sessions without MCP file tools.
struct RedactedRead: ParsableCommand {
    static let configuration = CommandConfiguration(commandName: "read", abstract: "Read a file through restorable secret placeholders")

    @Argument(help: "File path to read")
    var path: String // WO-658@v2: the real path selects file-aware guard policy.

    @Option(name: .long, help: "One-based first redacted line")
    var startLine: Int? // WO-658@v2: windows are selected after whole-file redaction.

    @Option(name: .long, help: "Maximum number of redacted lines")
    var lineCount: Int? // WO-658@v2: omission reads through EOF.

    // WO-658@v2: only the engine decides what may leave; stderr contains consistency and manifest metadata.
    func run() throws {
        guard startLine.map({ $0 > 0 }) ?? true, lineCount.map({ $0 > 0 }) ?? true else {
            FileHandle.standardError.write(Data("Line ranges must be positive.\n".utf8))
            throw ExitCode(2)
        }
        let config = try requireValidatedConfig()
        do {
            let view = try RedactedEdit.read(filePath: path, store: RedactionStore(placeholderPrefix: config.placeholderPrefix),
                                             config: config, startLine: startLine, lineCount: lineCount)
            FileHandle.standardOutput.write(Data(view.content.utf8))
            // WO-658@v2: expose a whole redacted-view token, never a digest of the underlying secrets.
            FileHandle.standardError.write(Data("view-token=\(view.viewToken)\n".utf8))
            for entry in view.redactions {
                FileHandle.standardError.write(Data("placeholder type=\(entry.type) line=\(entry.line) marker=\(entry.placeholder)\n".utf8))
            }
        } catch let error as RedactedEditError {
            FileHandle.standardError.write(Data((error.localizedDescription + "\n").utf8))
            throw ExitCode(1)
        } catch let error as MCPReadRedactionError {
            FileHandle.standardError.write(Data((error.localizedDescription + "\n").utf8))
            throw ExitCode(1)
        } catch {
            FileHandle.standardError.write(Data("Read refused: inspection failed.\n".utf8))
            throw ExitCode(1)
        }
    }
}
