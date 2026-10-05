import ArgumentParser
import Foundation
import PastewatchCore

// WO-658@v2: the CLI edit surface delegates authorization, restoration and writes to the shared engine.
struct RedactedEditCommand: ParsableCommand {
    static let configuration = CommandConfiguration(commandName: "edit", abstract: "Edit one unique string in a redacted file view")

    @Argument(help: "File path to edit")
    var path: String // WO-658@v2: target mappings and consistency are file-scoped.

    @Option(name: .long, help: "Exact old text from the redacted view; mutually exclusive with --old-file")
    var old: String? // WO-658@v2: input is never included in diagnostics.

    @Option(name: .long, help: "Replacement text; mutually exclusive with --new-file")
    var new: String? // WO-658@v2: the engine rejects newly authored plaintext secrets.

    @Option(name: .long, help: "UTF-8 file containing multiline old text")
    var oldFile: String? // WO-658@v2: payload reads use the existing bounded reader.

    @Option(name: .long, help: "UTF-8 file containing multiline replacement text")
    var newFile: String? // WO-658@v2: no separate mutation or restoration logic lives here.

    @Option(name: .long, help: "Required whole-file redacted view token printed by read")
    var expectViewToken: String? // WO-658@v2: refuse stale placeholder numbering before a disk mutation.

    // WO-658@v2: validate usage without printing arguments, then delegate one consistency-checked edit.
    func run() throws {
        guard let token = expectViewToken,
              token.range(of: #"\A[0-9a-fA-F]{64}\z"#, options: .regularExpression) != nil,
              (old == nil) != (oldFile == nil), (new == nil) != (newFile == nil) else {
            FileHandle.standardError.write(Data("Use exactly one of --old/--old-file and --new/--new-file, with --expect-view-token.\n".utf8))
            throw ExitCode(2)
        }
        let config = try requireValidatedConfig()
        do {
            let request = RedactedEditRequest(filePath: path, oldString: try payload(text: old, file: oldFile),
                                              newString: try payload(text: new, file: newFile), expectedViewToken: token)
            let result = try RedactedEdit.edit(request, store: RedactionStore(placeholderPrefix: config.placeholderPrefix), config: config)
            print("Edited: linesChanged=\(result.linesChanged) redactions=\(result.redactions)")
        } catch let error as RedactedEditError {
            FileHandle.standardError.write(Data((error.localizedDescription + "\n").utf8))
            throw ExitCode(1)
        } catch let error as MCPReadRedactionError {
            FileHandle.standardError.write(Data((error.localizedDescription + "\n").utf8))
            throw ExitCode(1)
        } catch {
            FileHandle.standardError.write(Data("Edit refused: payload or inspection failed.\n".utf8))
            throw ExitCode(1)
        }
    }

    // WO-658@v2: payload transport is bounded UTF-8 only, never an alternate secret rewrite path.
    private func payload(text: String?, file: String?) throws -> String {
        if let text { return text }
        guard let file,
              let content = String(data: try DetectionRules.readBoundedFileData(atPath: file), encoding: .utf8) else {
            throw RedactedEditError.inspectionFailed
        }
        return content
    }
}
