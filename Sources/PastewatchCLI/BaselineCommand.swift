import ArgumentParser
import Foundation
import PastewatchCore

struct BaselineGroup: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "baseline",
        abstract: "Manage baseline of known findings",
        subcommands: [Create.self]
    )
}

extension BaselineGroup {
    struct Create: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Create baseline from current scan results"
        )

        @Option(name: .long, help: "Directory to scan")
        var dir: String

        @Option(name: [.short, .long], help: "Output file path")
        var output: String = ".pastewatch-baseline.json"

        func run() throws {
            // WO-574@v4: baseline evidence is invalid when active detector policy cannot load.
            let config = try requireValidatedConfig()

            guard FileManager.default.fileExists(atPath: dir) else {
                FileHandle.standardError.write(Data("error: directory not found: \(dir)\n".utf8))
                throw ExitCode(rawValue: 2)
            }

            let fileResults = try DirectoryScanner.scan(directory: dir, config: config)

            var entries: [BaselineEntry] = []
            for fr in fileResults {
                for match in fr.matches {
                    entries.append(BaselineEntry.from(match: match, filePath: fr.filePath))
                }
            }

            let baseline = BaselineFile(entries: entries)
            try baseline.save(to: output)

            let totalFindings = fileResults.reduce(0) { $0 + $1.matches.count }
            print("baseline created: \(entries.count) entries from \(totalFindings) findings in \(fileResults.count) files")
            print("saved to \(output)")
        }
    }
}
