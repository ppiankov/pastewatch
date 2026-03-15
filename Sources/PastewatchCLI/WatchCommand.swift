import ArgumentParser
import Foundation
import PastewatchCore

struct Watch: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Watch directory for file changes and scan continuously"
    )

    @Option(name: .long, help: "Directory to watch")
    var dir: String = "."

    @Option(name: .long, help: "Minimum severity to report: critical, high, medium, low")
    var severity: Severity?

    @Flag(name: .long, help: "Output newline-delimited JSON")
    var json = false

    func run() throws {
        let fm = FileManager.default
        let dirPath = (dir as NSString).standardizingPath
        guard fm.fileExists(atPath: dirPath) else {
            FileHandle.standardError.write(Data("error: directory not found: \(dirPath)\n".utf8))
            throw ExitCode(rawValue: 2)
        }

        let config = PastewatchConfig.resolve()

        if !json {
            FileHandle.standardError.write(Data("watching \(dirPath) (ctrl-c to stop)\n".utf8))
        }

        let watcher = FileWatcher(
            directory: dirPath,
            config: config,
            severity: severity,
            jsonOutput: json
        )

        // Handle SIGINT for graceful shutdown
        signal(SIGINT) { _ in
            FileHandle.standardError.write(Data("\nstopped.\n".utf8))
            Darwin.exit(0)
        }

        watcher.start()
    }
}
