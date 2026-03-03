import ArgumentParser
import Foundation
import PastewatchCore

struct CanaryGroup: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "canary",
        abstract: "Canary secrets for AI agent leak detection",
        subcommands: [Generate.self, Verify.self, Check.self]
    )
}

extension CanaryGroup {
    struct Generate: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Generate canary tokens for leak detection"
        )

        @Option(name: .long, help: "Prefix embedded in canary values for source tracking (default: canary)")
        var prefix: String = "canary"

        @Option(name: .long, help: "Output file path (default: .pastewatch-canaries.json)")
        var output: String = ".pastewatch-canaries.json"

        func run() throws {
            let manifest = CanaryGenerator.generate(prefix: prefix)

            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            let data = try encoder.encode(manifest)
            try data.write(to: URL(fileURLWithPath: output))

            print("Generated \(manifest.canaries.count) canary tokens → \(output)")
            for token in manifest.canaries {
                print("  \(token.type): \(token.value)")
            }
        }
    }

    struct Verify: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Verify canaries are detected by pastewatch"
        )

        @Option(name: .long, help: "Path to canary manifest (default: .pastewatch-canaries.json)")
        var file: String = ".pastewatch-canaries.json"

        func validate() throws {
            guard FileManager.default.fileExists(atPath: file) else {
                throw ValidationError("canary manifest not found: \(file)")
            }
        }

        func run() throws {
            let data = try Data(contentsOf: URL(fileURLWithPath: file))
            let manifest = try JSONDecoder().decode(CanaryManifest.self, from: data)
            let results = CanaryGenerator.verify(manifest: manifest)

            var allPassed = true
            for result in results {
                let status = result.detected ? "PASS" : "FAIL"
                let detail = result.detectedAs.map { " (as \($0))" } ?? ""
                print("  [\(status)] \(result.type)\(detail)")
                if !result.detected { allPassed = false }
            }

            if allPassed {
                print("\nAll \(results.count) canaries detected.")
            } else {
                let failed = results.filter { !$0.detected }.count
                FileHandle.standardError.write(
                    Data("\(failed) canary type(s) not detected\n".utf8)
                )
                throw ExitCode(rawValue: 1)
            }
        }
    }

    struct Check: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Check if canary values leaked in external logs"
        )

        @Option(name: .long, help: "Path to log file to search (CloudTrail JSON, any text)")
        var log: String

        @Option(name: .long, help: "Path to canary manifest (default: .pastewatch-canaries.json)")
        var file: String = ".pastewatch-canaries.json"

        func validate() throws {
            guard FileManager.default.fileExists(atPath: file) else {
                throw ValidationError("canary manifest not found: \(file)")
            }
            guard FileManager.default.fileExists(atPath: log) else {
                throw ValidationError("log file not found: \(log)")
            }
        }

        func run() throws {
            let manifestData = try Data(contentsOf: URL(fileURLWithPath: file))
            let manifest = try JSONDecoder().decode(CanaryManifest.self, from: manifestData)
            let logContent = try String(contentsOfFile: log, encoding: .utf8)
            let results = CanaryGenerator.checkLog(manifest: manifest, logContent: logContent)

            var anyLeaked = false
            for result in results {
                let status = result.found ? "LEAKED" : "clean"
                print("  [\(status)] \(result.type)")
                if result.found { anyLeaked = true }
            }

            if anyLeaked {
                let leaked = results.filter { $0.found }.count
                FileHandle.standardError.write(
                    Data("WARNING: \(leaked) canary value(s) found in log — secrets leaked\n".utf8)
                )
                throw ExitCode(rawValue: 1)
            } else {
                print("\nNo canary values found in log. Clean.")
            }
        }
    }
}
