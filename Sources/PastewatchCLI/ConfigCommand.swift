import ArgumentParser
import Foundation
import PastewatchCore

struct ConfigGroup: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "config",
        abstract: "Configuration management",
        subcommands: [Check.self]
    )
}

extension ConfigGroup {
    struct Check: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Validate configuration files"
        )

        @Option(name: .long, help: "Path to config file (uses resolved config if omitted)")
        var file: String?

        func run() throws {
            let result = ConfigValidator.validate(path: file)
            if result.isValid {
                print("config: valid")
            } else {
                for error in result.errors {
                    FileHandle.standardError.write(Data("error: \(error)\n".utf8))
                }
                throw ExitCode(rawValue: 2)
            }
        }
    }
}
