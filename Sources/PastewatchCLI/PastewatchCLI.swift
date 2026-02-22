import ArgumentParser

@main
struct PastewatchCLI: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "pastewatch-cli",
        abstract: "Scan text for sensitive data patterns",
        version: "0.3.0",
        subcommands: [Scan.self, Version.self],
        defaultSubcommand: Scan.self
    )
}
