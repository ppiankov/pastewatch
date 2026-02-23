import ArgumentParser

@main
struct PastewatchCLI: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "pastewatch-cli",
        abstract: "Scan text for sensitive data patterns",
        version: "0.5.0",
        subcommands: [Scan.self, Version.self, Init.self, BaselineGroup.self, HookGroup.self, MCP.self, Explain.self, ConfigGroup.self],
        defaultSubcommand: Scan.self
    )
}
