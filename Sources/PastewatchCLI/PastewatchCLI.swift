import ArgumentParser

@main
struct PastewatchCLI: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "pastewatch-cli",
        abstract: "Scan text for sensitive data patterns",
        version: "0.17.3",
        subcommands: [Scan.self, Fix.self, Version.self, Init.self, BaselineGroup.self, HookGroup.self, MCP.self, Explain.self, ConfigGroup.self, Guard.self, GuardRead.self, GuardWrite.self, Inventory.self, Doctor.self],
        defaultSubcommand: Scan.self
    )
}
