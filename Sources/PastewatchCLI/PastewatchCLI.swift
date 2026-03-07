import ArgumentParser

@main
struct PastewatchCLI: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "pastewatch-cli",
        abstract: "Scan text for sensitive data patterns",
        version: "0.19.2",
        subcommands: [Scan.self, Fix.self, Version.self, Init.self, BaselineGroup.self, HookGroup.self, MCP.self, Explain.self, ConfigGroup.self, Guard.self, GuardRead.self, GuardWrite.self, Inventory.self, Doctor.self, Setup.self, Report.self, CanaryGroup.self, VaultGroup.self, Posture.self],
        defaultSubcommand: Scan.self
    )
}
