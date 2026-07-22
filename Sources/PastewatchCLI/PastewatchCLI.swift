import ArgumentParser
import PastewatchCore

@main
struct PastewatchCLI: ParsableCommand {
    // WO-526@v2: expose the structured mutation guard without changing legacy guards.
    static let configuration = CommandConfiguration(
        commandName: "pastewatch-cli",
        abstract: "Scan text for sensitive data patterns",
        version: AppVersion.current,
        subcommands: [Scan.self, Fix.self, Version.self, Init.self, BaselineGroup.self, HookGroup.self, MCP.self, Explain.self, ConfigGroup.self, Guard.self, GuardRead.self, GuardWrite.self, GuardMutation.self, Inventory.self, Doctor.self, Setup.self, Report.self, CanaryGroup.self, VaultGroup.self, Posture.self, Watch.self, DashboardCommand.self, Proxy.self, Launch.self],
        defaultSubcommand: Scan.self
    )
}
