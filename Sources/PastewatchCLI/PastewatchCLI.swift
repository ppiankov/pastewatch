import ArgumentParser
import Foundation
import PastewatchCore

// WO-574@v4: every enforcement command shares one fail-closed config boundary.
func requireValidatedConfig() throws -> PastewatchConfig {
    do {
        return try ConfigValidator.resolveValidated().config
    } catch {
        FileHandle.standardError.write(Data("error: \(error.localizedDescription)\n".utf8))
        throw ExitCode(rawValue: 2)
    }
}

@main
struct PastewatchCLI: ParsableCommand {
    // WO-526@v3: expose the structured mutation guard without changing legacy guards.
    static let configuration = CommandConfiguration(
        commandName: "pastewatch-cli",
        abstract: "Scan text for sensitive data patterns",
        version: AppVersion.current,
        subcommands: [Scan.self, Fix.self, Version.self, Init.self, BaselineGroup.self, HookGroup.self, MCP.self, Explain.self, ConfigGroup.self, Guard.self, GuardRead.self, GuardWrite.self, GuardMutation.self, Inventory.self, Doctor.self, Setup.self, Report.self, CanaryGroup.self, VaultGroup.self, Posture.self, Watch.self, DashboardCommand.self, Proxy.self, Launch.self],
        defaultSubcommand: Scan.self
    )
}
