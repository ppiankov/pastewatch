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

// WO-658@v2: register the engine-backed redacted remedies without changing existing commands.
// WO-637: register the read-only per-surface diagnostic without changing the default scanner.
@main
struct PastewatchCLI: ParsableCommand {
    // WO-526@v3: expose the structured mutation guard without changing legacy guards.
    static let configuration = CommandConfiguration(
        commandName: "pastewatch-cli",
        abstract: "Scan text for sensitive data patterns",
        version: AppVersion.current,
        // WO-658@v2: read/edit share the core engine; the default scanner and other dispatch remain unchanged.
        // WO-673@v2: the operator valve is distinct from scanner policy configuration.
        // WO-711@v1: operator-selected advisories can produce print-only custom-rule suggestions.
        subcommands: [Scan.self, Fix.self, Version.self, Init.self, BaselineGroup.self, HookGroup.self, MCP.self, Explain.self, ConfigGroup.self, Guard.self, GuardRead.self, GuardWrite.self, GuardMutation.self, Inventory.self, Doctor.self, Check.self, RedactedRead.self, RedactedEditCommand.self, Setup.self, Report.self, CanaryGroup.self, VaultGroup.self, Posture.self, Watch.self, DashboardCommand.self, Proxy.self, Launch.self, AllowBinary.self, SuggestRule.self],
        defaultSubcommand: Scan.self
    )

    // WO-658@v2: new remedy usage errors return 2 without echoing parser arguments; other commands keep their errors.
    static func main() {
        let arguments = Array(CommandLine.arguments.dropFirst())
        do {
            var command = try parseAsRoot(arguments)
            try command.run()
        } catch {
            // WO-711@v1: parser failures can echo rejected arguments, which may contain the very value being protected.
            if arguments.first == "suggest-rule", exitCode(for: error) == .validationFailure {
                FileHandle.standardError.write(Data("Invalid suggest-rule arguments. Use --file with --line, or --stdin. Values are never accepted as arguments. Run suggest-rule --help.\n".utf8))
                exit(withError: ExitCode(64))
            }
            if let name = arguments.first, ["read", "edit"].contains(name), exitCode(for: error) == .validationFailure {
                FileHandle.standardError.write(Data("Invalid read/edit arguments. Use read --help or edit --help. No value was printed.\n".utf8))
                exit(withError: ExitCode(2))
            }
            exit(withError: error)
        }
    }
}
