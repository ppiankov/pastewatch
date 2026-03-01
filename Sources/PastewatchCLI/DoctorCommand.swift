import ArgumentParser
import Foundation
import PastewatchCore

struct Doctor: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Check installation health and show active configuration"
    )

    @Flag(name: .long, help: "Output results as JSON")
    var json = false

    func run() throws {
        var checks: [(String, String, String)] = [] // (label, status, detail)

        // 1. CLI version and binary path
        let version = "0.16.0"
        let binaryPath = ProcessInfo.processInfo.arguments.first ?? "unknown"
        checks.append(("cli", "ok", "v\(version) at \(binaryPath)"))

        // 2. PATH check — is pastewatch-cli on PATH?
        let pathStatus = checkOnPath()
        checks.append(("path", pathStatus.0, pathStatus.1))

        // 3. Config resolution
        let configChecks = checkConfig()
        checks.append(contentsOf: configChecks)

        // 4. Pre-commit hook
        let hookCheck = checkHook()
        checks.append(("hook", hookCheck.0, hookCheck.1))

        // 5. Allowlist file
        let allowCheck = checkFile(".pastewatch-allow", label: "allowlist")
        checks.append(allowCheck)

        // 6. Ignore file
        let ignoreCheck = checkFile(".pastewatchignore", label: "ignore")
        checks.append(ignoreCheck)

        // 7. Baseline file
        let baselineCheck = checkFile(".pastewatch-baseline.json", label: "baseline")
        checks.append(baselineCheck)

        // 8. MCP server processes
        let mcpCheck = checkMCPProcesses()
        checks.append(("mcp", mcpCheck.0, mcpCheck.1))

        // 9. Homebrew
        let brewCheck = checkHomebrew(currentVersion: version)
        checks.append(("homebrew", brewCheck.0, brewCheck.1))

        if json {
            printJSON(checks)
        } else {
            printText(checks)
        }
    }

    private func checkOnPath() -> (String, String) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/which")
        process.arguments = ["pastewatch-cli"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
            process.waitUntilExit()
            if process.terminationStatus == 0 {
                let data = pipe.fileHandleForReading.readDataToEndOfFile()
                let path = String(data: data, encoding: .utf8)?
                    .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
                return ("ok", path)
            }
        } catch {}
        return ("warn", "pastewatch-cli not found on PATH")
    }

    private func checkConfig() -> [(String, String, String)] {
        var results: [(String, String, String)] = []
        let fm = FileManager.default
        let cwd = fm.currentDirectoryPath

        let projectPath = cwd + "/.pastewatch.json"
        let userPath = PastewatchConfig.configPath.path

        let projectExists = fm.fileExists(atPath: projectPath)
        let userExists = fm.fileExists(atPath: userPath)

        // Which config is active?
        if projectExists {
            results.append(("config", "ok", "project: \(projectPath)"))
            let validation = ConfigValidator.validate(path: projectPath)
            if !validation.isValid {
                for err in validation.errors {
                    results.append(("config", "warn", err))
                }
            }
        } else if userExists {
            results.append(("config", "ok", "user: \(userPath)"))
            let validation = ConfigValidator.validate(path: userPath)
            if !validation.isValid {
                for err in validation.errors {
                    results.append(("config", "warn", err))
                }
            }
        } else {
            results.append(("config", "ok", "defaults (no config file found)"))
        }

        // Show inactive config if it exists
        if projectExists && userExists {
            results.append(("config", "info", "user config exists but overridden: \(userPath)"))
        }

        return results
    }

    private func checkHook() -> (String, String) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/git")
        process.arguments = ["rev-parse", "--git-path", "hooks"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
            process.waitUntilExit()
            guard process.terminationStatus == 0 else {
                return ("info", "not a git repository")
            }
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            var hooksDir = String(data: data, encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            if !hooksDir.hasPrefix("/") {
                hooksDir = FileManager.default.currentDirectoryPath + "/" + hooksDir
            }
            let hookPath = hooksDir + "/pre-commit"
            guard FileManager.default.fileExists(atPath: hookPath) else {
                return ("warn", "no pre-commit hook")
            }
            let content = (try? String(contentsOfFile: hookPath, encoding: .utf8)) ?? ""
            if content.contains("BEGIN PASTEWATCH") {
                return ("ok", "installed at \(hookPath)")
            }
            return ("warn", "pre-commit hook exists but no pastewatch section")
        } catch {
            return ("info", "not a git repository")
        }
    }

    private func checkFile(_ name: String, label: String) -> (String, String, String) {
        let cwd = FileManager.default.currentDirectoryPath
        let path = cwd + "/" + name
        if FileManager.default.fileExists(atPath: path) {
            return (label, "ok", path)
        }
        return (label, "info", "not found")
    }

    private func checkMCPProcesses() -> (String, String) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/pgrep")
        process.arguments = ["-fl", "pastewatch-cli.*mcp"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
            process.waitUntilExit()
            if process.terminationStatus == 0 {
                let data = pipe.fileHandleForReading.readDataToEndOfFile()
                let output = String(data: data, encoding: .utf8)?
                    .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
                let lines = output.split(separator: "\n")
                let pids = lines.compactMap { line -> String? in
                    let parts = line.split(separator: " ", maxSplits: 1)
                    return parts.first.map(String.init)
                }
                return ("ok", "\(pids.count) running (PIDs: \(pids.joined(separator: ", ")))")
            }
        } catch {}
        return ("info", "no MCP server processes found")
    }

    private func checkHomebrew(currentVersion: String) -> (String, String) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = ["brew", "info", "--json=v2", "ppiankov/tap/pastewatch"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
            process.waitUntilExit()
            guard process.terminationStatus == 0 else {
                return ("info", "not installed via Homebrew")
            }
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            if let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               let formulae = json["formulae"] as? [[String: Any]],
               let formula = formulae.first {
                let formulaVersion = formula["versions"] as? [String: Any]
                let stable = formulaVersion?["stable"] as? String ?? "unknown"
                let installed = formula["installed"] as? [[String: Any]]
                let installedVersion = installed?.first?["version"] as? String ?? "not installed"
                var detail = "formula: \(stable), installed: \(installedVersion)"
                if stable != currentVersion {
                    detail += " (formula outdated — CLI is \(currentVersion))"
                    return ("warn", detail)
                }
                if installedVersion != stable {
                    detail += " (run: brew upgrade ppiankov/tap/pastewatch)"
                    return ("warn", detail)
                }
                return ("ok", detail)
            }
        } catch {}
        return ("info", "not installed via Homebrew")
    }

    private func printText(_ checks: [(String, String, String)]) {
        for (label, status, detail) in checks {
            let icon: String
            switch status {
            case "ok": icon = "ok"
            case "warn": icon = "WARN"
            case "info": icon = "--"
            default: icon = "??"
            }
            let paddedLabel = label.padding(toLength: 12, withPad: " ", startingAt: 0)
            print("  [\(icon)] \(paddedLabel) \(detail)")
        }
    }

    private func printJSON(_ checks: [(String, String, String)]) {
        var entries: [String] = []
        for (label, status, detail) in checks {
            let escapedDetail = detail
                .replacingOccurrences(of: "\\", with: "\\\\")
                .replacingOccurrences(of: "\"", with: "\\\"")
            entries.append("    {\"check\": \"\(label)\", \"status\": \"\(status)\", \"detail\": \"\(escapedDetail)\"}")
        }
        print("[\n\(entries.joined(separator: ",\n"))\n]")
    }
}
