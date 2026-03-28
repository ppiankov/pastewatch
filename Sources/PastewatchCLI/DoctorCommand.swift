import ArgumentParser
import Foundation
import PastewatchCore

private struct CheckResult {
    let check: String
    let status: String
    let detail: String
}

struct Doctor: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Check installation health and show active configuration"
    )

    @Flag(name: .long, help: "Output results as JSON")
    var json = false

    func run() throws {
        var checks: [CheckResult] = []

        // 1. CLI version and binary path
        let version = "0.25.8"
        let binaryPath = ProcessInfo.processInfo.arguments.first ?? "unknown"
        checks.append(CheckResult(check: "cli", status: "ok", detail: "v\(version) at \(binaryPath)"))

        // 2. PATH check — is pastewatch-cli on PATH?
        checks.append(checkOnPath())

        // 3. Config resolution
        checks.append(contentsOf: checkConfig())

        // 4. Pre-commit hook
        let hookResult = checkHook()
        checks.append(CheckResult(check: "hook", status: hookResult.status, detail: hookResult.detail))

        // 5. Allowlist file
        checks.append(checkFile(".pastewatch-allow", label: "allowlist"))

        // 6. Ignore file
        checks.append(checkFile(".pastewatchignore", label: "ignore"))

        // 7. Baseline file
        checks.append(checkFile(".pastewatch-baseline.json", label: "baseline"))

        // 8. MCP server processes
        checks.append(contentsOf: checkMCPProcesses())

        // 9. Homebrew
        let brewResult = checkHomebrew(currentVersion: version)
        checks.append(CheckResult(check: "homebrew", status: brewResult.status, detail: brewResult.detail))

        if json {
            printJSON(checks)
        } else {
            printText(checks)
        }
    }

    private func checkOnPath() -> CheckResult {
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
                return CheckResult(check: "path", status: "ok", detail: path)
            }
        } catch {}
        return CheckResult(check: "path", status: "warn", detail: "pastewatch-cli not found on PATH")
    }

    private func checkConfig() -> [CheckResult] {
        var results: [CheckResult] = []
        let fm = FileManager.default
        let cwd = fm.currentDirectoryPath

        let systemPath = PastewatchConfig.systemConfigPath
        let projectPath = cwd + "/.pastewatch.json"
        let userPath = PastewatchConfig.configPath.path

        let systemExists = fm.fileExists(atPath: systemPath)
        let projectExists = fm.fileExists(atPath: projectPath)
        let userExists = fm.fileExists(atPath: userPath)

        if systemExists {
            results.append(CheckResult(check: "config", status: "ok", detail: "system (admin): \(systemPath)"))
            let validation = ConfigValidator.validate(path: systemPath)
            if !validation.isValid {
                for err in validation.errors {
                    results.append(CheckResult(check: "config", status: "warn", detail: err))
                }
            }
            if projectExists {
                results.append(CheckResult(
                    check: "config", status: "info",
                    detail: "project config exists but overridden by system: \(projectPath)"
                ))
            }
            if userExists {
                results.append(CheckResult(
                    check: "config", status: "info",
                    detail: "user config exists but overridden by system: \(userPath)"
                ))
            }
        } else if projectExists {
            results.append(CheckResult(check: "config", status: "ok", detail: "project: \(projectPath)"))
            let validation = ConfigValidator.validate(path: projectPath)
            if !validation.isValid {
                for err in validation.errors {
                    results.append(CheckResult(check: "config", status: "warn", detail: err))
                }
            }
        } else if userExists {
            results.append(CheckResult(check: "config", status: "ok", detail: "user: \(userPath)"))
            let validation = ConfigValidator.validate(path: userPath)
            if !validation.isValid {
                for err in validation.errors {
                    results.append(CheckResult(check: "config", status: "warn", detail: err))
                }
            }
        } else {
            results.append(CheckResult(check: "config", status: "ok", detail: "defaults (no config file found)"))
        }

        if !systemExists && projectExists && userExists {
            results.append(CheckResult(check: "config", status: "info", detail: "user config exists but overridden: \(userPath)"))
        }

        // Show mcpMinSeverity from resolved config
        let config = PastewatchConfig.resolve()
        results.append(CheckResult(check: "config", status: "info", detail: "mcpMinSeverity: \(config.mcpMinSeverity)"))

        return results
    }

    private func checkHook() -> (status: String, detail: String) {
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

    private func checkFile(_ name: String, label: String) -> CheckResult {
        let cwd = FileManager.default.currentDirectoryPath
        let path = cwd + "/" + name
        if FileManager.default.fileExists(atPath: path) {
            return CheckResult(check: label, status: "ok", detail: path)
        }
        return CheckResult(check: label, status: "info", detail: "not found")
    }

    private func checkMCPProcesses() -> [CheckResult] {
        var results: [CheckResult] = []
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/pgrep")
        process.arguments = ["-fl", "pastewatch-cli.*mcp"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
            process.waitUntilExit()
            guard process.terminationStatus == 0 else {
                results.append(CheckResult(check: "mcp", status: "info", detail: "no MCP server processes found"))
                return results
            }
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: data, encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            let lines = output.split(separator: "\n")
                .filter { $0.contains("pastewatch-cli mcp") }

            if lines.isEmpty {
                results.append(CheckResult(check: "mcp", status: "info", detail: "no MCP server processes found"))
                return results
            }

            results.append(CheckResult(check: "mcp", status: "ok", detail: "\(lines.count) running"))

            for line in lines {
                let parts = line.split(separator: " ", maxSplits: 1)
                let pid = parts.first.map(String.init) ?? "?"
                let cmdLine = parts.count > 1 ? String(parts[1]) : ""

                let severity = extractFlag(cmdLine, flag: "--min-severity") ?? "high (default)"
                let auditLog = extractFlag(cmdLine, flag: "--audit-log") ?? "none"

                results.append(CheckResult(
                    check: "mcp",
                    status: "info",
                    detail: "PID \(pid): min-severity=\(severity), audit-log=\(auditLog)"
                ))
            }
        } catch {
            results.append(CheckResult(check: "mcp", status: "info", detail: "no MCP server processes found"))
        }
        return results
    }

    private func extractFlag(_ cmdLine: String, flag: String) -> String? {
        guard let flagRange = cmdLine.range(of: flag) else { return nil }
        let afterFlag = cmdLine[flagRange.upperBound...].trimmingCharacters(in: .whitespaces)
        return afterFlag.split(separator: " ").first.map(String.init)
    }

    private func checkHomebrew(currentVersion: String) -> (status: String, detail: String) {
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

    private func printText(_ checks: [CheckResult]) {
        for entry in checks {
            let icon: String
            switch entry.status {
            case "ok": icon = "ok"
            case "warn": icon = "WARN"
            case "info": icon = "--"
            default: icon = "??"
            }
            let paddedLabel = entry.check.padding(toLength: 12, withPad: " ", startingAt: 0)
            print("  [\(icon)] \(paddedLabel) \(entry.detail)")
        }
    }

    private func printJSON(_ checks: [CheckResult]) {
        var entries: [String] = []
        for entry in checks {
            let escapedDetail = entry.detail
                .replacingOccurrences(of: "\\", with: "\\\\")
                .replacingOccurrences(of: "\"", with: "\\\"")
            entries.append("    {\"check\": \"\(entry.check)\", \"status\": \"\(entry.status)\", \"detail\": \"\(escapedDetail)\"}")
        }
        print("[\n\(entries.joined(separator: ",\n"))\n]")
    }
}
