import ArgumentParser
import Foundation
import PastewatchCore

private struct CheckResult {
    let check: String
    let status: String
    let detail: String
}

// WO-649@v1: doctor reports the same dependency selection used by startup and execution.
func doctorCurlStatus(lookup: () -> String? = { CurlExecutable.resolve() }) -> (status: String, detail: String) {
    guard let path = lookup() else {
        return ("warn", CurlExecutable.missingDependencyMessage)
    }
    return ("ok", path)
}

// WO-636@v2: the walkthrough is opt-in; the existing health report remains unchanged.
struct Doctor: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Check installation health and show active configuration"
    )

    @Flag(name: .long, help: "Output results as JSON")
    var json = false

    // WO-636@v2: explain effective policy without changing the default doctor path.
    @Flag(name: .long, help: "Explain config resolution, rule coverage, and surface outcomes")
    var explain = false

    // WO-649@v1: command decoding retains its existing fields and delegates transport lookup.
    func run() throws {
        try run(curlLookup: { CurlExecutable.resolve() })
    }

    // WO-649@v1: inject lookup through execution without adding a command or environment override.
    // WO-636@v2: return before legacy checks only when the walkthrough was requested.
    // WO-670@v1: allow-file health reflects actual target-root loading, not mere presence.
    func run(curlLookup: () -> String?) throws {
        if explain {
            try printExplanation(ConfigExplanation())
            return
        }
        var checks: [CheckResult] = []

        // 1. CLI version and binary path
        let version = AppVersion.current
        let binaryPath = ProcessInfo.processInfo.arguments.first ?? "unknown"
        checks.append(CheckResult(check: "cli", status: "ok", detail: "v\(version) at \(binaryPath)"))

        // 2. PATH check — is pastewatch-cli on PATH?
        checks.append(checkOnPath())

        // WO-649@v1: keep macOS output unchanged while reporting Linux curl availability.
        #if os(Linux)
        let curlResult = doctorCurlStatus(lookup: curlLookup)
        checks.append(CheckResult(check: "curl", status: curlResult.status, detail: curlResult.detail))
        #endif

        // 3. Config resolution
        checks.append(contentsOf: checkConfig())

        // 4. Pre-commit hook
        let hookResult = checkHook()
        checks.append(CheckResult(check: "hook", status: hookResult.status, detail: hookResult.detail))

        // WO-670@v1: the diagnostic directory is an explicit target context.
        let allowFile = Allowlist.projectFile(for: FileManager.default.currentDirectoryPath)
        checks.append(CheckResult(check: "allowlist", status: allowFile.loaded ? allowFile.status : "warn",
                                  detail: projectAllowlistDetail(allowFile)))

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

    // WO-636@v2: CLI and tests render the same metadata-only representation.
    // WO-670@v1: the walkthrough includes the same safe allow-file evidence as plain doctor.
    func printExplanation(_ explanation: ConfigExplanation) throws {
        let allowFile = Allowlist.projectFile(for: FileManager.default.currentDirectoryPath)
        if json {
            var payload = try JSONSerialization.jsonObject(with: explanation.jsonData()) as? [String: Any] ?? [:]
            // WO-670@v1: explicit encoding excludes allow-file contents from diagnostics.
            payload["projectAllowlist"] = try JSONSerialization.jsonObject(with: JSONEncoder().encode(allowFile))
            FileHandle.standardOutput.write(try JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys]))
            FileHandle.standardOutput.write(Data("\n".utf8))
        } else {
            print(explanation.text())
            // WO-670@v1: an unloaded or ineffective file is never presented as active.
            print("Project allow file\n[\(allowFile.loaded ? allowFile.status : "warn")] \(projectAllowlistDetail(allowFile))")
        }
    }

    // WO-670@v1: only path, loading status and entry counts are public.
    private func projectAllowlistDetail(_ report: ProjectAllowlistResolution) -> String {
        "\(report.path ?? "none"); loaded=\(report.loaded), effectiveEntries=\(report.effectiveEntries), " +
            "ignoredIntrinsicEntries=\(report.ignoredIntrinsicEntries); file targets only"
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

    // WO-672@v1: health checks report the same merged, metadata-only policy as the walkthrough.
    private func checkConfig() -> [CheckResult] {
        let report = ConfigExplanation()
        var results = [CheckResult(check: "config", status: report.valid ? "ok" : "warn",
                                   detail: "\(report.source); \(report.customRules.count) custom rules loaded")]
        results += report.resolution.filter(\.exists).map {
            CheckResult(check: "config", status: $0.parseOK && $0.validationErrors == 0 ? "info" : "warn",
                        detail: "\($0.source): \($0.path) [\($0.disposition)]")
        }
        results += report.fieldSources.keys.sorted().map {
            CheckResult(check: "config", status: "info", detail: "\($0): \(report.fieldSources[$0, default: []].joined(separator: ", "))")
        }
        results += report.warnings.map { CheckResult(check: "config", status: "warn", detail: $0) }
        results.append(CheckResult(check: "config", status: "info", detail: "mcpMinSeverity: \(report.mcpMinSeverity)"))
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
