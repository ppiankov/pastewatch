import ArgumentParser
import Foundation
import PastewatchCore

// WO-671@v2: process-health fixtures inspect the same metadata-only rows printed by doctor.
struct CheckResult {
    let check: String
    let status: String
    let detail: String
}

// WO-671@v2: process age and optional reported version identify sessions that survived an upgrade.
struct MCPProcessSnapshot {
    let pid: Int
    let startedAt: Date?
    var serverVersion: String?
    var minimumSeverity = "high (default)"
    var auditLog = "none"
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

    // WO-673@v2: plain doctor lists active, expired and malformed grants as their own health rows.
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

        // WO-672@v1: configuration and allow-file diagnostics share one validated effective policy.
        let explanation = ConfigExplanation()
        checks.append(contentsOf: checkConfig(explanation))

        // 4. Pre-commit hook
        let hookResult = checkHook()
        checks.append(CheckResult(check: "hook", status: hookResult.status, detail: hookResult.detail))

        // WO-672@v1: ignored entries reflect effective custom rules, not only built-in recognition.
        let allowFile = Allowlist.projectFile(for: FileManager.default.currentDirectoryPath,
                                              config: try? explanation.validatedConfiguration())
        checks.append(CheckResult(check: "allowlist", status: allowFile.loaded ? allowFile.status : "warn",
                                  detail: projectAllowlistDetail(allowFile)))

        // 6. Ignore file
        checks.append(checkFile(".pastewatchignore", label: "ignore"))

        // 7. Baseline file
        checks.append(checkFile(".pastewatch-baseline.json", label: "baseline"))

        // 8. MCP server processes
        checks.append(contentsOf: checkMCPProcesses())
        // WO-673@v2: grant diagnostics share the user-store validation used by admission.
        checks.append(contentsOf: checkBinaryGrants())

        // 9. Homebrew
        let brewResult = checkHomebrew(currentVersion: version)
        checks.append(CheckResult(check: "homebrew", status: brewResult.status, detail: brewResult.detail))

        if json {
            printJSON(checks)
        } else {
            printText(checks)
        }
    }

    // WO-673@v2: the walkthrough exposes only grant paths, short hashes, expiry and fixed store warnings.
    // WO-672@v1: the walkthrough accounts for exemptions against its validated effective rules.
    // WO-636@v2: CLI and tests render the same metadata-only representation.
    // WO-670@v1: the walkthrough includes the same safe allow-file evidence as plain doctor.
    func printExplanation(_ explanation: ConfigExplanation) throws {
        // WO-672@v1: invalid policy cannot yield an active allow-file diagnostic.
        let allowFile = Allowlist.projectFile(for: FileManager.default.currentDirectoryPath,
                                              config: try? explanation.validatedConfiguration())
        if json {
            var payload = try JSONSerialization.jsonObject(with: explanation.jsonData()) as? [String: Any] ?? [:]
            // WO-670@v1: explicit encoding excludes allow-file contents from diagnostics.
            payload["projectAllowlist"] = try JSONSerialization.jsonObject(with: JSONEncoder().encode(allowFile))
            // WO-673@v2: never encode the grant store or a file's content into a diagnostic response.
            payload["binaryGrants"] = checkBinaryGrants().map { ["check": $0.check, "status": $0.status, "detail": $0.detail] }
            FileHandle.standardOutput.write(try JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys]))
            FileHandle.standardOutput.write(Data("\n".utf8))
        } else {
            print(explanation.text())
            // WO-670@v1: an unloaded or ineffective file is never presented as active.
            print("Project allow file\n[\(allowFile.loaded ? allowFile.status : "warn")] \(projectAllowlistDetail(allowFile))")
            // WO-673@v2: every grant row states whether its expiry still permits admission.
            print("Binary transfer grants")
            for row in checkBinaryGrants() { print("[\(row.status)] \(row.detail)") }
        }
    }

    // WO-673@v2: an injected clock makes active and expired diagnostics deterministic without reading file bytes.
    func checkBinaryGrants(clock: () -> Date = { Date() }) -> [CheckResult] {
        let loaded = BinaryTransferGrants.load()
        if let warning = loaded.warning { return [CheckResult(check: "binary-grants", status: "warn", detail: warning)] }
        let now = clock()
        let formatter = ISO8601DateFormatter()
        let active = loaded.grants.filter { $0.expiresAt > now }.count
        var rows = [CheckResult(check: "binary-grants", status: "info",
                                detail: "\(active) active, \(loaded.grants.count - active) expired; operator-only transfers")]
        rows += loaded.grants.map { grant in
            CheckResult(check: "binary-grants", status: "info",
                        detail: "\(grant.expiresAt > now ? "active" : "expired"): \(grant.realpath); " +
                            "sha256-prefix=\(grant.sha256.prefix(8)); expiresAt=\(formatter.string(from: grant.expiresAt))")
        }
        return rows
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
    private func checkConfig(_ report: ConfigExplanation) -> [CheckResult] {
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

    // WO-671@v2: injected process and clock snapshots exercise the production stale-session diagnosis.
    func checkMCPProcesses(
        processList: (() throws -> [MCPProcessSnapshot])? = nil,
        binaryModifiedAt: () -> Date? = Doctor.installedBinaryModificationDate,
        clock: () -> Date = { Date() }
    ) -> [CheckResult] {
        do {
            let processes = try processList?() ?? runningMCPProcesses()
            guard !processes.isEmpty else {
                return [CheckResult(check: "mcp", status: "info", detail: "no MCP server processes found")]
            }
            let modifiedAt = binaryModifiedAt()
            let now = clock()
            let rows = processes.map { checkMCPProcess($0, binaryModifiedAt: modifiedAt, now: now) }
            let status = rows.contains { $0.status == "warn" } ? "warn" : "ok"
            return [CheckResult(check: "mcp", status: status, detail: "\(processes.count) running")] + rows
        } catch {
            return [CheckResult(check: "mcp", status: "warn", detail: "unable to inspect MCP server processes")]
        }
    }

    // WO-671@v2: warnings identify stale or unverifiable servers without probing their executable or stdin.
    private func checkMCPProcess(_ snapshot: MCPProcessSnapshot, binaryModifiedAt: Date?, now: Date) -> CheckResult {
        var detail = "PID \(snapshot.pid): min-severity=\(snapshot.minimumSeverity), audit-log=\(snapshot.auditLog)"
        var reasons: [String] = []
        if let version = snapshot.serverVersion, version != AppVersion.current {
            reasons.append("server version \(version) differs from installed \(AppVersion.current)")
        }
        if let startedAt = snapshot.startedAt {
            detail += ", age-seconds=\(Int(max(0, now.timeIntervalSince(startedAt))))"
            if let binaryModifiedAt, startedAt < binaryModifiedAt {
                reasons.append("started before the installed binary was updated")
            }
        } else if snapshot.serverVersion == nil {
            reasons.append("server start time and version are unavailable; freshness cannot be verified")
        }
        guard !reasons.isEmpty else { return CheckResult(check: "mcp", status: "info", detail: detail) }
        detail += "; " + reasons.joined(separator: "; ") + "; reconnect MCP or restart the agent session"
        return CheckResult(check: "mcp", status: "warn", detail: detail)
    }

    // WO-671@v2: compare process start time with the installed target, not a Homebrew symlink timestamp.
    private static func installedBinaryModificationDate() -> Date? {
        guard let argument = ProcessInfo.processInfo.arguments.first else { return nil }
        let path = URL(fileURLWithPath: argument).resolvingSymlinksInPath().path
        return (try? FileManager.default.attributesOfItem(atPath: path))?[.modificationDate] as? Date
    }

    // WO-671@v2: one process snapshot supplies real start times on Darwin and Linux without running old binaries.
    private func runningMCPProcesses() throws -> [MCPProcessSnapshot] {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/ps")
        process.arguments = ["-axo", "pid=,lstart=,command="]
        process.environment = ["LC_ALL": "C"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        try process.run()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else { throw CocoaError(.fileReadUnknown) }
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = .current
        formatter.dateFormat = "EEE MMM d HH:mm:ss yyyy"
        guard let output = String(data: data, encoding: .utf8) else { throw CocoaError(.fileReadInapplicableStringEncoding) }
        return output.split(separator: "\n").compactMap {
            parseMCPProcess(String($0), dateFormatter: formatter)
        }
    }

    // WO-671@v2: accept only an actual MCP executable/subcommand pair, not matching text in a shell command.
    func parseMCPProcess(_ line: String, dateFormatter: DateFormatter) -> MCPProcessSnapshot? {
        let fields = line.split(maxSplits: 6, whereSeparator: { $0.isWhitespace })
        guard fields.count == 7, let pid = Int(fields[0]) else { return nil }
        let command = String(fields[6])
        let words = command.split(whereSeparator: { $0.isWhitespace })
        guard words.count >= 2, words[1] == "mcp",
              ["pastewatch-cli", "pastewatchcli"].contains(URL(fileURLWithPath: String(words[0])).lastPathComponent.lowercased()) else {
            return nil
        }
        let startedAt = dateFormatter.date(from: fields[1...5].joined(separator: " "))
        return MCPProcessSnapshot(pid: pid, startedAt: startedAt,
                                  minimumSeverity: extractFlag(command, flag: "--min-severity") ?? "high (default)",
                                  auditLog: extractFlag(command, flag: "--audit-log") ?? "none")
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
