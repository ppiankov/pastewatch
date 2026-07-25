import ArgumentParser
import Foundation
import PastewatchCore

struct Init: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Generate project configuration files"
    )

    @Flag(name: .long, help: "Overwrite existing files")
    var force = false

    @Option(name: .long, help: "Configuration profile (default, banking)")
    var profile: String?

    func run() throws {
        let fm = FileManager.default
        let cwd = fm.currentDirectoryPath

        let configPath = cwd + "/.pastewatch.json"
        let allowPath = cwd + "/.pastewatch-allow"

        // Check for existing files
        if !force {
            if fm.fileExists(atPath: configPath) {
                FileHandle.standardError.write(Data("error: .pastewatch.json already exists (use --force to overwrite)\n".utf8))
                throw ExitCode(rawValue: 2)
            }
            if fm.fileExists(atPath: allowPath) {
                FileHandle.standardError.write(Data("error: .pastewatch-allow already exists (use --force to overwrite)\n".utf8))
                throw ExitCode(rawValue: 2)
            }
        }

        let configTemplate: String
        if let profile = profile {
            guard let tmpl = Self.profileTemplate(profile) else {
                FileHandle.standardError.write(Data("error: unknown profile '\(profile)' (available: banking)\n".utf8))
                throw ExitCode(rawValue: 2)
            }
            configTemplate = tmpl
        } else {
            configTemplate = Self.defaultTemplate()
        }

        try configTemplate.write(toFile: configPath, atomically: true, encoding: .utf8)

        // Write .pastewatch-allow
        let allowTemplate = """
        # Pastewatch allowlist
        # One value per line. Lines starting with # are comments.
        # Values listed here will be excluded from scan results.
        #
        # Examples:
        # test@example.com
        # 192.168.1.1
        # MYCO-000000

        """
        try allowTemplate.write(toFile: allowPath, atomically: true, encoding: .utf8)

        let profileLabel = profile.map { " (profile: \($0))" } ?? ""
        print("created .pastewatch.json\(profileLabel)")
        print("created .pastewatch-allow")
        // WO-532: JSON cannot carry comments, so keep opt-in examples adjacent in CLI output.
        print("obfuscate examples: exact email, @example.com, exact host, .example.com")
    }

    // WO-532: internal visibility keeps generated config behavior directly testable.
    static func defaultTemplate() -> String {
        return """
        {
          "enabled": true,
          "enabledTypes": \(defaultEnabledTypesJSON()),
          "showNotifications": true,
          "soundEnabled": false,
          "allowedValues": [],
          "allowedPatterns": [],
          "customRules": [],
          "safeHosts": [],
          "sensitiveHosts": [],
          "sensitiveIPPrefixes": [],
          "mcpMinSeverity": "high",
          "xmlSensitiveTags": [],
          "placeholderPrefix": null,
          "obfuscate": []
        }
        """
    }

    private static func profileTemplate(_ name: String) -> String? {
        switch name {
        case "banking":
            return bankingTemplate()
        default:
            return nil
        }
    }

    static func bankingTemplate() -> String {
        return """
        {
          "enabled": true,
          "enabledTypes": \(defaultEnabledTypesJSON()),
          "showNotifications": true,
          "soundEnabled": false,
          "allowedValues": [],
          "allowedPatterns": [],
          "customRules": [
            {"name": "Service Account", "pattern": "svc_[a-zA-Z0-9_]+@[a-zA-Z0-9.-]+", "severity": "high"},
            {"name": "Internal URI", "pattern": "https?://[a-zA-Z0-9.-]+\\\\.internal\\\\.[a-zA-Z0-9.-]+[^\\\\s]*", "severity": "high"}
          ],
          "safeHosts": [],
          "sensitiveHosts": [".internal.YOURBANK.com", ".corp.YOURBANK.net"],
          "sensitiveIPPrefixes": ["10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "192.168."],
          "mcpMinSeverity": "medium",
          "xmlSensitiveTags": ["password", "connectionString", "jdbcUrl", "datasource"],
          "placeholderPrefix": null,
          "obfuscate": [
            {"type": "email", "pattern": "@YOURBANK.com"},
            {"type": "host", "pattern": ".internal.YOURBANK.com"},
            {"type": "host", "pattern": ".corp.YOURBANK.net"}
          ]
        }
        """
    }

    private static func defaultEnabledTypesJSON() -> String {
        // WO-529@v3: Only enable intrinsic detectors by default, not ambiguous classes.
        let types = SensitiveDataType.allCases
            .filter { !$0.isAmbiguousClass }
            .map { "\"\($0.rawValue)\"" }
        return "[\(types.joined(separator: ", "))]"
    }
}
