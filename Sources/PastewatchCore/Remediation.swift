import Foundation

/// A single fix action to externalize a secret to an environment variable.
public struct FixAction {
    public let filePath: String
    public let line: Int
    public let secretValue: String
    public let envVarName: String
    public let replacement: String
    public let type: SensitiveDataType
    public let severity: Severity
}

/// Complete fix plan for a directory scan.
public struct FixPlan {
    public let actions: [FixAction]

    /// Deduplicated env entries (key → value) for .env file generation.
    public var envEntries: [(key: String, value: String)] {
        var seen = Set<String>()
        var entries: [(key: String, value: String)] = []
        for action in actions {
            guard !seen.contains(action.envVarName) else { continue }
            seen.insert(action.envVarName)
            entries.append((key: action.envVarName, value: action.secretValue))
        }
        return entries
    }
}

/// Builds and applies fix plans for externalizing secrets to environment variables.
public enum Remediation {

    // MARK: - Plan building

    /// Build a fix plan from directory scan results.
    public static func buildPlan(
        results: [FileScanResult],
        minSeverity: Severity = .high
    ) -> FixPlan {
        var actions: [FixAction] = []
        var usedNames: [String: Int] = [:]

        for fr in results {
            let fileName = URL(fileURLWithPath: fr.filePath).lastPathComponent
            let isEnvFile = fileName == ".env" || fileName.hasSuffix(".env")
            let ext = isEnvFile ? "env" : URL(fileURLWithPath: fr.filePath).pathExtension.lowercased()
            for match in fr.matches {
                guard match.effectiveSeverity >= minSeverity else { continue }

                var name = suggestEnvVarName(match: match, fileContent: fr.content)
                name = deduplicateName(name, usedNames: &usedNames)

                let replacement = envVarReference(name: name, ext: ext)
                actions.append(FixAction(
                    filePath: fr.filePath,
                    line: match.line,
                    secretValue: match.value,
                    envVarName: name,
                    replacement: replacement,
                    type: match.type,
                    severity: match.effectiveSeverity
                ))
            }
        }

        return FixPlan(actions: actions)
    }

    // MARK: - Env var name suggestion

    /// Suggest an environment variable name for a detected match.
    public static func suggestEnvVarName(match: DetectedMatch, fileContent: String) -> String {
        // Priority 1: Extract key from the source line
        if let keyFromLine = extractKeyFromLine(match: match, content: fileContent) {
            return normalizeToEnvVar(keyFromLine)
        }

        // Priority 2: Type-based defaults
        return defaultEnvVarName(for: match.type)
    }

    /// Generate a language-aware environment variable reference.
    public static func envVarReference(name: String, ext: String) -> String {
        switch ext.lowercased() {
        case "py":
            return "os.environ[\"\(name)\"]"
        case "js", "ts", "mjs", "cjs":
            return "process.env.\(name)"
        case "go":
            return "os.Getenv(\"\(name)\")"
        case "rb":
            return "ENV[\"\(name)\"]"
        case "swift":
            return "ProcessInfo.processInfo.environment[\"\(name)\"] ?? \"\""
        case "sh", "bash", "zsh":
            return "${\(name)}"
        case "env":
            return ""
        default:
            return "${\(name)}"
        }
    }

    // MARK: - Plan application

    /// Apply a fix plan: patch source files and generate .env file.
    public static func apply(plan: FixPlan, dirPath: String, envFilePath: String) throws {
        // Group actions by file and apply patches
        let grouped = Dictionary(grouping: plan.actions, by: { $0.filePath })
        for (relPath, actions) in grouped {
            let fullPath = (dirPath as NSString).appendingPathComponent(relPath)
            try patchFile(at: fullPath, actions: actions)
        }

        // Generate .env file
        try writeEnvFile(plan: plan, dirPath: dirPath, envFilePath: envFilePath)
    }

    /// Check if .gitignore contains a .env entry.
    public static func gitignoreContainsEnv(dirPath: String) -> Bool {
        let gitignorePath = (dirPath as NSString).appendingPathComponent(".gitignore")
        guard let content = try? String(contentsOfFile: gitignorePath, encoding: .utf8) else {
            return false
        }
        let lines = content.components(separatedBy: .newlines)
        return lines.contains { line in
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            return trimmed == ".env" || trimmed == ".env*" || trimmed == "*.env"
        }
    }

    // MARK: - Private helpers

    /// Extract the key name from the line containing the match.
    private static func extractKeyFromLine(match: DetectedMatch, content: String) -> String? {
        let lines = content.components(separatedBy: .newlines)
        let lineIndex = match.line - 1
        guard lineIndex >= 0, lineIndex < lines.count else { return nil }
        let line = lines[lineIndex]

        // Try common assignment patterns: key = "value", key: value, key=value
        let patterns = [
            "([a-zA-Z_][a-zA-Z0-9_]*)\\s*=",   // key = or key=
            "([a-zA-Z_][a-zA-Z0-9_]*)\\s*:",    // key: (YAML style)
            "\"([a-zA-Z_][a-zA-Z0-9_]*)\"\\s*:"  // "key": (JSON style)
        ]

        for pattern in patterns {
            guard let regex = try? NSRegularExpression(pattern: pattern),
                  let result = regex.firstMatch(in: line, range: NSRange(line.startIndex..., in: line)),
                  let keyRange = Range(result.range(at: 1), in: line) else { continue }
            let key = String(line[keyRange])
            // Verify the match value appears after the key on this line
            if let keyEnd = line.range(of: key)?.upperBound,
               line[keyEnd...].contains(match.value) {
                return key
            }
        }

        return nil
    }

    /// Normalize a key name to SCREAMING_SNAKE_CASE.
    static func normalizeToEnvVar(_ key: String) -> String {
        var result = ""
        for (i, char) in key.enumerated() {
            if char.isUppercase && i > 0 {
                let prev = key[key.index(key.startIndex, offsetBy: i - 1)]
                if prev.isLowercase || prev.isNumber {
                    result += "_"
                }
            }
            result += String(char)
        }
        return result
            .replacingOccurrences(of: "-", with: "_")
            .replacingOccurrences(of: ".", with: "_")
            .uppercased()
    }

    /// Default env var name based on detection type.
    static func defaultEnvVarName(for type: SensitiveDataType) -> String {
        switch type {
        case .awsKey: return "AWS_ACCESS_KEY_ID"
        case .dbConnectionString: return "DATABASE_URL"
        case .openaiKey: return "OPENAI_API_KEY"
        case .anthropicKey: return "ANTHROPIC_API_KEY"
        case .huggingfaceToken: return "HF_TOKEN"
        case .groqKey: return "GROQ_API_KEY"
        case .npmToken: return "NPM_TOKEN"
        case .pypiToken: return "PYPI_TOKEN"
        case .rubygemsToken: return "GEM_HOST_API_KEY"
        case .gitlabToken: return "GITLAB_TOKEN"
        case .telegramBotToken: return "TELEGRAM_BOT_TOKEN"
        case .sendgridKey: return "SENDGRID_API_KEY"
        case .shopifyToken: return "SHOPIFY_ACCESS_TOKEN"
        case .digitaloceanToken: return "DIGITALOCEAN_TOKEN"
        case .genericApiKey: return "API_KEY"
        case .jwtToken: return "JWT_SECRET"
        case .slackWebhook: return "SLACK_WEBHOOK_URL"
        case .discordWebhook: return "DISCORD_WEBHOOK_URL"
        case .azureConnectionString: return "AZURE_CONNECTION_STRING"
        case .gcpServiceAccount: return "GCP_SERVICE_ACCOUNT"
        case .credential: return "SECRET"
        case .sshPrivateKey: return "SSH_PRIVATE_KEY"
        case .creditCard: return "CARD_NUMBER"
        case .email: return "EMAIL"
        case .phone: return "PHONE"
        case .ipAddress: return "IP_ADDRESS"
        case .hostname: return "HOSTNAME"
        case .filePath: return "FILE_PATH"
        case .uuid: return "UUID"
        }
    }

    /// Add numeric suffix to deduplicate env var names.
    private static func deduplicateName(_ name: String, usedNames: inout [String: Int]) -> String {
        let count = (usedNames[name] ?? 0) + 1
        usedNames[name] = count
        if count == 1 { return name }
        return "\(name)_\(count)"
    }

    /// Patch a single file by replacing secret values with env var references.
    private static func patchFile(at path: String, actions: [FixAction]) throws {
        guard var content = try? String(contentsOfFile: path, encoding: .utf8) else { return }
        var lines = content.components(separatedBy: "\n")

        // Process from bottom to top to preserve line indices
        let sortedActions = actions.sorted { $0.line > $1.line }
        for action in sortedActions {
            let lineIndex = action.line - 1
            guard lineIndex >= 0, lineIndex < lines.count else { continue }

            if action.replacement.isEmpty {
                // .env file: clear the value after the = sign
                if let eqIndex = lines[lineIndex].firstIndex(of: "=") {
                    let key = String(lines[lineIndex][...eqIndex])
                    lines[lineIndex] = key
                }
            } else {
                // Try replacing quoted value first (strip surrounding quotes)
                let doubleQuoted = "\"\(action.secretValue)\""
                let singleQuoted = "'\(action.secretValue)'"
                if lines[lineIndex].contains(doubleQuoted) {
                    lines[lineIndex] = lines[lineIndex].replacingOccurrences(
                        of: doubleQuoted, with: action.replacement
                    )
                } else if lines[lineIndex].contains(singleQuoted) {
                    lines[lineIndex] = lines[lineIndex].replacingOccurrences(
                        of: singleQuoted, with: action.replacement
                    )
                } else {
                    lines[lineIndex] = lines[lineIndex].replacingOccurrences(
                        of: action.secretValue, with: action.replacement
                    )
                }
            }
        }

        content = lines.joined(separator: "\n")
        try content.write(toFile: path, atomically: true, encoding: .utf8)
    }

    /// Write or append entries to a .env file.
    private static func writeEnvFile(
        plan: FixPlan, dirPath: String, envFilePath: String
    ) throws {
        let envPath = (dirPath as NSString).appendingPathComponent(envFilePath)
        var existingKeys = Set<String>()

        // Read existing .env if present
        if let existing = try? String(contentsOfFile: envPath, encoding: .utf8) {
            for line in existing.components(separatedBy: .newlines) {
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                if trimmed.isEmpty || trimmed.hasPrefix("#") { continue }
                if let eqIndex = trimmed.firstIndex(of: "=") {
                    existingKeys.insert(String(trimmed[..<eqIndex]).trimmingCharacters(in: .whitespaces))
                }
            }
        }

        // Build new entries
        var newEntries: [String] = []
        let grouped = Dictionary(grouping: plan.actions, by: { $0.envVarName })
        for entry in plan.envEntries {
            guard !existingKeys.contains(entry.key) else { continue }
            if let action = grouped[entry.key]?.first {
                newEntries.append("# From \(action.filePath):\(action.line) (\(action.type.rawValue))")
            }
            newEntries.append("\(entry.key)=\(entry.value)")
        }

        guard !newEntries.isEmpty else { return }

        var output = ""
        if FileManager.default.fileExists(atPath: envPath) {
            let existing = try String(contentsOfFile: envPath, encoding: .utf8)
            output = existing
            if !output.hasSuffix("\n") { output += "\n" }
        }
        output += newEntries.joined(separator: "\n") + "\n"
        try output.write(toFile: envPath, atomically: true, encoding: .utf8)
    }
}
