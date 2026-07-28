import Foundation

/// A single fix action to externalize a secret to an environment variable.
public struct FixAction {
    public let filePath: String
    public let line: Int
    public let secretValue: String
    public let sourceRange: NSRange? // WO-587@v3: authorize one exact source occurrence.
    public let envVarName: String
    public let replacement: String
    public let type: SensitiveDataType
    public let severity: Severity

    // WO-587@v3: callers may retain exact source ownership without breaking legacy actions.
    public init(
        filePath: String,
        line: Int,
        secretValue: String,
        sourceRange: NSRange? = nil,
        envVarName: String,
        replacement: String,
        type: SensitiveDataType,
        severity: Severity
    ) {
        self.filePath = filePath
        self.line = line
        self.secretValue = secretValue
        self.sourceRange = sourceRange
        self.envVarName = envVarName
        self.replacement = replacement
        self.type = type
        self.severity = severity
    }
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

    // WO-559@v2: remediation applies its own named severity default.
    /// Build a fix plan from directory scan results.
    public static func buildPlan(
        results: [FileScanResult],
        minSeverity: Severity = .defaultRemediationThreshold
    ) -> FixPlan {
        var actions: [FixAction] = []
        var usedNames: [String: Int] = [:]

        for fr in results {
            let fileName = URL(fileURLWithPath: fr.filePath).lastPathComponent
            let isEnvFile = DotenvClassifier.isDotenvFile(fileName)
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
                    sourceRange: NSRange(match.range, in: fr.content),
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
        try patchFiles(plan: plan, dirPath: dirPath)

        // Generate .env file
        try writeEnvFile(plan: plan, dirPath: dirPath, envFilePath: envFilePath)
    }

    /// Patch source files only (no .env generation). Used by --encrypt vault path.
    public static func patchFiles(plan: FixPlan, dirPath: String) throws {
        let grouped = Dictionary(grouping: plan.actions, by: { $0.filePath })
        for (relPath, actions) in grouped {
            let fullPath = (dirPath as NSString).appendingPathComponent(relPath)
            try patchFile(at: fullPath, actions: actions)
        }
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

    // WO-587@v3: assignment parsing carries the header needed to bound its value token.
    private struct AssignmentHeader {
        let key: String
        let range: NSRange
    }

    /// Extract the key whose value span owns the detected source range.
    private static func extractKeyFromLine(match: DetectedMatch, content: String) -> String? {
        guard String(content[match.range]) == match.value else {
            return nil
        }

        let lineStart = content[..<match.range.lowerBound].lastIndex(of: "\n")
            .map { content.index(after: $0) } ?? content.startIndex
        let lineEnd = content[match.range.upperBound...].firstIndex(of: "\n") ?? content.endIndex
        let line = String(content[lineStart..<lineEnd])
        let localMatchRange = NSRange(
            location: content[lineStart..<match.range.lowerBound].utf16.count,
            length: content[match.range].utf16.count
        )
        let headers = assignmentHeaders(in: line)

        // WO-587@v3: authorization follows exact source ownership, never substring presence.
        for (index, header) in headers.enumerated() {
            let nextHeaderStart = index + 1 < headers.count
                ? headers[index + 1].range.location
                : line.utf16.count
            guard let valueRange = assignmentValueRange(
                after: header,
                before: nextHeaderStart,
                in: line as NSString
            ) else {
                continue
            }
            if localMatchRange.location >= valueRange.location,
               NSMaxRange(localMatchRange) <= NSMaxRange(valueRange) {
                return header.key
            }
        }
        return nil
    }

    // WO-587@v3: headers are candidates only; value ownership is proven separately.
    private static func assignmentHeaders(in line: String) -> [AssignmentHeader] {
        let pattern = "(?:\"([a-zA-Z_][a-zA-Z0-9_]*)\"|([a-zA-Z_][a-zA-Z0-9_]*))\\s*([:=])\\s*"
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return [] }
        let nsLine = line as NSString
        return regex.matches(in: line, range: NSRange(location: 0, length: nsLine.length)).compactMap { result in
            let quotedKeyRange = result.range(at: 1)
            let unquotedKeyRange = result.range(at: 2)
            let startsAtBoundary = quotedKeyRange.location != NSNotFound
                || isAssignmentBoundary(at: result.range.location, in: nsLine)
            guard !isInsideQuotedValue(at: result.range.location, in: nsLine),
                  startsAtBoundary,
                  let keyRange = [quotedKeyRange, unquotedKeyRange]
                    .first(where: { $0.location != NSNotFound }),
                  let delimiterRange = Range(result.range(at: 3), in: line) else {
                return nil
            }
            let delimiter = line[delimiterRange]
            if delimiter == ":",
               NSMaxRange(result.range) + 1 < nsLine.length,
               nsLine.substring(
                   with: NSRange(location: NSMaxRange(result.range), length: 2)
               ) == "//" {
                return nil
            }
            return AssignmentHeader(
                key: nsLine.substring(with: keyRange),
                range: result.range
            )
        }
    }

    // WO-587@v3: bound quoted and scalar assignment values before trailing code/comments.
    private static func assignmentValueRange(
        after header: AssignmentHeader,
        before upperBound: Int,
        in line: NSString
    ) -> NSRange? {
        var start = NSMaxRange(header.range)
        guard start < upperBound else { return nil }

        let first = line.character(at: start)
        if first == 0x22 || first == 0x27 {
            let quote = first
            start += 1
            var cursor = start
            var escaped = false
            while cursor < upperBound {
                let character = line.character(at: cursor)
                if escaped {
                    escaped = false
                } else if character == 0x5C {
                    escaped = true
                } else if character == quote {
                    return NSRange(location: start, length: cursor - start)
                }
                cursor += 1
            }
            return nil
        }

        var end = upperBound
        var cursor = start
        while cursor < upperBound {
            let character = line.character(at: cursor)
            let startsComment = (character == 0x23 || isSlashComment(at: cursor, in: line))
                && (cursor == start || isWhitespace(line.character(at: cursor - 1)))
            if character == 0x3B || character == 0x2C || character == 0x29 || startsComment {
                end = cursor
                break
            }
            cursor += 1
        }
        while end > start && isWhitespace(line.character(at: end - 1)) {
            end -= 1
        }
        return end > start ? NSRange(location: start, length: end - start) : nil
    }

    private static func isSlashComment(at offset: Int, in line: NSString) -> Bool {
        offset + 1 < line.length
            && line.character(at: offset) == 0x2F
            && line.character(at: offset + 1) == 0x2F
    }

    private static func isWhitespace(_ character: unichar) -> Bool {
        UnicodeScalar(character).map(CharacterSet.whitespaces.contains) ?? false
    }

    // WO-587@v3: member and keyword assignments are valid header boundaries.
    private static func isAssignmentBoundary(at offset: Int, in line: NSString) -> Bool {
        guard offset > 0 else { return true }
        let previous = line.character(at: offset - 1)
        return isWhitespace(previous)
            || previous == 0x7B // {
            || previous == 0x5B // [
            || previous == 0x2C // ,
            || previous == 0x3B // ;
            || previous == 0x2E // .
            || previous == 0x28 // (
    }

    // WO-587@v3: assignment-like text inside an existing string is never a header.
    private static func isInsideQuotedValue(at offset: Int, in line: NSString) -> Bool {
        var activeQuote: unichar?
        var escaped = false
        for index in 0..<offset {
            let character = line.character(at: index)
            if escaped {
                escaped = false
            } else if character == 0x5C {
                escaped = true
            } else if let quote = activeQuote {
                if character == quote { activeQuote = nil }
            } else if character == 0x22 || character == 0x27 {
                activeQuote = character
            }
        }
        return activeQuote != nil
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
    private static let defaultEnvVarNames: [SensitiveDataType: String] = [
        .awsKey: "AWS_ACCESS_KEY_ID",
        .dbConnectionString: "DATABASE_URL",
        .openaiKey: "OPENAI_API_KEY",
        .anthropicKey: "ANTHROPIC_API_KEY",
        .huggingfaceToken: "HF_TOKEN",
        .groqKey: "GROQ_API_KEY",
        .npmToken: "NPM_TOKEN",
        .pypiToken: "PYPI_TOKEN",
        .rubygemsToken: "GEM_HOST_API_KEY",
        .gitlabToken: "GITLAB_TOKEN",
        .telegramBotToken: "TELEGRAM_BOT_TOKEN",
        .sendgridKey: "SENDGRID_API_KEY",
        .shopifyToken: "SHOPIFY_ACCESS_TOKEN",
        .digitaloceanToken: "DIGITALOCEAN_TOKEN",
        .genericApiKey: "API_KEY",
        .jwtToken: "JWT_SECRET",
        .slackWebhook: "SLACK_WEBHOOK_URL",
        .discordWebhook: "DISCORD_WEBHOOK_URL",
        .azureConnectionString: "AZURE_CONNECTION_STRING",
        .gcpServiceAccount: "GCP_SERVICE_ACCOUNT",
        .credential: "SECRET",
        .sshPrivateKey: "SSH_PRIVATE_KEY",
        .creditCard: "CARD_NUMBER",
        .email: "EMAIL",
        .phone: "PHONE",
        .ipAddress: "IP_ADDRESS",
        .hostname: "HOSTNAME",
        .filePath: "FILE_PATH",
        .uuid: "UUID",
        .highEntropyString: "SECRET"
    ]

    static func defaultEnvVarName(for type: SensitiveDataType) -> String {
        defaultEnvVarNames[type] ?? "SECRET"
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

        // WO-587@v3: mutate exact source ranges from bottom to top; never broad-replace equals.
        let exactActions = actions.compactMap { action -> (FixAction, NSRange)? in
            guard let range = action.sourceRange else { return nil }
            return (action, range)
        }.sorted { $0.1.location > $1.1.location }
        for (action, sourceRange) in exactActions {
            guard let valueRange = Range(sourceRange, in: content),
                  String(content[valueRange]) == action.secretValue else {
                continue
            }
            let replacementRange = quotedRange(
                around: valueRange,
                in: content,
                removeQuotes: true
            )
            content.replaceSubrange(replacementRange, with: action.replacement)
        }

        // Legacy/manual actions without source ranges retain line-scoped behavior.
        let legacyActions = actions.filter { $0.sourceRange == nil }
        if !legacyActions.isEmpty {
            content = patchLegacyActions(legacyActions, in: content)
        }
        try content.write(toFile: path, atomically: true, encoding: .utf8)
    }

    // WO-587@v3: remove only quotes that directly enclose the authorized range.
    private static func quotedRange(
        around range: Range<String.Index>,
        in content: String,
        removeQuotes: Bool
    ) -> Range<String.Index> {
        guard removeQuotes,
              range.lowerBound > content.startIndex,
              range.upperBound < content.endIndex else {
            return range
        }
        let previous = content.index(before: range.lowerBound)
        let next = range.upperBound
        let quote = content[previous]
        guard quote == "\"" || quote == "'", content[next] == quote else {
            return range
        }
        return previous..<content.index(after: next)
    }

    // WO-587@v3: legacy actions remain line-scoped only when no exact range exists.
    private static func patchLegacyActions(
        _ actions: [FixAction],
        in content: String
    ) -> String {
        var lines = content.components(separatedBy: "\n")
        for action in actions.sorted(by: { $0.line > $1.line }) {
            let lineIndex = action.line - 1
            guard lineIndex >= 0, lineIndex < lines.count else { continue }
            if action.replacement.isEmpty {
                if let eqIndex = lines[lineIndex].firstIndex(of: "=") {
                    lines[lineIndex] = String(lines[lineIndex][...eqIndex])
                }
            } else {
                let doubleQuoted = "\"\(action.secretValue)\""
                let singleQuoted = "'\(action.secretValue)'"
                if lines[lineIndex].contains(doubleQuoted) {
                    lines[lineIndex] = lines[lineIndex].replacingOccurrences(
                        of: doubleQuoted,
                        with: action.replacement
                    )
                } else if lines[lineIndex].contains(singleQuoted) {
                    lines[lineIndex] = lines[lineIndex].replacingOccurrences(
                        of: singleQuoted,
                        with: action.replacement
                    )
                } else {
                    lines[lineIndex] = lines[lineIndex].replacingOccurrences(
                        of: action.secretValue,
                        with: action.replacement
                    )
                }
            }
        }
        return lines.joined(separator: "\n")
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
