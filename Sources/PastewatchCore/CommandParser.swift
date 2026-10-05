import Foundation

/// Extracts file paths from shell command strings.
/// Used by the `guard` subcommand to determine which files a Bash command would access.
public struct CommandParser {

    // WO-644@v2: paths and unsupported command names come from the same source-role parse.
    public struct FileAccess {
        public let paths: [String]
        public let unsupportedCommands: [String]
        public let hasUnsafeRedactedCommand: Bool // WO-658@v2: unresolved remedy paths cannot acquire a guard exemption.
    }

    // WO-638: source reads are guarded before a copy can change the destination's policy context.
    private static let copyCommands: Set<String> = ["cp", "mv", "install", "rsync", "ditto"]

    /// Commands that read file contents (output goes to stdout → cloud API).
    private static let fileReaders: Set<String> = [
        "cat", "head", "tail", "less", "more", "bat", "tac", "nl",
    ]

    /// Commands that modify files in-place.
    private static let fileWriters: Set<String> = [
        "sed", "awk",
    ]

    /// Commands that search file contents (output includes matching lines).
    private static let fileSearchers: Set<String> = [
        "grep", "egrep", "fgrep", "rg", "ag",
    ]

    /// Commands that source/execute a file.
    private static let fileSourcers: Set<String> = [
        "source", ".",
    ]

    /// Scripting interpreters that execute a script file (first positional arg).
    private static let scriptInterpreters: Set<String> = [
        "python3", "python", "python3.11", "python3.12", "python3.13",
        "ruby", "node", "perl", "php", "lua",
    ]

    /// Flags that take inline code for scripting interpreters (skip — can't parse).
    private static let scriptInlineFlags: Set<String> = ["-c", "-e"]

    /// File transfer and remote tools that read local files.
    private static let fileTransferTools: Set<String> = [
        "scp", "rsync", "ssh", "ssh-keygen",
    ]

    /// Flags that take a file path for transfer/remote tools.
    private static let transferFlagsWithFile: [String: Set<String>] = [
        "scp": [],
        "rsync": ["--password-file", "--include-from", "--exclude-from"],
        "ssh": ["-i", "-F"],
        "ssh-keygen": ["-f"],
    ]

    /// Database CLI tools that may read credential files or contain inline secrets.
    private static let databaseCLIs: Set<String> = [
        "psql", "mysql", "mongosh", "mongo", "redis-cli", "sqlite3",
    ]

    /// Flags that take a file path for database CLIs.
    private static let dbFlagsWithFile: [String: Set<String>] = [
        "psql": ["-f", "--file"],
        "mysql": ["--defaults-file", "--defaults-extra-file"],
        "mongosh": [],
        "mongo": [],
        "redis-cli": [],
        "sqlite3": [],
    ]

    /// Infrastructure tools that read config/inventory files via flags and positional args.
    private static let infraTools: Set<String> = [
        "ansible-playbook", "ansible", "ansible-vault",
        "terraform", "docker-compose", "docker", "kubectl", "helm",
    ]

    /// Flags that take a file path as their next argument, per infra tool.
    private static let infraFlagsWithFile: [String: Set<String>] = [
        "ansible-playbook": ["-i", "--inventory", "--vault-password-file", "--private-key", "-e", "--extra-vars"],
        "ansible": ["-i", "--inventory", "--vault-password-file", "--private-key", "-e", "--extra-vars"],
        "ansible-vault": ["--vault-password-file"],
        "terraform": ["-var-file"],
        "docker-compose": ["-f", "--file", "--env-file"],
        "docker": ["--env-file"],
        "kubectl": ["-f", "--filename", "--kubeconfig"],
        "helm": ["-f", "--values", "--kubeconfig"],
    ]

    // WO-644@v2: existing callers retain the path-only API and the shared parsing decisions.
    /// Extract file paths from a shell command string.
    /// Handles pipe chains (|), command chaining (&&, ||, ;), redirects, and subshells.
    /// Returns absolute paths resolved against `workingDirectory`.
    /// Returns empty array for unknown commands (allow by default).
    public static func extractFilePaths(
        from command: String,
        workingDirectory: String = FileManager.default.currentDirectoryPath
    ) -> [String] {
        fileAccess(from: command, workingDirectory: workingDirectory).paths
    }

    // WO-644@v2: unsupported copy syntax is reported without including any operand values.
    // WO-658@v2: sanctioned redacted segments never hide readers in other chain or substitution segments.
    public static func fileAccess(
        from command: String,
        workingDirectory: String = FileManager.default.currentDirectoryPath
    ) -> FileAccess {
        var allPaths: [String] = []
        var unsupportedCommands: Set<String> = []
        var hasUnsafeRedactedCommand = false

        // Process main command segments
        let segments = splitCommandChain(command)
        for segment in segments {
            // WO-658@v2: a redefined executable name cannot earn the redacted-reader exemption.
            hasUnsafeRedactedCommand = hasUnsafeRedactedCommand || definesRedactedRemedy(segment)
            let (cleaned, inputFiles) = stripRedirects(segment)
            allPaths.append(contentsOf: inputFiles.flatMap {
                expandAndResolve($0, workingDirectory: workingDirectory)
            })
            // WO-658@v2: only a literal target and substitution-free remedy segment may bypass raw file reads.
            if let safe = redactedRemedyIsSafe(segment) {
                hasUnsafeRedactedCommand = hasUnsafeRedactedCommand || !safe
                continue
            }
            allPaths.append(contentsOf: extractFilePathsSingle(
                from: cleaned, workingDirectory: workingDirectory, unsupportedCommands: &unsupportedCommands
            ))
        }

        // Extract and process subshell commands (one level deep)
        let subshellCommands = extractSubshellCommands(command)
        for subCmd in subshellCommands {
            let subSegments = splitCommandChain(subCmd)
            for segment in subSegments {
                // WO-658@v2: definitions in substitutions retain the same fail-closed shadowing rule.
                hasUnsafeRedactedCommand = hasUnsafeRedactedCommand || definesRedactedRemedy(segment)
                let (cleaned, inputFiles) = stripRedirects(segment)
                allPaths.append(contentsOf: inputFiles.flatMap {
                    expandAndResolve($0, workingDirectory: workingDirectory)
                })
                // WO-658@v2: nested segments retain the same literal-path contract.
                if let safe = redactedRemedyIsSafe(segment) {
                    hasUnsafeRedactedCommand = hasUnsafeRedactedCommand || !safe
                    continue
                }
                allPaths.append(contentsOf: extractFilePathsSingle(
                    from: cleaned, workingDirectory: workingDirectory, unsupportedCommands: &unsupportedCommands
                ))
            }
        }

        // WO-658@v2: return unresolved remedy state without exposing any operands.
        return FileAccess(paths: allPaths, unsupportedCommands: unsupportedCommands.sorted(),
                          hasUnsafeRedactedCommand: hasUnsafeRedactedCommand)
    }

    // WO-658@v2: inspect executable definitions through the existing lexer, not quoted mentions in ordinary arguments.
    private static func definesRedactedRemedy(_ segment: String) -> Bool {
        let command = segment.drop { $0.isWhitespace || "({".contains($0) }
        let tokens = tokenize(String(command))
        let head = tokens.prefix(3).joined(separator: " ")
        let functionPattern = #"^(?:pastewatch-cli\s*\(\s*\)|function\s+pastewatch-cli(?:\s|\(|$))"#
        if head.range(of: functionPattern, options: .regularExpression) != nil { return true }
        return tokens.first == "alias" && tokens.dropFirst().contains { $0.hasPrefix("pastewatch-cli=") }
    }

    // WO-658@v2: recognize only the named remedy executable and subcommands through the existing shell lexer.
    private static func redactedRemedyIsSafe(_ segment: String) -> Bool? {
        let cleaned = stripRedirects(segment).command
        let loose = tokenize(cleaned)
        guard loose.count >= 2, loose[0] == "pastewatch-cli", ["read", "edit"].contains(loose[1]) else { return nil }
        guard extractSubshellCommands(segment).isEmpty,
              let tokens = tokenizeArguments(cleaned, requiringLiteralArguments: true), tokens.count >= 2,
              tokens[0].isLiteral, tokens[1].isLiteral else { return false }
        let arguments = Array(tokens.dropFirst(2))
        if arguments.count == 1, ["--help", "-h", "--version"].contains(arguments[0].value) { return true }
        guard let path = redactedRemedyPath(arguments, command: tokens[1].value) else { return false }
        return path.isLiteral && !path.hasWordExpansion
    }

    // WO-658@v2: option values are not targets; only one literal positional file earns the exemption.
    private static func redactedRemedyPath(_ arguments: [CommandToken], command: String) -> CommandToken? {
        let options: Set<String> = command == "read" ? ["--start-line", "--line-count"]
            : ["--old", "--new", "--old-file", "--new-file", "--expect-view-token"]
        var path: CommandToken?
        var index = 0
        var endOfOptions = false
        while index < arguments.count {
            let token = arguments[index]
            index += 1
            if token.value == "--", !endOfOptions { endOfOptions = true; continue }
            if token.value.hasPrefix("-"), !endOfOptions {
                let parts = token.value.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
                guard let name = parts.first, options.contains(String(name)) else { return nil }
                if parts.count == 1 {
                    guard index < arguments.count else { return nil }
                    index += 1
                }
            } else {
                guard path == nil else { return nil }
                path = token
            }
        }
        return path
    }

    // WO-644@v2: copy parse failures retain existing fallbacks and provide command-only diagnostics.
    /// Extract file paths from a single command (no pipes or chaining).
    private static func extractFilePathsSingle(
        from command: String,
        workingDirectory: String,
        unsupportedCommands: inout Set<String>
    ) -> [String] {
        let tokens = tokenize(command)
        guard let rawCmd = tokens.first else { return [] }

        let args = Array(tokens.dropFirst())

        // Check sourcers first (before path stripping, since "." is a valid command name)
        if fileSourcers.contains(rawCmd) {
            let rawPaths = args.isEmpty ? [] : [args[0]]
            return rawPaths.flatMap { expandAndResolve($0, workingDirectory: workingDirectory) }
        }

        // Strip path prefix: /usr/bin/cat → cat
        let cmd: String
        if rawCmd.contains("/") {
            cmd = (rawCmd as NSString).lastPathComponent
        } else {
            cmd = rawCmd
        }

        // WO-644@v2: only genuinely unsupported source roles add a diagnostic.
        if copyCommands.contains(cmd) {
            if let paths = copySourcePaths(from: command, commandName: cmd, workingDirectory: workingDirectory) {
                return paths
            }
            unsupportedCommands.insert(cmd)
        }

        let rawPaths: [String]

        if fileReaders.contains(cmd) {
            rawPaths = extractPositionalArgs(args)
        } else if fileWriters.contains(cmd) {
            rawPaths = extractLastFileArg(args)
        } else if fileSearchers.contains(cmd) {
            rawPaths = extractGrepFileArgs(args)
        } else if scriptInterpreters.contains(cmd) {
            rawPaths = extractScriptFileArgs(args)
        } else if fileTransferTools.contains(cmd) {
            rawPaths = extractTransferFileArgs(cmd, args: args)
        } else if infraTools.contains(cmd) {
            rawPaths = extractInfraFileArgs(cmd, args: args)
        } else if databaseCLIs.contains(cmd) {
            rawPaths = extractDBFileArgs(cmd, args: args)
        } else {
            return []
        }

        return rawPaths.flatMap { expandAndResolve($0, workingDirectory: workingDirectory) }
    }

    // WO-644@v2: strict copy tokenization preserves the existing directory and expansion policy.
    private static func copySourcePaths(
        from command: String, commandName: String, workingDirectory: String
    ) -> [String]? {
        guard let tokens = tokenizeArguments(command, requiringLiteralArguments: true),
              !tokens.isEmpty,
              let sources = extractCopySourceArgs(commandName, args: Array(tokens.dropFirst())) else { return nil }
        return sources.flatMap { expandAndResolve($0, workingDirectory: workingDirectory) }.filter { path in
            var isDirectory: ObjCBool = false
            return !FileManager.default.fileExists(atPath: path, isDirectory: &isDirectory) || !isDirectory.boolValue
        }
    }

    // MARK: - Command chain splitting

    /// Split a command string on pipes (|) and chain operators (&&, ||, ;).
    /// Respects quotes — operators inside quotes are not split on.
    static func splitCommandChain(_ command: String) -> [String] {
        var segments: [String] = []
        var current = ""
        var inSingle = false
        var inDouble = false
        var escaped = false
        let chars = Array(command)
        var i = 0

        while i < chars.count {
            let char = chars[i]

            if escaped {
                current.append(char)
                escaped = false
                i += 1
                continue
            }

            if char == "\\" && !inSingle {
                escaped = true
                current.append(char)
                i += 1
                continue
            }

            if char == "'" && !inDouble {
                inSingle.toggle()
                current.append(char)
                i += 1
                continue
            }

            if char == "\"" && !inSingle {
                inDouble.toggle()
                current.append(char)
                i += 1
                continue
            }

            // Only split when not inside quotes
            if !inSingle && !inDouble {
                // Check for && or ||
                if i + 1 < chars.count {
                    let next = chars[i + 1]
                    if (char == "&" && next == "&") || (char == "|" && next == "|") {
                        let trimmed = current.trimmingCharacters(in: .whitespaces)
                        if !trimmed.isEmpty { segments.append(trimmed) }
                        current = ""
                        i += 2
                        continue
                    }
                }

                // Single pipe (not ||)
                if char == "|" {
                    let trimmed = current.trimmingCharacters(in: .whitespaces)
                    if !trimmed.isEmpty { segments.append(trimmed) }
                    current = ""
                    i += 1
                    continue
                }

                // Semicolon
                if char == ";" {
                    let trimmed = current.trimmingCharacters(in: .whitespaces)
                    if !trimmed.isEmpty { segments.append(trimmed) }
                    current = ""
                    i += 1
                    continue
                }
            }

            current.append(char)
            i += 1
        }

        let trimmed = current.trimmingCharacters(in: .whitespaces)
        if !trimmed.isEmpty { segments.append(trimmed) }

        return segments
    }

    // MARK: - Redirect stripping

    /// Strip redirect operators and their targets from a command segment.
    /// Returns the cleaned command and any input redirect source files.
    /// Works at the character level to preserve quoting in the original string.
    static func stripRedirects(_ segment: String) -> (command: String, inputFiles: [String]) {
        var inputFiles: [String] = []
        let chars = Array(segment)
        var result: [Character] = []
        var inSingle = false
        var inDouble = false
        var escaped = false
        var i = 0

        while i < chars.count {
            if escaped {
                result.append(chars[i])
                escaped = false
                i += 1
                continue
            }
            if chars[i] == "\\" && !inSingle {
                escaped = true
                result.append(chars[i])
                i += 1
                continue
            }
            if chars[i] == "'" && !inDouble {
                inSingle.toggle()
                result.append(chars[i])
                i += 1
                continue
            }
            if chars[i] == "\"" && !inSingle {
                inDouble.toggle()
                result.append(chars[i])
                i += 1
                continue
            }

            // Only detect redirects outside quotes
            if !inSingle && !inDouble {
                let remaining = chars[i...]

                // Check for output redirects (order: longest prefix first)
                if let skip = matchOutputRedirect(remaining) {
                    i += skip
                    continue
                }

                // Check for input redirect: < (not <<)
                if chars[i] == "<" && !(i + 1 < chars.count && chars[i + 1] == "<") {
                    i += 1
                    // Skip whitespace
                    while i < chars.count && chars[i] == " " { i += 1 }
                    // Collect the file path
                    let file = collectWord(chars, from: &i)
                    if !file.isEmpty { inputFiles.append(file) }
                    continue
                }

                // Skip heredoc << or <<-
                if chars[i] == "<" && i + 1 < chars.count && chars[i + 1] == "<" {
                    i += 2
                    if i < chars.count && chars[i] == "-" { i += 1 }
                    while i < chars.count && chars[i] == " " { i += 1 }
                    // Skip the delimiter word
                    _ = collectWord(chars, from: &i)
                    continue
                }
            }

            result.append(chars[i])
            i += 1
        }

        let cleaned = String(result).trimmingCharacters(in: .whitespaces)
        // Collapse multiple spaces
        let collapsed = cleaned.replacingOccurrences(
            of: "  +", with: " ", options: .regularExpression
        )
        return (command: collapsed, inputFiles: inputFiles)
    }

    /// Match an output redirect operator at the current position.
    /// Returns the number of characters to skip (operator + whitespace + target word), or nil.
    private static func matchOutputRedirect(_ chars: ArraySlice<Character>) -> Int? {
        let prefixes: [(String, Int)] = [
            ("&>>", 3), ("&>", 2), ("2>>", 3), ("2>", 2), (">>", 2), (">", 1),
        ]
        let arr = Array(chars)
        for (prefix, len) in prefixes where arr.count >= len {
            let candidate = String(arr[0..<len])
            if candidate == prefix {
                var skip = len
                // Skip whitespace after operator
                while skip < arr.count && arr[skip] == " " { skip += 1 }
                // Skip the target word (handles quoted targets)
                var pos = skip
                _ = collectWord(arr, from: &pos)
                return pos
            }
        }
        return nil
    }

    /// Collect a word (possibly quoted) starting at position, advancing the index.
    private static func collectWord(_ chars: [Character], from i: inout Int) -> String {
        guard i < chars.count else { return "" }
        var word = ""

        // Handle quoted word
        if chars[i] == "'" || chars[i] == "\"" {
            let quote = chars[i]
            i += 1
            while i < chars.count && chars[i] != quote {
                word.append(chars[i])
                i += 1
            }
            if i < chars.count { i += 1 } // skip closing quote
            return word
        }

        // Unquoted word — collect until space
        while i < chars.count && chars[i] != " " {
            word.append(chars[i])
            i += 1
        }
        return word
    }

    // MARK: - Subshell extraction

    /// Extract commands from $(...) and backtick expressions.
    /// Returns inner commands for recursive processing.
    /// One level deep only — does not parse nested subshells.
    static func extractSubshellCommands(_ command: String) -> [String] {
        var commands: [String] = []
        var inSingle = false
        var inDouble = false
        var escaped = false
        let chars = Array(command)
        var i = 0

        while i < chars.count {
            let char = chars[i]

            if escaped {
                escaped = false
                i += 1
                continue
            }

            if char == "\\" && !inSingle {
                escaped = true
                i += 1
                continue
            }

            if char == "'" && !inDouble {
                inSingle.toggle()
                i += 1
                continue
            }

            if char == "\"" && !inSingle {
                inDouble.toggle()
                i += 1
                continue
            }

            // $(...) outside quotes (or inside double quotes — subshells expand there)
            if !inSingle && char == "$" && i + 1 < chars.count && chars[i + 1] == "(" {
                // Find matching closing paren
                var depth = 1
                var j = i + 2
                while j < chars.count && depth > 0 {
                    if chars[j] == "(" { depth += 1 }
                    if chars[j] == ")" { depth -= 1 }
                    j += 1
                }
                // Extract content between $( and )
                let start = i + 2
                let end = j - 1
                if start < end {
                    let inner = String(chars[start..<end])
                    commands.append(inner)
                }
                i = j
                continue
            }

            // Backtick outside quotes
            if !inSingle && char == "`" {
                // Find matching closing backtick
                var j = i + 1
                while j < chars.count && chars[j] != "`" {
                    j += 1
                }
                if j < chars.count {
                    let inner = String(chars[(i + 1)..<j])
                    commands.append(inner)
                    i = j + 1
                } else {
                    i += 1
                }
                continue
            }

            i += 1
        }

        return commands
    }

    // MARK: - Tokenizer

    // WO-638: source classification keeps literal status alongside each shell token.
    private struct CommandToken {
        let value: String
        let isLiteral: Bool
        let hasWordExpansion: Bool // WO-658@v2: distinguish literal remedy paths without changing copy-source semantics.

        // WO-658@v2: existing token constructors retain their previous literal classification.
        init(value: String, isLiteral: Bool, hasWordExpansion: Bool = false) {
            self.value = value
            self.isLiteral = isLiteral
            self.hasWordExpansion = hasWordExpansion
        }
    }

    // WO-638: substitutions retain whitespace within one unresolved operand.
    private struct ShellExpansion {
        var opening: Character?
        var depth = 0
        var backtick = false
        var isOpen: Bool { opening != nil || backtick }

        // WO-638: consume a substitution without changing the surrounding quote state.
        mutating func consume(_ char: Character) -> Bool {
            if backtick {
                if char == "`" { backtick = false }
                return true
            }
            guard let opening else { return false }
            let closing: Character = opening == "(" ? ")" : "}"
            if char == opening { depth += 1 }
            if char == closing { depth -= 1 }
            if depth == 0 { self.opening = nil }
            return true
        }

        // WO-638: variables and command substitutions mark only their owning token unknown.
        mutating func begin(_ char: Character, next: Character?) -> Bool {
            if char == "`" { backtick = true; return true }
            guard char == "$" else { return false }
            if next == "(" || next == "{" { opening = next }
            return true
        }
    }

    // WO-638: legacy callers retain their token values and copy parsing uses token metadata.
    /// Split a command string into tokens, respecting single and double quotes.
    static func tokenize(_ command: String, requiringLiteralArguments: Bool = false) -> [String] {
        (tokenizeArguments(command, requiringLiteralArguments: requiringLiteralArguments) ?? []).map { $0.value }
    }

    // WO-638: an expansion marks its token unknown without discarding other literal operands.
    // WO-658@v2: separately retain unquoted word expansions for sanctioned read/edit target checks.
    private static func tokenizeArguments(_ command: String, requiringLiteralArguments: Bool) -> [CommandToken]? {
        var tokens: [CommandToken] = []
        var current = ""
        var isLiteral = true
        var hasWordExpansion = false
        var inSingle = false
        var inDouble = false
        var escaped = false
        var expansion = ShellExpansion()
        let characters = Array(command)

        for (index, char) in characters.enumerated() {
            if escaped {
                current.append(char)
                escaped = false
                continue
            }

            // WO-638: whitespace inside substitutions belongs to the same unknown operand.
            if expansion.consume(char) {
                current.append(char)
                continue
            }

            if char == "\\" && !inSingle {
                escaped = true
                continue
            }

            if char == "'" && !inDouble {
                inSingle.toggle()
                continue
            }

            if char == "\"" && !inSingle {
                inDouble.toggle()
                continue
            }

            // WO-638: unresolved expansions change only this token's literal status.
            let next = index + 1 < characters.count ? characters[index + 1] : nil
            // WO-658@v2: quoted or escaped glob/tilde characters remain literal filenames.
            if requiringLiteralArguments && !inSingle && !inDouble && isWordExpansion(char, leading: current.isEmpty) {
                hasWordExpansion = true
            }
            if requiringLiteralArguments && !inSingle && expansion.begin(char, next: next) {
                isLiteral = false
            }
            if (char == " " || (requiringLiteralArguments && char.isWhitespace)) && !inSingle && !inDouble {
                if !current.isEmpty {
                    // WO-658@v2: word-expansion metadata does not alter existing source-role literal status.
                    tokens.append(CommandToken(value: current, isLiteral: isLiteral, hasWordExpansion: hasWordExpansion))
                    current = ""
                    isLiteral = true
                    hasWordExpansion = false
                }
                continue
            }

            current.append(char)
        }

        // WO-638: unmatched syntax keeps the pre-existing allow behavior for unsupported commands.
        if requiringLiteralArguments && (inSingle || inDouble || escaped || expansion.isOpen) { return nil }
        if !current.isEmpty {
            // WO-658@v2: the final operand carries the same independent expansion metadata.
            tokens.append(CommandToken(value: current, isLiteral: isLiteral, hasWordExpansion: hasWordExpansion))
        }

        return tokens
    }

    // WO-658@v2: unquoted shell word expansions cannot designate a literal protected-tool path.
    private static func isWordExpansion(_ character: Character, leading: Bool) -> Bool {
        "*?[{".contains(character) || (leading && character == "~")
    }

    // MARK: - Argument extractors

    // WO-644@v2: optional long-option values are attached and never consume a source operand.
    private enum CopyOption {
        case flag, optionalValue, value, targetDirectory, inputFile, directoryOnly
    }

    // WO-644@v2: common GNU metadata options retain their documented argument arity.
    private static func copyMetadataOption(_ name: String, command: String) -> CopyOption? {
        guard ["cp", "mv", "install"].contains(command) else { return nil }
        if name == "backup" { return .optionalValue }
        if name == "context" { return .optionalValue }
        if name == "Z" { return .flag }
        if command == "cp" {
            if ["preserve", "reflink"].contains(name) { return .optionalValue }
            if ["no-preserve", "sparse"].contains(name) { return .value }
        }
        return nil
    }

    // WO-644@v2: supported flags and metadata values retain source positions.
    private static func copyOption(_ name: String, command: String) -> CopyOption? {
        if let kind = copyMetadataOption(name, command: command) { return kind }
        if ["cp", "mv", "install"].contains(command) {
            if ["t", "target-directory"].contains(name) { return .targetDirectory }
            if ["S", "suffix"].contains(name) { return .value }
        }
        if command == "install" {
            if ["m", "mode", "o", "owner", "g", "group"].contains(name) { return .value }
            if ["d", "directory"].contains(name) { return .directoryOnly }
        }
        if command == "rsync" {
            if ["password-file", "include-from", "exclude-from", "files-from"].contains(name) { return .inputFile }
            if ["e", "rsh", "f", "filter", "B", "block-size", "T", "temp-dir"].contains(name) { return .value }
        }
        let shortFlags: [String: String] = [
            // WO-644@v2: backup and update flags do not take a following argument.
            "cp": "baRrpfivnHLPlsduxXTc", "mv": "bfinvuT", "install": "bCcDpsv",
            "rsync": "avzrtplogDHRWcnuqIhSxKLOJ", "ditto": "vVXckxz"
        ]
        let longFlags: [String: Set<String>] = [
            // WO-644@v2: ordinary copy metadata flags cannot disable source inspection.
            "cp": ["force", "interactive", "no-clobber", "verbose", "recursive", "archive", "no-target-directory",
                   "parents", "update"],
            "mv": ["force", "interactive", "no-clobber", "verbose", "no-target-directory", "update"],
            "install": ["verbose", "no-target-directory", "preserve-timestamps", "strip"],
            "rsync": ["verbose", "recursive", "archive", "dry-run", "delete", "progress"],
            "ditto": ["rsrc", "norsrc", "extattr", "noextattr", "acl", "noacl"]
        ]
        if name.count == 1 && (shortFlags[command] ?? "").contains(name) { return .flag }
        return longFlags[command]?.contains(name) == true ? .flag : nil
    }

    // WO-644@v2: unknown option spelling does not disable known source checks.
    private static func parseCopyOption(_ argument: String, command: String) -> (kind: CopyOption, value: String?)? {
        if argument.hasPrefix("--") {
            let parts = argument.dropFirst(2).split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            guard let name = parts.first else { return nil }
            guard let kind = copyOption(String(name), command: command) else { return (.flag, nil) }
            if kind == .flag && parts.count > 1 { return nil }
            return (kind, parts.count > 1 ? String(parts[1]) : nil)
        }
        let flags = argument.dropFirst()
        for index in flags.indices {
            // WO-644@v2: an unknown short flag never discards literal positional operands.
            let kind = copyOption(String(flags[index]), command: command) ?? .flag
            if kind != .flag {
                let rest = flags[flags.index(after: index)...]
                return (kind, rest.isEmpty ? nil : String(rest))
            }
        }
        return (.flag, nil)
    }

    // WO-644@v2: options retain source roles even when their spelling is not in a flag table.
    private static func extractCopySourceArgs(_ command: String, args: [CommandToken]) -> [String]? {
        var sources: [CommandToken] = []
        var inputFiles: [CommandToken] = []
        var targetDirectory = false
        var endOfOptions = false
        var index = 0
        while index < args.count {
            // WO-638: use token text for option arity and keep its literal status for source selection.
            let token = args[index]
            let argument = token.value
            index += 1
            if !endOfOptions && argument == "--" { endOfOptions = true; continue }
            if endOfOptions || !argument.hasPrefix("-") || argument == "-" {
                sources.append(token)
                continue
            }
            guard let option = parseCopyOption(argument, command: command) else { return nil }
            if option.kind == .directoryOnly { return [] }
            // WO-644@v2: optional GNU values use the equals form and do not consume a positional.
            if option.kind == .flag || option.kind == .optionalValue { continue }
            // WO-638: an expanded option value still consumes its argument, never a source.
            let value: CommandToken
            if let attached = option.value {
                value = CommandToken(value: attached, isLiteral: token.isLiteral)
            } else {
                guard index < args.count else { return nil }
                value = args[index]
                index += 1
            }
            guard !value.value.isEmpty else { return nil }
            if option.kind == .targetDirectory { targetDirectory = true }
            if option.kind == .inputFile { inputFiles.append(value) }
        }
        guard sources.count >= (targetDirectory ? 1 : 2) else { return nil }
        if !targetDirectory { sources.removeLast() }
        // WO-638: filtering after role classification prevents an unknown destination from shifting sources.
        return inputFiles.filter { $0.isLiteral }.map { $0.value } + sources.filter {
            $0.isLiteral && (command != "rsync" || !$0.value.contains(":"))
        }.map { $0.value }
    }

    /// Extract positional (non-flag) arguments — used for cat, head, tail, etc.
    /// Skips flags (tokens starting with `-`) and their values for known flag patterns.
    private static func extractPositionalArgs(_ args: [String]) -> [String] {
        // Flags that take a value for file-reader commands (head -n 10, tail -c 100)
        let readerFlagsWithValue: Set<String> = ["-n", "-c"]

        var paths: [String] = []
        var skipNext = false

        for arg in args {
            if skipNext {
                skipNext = false
                continue
            }

            if arg == "--" {
                continue
            }

            if arg.hasPrefix("-") {
                if readerFlagsWithValue.contains(arg) {
                    skipNext = true
                }
                continue
            }

            paths.append(arg)
        }

        return paths
    }

    /// For sed/awk: extract the last non-flag argument (the file path).
    /// Skips the script argument and flags.
    private static func extractLastFileArg(_ args: [String]) -> [String] {
        // Find the last token that looks like a file path (not a flag, not a sed script)
        let positional = args.filter { !$0.hasPrefix("-") }
        // For sed: first positional is usually the script, rest are files
        // For awk: first positional is the script, last is the file
        guard positional.count >= 2 else { return [] }
        return Array(positional.dropFirst())
    }

    /// For grep/rg: extract file arguments after the pattern.
    /// Pattern is the first positional arg; remaining positional args are files.
    private static func extractGrepFileArgs(_ args: [String]) -> [String] {
        // Flags that consume the next token as a value for grep
        let grepFlagsWithValue: Set<String> = [
            "-e", "-f", "-m",
            "-A", "-B", "-C",
            "--include", "--exclude", "--max-count",
        ]

        var positional: [String] = []
        var skipNext = false

        for arg in args {
            if skipNext {
                skipNext = false
                continue
            }
            if arg.hasPrefix("-") {
                if grepFlagsWithValue.contains(arg) {
                    skipNext = true
                }
                continue
            }
            positional.append(arg)
        }

        // First positional is the pattern, rest are files
        guard positional.count >= 2 else { return [] }
        return Array(positional.dropFirst())
    }

    /// For scripting interpreters: extract the script file (first positional arg).
    /// Skips -c/-e inline code flags and their arguments.
    private static func extractScriptFileArgs(_ args: [String]) -> [String] {
        var skipNext = false

        for arg in args {
            if skipNext {
                skipNext = false
                continue
            }

            // -c/-e take inline code as next arg — skip both
            if scriptInlineFlags.contains(arg) {
                skipNext = true
                continue
            }

            // Skip other flags
            if arg.hasPrefix("-") {
                continue
            }

            // First positional arg is the script file
            return [arg]
        }

        return []
    }

    /// For file transfer tools: extract file paths from flags and positional args.
    private static func extractTransferFileArgs(_ cmd: String, args: [String]) -> [String] {
        let flagsWithFile = transferFlagsWithFile[cmd] ?? []
        var paths: [String] = []
        var skipNext = false

        for arg in args {
            if skipNext {
                paths.append(arg)
                skipNext = false
                continue
            }

            if arg.hasPrefix("-") {
                if flagsWithFile.contains(arg) {
                    skipNext = true
                }
                continue
            }

            // For scp/rsync: positional args that don't contain ":" are local files
            if cmd == "scp" || cmd == "rsync" {
                if !arg.contains(":") {
                    paths.append(arg)
                }
            }
        }

        return paths
    }

    /// For infrastructure tools: extract file paths from known flags and positional args.
    /// Positional args that look like file paths (contain / or .) are included.
    private static func extractInfraFileArgs(_ cmd: String, args: [String]) -> [String] {
        let flagsWithFile = infraFlagsWithFile[cmd] ?? []
        var paths: [String] = []
        var skipNext = false

        for arg in args {
            if skipNext {
                // Handle ansible -e @file syntax
                if arg.hasPrefix("@") {
                    paths.append(String(arg.dropFirst()))
                } else {
                    paths.append(arg)
                }
                skipNext = false
                continue
            }

            // Check for --flag=value syntax
            if arg.contains("=") {
                let parts = arg.split(separator: "=", maxSplits: 1)
                let flag = String(parts[0])
                if flagsWithFile.contains(flag), parts.count == 2 {
                    let value = String(parts[1])
                    if value.hasPrefix("@") {
                        paths.append(String(value.dropFirst()))
                    } else {
                        paths.append(value)
                    }
                }
                continue
            }

            if arg.hasPrefix("-") {
                if flagsWithFile.contains(arg) {
                    skipNext = true
                }
                continue
            }

            // Positional args — include if they look like file paths
            let lowerArg = arg.lowercased()
            let hasPathChars = arg.contains("/") || arg.contains(".")
            let isKnownExt = lowerArg.hasSuffix(".yml") || lowerArg.hasSuffix(".yaml")
                || lowerArg.hasSuffix(".json") || lowerArg.hasSuffix(".tf")
                || lowerArg.hasSuffix(".env") || lowerArg.hasSuffix(".toml")
                || lowerArg.hasSuffix(".cfg") || lowerArg.hasSuffix(".ini")
                || lowerArg.hasSuffix(".conf")
            if hasPathChars || isKnownExt {
                paths.append(arg)
            }
        }

        return paths
    }

    /// For database CLIs: extract file paths from known flags.
    private static func extractDBFileArgs(_ cmd: String, args: [String]) -> [String] {
        let flagsWithFile = dbFlagsWithFile[cmd] ?? []
        var paths: [String] = []
        var skipNext = false

        for arg in args {
            if skipNext {
                paths.append(arg)
                skipNext = false
                continue
            }

            // Check for --flag=value syntax
            if arg.contains("=") {
                let parts = arg.split(separator: "=", maxSplits: 1)
                let flag = String(parts[0])
                if flagsWithFile.contains(flag), parts.count == 2 {
                    paths.append(String(parts[1]))
                }
                continue
            }

            if arg.hasPrefix("-") {
                if flagsWithFile.contains(arg) {
                    skipNext = true
                }
                continue
            }

            // For sqlite3: first positional arg is the database file
            if cmd == "sqlite3" && paths.isEmpty {
                paths.append(arg)
                break
            }
        }

        return paths
    }

    // MARK: - Inline value extraction

    /// Extract inline values from a command that may contain secrets.
    /// These are argument values (not file paths) to scan with DetectionRules.
    /// Returns raw strings to be scanned directly.
    public static func extractInlineValues(from command: String) -> [String] {
        let segments = splitCommandChain(command)
        var allValues: [String] = []
        for segment in segments {
            let (cleaned, _) = stripRedirects(segment)
            allValues.append(contentsOf: extractInlineValuesSingle(from: cleaned))
        }
        return allValues
    }

    /// Extract inline values from a single command.
    private static func extractInlineValuesSingle(from command: String) -> [String] {
        let tokens = tokenize(command)
        guard let rawCmd = tokens.first else { return [] }

        let args = Array(tokens.dropFirst())

        let cmd: String
        if rawCmd.contains("/") {
            cmd = (rawCmd as NSString).lastPathComponent
        } else {
            cmd = rawCmd
        }

        guard databaseCLIs.contains(cmd) else { return [] }

        if let extractor = inlineExtractors[cmd] {
            return extractor(args)
        }
        return []
    }

    /// Per-CLI inline value extractors, dispatched by command name.
    private static let inlineExtractors: [String: ([String]) -> [String]] = [
        "psql": extractPsqlInlineValues,
        "mysql": extractMysqlInlineValues,
        "mongosh": extractMongoInlineValues,
        "mongo": extractMongoInlineValues,
        "redis-cli": extractRedisInlineValues,
    ]

    /// psql: first positional arg containing :// is a connection string.
    private static func extractPsqlInlineValues(_ args: [String]) -> [String] {
        var skipNext = false
        for arg in args {
            if skipNext { skipNext = false; continue }
            if arg == "-f" || arg == "--file" || arg == "-h" || arg == "-p"
                || arg == "-U" || arg == "-d" || arg == "-o" {
                skipNext = true
                continue
            }
            if arg.hasPrefix("-") { continue }
            if arg.contains("://") { return [arg] }
        }
        return []
    }

    /// mysql: -p<password> (attached), --password=<value>, -p <password> (space).
    private static func extractMysqlInlineValues(_ args: [String]) -> [String] {
        var values: [String] = []
        var i = 0
        while i < args.count {
            let arg = args[i]

            // --password=value
            if arg.hasPrefix("--password=") {
                let value = String(arg.dropFirst("--password=".count))
                if !value.isEmpty { values.append(value) }
                i += 1
                continue
            }

            // -pPASSWORD (attached, no space) — not -P (port) or --p* long flags
            if arg.hasPrefix("-p") && arg.count > 2 && !arg.hasPrefix("-P")
                && !arg.hasPrefix("--") {
                values.append(String(arg.dropFirst(2)))
                i += 1
                continue
            }

            // First positional containing :// is a connection string
            if !arg.hasPrefix("-") && arg.contains("://") {
                values.append(arg)
            }

            i += 1
        }
        return values
    }

    /// mongosh/mongo: first positional arg containing :// is a connection string.
    private static func extractMongoInlineValues(_ args: [String]) -> [String] {
        for arg in args {
            if arg.hasPrefix("-") { continue }
            if arg.contains("://") { return [arg] }
        }
        return []
    }

    /// redis-cli: -a (auth password), -u (URL with auth).
    private static func extractRedisInlineValues(_ args: [String]) -> [String] {
        var values: [String] = []
        var i = 0
        while i < args.count {
            let arg = args[i]
            if arg == "-a" && i + 1 < args.count {
                values.append(args[i + 1])
                i += 2
                continue
            }
            if arg == "-u" && i + 1 < args.count {
                values.append(args[i + 1])
                i += 2
                continue
            }
            i += 1
        }
        return values
    }

    // MARK: - Path resolution

    /// Resolve a raw path to absolute, expanding globs if present.
    private static func expandAndResolve(
        _ rawPath: String,
        workingDirectory: String
    ) -> [String] {
        // Check for glob characters
        if rawPath.contains("*") || rawPath.contains("?") || rawPath.contains("[") {
            return expandGlob(rawPath, workingDirectory: workingDirectory)
        }

        return [resolvePath(rawPath, workingDirectory: workingDirectory)]
    }

    /// Resolve a single path to absolute.
    static func resolvePath(_ path: String, workingDirectory: String) -> String {
        if path.hasPrefix("/") {
            return path
        }
        if path.hasPrefix("~/") {
            return NSString(string: path).expandingTildeInPath
        }
        let base = URL(fileURLWithPath: workingDirectory)
        return base.appendingPathComponent(path).standardized.path
    }

    /// Expand a glob pattern to matching file paths.
    private static func expandGlob(_ pattern: String, workingDirectory: String) -> [String] {
        let resolved = resolvePath(pattern, workingDirectory: workingDirectory)
        let nsPattern = resolved as NSString

        let dir = nsPattern.deletingLastPathComponent
        let filePattern = nsPattern.lastPathComponent

        guard let enumerator = FileManager.default.enumerator(
            atPath: dir.isEmpty ? "." : dir
        ) else {
            return []
        }

        var matches: [String] = []
        while let file = enumerator.nextObject() as? String {
            enumerator.skipDescendants()
            if fnmatch(filePattern, file, 0) == 0 {
                let fullPath = (dir as NSString).appendingPathComponent(file)
                matches.append(fullPath)
            }
        }

        return matches
    }
}
