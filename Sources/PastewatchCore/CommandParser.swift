import Foundation

/// Extracts file paths from shell command strings.
/// Used by the `guard` subcommand to determine which files a Bash command would access.
public struct CommandParser {

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

    /// Extract file paths from a shell command string.
    /// Handles pipe chains (|), command chaining (&&, ||, ;), redirects, and subshells.
    /// Returns absolute paths resolved against `workingDirectory`.
    /// Returns empty array for unknown commands (allow by default).
    public static func extractFilePaths(
        from command: String,
        workingDirectory: String = FileManager.default.currentDirectoryPath
    ) -> [String] {
        var allPaths: [String] = []

        // Process main command segments
        let segments = splitCommandChain(command)
        for segment in segments {
            let (cleaned, inputFiles) = stripRedirects(segment)
            allPaths.append(contentsOf: inputFiles.flatMap {
                expandAndResolve($0, workingDirectory: workingDirectory)
            })
            allPaths.append(contentsOf: extractFilePathsSingle(
                from: cleaned, workingDirectory: workingDirectory
            ))
        }

        // Extract and process subshell commands (one level deep)
        let subshellCommands = extractSubshellCommands(command)
        for subCmd in subshellCommands {
            let subSegments = splitCommandChain(subCmd)
            for segment in subSegments {
                let (cleaned, inputFiles) = stripRedirects(segment)
                allPaths.append(contentsOf: inputFiles.flatMap {
                    expandAndResolve($0, workingDirectory: workingDirectory)
                })
                allPaths.append(contentsOf: extractFilePathsSingle(
                    from: cleaned, workingDirectory: workingDirectory
                ))
            }
        }

        return allPaths
    }

    /// Extract file paths from a single command (no pipes or chaining).
    private static func extractFilePathsSingle(
        from command: String,
        workingDirectory: String
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

    /// Split a command string into tokens, respecting single and double quotes.
    static func tokenize(_ command: String) -> [String] {
        var tokens: [String] = []
        var current = ""
        var inSingle = false
        var inDouble = false
        var escaped = false

        for char in command {
            if escaped {
                current.append(char)
                escaped = false
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

            if char == " " && !inSingle && !inDouble {
                if !current.isEmpty {
                    tokens.append(current)
                    current = ""
                }
                continue
            }

            current.append(char)
        }

        if !current.isEmpty {
            tokens.append(current)
        }

        return tokens
    }

    // MARK: - Argument extractors

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
