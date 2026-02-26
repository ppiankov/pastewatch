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

    /// Extract file paths from a shell command string.
    /// Returns absolute paths resolved against `workingDirectory`.
    /// Returns empty array for unknown commands (allow by default).
    public static func extractFilePaths(
        from command: String,
        workingDirectory: String = FileManager.default.currentDirectoryPath
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
        } else {
            return []
        }

        return rawPaths.flatMap { expandAndResolve($0, workingDirectory: workingDirectory) }
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
