import Foundation

/// Result of scanning a single file.
public struct FileScanResult {
    public let filePath: String
    public let matches: [DetectedMatch]
    public let content: String
    public let gitignored: Bool

    public init(filePath: String, matches: [DetectedMatch], content: String, gitignored: Bool = false) {
        self.filePath = filePath
        self.matches = matches
        self.content = content
        self.gitignored = gitignored
    }
}

/// Recursive directory scanner for sensitive data detection.
public struct DirectoryScanner {

    /// File extensions to scan.
    static let allowedExtensions: Set<String> = [
        "env", "yml", "yaml", "json", "toml", "conf", "xml", "tf",
        "sh", "py", "go", "js", "ts", "rb", "swift", "java",
        "properties", "cfg", "ini", "txt", "md", "pem", "key"
    ]

    /// Directories to skip.
    static let skipDirectories: Set<String> = [
        ".git", "node_modules", ".build", "vendor", "DerivedData",
        ".swiftpm", "__pycache__", "dist", "build", ".tox"
    ]

    /// Scan all files in a directory recursively.
    public static func scan(
        directory: String,
        config: PastewatchConfig,
        ignoreFile: IgnoreFile? = nil,
        extraIgnorePatterns: [String] = [],
        bail: Bool = false
    ) throws -> [FileScanResult] {
        let dirURL = URL(fileURLWithPath: directory).standardizedFileURL
        let dirPath = dirURL.path
        var results: [FileScanResult] = []

        let mergedIgnore: IgnoreFile?
        if let ig = ignoreFile {
            if extraIgnorePatterns.isEmpty {
                mergedIgnore = ig
            } else {
                mergedIgnore = IgnoreFile(patterns: ig.patterns + extraIgnorePatterns)
            }
        } else if !extraIgnorePatterns.isEmpty {
            mergedIgnore = IgnoreFile(patterns: extraIgnorePatterns)
        } else {
            mergedIgnore = nil
        }

        guard let enumerator = FileManager.default.enumerator(
            at: dirURL,
            includingPropertiesForKeys: [.isRegularFileKey, .isDirectoryKey],
            options: []
        ) else {
            return results
        }

        while let fileURL = enumerator.nextObject() as? URL {
            let fileName = fileURL.lastPathComponent

            // Skip directories in skiplist
            if skipDirectories.contains(fileName) {
                enumerator.skipDescendants()
                continue
            }

            // Check if it's a regular file
            guard let resourceValues = try? fileURL.resourceValues(forKeys: [.isRegularFileKey]),
                  resourceValues.isRegularFile == true else {
                continue
            }

            // Check extension (handle .env as special case -- no extension but starts with dot)
            let ext = fileURL.pathExtension.lowercased()
            let isEnvFile = fileName == ".env" || fileName.hasSuffix(".env")

            guard isEnvFile || allowedExtensions.contains(ext) else {
                continue
            }

            // Compute relative path from the directory root
            let filePath = fileURL.standardizedFileURL.path
            let relativePath = filePath.hasPrefix(dirPath + "/")
                ? String(filePath.dropFirst(dirPath.count + 1))
                : fileURL.lastPathComponent

            // Skip files matching ignore patterns
            if let ignore = mergedIgnore, ignore.shouldIgnore(relativePath) {
                continue
            }

            // Skip binary files (check first 8192 bytes for null bytes)
            guard !isBinaryFile(at: fileURL) else {
                continue
            }

            // Read and scan
            guard let content = try? String(contentsOf: fileURL, encoding: .utf8),
                  !content.isEmpty else {
                continue
            }

            // Format-aware scanning
            let parsedExt = isEnvFile ? "env" : fileURL.pathExtension.lowercased()
            var fileMatches = scanFileContent(
                content: content, ext: parsedExt,
                relativePath: relativePath, config: config
            )

            fileMatches = Allowlist.filterInlineAllow(matches: fileMatches, content: content)

            if !fileMatches.isEmpty {
                results.append(FileScanResult(
                    filePath: relativePath,
                    matches: fileMatches,
                    content: content
                ))
                if bail { return results }
            }
        }

        let sorted = results.sorted { $0.filePath < $1.filePath }

        // Tag gitignored files
        let ignoredSet = gitIgnoredFiles(in: directory, paths: sorted.map { $0.filePath })
        if ignoredSet.isEmpty {
            return sorted
        }
        return sorted.map { result in
            if ignoredSet.contains(result.filePath) {
                return FileScanResult(
                    filePath: result.filePath,
                    matches: result.matches,
                    content: result.content,
                    gitignored: true
                )
            }
            return result
        }
    }

    /// Check which paths are gitignored using `git check-ignore`.
    /// Returns empty set if not in a git repo or git is not available.
    public static func gitIgnoredFiles(in directory: String, paths: [String]) -> Set<String> {
        guard !paths.isEmpty else { return [] }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/git")
        process.arguments = ["-C", directory, "check-ignore", "--stdin"]
        process.currentDirectoryURL = URL(fileURLWithPath: directory)

        let inputPipe = Pipe()
        let outputPipe = Pipe()
        process.standardInput = inputPipe
        process.standardOutput = outputPipe
        process.standardError = FileHandle.nullDevice

        do {
            try process.run()
        } catch {
            return []
        }

        let input = paths.joined(separator: "\n") + "\n"
        inputPipe.fileHandleForWriting.write(Data(input.utf8))
        inputPipe.fileHandleForWriting.closeFile()

        process.waitUntilExit()

        let data = outputPipe.fileHandleForReading.readDataToEndOfFile()
        guard let output = String(data: data, encoding: .utf8) else { return [] }

        return Set(
            output.components(separatedBy: .newlines)
                .map { $0.trimmingCharacters(in: .whitespaces) }
                .filter { !$0.isEmpty }
        )
    }

    /// Scan file content using format-aware parsing when available.
    public static func scanFileContent(
        content: String, ext: String,
        relativePath: String, config: PastewatchConfig
    ) -> [DetectedMatch] {
        guard let parser = parserForExtension(ext, config: config) else {
            return DetectionRules.scan(content, config: config).map { match in
                DetectedMatch(
                    type: match.type, value: match.value, range: match.range,
                    line: match.line, filePath: relativePath,
                    customRuleName: match.customRuleName, customSeverity: match.customSeverity
                )
            }
        }

        // Format-aware: extract values and scan each
        var matches: [DetectedMatch] = []
        for pv in parser.parseValues(from: content) {
            for vm in DetectionRules.scan(pv.value, config: config) {
                matches.append(DetectedMatch(
                    type: vm.type, value: vm.value, range: vm.range,
                    line: pv.line, filePath: relativePath,
                    customRuleName: vm.customRuleName, customSeverity: vm.customSeverity
                ))
            }
        }

        // XML files: also run raw detection for XML-specific tag patterns
        // (e.g., <password>plain</password> where the extracted value alone
        // wouldn't match any pattern rule)
        if ext.lowercased() == "xml" {
            let rawMatches = DetectionRules.scan(content, config: config)
            for rm in rawMatches {
                // Only add XML-specific types not already found
                guard rm.type == .xmlCredential || rm.type == .xmlUsername || rm.type == .xmlHostname else {
                    continue
                }
                let alreadyFound = matches.contains { $0.line == rm.line && $0.type == rm.type }
                if !alreadyFound {
                    matches.append(DetectedMatch(
                        type: rm.type, value: rm.value, range: rm.range,
                        line: rm.line, filePath: relativePath,
                        customRuleName: rm.customRuleName, customSeverity: rm.customSeverity
                    ))
                }
            }
        }

        return matches
    }

    /// Check if a file appears to be binary by looking for null bytes.
    private static func isBinaryFile(at url: URL) -> Bool {
        guard let handle = try? FileHandle(forReadingFrom: url) else {
            return true
        }
        defer { handle.closeFile() }

        let data = handle.readData(ofLength: 8192)
        return data.contains(0)
    }
}
