import Foundation

/// Result of scanning a single file.
public struct FileScanResult {
    public let filePath: String
    public let matches: [DetectedMatch]
    public let content: String

    public init(filePath: String, matches: [DetectedMatch], content: String) {
        self.filePath = filePath
        self.matches = matches
        self.content = content
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
        extraIgnorePatterns: [String] = []
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
            var fileMatches: [DetectedMatch]
            if let parser = parserForExtension(parsedExt) {
                let parsedValues = parser.parseValues(from: content)
                fileMatches = []
                for pv in parsedValues {
                    let valueMatches = DetectionRules.scan(pv.value, config: config)
                    for vm in valueMatches {
                        fileMatches.append(DetectedMatch(
                            type: vm.type,
                            value: vm.value,
                            range: vm.range,
                            line: pv.line,
                            filePath: relativePath,
                            customRuleName: vm.customRuleName,
                            customSeverity: vm.customSeverity
                        ))
                    }
                }
            } else {
                let matches = DetectionRules.scan(content, config: config)
                fileMatches = matches.map { match in
                    DetectedMatch(
                        type: match.type,
                        value: match.value,
                        range: match.range,
                        line: match.line,
                        filePath: relativePath,
                        customRuleName: match.customRuleName,
                        customSeverity: match.customSeverity
                    )
                }
            }

            fileMatches = Allowlist.filterInlineAllow(matches: fileMatches, content: content)

            if !fileMatches.isEmpty {
                results.append(FileScanResult(
                    filePath: relativePath,
                    matches: fileMatches,
                    content: content
                ))
            }
        }

        return results.sorted { $0.filePath < $1.filePath }
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
