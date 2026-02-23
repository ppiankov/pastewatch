import Foundation

public struct IgnoreFile {
    public let patterns: [String]

    public init(patterns: [String]) {
        self.patterns = patterns
    }

    public static func load(from directory: String) -> IgnoreFile? {
        let path = (directory as NSString).appendingPathComponent(".pastewatchignore")
        guard FileManager.default.fileExists(atPath: path),
              let content = try? String(contentsOfFile: path, encoding: .utf8) else {
            return nil
        }
        let patterns = content
            .components(separatedBy: .newlines)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty && !$0.hasPrefix("#") }
        return IgnoreFile(patterns: patterns)
    }

    public func shouldIgnore(_ relativePath: String) -> Bool {
        patterns.contains { matchesPattern(relativePath, pattern: $0) }
    }

    private func matchesPattern(_ path: String, pattern: String) -> Bool {
        // Directory pattern (ends with /)
        if pattern.hasSuffix("/") {
            let dirName = String(pattern.dropLast())
            let components = path.split(separator: "/").map(String.init)
            return components.contains(dirName)
        }

        // Pattern with path separator — match against full relative path
        if pattern.contains("/") {
            return globMatch(path, pattern: pattern)
        }

        // Simple filename pattern — match against last component and full path
        let filename = URL(fileURLWithPath: path).lastPathComponent
        return globMatch(filename, pattern: pattern) || globMatch(path, pattern: pattern)
    }

    /// Simple glob matching: * matches any sequence, ? matches single character.
    private func globMatch(_ string: String, pattern: String) -> Bool {
        var si = string.startIndex
        var pi = pattern.startIndex
        var starSi = string.endIndex
        var starPi = pattern.endIndex

        while si < string.endIndex {
            if pi < pattern.endIndex && (pattern[pi] == "?" || pattern[pi] == string[si]) {
                si = string.index(after: si)
                pi = pattern.index(after: pi)
            } else if pi < pattern.endIndex && pattern[pi] == "*" {
                starPi = pi
                starSi = si
                pi = pattern.index(after: pi)
            } else if starPi < pattern.endIndex {
                pi = pattern.index(after: starPi)
                starSi = string.index(after: starSi)
                si = starSi
            } else {
                return false
            }
        }

        while pi < pattern.endIndex && pattern[pi] == "*" {
            pi = pattern.index(after: pi)
        }

        return pi == pattern.endIndex
    }
}
