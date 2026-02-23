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
        for pattern in patterns {
            if matchesPattern(relativePath, pattern: pattern) {
                return true
            }
        }
        return false
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
            let predicate = NSPredicate(format: "SELF LIKE %@", pattern)
            return predicate.evaluate(with: path)
        }

        // Simple filename pattern — match against last component and full path
        let filename = (path as NSString).lastPathComponent
        let predicate = NSPredicate(format: "SELF LIKE %@", pattern)
        return predicate.evaluate(with: filename) || predicate.evaluate(with: path)
    }
}
