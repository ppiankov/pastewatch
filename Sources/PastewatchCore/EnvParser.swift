import Foundation

/// Parser for .env files (KEY=VALUE format).
public struct EnvParser: FormatParser {
    public init() {}

    public func parseValues(from content: String) -> [ParsedValue] {
        var results: [ParsedValue] = []
        let lines = content.components(separatedBy: .newlines)

        for (index, line) in lines.enumerated() {
            let trimmed = line.trimmingCharacters(in: .whitespaces)

            // Skip empty lines and comments
            if trimmed.isEmpty || trimmed.hasPrefix("#") { continue }

            // Find KEY=VALUE separator
            guard let eqIndex = trimmed.firstIndex(of: "=") else { continue }

            let key = String(trimmed[trimmed.startIndex..<eqIndex]).trimmingCharacters(in: .whitespaces)
            var value = String(trimmed[trimmed.index(after: eqIndex)...]).trimmingCharacters(in: .whitespaces)

            // Strip surrounding quotes
            if (value.hasPrefix("\"") && value.hasSuffix("\"")) ||
               (value.hasPrefix("'") && value.hasSuffix("'")) {
                value = String(value.dropFirst().dropLast())
            }

            if !value.isEmpty {
                results.append(ParsedValue(value: value, line: index + 1, key: key))
            }
        }

        return results
    }
}
