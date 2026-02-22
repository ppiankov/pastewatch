import Foundation

/// Simple line-by-line YAML value parser.
/// Handles key: value pairs. NOT a full YAML spec parser.
public struct YAMLValueParser: FormatParser {
    public init() {}

    public func parseValues(from content: String) -> [ParsedValue] {
        var results: [ParsedValue] = []
        let lines = content.components(separatedBy: .newlines)

        for (index, line) in lines.enumerated() {
            let trimmed = line.trimmingCharacters(in: .whitespaces)

            // Skip empty lines, comments, document markers
            if trimmed.isEmpty || trimmed.hasPrefix("#") || trimmed == "---" || trimmed == "..." { continue }

            // Skip list items that are just dashes
            let processLine = trimmed.hasPrefix("- ") ? String(trimmed.dropFirst(2)) : trimmed

            // Find key: value separator (but not in URLs like http://)
            if let colonRange = processLine.range(of: ": ") {
                let key = String(processLine[processLine.startIndex..<colonRange.lowerBound])
                    .trimmingCharacters(in: .whitespaces)
                var value = String(processLine[colonRange.upperBound...])
                    .trimmingCharacters(in: .whitespaces)

                // Strip surrounding quotes
                if (value.hasPrefix("\"") && value.hasSuffix("\"")) ||
                   (value.hasPrefix("'") && value.hasSuffix("'")) {
                    value = String(value.dropFirst().dropLast())
                }

                if !value.isEmpty {
                    results.append(ParsedValue(value: value, line: index + 1, key: key))
                }
            } else if processLine.hasSuffix(":") {
                // Key without value (block mapping) — skip
                continue
            }
        }

        return results
    }
}
