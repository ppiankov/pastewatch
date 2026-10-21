import Foundation

/// Simple line-by-line YAML value parser.
/// Handles key: value pairs. NOT a full YAML spec parser.
public struct YAMLValueParser: FormatParser {
    public init() {}

    // WO-716@v2: scalar syntax must not enlarge downstream key-aware finding ranges.
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
                let value = scalarValue(String(processLine[colonRange.upperBound...])
                    .trimmingCharacters(in: .whitespaces))

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

    // WO-716@v2: preserve encoded scalar bytes so source-range mapping does not need an unescape pass.
    private func scalarValue(_ text: String) -> String {
        if let quote = text.first, quote == "\"" || quote == "'" {
            guard let end = quotedScalarEnd(in: text, quote: quote) else { return text }
            return String(text[text.index(after: text.startIndex)..<end])
        }
        if let comment = text.range(of: #"[ \t]+#"#, options: .regularExpression) {
            return String(text[..<comment.lowerBound]).trimmingCharacters(in: .whitespaces)
        }
        return text
    }

    // WO-716@v2: escaped delimiters stay inside the value; only a trailing YAML comment may follow its closing quote.
    private func quotedScalarEnd(in text: String, quote: Character) -> String.Index? {
        var index = text.index(after: text.startIndex)
        while index < text.endIndex {
            let next = text.index(after: index)
            if quote == "\"", text[index] == "\\" {
                guard next < text.endIndex else { return nil }
                index = text.index(after: next)
            } else if text[index] == quote {
                if quote == "'", next < text.endIndex, text[next] == quote {
                    index = text.index(after: next)
                    continue
                }
                let tail = text[next...]
                let remainder = tail.drop { $0.isWhitespace }
                guard remainder.isEmpty || (tail.first?.isWhitespace == true && remainder.first == "#") else { return nil }
                return index
            } else {
                index = next
            }
        }
        return nil
    }
}
