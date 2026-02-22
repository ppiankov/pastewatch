import Foundation

/// Parser for .properties / .cfg / .ini files.
public struct PropertiesParser: FormatParser {
    public init() {}

    public func parseValues(from content: String) -> [ParsedValue] {
        var results: [ParsedValue] = []
        let lines = content.components(separatedBy: .newlines)

        for (index, line) in lines.enumerated() {
            let trimmed = line.trimmingCharacters(in: .whitespaces)

            // Skip empty lines, comments (# and !), section headers [section]
            if trimmed.isEmpty || trimmed.hasPrefix("#") || trimmed.hasPrefix("!") || trimmed.hasPrefix("[") {
                continue
            }

            // Find separator (= or :)
            var separatorIndex: String.Index?
            for char in ["=", ":"] {
                if let idx = trimmed.firstIndex(of: Character(char)) {
                    if separatorIndex == nil || idx < separatorIndex! {
                        separatorIndex = idx
                    }
                }
            }

            guard let sepIdx = separatorIndex else { continue }

            let key = String(trimmed[trimmed.startIndex..<sepIdx]).trimmingCharacters(in: .whitespaces)
            let value = String(trimmed[trimmed.index(after: sepIdx)...]).trimmingCharacters(in: .whitespaces)

            if !value.isEmpty {
                results.append(ParsedValue(value: value, line: index + 1, key: key))
            }
        }

        return results
    }
}
