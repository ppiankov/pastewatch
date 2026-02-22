import Foundation

/// Parser for JSON files — extracts all string values recursively.
public struct JSONValueParser: FormatParser {
    public init() {}

    public func parseValues(from content: String) -> [ParsedValue] {
        guard let data = content.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: data) else {
            return []
        }

        var results: [ParsedValue] = []
        extractStrings(from: json, key: nil, results: &results, content: content)
        return results
    }

    private func extractStrings(from object: Any, key: String?, results: inout [ParsedValue], content: String) {
        switch object {
        case let str as String:
            let line = findLine(of: str, in: content)
            results.append(ParsedValue(value: str, line: line, key: key))
        case let dict as [String: Any]:
            for (k, v) in dict {
                extractStrings(from: v, key: k, results: &results, content: content)
            }
        case let array as [Any]:
            for item in array {
                extractStrings(from: item, key: key, results: &results, content: content)
            }
        default:
            break
        }
    }

    /// Approximate line number by searching for the string value in the content.
    private func findLine(of value: String, in content: String) -> Int {
        // Search for the value in the content to find its line
        guard let range = content.range(of: value) else { return 1 }
        var line = 1
        var current = content.startIndex
        while current < range.lowerBound {
            if content[current] == "\n" { line += 1 }
            current = content.index(after: current)
        }
        return line
    }
}
