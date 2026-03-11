import Foundation

/// Regex-based XML value parser for sensitive tag content extraction.
/// Extracts text content from known sensitive XML tags (ClickHouse, Hadoop, etc.).
/// NOT a full DOM parser — intentionally lightweight for config file scanning.
public struct XMLValueParser: FormatParser {

    /// Default sensitive tags covering ClickHouse and common XML config patterns.
    public static let defaultSensitiveTags: Set<String> = [
        // Credentials
        "password", "password_sha256_hex", "password_double_sha1_hex",
        "access_key_id", "secret_access_key",
        // Usernames
        "user", "name", "quota_key",
        // Hostnames
        "host", "hostname", "interserver_http_host",
        // Connection strings
        "connection_string", "url",
    ]

    private let sensitiveTags: Set<String>

    public init(sensitiveTags: Set<String>? = nil) {
        self.sensitiveTags = sensitiveTags ?? Self.defaultSensitiveTags
    }

    public func parseValues(from content: String) -> [ParsedValue] {
        var results: [ParsedValue] = []
        let lines = content.components(separatedBy: .newlines)

        for (index, line) in lines.enumerated() {
            let trimmed = line.trimmingCharacters(in: .whitespaces)

            // Skip XML comments, processing instructions, declarations
            if trimmed.hasPrefix("<!--") || trimmed.hasPrefix("<?") || trimmed.hasPrefix("<!") {
                continue
            }

            // Match <tag>value</tag> on a single line
            // Handles optional attributes: <tag attr="val">value</tag>
            let tagValues = extractTagValues(from: trimmed)
            for (tagName, value) in tagValues {
                let tagLower = tagName.lowercased()
                guard sensitiveTags.contains(tagLower) else { continue }

                // Strip CDATA wrapper if present
                let cleanValue = stripCDATA(value)
                guard !cleanValue.isEmpty else { continue }

                results.append(ParsedValue(value: cleanValue, line: index + 1, key: tagName))
            }
        }

        return results
    }

    /// Extract (tagName, textContent) pairs from a line.
    private func extractTagValues(from line: String) -> [(String, String)] {
        var results: [(String, String)] = []

        // Pattern: <tagName ...>content</tagName>
        // Captures: tag name (group 1), optional attributes (group 2), content (group 3), closing tag (group 4)
        // Content allows CDATA (which contains < and >) via (.+?) non-greedy match
        guard let regex = try? NSRegularExpression(
            pattern: #"<([a-zA-Z_][\w.-]*)\b([^>]*)>(.+?)</([a-zA-Z_][\w.-]*)>"#,
            options: []
        ) else {
            return results
        }

        let nsRange = NSRange(line.startIndex..., in: line)
        let matches = regex.matches(in: line, options: [], range: nsRange)

        for match in matches where match.numberOfRanges >= 5 {
            guard let openRange = Range(match.range(at: 1), in: line),
                  let contentRange = Range(match.range(at: 3), in: line),
                  let closeRange = Range(match.range(at: 4), in: line) else {
                continue
            }

            let openTag = String(line[openRange])
            let closeTag = String(line[closeRange])

            // Open and close tags must match
            guard openTag == closeTag else { continue }

            let content = String(line[contentRange]).trimmingCharacters(in: .whitespaces)
            if !content.isEmpty {
                results.append((openTag, content))
            }
        }

        return results
    }

    /// Strip CDATA wrapper: <![CDATA[...]]> → content
    private func stripCDATA(_ value: String) -> String {
        let trimmed = value.trimmingCharacters(in: .whitespaces)
        if trimmed.hasPrefix("<![CDATA["), trimmed.hasSuffix("]]>") {
            let start = trimmed.index(trimmed.startIndex, offsetBy: 9)
            let end = trimmed.index(trimmed.endIndex, offsetBy: -3)
            guard start < end else { return "" }
            return String(trimmed[start..<end])
        }
        return trimmed
    }
}
