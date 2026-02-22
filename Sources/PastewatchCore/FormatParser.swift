import Foundation

/// A parsed value from a structured file.
public struct ParsedValue {
    public let value: String
    public let line: Int
    public let key: String?

    public init(value: String, line: Int, key: String? = nil) {
        self.value = value
        self.line = line
        self.key = key
    }
}

/// Protocol for format-specific file parsers.
public protocol FormatParser {
    func parseValues(from content: String) -> [ParsedValue]
}

/// Select appropriate parser for a file extension.
public func parserForExtension(_ ext: String) -> FormatParser? {
    switch ext.lowercased() {
    case "env":
        return EnvParser()
    case "json":
        return JSONValueParser()
    case "yml", "yaml":
        return YAMLValueParser()
    case "properties", "cfg", "ini":
        return PropertiesParser()
    default:
        return nil
    }
}
