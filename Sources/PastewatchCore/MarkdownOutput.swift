import Foundation

public enum MarkdownFormatter {
    /// Format findings for a single file/stdin scan.
    public static func formatSingle(matches: [DetectedMatch], filePath: String?, obfuscated: String?) -> String {
        var lines: [String] = []
        lines.append("## Pastewatch Scan Results")
        lines.append("")
        lines.append("\(matches.count) finding(s) detected")
        lines.append("")
        lines.append("| Severity | Type | Line | Value |")
        lines.append("|----------|------|------|-------|")
        for match in matches {
            let sev = match.effectiveSeverity.rawValue
            let name = match.displayName
            let line = match.line
            let val = "`\(match.value)`"
            lines.append("| \(sev) | \(name) | \(line) | \(val) |")
        }
        lines.append("")
        return lines.joined(separator: "\n")
    }

    /// Format findings for a directory scan.
    public static func formatDirectory(results: [FileScanResult]) -> String {
        let totalFindings = results.reduce(0) { $0 + $1.matches.count }
        var lines: [String] = []
        lines.append("## Pastewatch Scan Results")
        lines.append("")
        lines.append("\(totalFindings) finding(s) in \(results.count) file(s)")
        lines.append("")
        for fr in results {
            lines.append("### \(fr.filePath)")
            lines.append("")
            lines.append("| Severity | Type | Line | Value |")
            lines.append("|----------|------|------|-------|")
            for match in fr.matches {
                let sev = match.effectiveSeverity.rawValue
                let name = match.displayName
                let line = match.line
                let val = "`\(match.value)`"
                lines.append("| \(sev) | \(name) | \(line) | \(val) |")
            }
            lines.append("")
        }
        return lines.joined(separator: "\n")
    }
}
