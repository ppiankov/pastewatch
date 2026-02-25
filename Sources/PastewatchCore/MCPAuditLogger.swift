import Foundation

/// Audit logger for MCP tool calls — writes to file and stderr.
/// Never logs actual secret values — only metadata (counts, types, paths).
public final class MCPAuditLogger {
    private let fileHandle: FileHandle?
    private let dateFormatter: ISO8601DateFormatter

    public init(path: String) {
        dateFormatter = ISO8601DateFormatter()
        dateFormatter.formatOptions = [.withInternetDateTime]

        if !FileManager.default.fileExists(atPath: path) {
            FileManager.default.createFile(atPath: path, contents: nil)
        }
        fileHandle = FileHandle(forWritingAtPath: path)
        fileHandle?.seekToEndOfFile()

        log("MCP audit log started")
    }

    deinit {
        fileHandle?.closeFile()
    }

    public func log(_ message: String) {
        let timestamp = dateFormatter.string(from: Date())
        let line = "\(timestamp) \(message)\n"
        if let data = line.data(using: .utf8) {
            fileHandle?.write(data)
            FileHandle.standardError.write(data)
        }
    }
}
