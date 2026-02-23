import ArgumentParser
import Foundation
import PastewatchCore

struct Init: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Generate project configuration files"
    )

    @Flag(name: .long, help: "Overwrite existing files")
    var force = false

    func run() throws {
        let fm = FileManager.default
        let cwd = fm.currentDirectoryPath

        let configPath = cwd + "/.pastewatch.json"
        let allowPath = cwd + "/.pastewatch-allow"

        // Check for existing files
        if !force {
            if fm.fileExists(atPath: configPath) {
                FileHandle.standardError.write(Data("error: .pastewatch.json already exists (use --force to overwrite)\n".utf8))
                throw ExitCode(rawValue: 2)
            }
            if fm.fileExists(atPath: allowPath) {
                FileHandle.standardError.write(Data("error: .pastewatch-allow already exists (use --force to overwrite)\n".utf8))
                throw ExitCode(rawValue: 2)
            }
        }

        // Write .pastewatch.json
        let config = PastewatchConfig.defaultConfig
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let configData = try encoder.encode(config)
        try configData.write(to: URL(fileURLWithPath: configPath))

        // Write .pastewatch-allow
        let allowTemplate = """
        # Pastewatch allowlist
        # One value per line. Lines starting with # are comments.
        # Values listed here will be excluded from scan results.
        #
        # Examples:
        # test@example.com
        # 192.168.1.1
        # MYCO-000000

        """
        try allowTemplate.write(toFile: allowPath, atomically: true, encoding: .utf8)

        print("created .pastewatch.json")
        print("created .pastewatch-allow")
    }
}
