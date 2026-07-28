import ArgumentParser
import Foundation
import PastewatchCore

struct HookGroup: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "hook",
        abstract: "Manage git pre-commit hook",
        subcommands: [Install.self, Uninstall.self]
    )
}

extension HookGroup {
    struct Install: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Install pre-commit hook"
        )

        @Flag(name: .long, help: "Append to existing hook instead of failing")
        var append = false

        func run() throws {
            let hooksDir = try findGitHooksDir()
            let hookPath = hooksDir + "/pre-commit"
            let fm = FileManager.default

            // Create hooks directory if needed
            if !fm.fileExists(atPath: hooksDir) {
                try fm.createDirectory(atPath: hooksDir, withIntermediateDirectories: true)
            }

            // WO-130: generated hooks must fail closed on scan setup/shared-pattern failures.
            let hookContent = """
            # BEGIN PASTEWATCH
            git diff --cached --diff-filter=d --no-color | pastewatch-cli scan --check
            PASTEWATCH_RESULT=$?
            # WO-580@v3: generated hooks consume the named scan findings contract.
            if [ "$PASTEWATCH_RESULT" -eq \(ScanExitContract.findingsDetected) ]; then
                echo "pastewatch: sensitive data detected in staged changes" >&2
                exit 1
            fi
            # WO-580@v3: only the named clean outcome permits the commit.
            if [ "$PASTEWATCH_RESULT" -ne \(ScanExitContract.clean) ]; then
                echo "pastewatch: scan failed with exit code $PASTEWATCH_RESULT" >&2
                exit 1
            fi
            # END PASTEWATCH
            """

            if fm.fileExists(atPath: hookPath) {
                let existing = try String(contentsOfFile: hookPath, encoding: .utf8)
                if existing.contains("BEGIN PASTEWATCH") {
                    FileHandle.standardError.write(Data("error: pastewatch hook already installed\n".utf8))
                    throw ExitCode(rawValue: 2)
                }
                if !append {
                    FileHandle.standardError.write(Data("error: pre-commit hook already exists (use --append to add pastewatch)\n".utf8))
                    throw ExitCode(rawValue: 2)
                }
                // Append to existing hook
                let updated = existing.trimmingCharacters(in: .whitespacesAndNewlines) + "\n\n" + hookContent + "\n"
                try updated.write(toFile: hookPath, atomically: true, encoding: .utf8)
            } else {
                // Create new hook with shebang
                let fullHook = "#!/bin/sh\n\n" + hookContent + "\n"
                try fullHook.write(toFile: hookPath, atomically: true, encoding: .utf8)
            }

            // Make executable (chmod +x)
            try fm.setAttributes([.posixPermissions: 0o755], ofItemAtPath: hookPath)

            print("installed pre-commit hook at \(hookPath)")
        }
    }

    struct Uninstall: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Remove pre-commit hook"
        )

        func run() throws {
            let hooksDir = try findGitHooksDir()
            let hookPath = hooksDir + "/pre-commit"
            let fm = FileManager.default

            guard fm.fileExists(atPath: hookPath) else {
                FileHandle.standardError.write(Data("error: no pre-commit hook found\n".utf8))
                throw ExitCode(rawValue: 2)
            }

            let content = try String(contentsOfFile: hookPath, encoding: .utf8)

            guard content.contains("BEGIN PASTEWATCH") else {
                FileHandle.standardError.write(Data("error: pre-commit hook does not contain pastewatch section\n".utf8))
                throw ExitCode(rawValue: 2)
            }

            // Remove pastewatch section between markers
            var lines = content.components(separatedBy: "\n")
            var inSection = false
            lines.removeAll { line in
                if line.contains("BEGIN PASTEWATCH") { inSection = true; return true }
                if line.contains("END PASTEWATCH") { inSection = false; return true }
                return inSection
            }

            // Clean up: remove consecutive empty lines at the end
            while lines.last?.trimmingCharacters(in: .whitespaces).isEmpty == true {
                lines.removeLast()
            }

            let remaining = lines.joined(separator: "\n").trimmingCharacters(in: .whitespacesAndNewlines)

            // If only the shebang remains (or empty), remove the file
            if remaining.isEmpty || remaining == "#!/bin/sh" || remaining == "#!/bin/bash" {
                try fm.removeItem(atPath: hookPath)
                print("removed pre-commit hook")
            } else {
                try (remaining + "\n").write(toFile: hookPath, atomically: true, encoding: .utf8)
                print("removed pastewatch section from pre-commit hook")
            }
        }
    }
}

/// Find the git hooks directory using git rev-parse.
private func findGitHooksDir() throws -> String {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/git")
    process.arguments = ["rev-parse", "--git-path", "hooks"]

    let pipe = Pipe()
    process.standardOutput = pipe
    process.standardError = FileHandle.nullDevice

    try process.run()
    process.waitUntilExit()

    guard process.terminationStatus == 0 else {
        FileHandle.standardError.write(Data("error: not a git repository\n".utf8))
        throw ExitCode(rawValue: 2)
    }

    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    let path = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

    guard !path.isEmpty else {
        FileHandle.standardError.write(Data("error: could not determine git hooks path\n".utf8))
        throw ExitCode(rawValue: 2)
    }

    // If relative, make absolute from CWD
    if path.hasPrefix("/") {
        return path
    }
    return FileManager.default.currentDirectoryPath + "/" + path
}
