import ArgumentParser
import Foundation
import PastewatchCore

#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

// WO-607: generated-section identity is shared by install and explicit upgrade.
private let pastewatchHookStartMarker = "# BEGIN PASTEWATCH"
private let pastewatchHookEndMarker = "# END PASTEWATCH"

// WO-594: the hook group exposes the staged-check and fixture authorization boundaries.
struct HookGroup: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "hook",
        abstract: "Manage git pre-commit hook",
        subcommands: [Install.self, Uninstall.self, CheckStaged.self, FixtureFingerprint.self]
    )
}

extension HookGroup {
    struct Install: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Install pre-commit hook"
        )

        @Flag(name: .long, help: "Append to existing hook instead of failing")
        var append = false

        // WO-607: replacing an installed Pastewatch section requires explicit operator intent.
        @Flag(name: .long, help: "Replace an existing Pastewatch hook section")
        var upgrade = false

        func run() throws {
            // WO-607: install and explicit upgrade share one operator-controlled entry point.
            let hooksDir = try findGitHooksDir()
            let hookPath = hooksDir + "/pre-commit"
            let fm = FileManager.default
            let hookPathExists = fm.fileExists(atPath: hookPath)
                || (try? fm.destinationOfSymbolicLink(atPath: hookPath)) != nil
            guard !(append && upgrade) else {
                FileHandle.standardError.write(
                    Data("error: --append and --upgrade cannot be used together\n".utf8)
                )
                throw ExitCode(rawValue: ScanExitContract.operationalFailure)
            }

            // Create hooks directory if needed
            if !fm.fileExists(atPath: hooksDir) {
                try fm.createDirectory(atPath: hooksDir, withIntermediateDirectories: true)
            }

            // WO-594: one command owns staged-diff authorization and scan exit propagation.
            let hookContent = """
            # BEGIN PASTEWATCH
            pastewatch-cli hook check-staged
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

            var createdHook = false
            if hookPathExists {
                if append || upgrade {
                    // WO-611@v2: a pinned descriptor rejects stale upgrade targets.
                    // WO-613@v2: the same descriptor prevents symlink-following during append.
                    let editor = try openHookFileEditor(atPath: hookPath)
                    let updated: String
                    if upgrade {
                        updated = try replacingPastewatchHookSection(
                            in: editor.content,
                            with: hookContent
                        )
                    } else if editor.content.contains(pastewatchHookStartMarker)
                                || editor.content.contains(pastewatchHookEndMarker) {
                        FileHandle.standardError.write(
                            Data("error: pastewatch hook already installed\n".utf8)
                        )
                        throw ExitCode(rawValue: ScanExitContract.operationalFailure)
                    } else {
                        updated = editor.content.trimmingCharacters(
                            in: .whitespacesAndNewlines
                        ) + "\n\n" + hookContent + "\n"
                    }
                    try replaceHookContent(updated, using: editor)
                } else {
                    let existing = try String(contentsOfFile: hookPath, encoding: .utf8)
                    if existing.contains(pastewatchHookStartMarker)
                        || existing.contains(pastewatchHookEndMarker) {
                        FileHandle.standardError.write(
                            Data("error: pastewatch hook already installed\n".utf8)
                        )
                    } else {
                        FileHandle.standardError.write(
                            Data(
                                (
                                    "error: pre-commit hook already exists "
                                        + "(use --append to add pastewatch)\n"
                                ).utf8
                            )
                        )
                    }
                    throw ExitCode(rawValue: ScanExitContract.operationalFailure)
                }
            } else {
                guard !upgrade else {
                    FileHandle.standardError.write(
                        Data("error: no installed Pastewatch hook to upgrade\n".utf8)
                    )
                    throw ExitCode(rawValue: ScanExitContract.operationalFailure)
                }
                // Create new hook with shebang
                let fullHook = "#!/bin/sh\n\n" + hookContent + "\n"
                try fullHook.write(toFile: hookPath, atomically: true, encoding: .utf8)
                createdHook = true
            }

            if createdHook {
                // Fresh hooks use the documented executable mode.
                try fm.setAttributes([.posixPermissions: 0o755], ofItemAtPath: hookPath)
            }

            print("installed pre-commit hook at \(hookPath)")
        }
    }

    // WO-594: generated hooks call this hidden boundary instead of a lossy shell pipeline.
    struct CheckStaged: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Check staged changes with committed fixture authorizations",
            shouldDisplay: false
        )

        func run() throws {
            // WO-594: the generated hook preserves scan and operational exit semantics.
            do {
                let filteredDiff = try GitDiffScanner.filteredHookStagedDiff()
                let status = try runScanCheck(input: filteredDiff)
                guard status == ScanExitContract.clean else {
                    throw ExitCode(rawValue: status)
                }
            } catch let exitCode as ExitCode {
                throw exitCode
            } catch {
                FileHandle.standardError.write(Data("error: \(error.localizedDescription)\n".utf8))
                throw ExitCode(rawValue: ScanExitContract.operationalFailure)
            }
        }
    }

    // WO-594: operators can create a manifest entry without printing fixture content.
    struct FixtureFingerprint: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "fixture-fingerprint",
            abstract: "Print a value-free authorization entry for one fixture line"
        )

        @Argument(help: "Repository-relative fixture file")
        var file: String

        @Option(name: .long, help: "One-based source line")
        var line: Int

        func run() throws {
            // WO-594: fixture metadata is derived without printing source content.
            let authorization = try GitDiffScanner.hookFixtureAuthorization(
                filePath: file,
                line: line
            )
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys]
            let data = try encoder.encode(authorization)
            guard let output = String(data: data, encoding: .utf8) else {
                throw ExitCode.failure
            }
            print(output)
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

// WO-611@v2: a pinned regular-file identity prevents path replacement from becoming a write target.
final class HookFileEditor {
    private struct Identity: Equatable {
        let device: UInt64
        let inode: UInt64
    }

    let content: String

    private let path: String
    private let identity: Identity
    private let handle: FileHandle

    init(path: String) throws {
        let descriptor = open(path, O_RDWR | O_NOFOLLOW)
        guard descriptor >= 0 else {
            throw HookFileEditorError.notRegular
        }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)

        var info = stat()
        guard fstat(descriptor, &info) == 0,
              (info.st_mode & mode_t(S_IFMT)) == mode_t(S_IFREG) else {
            try? handle.close()
            throw HookFileEditorError.notRegular
        }
        guard info.st_nlink == 1 else {
            try? handle.close()
            throw HookFileEditorError.multiplyLinked
        }
        // WO-617: nil means a valid zero-byte file, not a decode failure.
        let data = try handle.readToEnd() ?? Data()
        guard let content = String(data: data, encoding: .utf8) else {
            try? handle.close()
            throw HookFileEditorError.invalidUTF8
        }

        self.path = path
        self.identity = Identity(
            device: UInt64(info.st_dev),
            inode: UInt64(info.st_ino)
        )
        self.handle = handle
        self.content = content
    }

    // WO-611@v2: identity checks bracket writes without following a replaced path.
    func replaceContent(_ replacement: String) throws {
        guard try currentPathIdentity() == identity else {
            throw HookFileEditorError.pathChanged
        }
        try handle.seek(toOffset: 0)
        try handle.truncate(atOffset: 0)
        try handle.write(contentsOf: Data(replacement.utf8))
        try handle.synchronize()
        guard try currentPathIdentity() == identity else {
            throw HookFileEditorError.pathChanged
        }
    }

    private func currentPathIdentity() throws -> Identity {
        // WO-611@v2: every path check must still identify the descriptor-pinned file.
        var info = stat()
        guard lstat(path, &info) == 0,
              (info.st_mode & mode_t(S_IFMT)) == mode_t(S_IFREG) else {
            throw HookFileEditorError.pathChanged
        }
        return Identity(
            device: UInt64(info.st_dev),
            inode: UInt64(info.st_ino)
        )
    }
}

// WO-611@v2: file-identity failures remain explicit operational errors.
enum HookFileEditorError: LocalizedError, Equatable {
    // WO-611@v2: unsafe file identities fail closed before any hook replacement.
    case notRegular
    case multiplyLinked
    case invalidUTF8
    case pathChanged

    var errorDescription: String? {
        switch self {
        case .notRegular:
            return "hook must be a regular file; update symlink-managed hooks at their target"
        case .multiplyLinked:
            return "hook has multiple hard links; update it through the owning hook manager"
        case .invalidUTF8:
            return "hook is not readable UTF-8"
        case .pathChanged:
            return "hook changed concurrently; no replacement path was written"
        }
    }
}

private func openHookFileEditor(atPath path: String) throws -> HookFileEditor {
    // WO-611@v2: translate file-identity failures to the hook operational contract.
    do {
        return try HookFileEditor(path: path)
    } catch {
        FileHandle.standardError.write(Data("error: \(error.localizedDescription)\n".utf8))
        throw ExitCode(rawValue: ScanExitContract.operationalFailure)
    }
}

// WO-611@v2: descriptor-pinned writes fail through the hook operational contract.
private func replaceHookContent(
    _ content: String,
    using editor: HookFileEditor
) throws {
    // WO-611@v2: descriptor-pinned replacement failures remain operational errors.
    do {
        try editor.replaceContent(content)
    } catch {
        FileHandle.standardError.write(Data("error: \(error.localizedDescription)\n".utf8))
        throw ExitCode(rawValue: ScanExitContract.operationalFailure)
    }
}

// WO-604: resolve the running binary independently of argv[0]'s PATH spelling.
private func runScanCheck(input: String) throws -> Int32 {
    guard let executableURL = Bundle.main.executableURL else {
        throw CocoaError(.fileNoSuchFile)
    }
    let process = Process()
    process.executableURL = executableURL
    process.arguments = ["scan", "--check"]

    let inputPipe = Pipe()
    process.standardInput = inputPipe

    try process.run()
    do {
        try inputPipe.fileHandleForWriting.write(contentsOf: Data(input.utf8))
        try inputPipe.fileHandleForWriting.close()
    } catch {
        if process.isRunning {
            process.terminate()
        }
        process.waitUntilExit()
        throw error
    }
    process.waitUntilExit()
    return process.terminationStatus
}

// WO-607: upgrade only one exact, well-formed generated section.
private func replacingPastewatchHookSection(
    in existing: String,
    with replacement: String
) throws -> String {
    let startRanges = exactLineRanges(of: pastewatchHookStartMarker, in: existing)
    let endRanges = exactLineRanges(of: pastewatchHookEndMarker, in: existing)
    guard startRanges.count == 1,
          endRanges.count == 1,
          startRanges[0].lowerBound < endRanges[0].lowerBound else {
        FileHandle.standardError.write(
            Data("error: existing Pastewatch hook markers are malformed\n".utf8)
        )
        throw ExitCode(rawValue: ScanExitContract.operationalFailure)
    }

    return existing.replacingCharacters(
        in: startRanges[0].lowerBound..<endRanges[0].upperBound,
        with: replacement
    )
}

// WO-607: only standalone marker lines can authorize a section replacement.
private func exactLineRanges(
    of marker: String,
    in content: String
) -> [Range<String.Index>] {
    var ranges: [Range<String.Index>] = []
    var searchStart = content.startIndex
    while searchStart < content.endIndex,
          let range = content.range(of: marker, range: searchStart..<content.endIndex) {
        let startsLine = range.lowerBound == content.startIndex
            || content[content.index(before: range.lowerBound)] == "\n"
        let endsLine = range.upperBound == content.endIndex
            || content[range.upperBound] == "\n"
            || (
                content[range.upperBound] == "\r"
                    && content.index(after: range.upperBound) < content.endIndex
                    && content[content.index(after: range.upperBound)] == "\n"
            )
        if startsLine && endsLine {
            ranges.append(range)
        }
        searchStart = range.upperBound
    }
    return ranges
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
