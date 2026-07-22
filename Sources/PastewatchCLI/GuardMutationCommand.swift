import ArgumentParser
import Foundation
import PastewatchCore

// WO-526@v3: normalized structured input keeps hook-specific JSON parsing out of policy code.
struct GuardMutationInput {
    // WO-526@v3: only structured mutation operations reach the evaluator.
    enum Operation {
        case edit(oldString: String, newString: String, replaceAll: Bool)
        case write(content: String)
    }

    let filePath: String
    let operation: Operation

    // WO-526@v3: malformed or foreign hook payloads fail closed before file access.
    static func parse(_ data: Data) throws -> GuardMutationInput {
        guard let root = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let tool = root["tool_name"] as? String,
              let input = root["tool_input"] as? [String: Any],
              let filePath = (input["file_path"] ?? input["filePath"]) as? String,
              !filePath.isEmpty else {
            throw GuardMutationInputError.invalidPayload
        }

        switch tool {
        case "Edit":
            guard let oldString = input["old_string"] as? String,
                  let newString = input["new_string"] as? String else {
                throw GuardMutationInputError.invalidPayload
            }
            return GuardMutationInput(
                filePath: filePath,
                operation: .edit(
                    oldString: oldString,
                    newString: newString,
                    replaceAll: input["replace_all"] as? Bool ?? false
                )
            )
        case "Write":
            guard let content = input["content"] as? String else {
                throw GuardMutationInputError.invalidPayload
            }
            return GuardMutationInput(filePath: filePath, operation: .write(content: content))
        default:
            throw GuardMutationInputError.invalidPayload
        }
    }
}

// WO-526@v3: parsing exposes no payload details in diagnostics.
private enum GuardMutationInputError: Error {
    case invalidPayload
}

// WO-526@v3: change-aware Edit/Write guard; guard-write remains the explicit legacy command.
struct GuardMutation: ParsableCommand {
    // WO-526@v3: keep the command explicit rather than changing guard-write semantics.
    static let configuration = CommandConfiguration(
        commandName: "guard-mutation",
        abstract: "Check a structured Edit or Write without blocking unrelated findings"
    )

    @Option(name: .long, help: "Minimum severity to block: critical, high, medium, low")
    var failOnSeverity: Severity = .high

    // WO-526@v3: stdin content is evaluated without copying secrets into argv.
    func run() throws {
        if ProcessInfo.processInfo.environment["PW_GUARD"] == "0" { return }

        let input: GuardMutationInput
        do {
            input = try GuardMutationInput.parse(FileHandle.standardInput.readDataToEndOfFile())
        } catch {
            try deny("invalid structured mutation input")
            return
        }

        let config = PastewatchConfig.resolve()
        guard !config.isPathProtected(input.filePath) else {
            try deny("target is inside a protected directory")
            return
        }

        let currentContent: String
        if FileManager.default.fileExists(atPath: input.filePath) {
            do {
                currentContent = try String(contentsOfFile: input.filePath, encoding: .utf8)
            } catch {
                try deny("target cannot be scanned safely")
                return
            }
        } else {
            currentContent = ""
        }

        switch input.operation {
        case .edit where currentContent.isEmpty:
            try deny("edit target is unavailable")
            return
        case .edit(_, let newString, _) where containsPlaceholder(newString, config: config):
            try deny("proposed content contains unresolved placeholders")
            return
        case .write(let content) where containsPlaceholder(content, config: config):
            try deny("proposed content contains unresolved placeholders")
            return
        default:
            break
        }

        let decision: GuardMutationDecision
        do {
            switch input.operation {
            case let .edit(oldString, newString, replaceAll):
                decision = try GuardMutationEvaluator.evaluateEdit(
                    currentContent: currentContent,
                    oldString: oldString,
                    newString: newString,
                    replaceAll: replaceAll,
                    filePath: input.filePath,
                    config: config,
                    minimumSeverity: failOnSeverity
                )
            case let .write(content):
                decision = try GuardMutationEvaluator.evaluateWrite(
                    currentContent: currentContent,
                    proposedContent: content,
                    filePath: input.filePath,
                    config: config,
                    minimumSeverity: failOnSeverity
                )
            }
        } catch {
            try deny("mutation scan failed")
            return
        }

        guard case .block(let reason) = decision else { return }
        try deny(reason == .touchesExistingFinding
            ? "proposed edit overlaps protected content"
            : "proposed mutation changes protected content")
    }

    // WO-526@v3: unresolved MCP placeholders still require the restorative write path.
    private func containsPlaceholder(_ content: String, config: PastewatchConfig) -> Bool {
        let fullRange = NSRange(content.startIndex..<content.endIndex, in: content)
        guard let structuredRegex = try? NSRegularExpression(pattern: Obfuscator.mcpPlaceholderPattern) else {
            return true
        }
        if structuredRegex.firstMatch(in: content, range: fullRange) != nil {
            return true
        }
        guard let prefix = config.placeholderPrefix else { return false }
        guard let customRegex = try? NSRegularExpression(
            pattern: Obfuscator.customPlaceholderPattern(prefix: prefix)
        ) else {
            return true
        }
        return customRegex.firstMatch(in: content, range: fullRange) != nil
    }

    // WO-526@v3: denial messages disclose policy class, never matched values.
    private func deny(_ reason: String) throws {
        FileHandle.standardError.write(Data("BLOCKED: \(reason)\n".utf8))
        print("Use pastewatch_read_file and pastewatch_write_file for protected mutations.")
        throw ExitCode(rawValue: 2)
    }
}
