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

// WO-526@v3: invalid active configuration is a distinct fail-closed boundary.
private enum GuardMutationConfigurationError: Error {
    case invalidConfiguration
}

// WO-526@v3: change-aware Edit/Write guard; guard-write remains the explicit legacy command.
struct GuardMutation: ParsableCommand {
    // WO-526@v3: keep the command explicit rather than changing guard-write semantics.
    static let configuration = CommandConfiguration(
        commandName: "guard-mutation",
        abstract: "Check a structured Edit or Write without blocking unrelated findings"
    )

    @Option(name: .long, help: "Minimum severity to block: critical, high, medium, low")
    var failOnSeverity: Severity = .defaultGuardThreshold

    // WO-687@v2: structured mutations always reach ownership and policy evaluation.
    // WO-672@v1: operator-owned targets are refused before target I/O or evaluation.
    // WO-526@v3: stdin content is evaluated without copying secrets into argv.
    func run() throws {
        // WO-687@v2: inherited settings cannot admit structured mutations.
        let limits = ScanInputLimits.current()
        let input: GuardMutationInput
        do {
            // WO-598@v2: bound the structured transport before parsing attacker-controlled JSON.
            let data = try DetectionRules.readBoundedInputData(
                from: FileHandle.standardInput,
                limits: limits
            )
            input = try GuardMutationInput.parse(data)
        } catch {
            try deny("invalid structured mutation input")
            return
        }

        // WO-672@v1: clean creation cannot grant the agent control over guard policy.
        try checkOperatorOwnership(input.filePath)

        let config: PastewatchConfig
        do {
            config = try validatedConfig()
        } catch {
            try deny("configuration is invalid")
            return
        }
        guard !config.isPathProtected(input.filePath) else {
            try deny("target is inside a protected directory")
            return
        }

        let currentContent: String
        if FileManager.default.fileExists(atPath: input.filePath) {
            do {
                // WO-598@v2: bound existing mutation targets before reading their bytes.
                let data = try DetectionRules.readBoundedFileData(
                    atPath: input.filePath,
                    limits: limits
                )
                guard let decoded = String(data: data, encoding: .utf8) else {
                    try deny("target cannot be scanned safely")
                    return
                }
                currentContent = decoded
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

        // WO-676@v4: observe existing policy scans; migration advice must never initiate another scan.
        var inlineMarkerNotices = 0
        // WO-687@v2: remember only whether existing policy scans selected findings.
        var hasFindings = false
        let onFindings: (String, [DetectedMatch]) -> Void = { content, matches in
            // WO-687@v2: observers collect diagnostic metadata without altering the evaluator.
            hasFindings = hasFindings || !matches.isEmpty
            inlineMarkerNotices = max(inlineMarkerNotices, FileGuard.inlineMarkerNoticeCount(matches: matches, content: content))
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
                    // WO-676@v4: the evaluator supplies only findings already selected for its decision.
                    minimumSeverity: failOnSeverity, onFindings: onFindings
                )
            case let .write(content):
                decision = try GuardMutationEvaluator.evaluateWrite(
                    currentContent: currentContent,
                    proposedContent: content,
                    filePath: input.filePath,
                    config: config,
                    // WO-676@v4: proposed and existing snapshots share the same diagnostic observer.
                    minimumSeverity: failOnSeverity, onFindings: onFindings
                )
            }
        } catch {
            try deny("mutation scan failed")
            return
        }

        guard case .block(let reason) = decision else { return }
        // WO-687@v2: only a finding-backed denial emits retirement advice, once per command.
        FileGuard.printGuardEnvironmentNotice(hasFindings: hasFindings)
        // WO-676@v4: notices accompany a denial only, never a clean or admitted mutation.
        try deny(reason == .touchesExistingFinding
            ? "proposed edit overlaps protected content"
            : "proposed mutation changes protected content", inlineMarkerNotices: inlineMarkerNotices)
    }

    // WO-672@v1: ownership refusal occurs before resolving policy or opening the mutation target.
    private func checkOperatorOwnership(_ path: String) throws {
        if GuardDecision.isOperatorOwnedPath(path) { try deny(GuardDecision.operatorOwnedFileMessage) }
    }

    // WO-526@v3: resolve only after the highest-priority active config validates.
    private func validatedConfig() throws -> PastewatchConfig {
        // WO-574@v4: use the same atomic read/decode/validate result as every guard.
        do {
            return try ConfigValidator.resolveValidated().config
        } catch {
            throw GuardMutationConfigurationError.invalidConfiguration
        }
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

    // WO-676@v4: human-facing denials may attach the finding-bound migration notice.
    // WO-671@v2: protected edits use the same narrow-first remedy as file guards.
    // WO-526@v3: denial messages disclose policy class, never matched values.
    private func deny(_ reason: String, inlineMarkerNotices: Int = 0) throws {
        FileHandle.standardError.write(Data("BLOCKED: \(reason)\n".utf8))
        // WO-676@v4: policy evaluators never print migration messages themselves.
        FileGuard.printInlineMarkerNotices(count: inlineMarkerNotices)
        // WO-671@v2: operator-owned policy files never receive an agent-edit remedy.
        if reason != GuardDecision.operatorOwnedFileMessage { FileGuard.printEditRemedies() }
        // WO-681@v1: append deciding-version guidance without changing mutation authorization.
        FileGuard.printDecisionVersion()
        throw ExitCode(rawValue: GuardExitContract.blocked)
    }
}
