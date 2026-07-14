import ArgumentParser
import Foundation
import PastewatchCore
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

// C-level fork — Swift marks fork() unavailable on Darwin but we need TTY inheritance
@_silgen_name("fork") private func _pw_fork() -> pid_t

// File-level refs for signal handler access
private var launchProxyProcess: Process?
private var launchProxyPid: pid_t = 0 // WO-438: signal-safe proxy child identity.
private var launchAgentPid: pid_t = 0
private var launchPendingSignal: Int32 = 0 // WO-438: deferred termination across startup windows.

// WO-438: handlers only mutate scalar state and call kill(), both safe for this signal path.
private func handleLaunchSignal(_ signalNumber: Int32) {
    launchPendingSignal = signalNumber
    if launchAgentPid > 0 {
        kill(launchAgentPid, signalNumber)
    } else if launchProxyPid > 0 {
        kill(launchProxyPid, SIGTERM)
    }
}

// WO-136/WO-137: test fixture HOME redirection must be unavailable in release builds.
private enum StartupSweepFixtureContext {
    static let probeEnvironmentKey = "PW_LAUNCH_FIXTURE_CONTEXT_PROBE" // WO-137: assertion-only context probe.
    static let probeMarker = "pastewatch-startup-sweep-fixture-context" // WO-137: stable test probe marker.
    static let preAgentDelayEnvironmentKey = "PW_LAUNCH_PRE_AGENT_DELAY_MS" // WO-438: startup signal seam.

    static let isEnabled: Bool = {
        var enabled = false
        assert({
            enabled = true
            return true
        }())
        return enabled
    }()
}

struct Launch: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Start the proxy and launch an agent through it in one command",
        discussion: """
        Starts the pastewatch proxy in the background, waits for it to be ready,
        then launches your agent. The proxy redacts supported Anthropic-shaped
        traffic, so ANTHROPIC_BASE_URL is pointed at it only for 'claude'; other
        agents launch without proxy interposition (a warning is printed) and stay
        covered by the pastewatch hooks and MCP server. When the agent exits, the
        proxy is stopped automatically.

        Examples:
          pastewatch-cli launch claude
          pastewatch-cli launch --port 9999 -- claude --model opus
          pastewatch-cli launch --audit-log /tmp/pw.log -- claude
        """
    )

    @Option(name: .long, help: "Proxy listen port")
    var port: UInt16 = 8443

    @Option(name: .long, help: "Upstream API URL")
    var upstream: String = "https://api.anthropic.com"

    @Option(name: .long, help: "Forward through corporate proxy (e.g., http://proxy.corp:8080)")
    var forwardProxy: String?

    @Option(name: .long, help: "Minimum severity to redact: critical, high, medium, low")
    var severity: Severity = .high

    @Option(name: .long, help: "Audit log file path")
    var auditLog: String?

    @Flag(name: .long, inversion: .prefixedNo, help: "Inject alert into response when secrets are redacted")
    var alert: Bool = true

    @Flag(name: .long, help: "Suppress proxy startup messages")
    var quiet: Bool = false

    @Flag(name: .long, inversion: .prefixedNo, help: "Run startup sweep for pre-existing shell config credentials")
    var startupSweep: Bool = true

    @Option(name: .long, help: "PEM CA bundle to trust for the upstream TLS handshake (in addition to system roots)")
    var caCert: String?

    @Flag(name: .long, help: "Skip upstream TLS verification (insecure; for private-CA gateways only)")
    var insecure: Bool = false

    @Argument(parsing: .captureForPassthrough)
    var command: [String] = []

    // WO-409: agents whose traffic the proxy can actually redact get ANTHROPIC_BASE_URL
    // pointed at the proxy. Exact basename match (not prefix) so a foreign wrapper like
    // `claude-openai-bridge` cannot accidentally route into the Anthropic-only proxy and
    // hit WO-408's fail-closed refusal. A future --force-proxy flag can override this.
    static let proxyRoutedAgents: Set<String> = ["claude"]

    static func isProxyRoutedAgent(_ binary: String) -> Bool {
        proxyRoutedAgents.contains(binary)
    }

    private static let anthropicBaseURLEnv = "ANTHROPIC_BASE_URL"

    // WO-409/WO-418: only wire ANTHROPIC_BASE_URL for agents the proxy actually redacts.
    // Clear stale local pastewatch proxy values for unsupported agents, but preserve remote
    // corporate/team gateways the operator intentionally configured.
    static func configureProxyEnv(agentBinary: String, port: UInt16, quiet: Bool = false) {
        if isProxyRoutedAgent(agentBinary) {
            setenv(anthropicBaseURLEnv, "http://127.0.0.1:\(port)", 1)
        } else if shouldClearExistingAnthropicBaseURL(ProcessInfo.processInfo.environment[anthropicBaseURLEnv]) {
            unsetenv(anthropicBaseURLEnv)
            if !quiet {
                FileHandle.standardError.write(Data(nonRoutedWarning(agentBinary: agentBinary, baseURLState: "not set").utf8))
            }
        } else {
            if !quiet {
                FileHandle.standardError.write(Data(nonRoutedWarning(agentBinary: agentBinary, baseURLState: "preserved").utf8))
            }
        }
    }

    static func shouldClearExistingAnthropicBaseURL(_ value: String?) -> Bool {
        guard let value = value?.trimmingCharacters(in: .whitespacesAndNewlines), !value.isEmpty else {
            return true
        }
        // WO-423: URLComponents requires brackets around IPv6 hosts; recognize only
        // unambiguous bare local literals and preserve ambiguous host:port text.
        if value == "::1" || value == "[::1]" || value == "::" || value == "[::]" {
            return true
        }
        let candidates = value.contains("://") ? [value] : [value, "http://\(value)"]
        return candidates.contains { candidate in
            guard let host = URLComponents(string: candidate)?.host else { return false }
            return isLocalAnthropicBaseURLHost(host)
        }
    }

    // WO-423: stale local proxy URLs can be written in non-canonical forms; preserve
    // remote gateways, but clear loopback/any-address spellings for non-routed agents.
    static func isLocalAnthropicBaseURLHost(_ host: String) -> Bool {
        let normalized = host.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        if normalized == "localhost" || normalized == "::1" || normalized == "::" || normalized == "0.0.0.0" {
            return true
        }
        if normalized.hasPrefix("::ffff:") {
            return isLocalIPv4AnthropicBaseURLHost(String(normalized.dropFirst("::ffff:".count)))
        }
        return isLocalIPv4AnthropicBaseURLHost(normalized)
    }

    static func isLocalIPv4AnthropicBaseURLHost(_ host: String) -> Bool {
        let parts = host.split(separator: ".", omittingEmptySubsequences: false)
        guard (1...4).contains(parts.count) else {
            return false
        }
        let numbers = parts.compactMap { parseIPv4Component(String($0)) }
        guard numbers.count == parts.count else { return false }

        let address: UInt32
        switch numbers.count {
        case 1:
            address = numbers[0]
        case 2:
            guard numbers[0] <= 0xff, numbers[1] <= 0x00ff_ffff else { return false }
            address = (numbers[0] << 24) | numbers[1]
        case 3:
            guard numbers[0] <= 0xff, numbers[1] <= 0xff, numbers[2] <= 0xffff else { return false }
            address = (numbers[0] << 24) | (numbers[1] << 16) | numbers[2]
        case 4:
            guard numbers.allSatisfy({ $0 <= 0xff }) else { return false }
            address = (numbers[0] << 24) | (numbers[1] << 16) | (numbers[2] << 8) | numbers[3]
        default:
            return false
        }

        return (address >> 24) == 127 || address == 0
    }

    // WO-423: stale local proxy URLs may use inet_aton-style abbreviated or octal IPv4.
    private static func parseIPv4Component(_ raw: String) -> UInt32? {
        guard !raw.isEmpty else { return nil }
        let lower = raw.lowercased()
        let radix: Int
        let digits: String
        if lower.hasPrefix("0x") {
            radix = 16
            digits = String(lower.dropFirst(2))
        } else if lower.count > 1 && lower.hasPrefix("0") {
            radix = 8
            digits = lower
        } else {
            radix = 10
            digits = lower
        }
        guard !digits.isEmpty else { return nil }
        return UInt32(digits, radix: radix)
    }

    static func nonRoutedWarning(agentBinary: String, baseURLState: String) -> String {
        let baseURLClause = baseURLState == "preserved"
            ? "preserving existing ANTHROPIC_BASE_URL."
            : "launching without proxy interposition (ANTHROPIC_BASE_URL not set)."
        return "warning: pastewatch proxy redaction is not wired for agent '\(agentBinary)'; " +
            "\(baseURLClause) " +
            "The proxy layer currently redacts Anthropic-shaped traffic only; 'claude' is " +
            "the only agent routed through it. Protect non-routed agents with configured " +
            "pastewatch hooks and MCP tools where available.\n"
    }

    func run() throws {
        try runStartupSweepFixtureProbeIfNeeded()
        let command = try normalizedCommand()
        installLaunchSignalHandlers()
        try throwIfLaunchTerminationRequested()
        runStartupSweepIfNeeded()
        let config = PastewatchConfig.resolve()
        writeBufferModeWarningIfNeeded(config: config)

        let agentBinary = (command[0] as NSString).lastPathComponent
        if !Launch.isProxyRoutedAgent(agentBinary) {
            // WO-434: proxy audit logs exist only when launch starts the proxy.
            if auditLog != nil {
                let message = "error: --audit-log is not supported for non-routed agent '\(agentBinary)'; " +
                    "proxy audit logging currently requires 'claude'. Remove --audit-log or " +
                    "run 'pastewatch-cli proxy --audit-log' separately.\n"
                FileHandle.standardError.write(Data(message.utf8))
                throw ExitCode(rawValue: 1)
            }
            // WO-414: do not start an unused proxy for agents whose traffic is not routed.
            Launch.configureProxyEnv(agentBinary: agentBinary, port: port, quiet: quiet)
            if !quiet {
                let cmdStr = command.joined(separator: " ")
                FileHandle.standardError.write(Data("launching: \(cmdStr)\n\n".utf8))
            }
            let exitCode = try runAgentProcess(command)
            if exitCode != 0 {
                throw ExitCode(rawValue: exitCode)
            }
            return
        }

        // Resolve our own binary to spawn the proxy subprocess
        let binaryPath = ProcessInfo.processInfo.arguments[0]

        // Build proxy arguments
        var proxyArgs = ["proxy", "--port", "\(port)", "--upstream", upstream, "--severity", severity.rawValue, "--quiet"]
        if let fp = forwardProxy { proxyArgs += ["--forward-proxy", fp] }
        if let al = auditLog { proxyArgs += ["--audit-log", al] }
        if !alert { proxyArgs.append("--no-alert") }
        if let ca = caCert { proxyArgs += ["--ca-cert", ca] }
        if insecure { proxyArgs.append("--insecure") }

        // Start proxy as child process
        let proxy = Process()
        proxy.executableURL = URL(fileURLWithPath: binaryPath)
        proxy.arguments = proxyArgs
        if quiet {
            proxy.standardOutput = FileHandle.nullDevice
            proxy.standardError = FileHandle.nullDevice
        } else {
            proxy.standardOutput = FileHandle.nullDevice
            proxy.standardError = FileHandle.standardError
        }
        launchProxyProcess = proxy

        do {
            try proxy.run()
        } catch {
            FileHandle.standardError.write(Data("error: failed to start proxy: \(error)\n".utf8))
            throw ExitCode(rawValue: 3)
        }
        launchProxyPid = proxy.processIdentifier
        defer {
            if proxy.isRunning {
                proxy.terminate()
            }
            proxy.waitUntilExit()
            launchProxyPid = 0
            launchProxyProcess = nil
        }
        delayBeforeAgentForTestingIfNeeded()
        try throwIfLaunchTerminationRequested()

        // Wait for proxy to accept connections
        guard waitForTCP(host: "127.0.0.1", port: port, timeout: 5.0) else {
            try throwIfLaunchTerminationRequested()
            FileHandle.standardError.write(Data("error: proxy failed to start (timeout waiting for port \(port))\n".utf8))
            throw ExitCode(rawValue: 3)
        }
        try throwIfLaunchTerminationRequested()

        if !quiet {
            let cmdStr = command.joined(separator: " ")
            FileHandle.standardError.write(Data("launching: \(cmdStr)\n\n".utf8))
        }

        Launch.configureProxyEnv(agentBinary: agentBinary, port: port, quiet: quiet)

        let exitCode = try runAgentProcess(command)
        if exitCode != 0 {
            throw ExitCode(rawValue: exitCode)
        }
    }

    private func runAgentProcess(_ command: [String]) throws -> Int32 {
        try throwIfLaunchTerminationRequested()
        // Fork: child exec's the agent (inherits TTY), parent waits and cleans up
        // Use @_silgen_name to bypass Swift's fork() unavailability on Darwin
        let pid = _pw_fork()

        if pid == -1 {
            FileHandle.standardError.write(Data("error: fork failed\n".utf8))
            throw ExitCode(rawValue: 3)
        }

        if pid == 0 {
            // Child process — exec the agent command
            // WO-438: pre-fork parent handlers must not survive the child launch
            // window or intercept termination intended for the agent.
            signal(SIGINT, SIG_DFL)
            signal(SIGTERM, SIG_DFL)
            // Build null-terminated C string array for execvp
            let args = Array(command)
            let cArgs = args.map { strdup($0) } + [nil]
            execvp(cArgs[0]!, cArgs)
            // execvp only returns on error
            perror("execvp")
            _exit(127)
        }

        // Parent process — wait for child, then clean up proxy.
        launchAgentPid = pid
        if launchPendingSignal != 0 {
            kill(launchAgentPid, launchPendingSignal)
        }

        var status: Int32 = 0
        while waitpid(pid, &status, 0) == -1 && errno == EINTR {}

        // Extract exit code
        let exitCode: Int32
        // WO-438: a cooperative child may trap SIGTERM and exit zero; the launch
        // process must still preserve the operator's terminating signal semantics.
        if launchPendingSignal != 0 {
            exitCode = 128 + launchPendingSignal
        } else if (status & 0x7f) == 0 {
            // Exited normally
            exitCode = (status >> 8) & 0xff
        } else {
            // Killed by signal
            exitCode = 128 + (status & 0x7f)
        }
        launchAgentPid = 0
        return exitCode
    }

    // WO-438: install before any child can exist so startup signals become state,
    // not default process termination that skips child cleanup.
    private func installLaunchSignalHandlers() {
        launchProxyPid = 0
        launchAgentPid = 0
        launchPendingSignal = 0
        signal(SIGINT, handleLaunchSignal)
        signal(SIGTERM, handleLaunchSignal)
    }

    private func writeBufferModeWarningIfNeeded(config: PastewatchConfig) {
        guard let warning = ProxyServer.bufferModeWarning(config: config, quiet: quiet) else { return }
        FileHandle.standardError.write(Data(warning.utf8))
    }

    private func throwIfLaunchTerminationRequested() throws {
        guard launchPendingSignal != 0 else { return }
        throw ExitCode(rawValue: 128 + launchPendingSignal)
    }

    // WO-438: assertion-gated delay makes the pre-agent signal window deterministic.
    private func delayBeforeAgentForTestingIfNeeded() {
        guard StartupSweepFixtureContext.isEnabled,
              let raw = ProcessInfo.processInfo.environment[StartupSweepFixtureContext.preAgentDelayEnvironmentKey],
              let milliseconds = UInt32(raw), milliseconds > 0 else { return }
        usleep(milliseconds * 1_000)
    }

    private func runStartupSweepFixtureProbeIfNeeded() throws {
        guard StartupSweepFixtureContext.isEnabled else { return }
        guard ProcessInfo.processInfo.environment[StartupSweepFixtureContext.probeEnvironmentKey] == "1" else {
            return
        }

        let context = startupSweepContext()
        // WO-137: prove fixture context before any startup sweep, proxy, or fork path.
        let output = """
        \(StartupSweepFixtureContext.probeMarker)
        home=\(context.homeDirectory.path)
        cwd=\(context.currentDirectory.path)

        """
        FileHandle.standardOutput.write(Data(output.utf8))
        throw ExitCode.success
    }

    private func normalizedCommand() throws -> [String] {
        let hasCommandSeparator = self.command.first == "--"
        // Strip leading "--" that captureForPassthrough may include
        let command = Array(self.command.drop(while: { $0 == "--" }))

        // WO-134: launch-level help must exit before startup sweep/proxy side effects.
        if !hasCommandSeparator, ["--help", "-h"].contains(command.first) {
            printLaunchHelp()
            throw ExitCode.success
        }

        guard !command.isEmpty else {
            FileHandle.standardError.write(Data("error: no command specified\n".utf8))
            FileHandle.standardError.write(Data("usage: pastewatch-cli launch <command> [args...]\n".utf8))
            FileHandle.standardError.write(Data("       pastewatch-cli launch -- <command> [args...]\n".utf8))
            throw ExitCode(rawValue: 2)
        }

        return command
    }

    private func runStartupSweepIfNeeded() {
        guard startupSweep else { return }

        // WO-121: warn before proxy/agent startup; findings never block launch.
        let context = startupSweepContext()
        let homeDirectory = context.homeDirectory
        let currentDirectory = context.currentDirectory
        let cache = StartupSweepCache(url: StartupSweepCache.defaultURL(homeDirectory: homeDirectory))
        let sweep = StartupSweep(homeDirectory: homeDirectory, currentDirectory: currentDirectory)
        if let warning = StartupSweepWarningRenderer.render(sweep.run(cache: cache)) {
            FileHandle.standardError.write(Data(warning.utf8))
        }
    }

    private func startupSweepContext() -> (homeDirectory: URL, currentDirectory: URL) {
        let realHomeDirectory = FileManager.default.homeDirectoryForCurrentUser
        let realCurrentDirectory = URL(fileURLWithPath: FileManager.default.currentDirectoryPath, isDirectory: true)

        guard StartupSweepFixtureContext.isEnabled else {
            return (realHomeDirectory, realCurrentDirectory)
        }

        let environment = ProcessInfo.processInfo.environment

        // WO-136: assertion-disabled release builds ignore test HOME fixture redirection.
        return (
            directoryOverride(environment["HOME"], fallback: realHomeDirectory),
            realCurrentDirectory
        )
    }

    private func directoryOverride(_ value: String?, fallback: URL) -> URL {
        guard let value, !value.isEmpty else { return fallback }
        return URL(fileURLWithPath: value, isDirectory: true)
    }

    private func printLaunchHelp() {
        let help = """
        OVERVIEW: Start the proxy and launch an agent through it in one command

        USAGE: pastewatch-cli launch [--port <port>] [--upstream <url>] [--forward-proxy <url>] [--severity <level>] [--audit-log <path>] [--no-alert] [--quiet] [--no-startup-sweep] [--ca-cert <path>] [--insecure] -- <command> [args...]

        OPTIONS:
          --port <port>             Proxy listen port
          --upstream <url>          Upstream API URL
          --forward-proxy <url>     Forward through corporate proxy
          --severity <level>        Minimum severity to redact: critical, high, medium, low
          --audit-log <path>        Audit log file path
          --no-alert                Do not inject alert into response when secrets are redacted
          --quiet                   Suppress proxy startup messages
          --no-startup-sweep        Disable startup sweep filesystem reads and warnings
          --ca-cert <path>          PEM CA bundle to trust for the upstream TLS handshake
          --insecure                Skip upstream TLS verification (private-CA gateways only)
          -h, --help                Show help information

        """
        FileHandle.standardOutput.write(Data(help.utf8))
    }

    private func waitForTCP(host: String, port: UInt16, timeout: TimeInterval) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            #if canImport(Darwin)
            let sock = socket(AF_INET, SOCK_STREAM, 0)
            #else
            let sock = socket(AF_INET, Int32(SOCK_STREAM.rawValue), 0)
            #endif
            guard sock >= 0 else {
                usleep(100_000)
                continue
            }
            defer { close(sock) }

            var addr = sockaddr_in()
            addr.sin_family = sa_family_t(AF_INET)
            addr.sin_port = port.bigEndian
            addr.sin_addr.s_addr = inet_addr(host)

            let result = withUnsafePointer(to: &addr) { ptr in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    connect(sock, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
            if result == 0 { return true }
            usleep(100_000)
        }
        return false
    }
}
