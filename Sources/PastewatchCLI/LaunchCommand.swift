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
private var launchAgentPid: pid_t = 0

struct Launch: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Start the proxy and launch an agent through it in one command",
        discussion: """
        Starts the pastewatch proxy in the background, waits for it to be ready,
        then launches your agent with ANTHROPIC_BASE_URL pointed at the proxy.
        When the agent exits, the proxy is stopped automatically.

        Examples:
          pastewatch-cli launch claude
          pastewatch-cli launch --port 9999 -- claude --model opus
          pastewatch-cli launch --audit-log /tmp/pw.log -- codex --full-auto
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

    @Argument(parsing: .captureForPassthrough)
    var command: [String] = []

    func run() throws {
        let command = try normalizedCommand()
        runStartupSweepIfNeeded()

        // Resolve our own binary to spawn the proxy subprocess
        let binaryPath = ProcessInfo.processInfo.arguments[0]

        // Build proxy arguments
        var proxyArgs = ["proxy", "--port", "\(port)", "--upstream", upstream, "--severity", severity.rawValue, "--quiet"]
        if let fp = forwardProxy { proxyArgs += ["--forward-proxy", fp] }
        if let al = auditLog { proxyArgs += ["--audit-log", al] }
        if !alert { proxyArgs.append("--no-alert") }

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

        // Wait for proxy to accept connections
        guard waitForTCP(host: "127.0.0.1", port: port, timeout: 5.0) else {
            proxy.terminate()
            proxy.waitUntilExit()
            FileHandle.standardError.write(Data("error: proxy failed to start (timeout waiting for port \(port))\n".utf8))
            throw ExitCode(rawValue: 3)
        }

        if !quiet {
            let cmdStr = command.joined(separator: " ")
            FileHandle.standardError.write(Data("launching: \(cmdStr)\n\n".utf8))
        }

        // Set ANTHROPIC_BASE_URL for the agent
        setenv("ANTHROPIC_BASE_URL", "http://127.0.0.1:\(port)", 1)

        // Fork: child exec's the agent (inherits TTY), parent waits and cleans up
        // Use @_silgen_name to bypass Swift's fork() unavailability on Darwin
        let pid = _pw_fork()

        if pid == -1 {
            proxy.terminate()
            proxy.waitUntilExit()
            FileHandle.standardError.write(Data("error: fork failed\n".utf8))
            throw ExitCode(rawValue: 3)
        }

        if pid == 0 {
            // Child process — exec the agent command
            // Build null-terminated C string array for execvp
            let args = Array(command)
            let cArgs = args.map { strdup($0) } + [nil]
            execvp(cArgs[0]!, cArgs)
            // execvp only returns on error
            perror("execvp")
            _exit(127)
        }

        // Parent process — wait for child, then clean up proxy
        // Forward SIGINT to child instead of killing everything
        launchAgentPid = pid
        signal(SIGINT) { _ in
            if launchAgentPid > 0 {
                kill(launchAgentPid, SIGINT)
            }
        }

        var status: Int32 = 0
        waitpid(pid, &status, 0)

        // Extract exit code
        let exitCode: Int32
        if (status & 0x7f) == 0 {
            // Exited normally
            exitCode = (status >> 8) & 0xff
        } else {
            // Killed by signal
            exitCode = 128 + (status & 0x7f)
        }

        // Clean up proxy
        proxy.terminate()
        proxy.waitUntilExit()

        if exitCode != 0 {
            throw ExitCode(rawValue: exitCode)
        }
    }

    private func normalizedCommand() throws -> [String] {
        // Strip leading "--" that captureForPassthrough may include
        let command = Array(self.command.drop(while: { $0 == "--" }))

        if command == ["--help"] || command == ["-h"] {
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
        let homeDirectory = FileManager.default.homeDirectoryForCurrentUser
        let currentDirectory = URL(fileURLWithPath: FileManager.default.currentDirectoryPath, isDirectory: true)
        let cache = StartupSweepCache(url: StartupSweepCache.defaultURL(homeDirectory: homeDirectory))
        let sweep = StartupSweep(homeDirectory: homeDirectory, currentDirectory: currentDirectory)
        if let warning = StartupSweepWarningRenderer.render(sweep.run(cache: cache)) {
            FileHandle.standardError.write(Data(warning.utf8))
        }
    }

    private func printLaunchHelp() {
        let help = """
        OVERVIEW: Start the proxy and launch an agent through it in one command

        USAGE: pastewatch-cli launch [--port <port>] [--upstream <url>] [--forward-proxy <url>] [--severity <level>] [--audit-log <path>] [--no-alert] [--quiet] [--no-startup-sweep] -- <command> [args...]

        OPTIONS:
          --port <port>             Proxy listen port
          --upstream <url>          Upstream API URL
          --forward-proxy <url>     Forward through corporate proxy
          --severity <level>        Minimum severity to redact: critical, high, medium, low
          --audit-log <path>        Audit log file path
          --no-alert                Do not inject alert into response when secrets are redacted
          --quiet                   Suppress proxy startup messages
          --no-startup-sweep        Disable startup sweep filesystem reads and warnings
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
