import ArgumentParser
import Foundation
import PastewatchCore
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

// File-level refs for signal handler access
private var launchProxyProcess: Process?
private var launchAgentProcess: Process?

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

    @Argument(parsing: .captureForPassthrough)
    var command: [String] = []

    func run() throws {
        guard !command.isEmpty else {
            FileHandle.standardError.write(Data("error: no command specified\n".utf8))
            FileHandle.standardError.write(Data("usage: pastewatch-cli launch <command> [args...]\n".utf8))
            FileHandle.standardError.write(Data("       pastewatch-cli launch -- <command> [args...]\n".utf8))
            throw ExitCode(rawValue: 2)
        }

        // Resolve our own binary to spawn the proxy subprocess
        let binaryPath = ProcessInfo.processInfo.arguments[0]

        // Build proxy arguments
        var proxyArgs = ["proxy", "--port", "\(port)", "--upstream", upstream, "--severity", severity.rawValue]
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

        // Install signal handler to clean up both processes
        signal(SIGINT) { _ in
            launchAgentProcess?.terminate()
            launchProxyProcess?.terminate()
            _exit(130)
        }

        // Launch agent with ANTHROPIC_BASE_URL set
        let agent = Process()
        agent.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        agent.arguments = Array(command)
        var env = ProcessInfo.processInfo.environment
        env["ANTHROPIC_BASE_URL"] = "http://127.0.0.1:\(port)"
        agent.environment = env
        launchAgentProcess = agent

        do {
            try agent.run()
        } catch {
            proxy.terminate()
            proxy.waitUntilExit()
            FileHandle.standardError.write(Data("error: failed to launch '\(command[0])': \(error)\n".utf8))
            throw ExitCode(rawValue: 127)
        }

        agent.waitUntilExit()
        let exitCode = agent.terminationStatus

        // Clean up proxy
        proxy.terminate()
        proxy.waitUntilExit()

        if exitCode != 0 {
            throw ExitCode(rawValue: exitCode)
        }
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
