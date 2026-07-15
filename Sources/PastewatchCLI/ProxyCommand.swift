import ArgumentParser
import Foundation
import PastewatchCore
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

// WO-234: global semaphore used by the SIGINT handler (C function pointer — cannot capture
// context) to wake the shutdown thread that calls server.stop() from a normal thread.
private let proxyShutdownSemaphore = DispatchSemaphore(value: 0)
// WO-308: brief SIGINT grace for the running=true -> onListening startup window.
private let proxyStartupSignalGraceMilliseconds = 100
// WO-366: SIGINT exits should be distinguishable from successful proxy shutdown.
let proxyInterruptedExitCode: Int32 = 130

// WO-473: proxy and launch share one strict startup gate; runtime scan paths
// must never silently reduce configured coverage to the valid subset.
func compileProxyCustomRules(_ config: PastewatchConfig) throws -> [CustomRule] {
    try CustomRule.compileForProxyStartup(config.customRules)
}

func writeProxyCustomRuleError(_ error: Error) {
    FileHandle.standardError.write(Data("error: \(error.localizedDescription)\n".utf8))
}

func requireValidProxyCustomRules(_ config: PastewatchConfig) throws -> [CustomRule] {
    do {
        return try compileProxyCustomRules(config)
    } catch {
        writeProxyCustomRuleError(error)
        throw ExitCode(rawValue: 2)
    }
}

func proxyShutdownExitCode(didStart: Bool) -> Int32 {
    didStart ? 0 : proxyInterruptedExitCode
}

struct Proxy: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Start API proxy that scans and redacts secrets from outbound requests"
    )

    @Option(name: .long, help: "Port to listen on")
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

    @Flag(name: .long, help: "Suppress redaction log to stderr (write to audit log only)")
    var quiet: Bool = false

    @Option(name: .long, help: "PEM CA bundle to trust for the upstream TLS handshake (in addition to system roots)")
    var caCert: String?

    @Flag(name: .long, help: "Skip upstream TLS verification (insecure; for private-CA gateways only)")
    var insecure: Bool = false

    func run() throws {
        guard let upstreamURL = URL(string: upstream) else {
            FileHandle.standardError.write(Data("error: invalid upstream URL: \(upstream)\n".utf8))
            throw ExitCode(rawValue: 2)
        }
        guard ProxyServer.upstreamHostHeader(for: upstreamURL) != nil else {
            // WO-310: fail fast instead of starting a proxy that forwards `Host: `.
            FileHandle.standardError.write(Data("error: upstream URL has no host component: \(upstream)\n".utf8))
            throw ExitCode(rawValue: 2)
        }

        var forwardProxyURL: URL?
        if let fp = forwardProxy {
            guard let url = URL(string: fp) else {
                FileHandle.standardError.write(Data("error: invalid forward proxy URL: \(fp)\n".utf8))
                throw ExitCode(rawValue: 2)
            }
            forwardProxyURL = url
        }

        let config = PastewatchConfig.resolve()
        let compiledCustomRules = try requireValidProxyCustomRules(config)
        let server = ProxyServer(
            port: port,
            upstream: upstreamURL,
            forwardProxy: forwardProxyURL,
            config: config,
            compiledCustomRules: compiledCustomRules,
            severity: severity,
            auditLogPath: auditLog,
            injectAlert: alert,
            quietLog: quiet,
            caCertPath: caCert,
            insecureTLS: insecure
        )

        FileHandle.standardError.write(Data("pastewatch proxy listening on http://127.0.0.1:\(port)\n".utf8))
        FileHandle.standardError.write(Data("upstream: \(upstream)\n".utf8))
        if let fp = forwardProxy {
            FileHandle.standardError.write(Data("forward-proxy: \(fp)\n".utf8))
        }
        FileHandle.standardError.write(Data("severity: \(severity.rawValue)\n".utf8))
        FileHandle.standardError.write(Data("alert-injection: \(alert ? "on" : "off")\n".utf8))
        if let warning = ProxyServer.bufferModeWarning(config: config, quiet: quiet) {
            FileHandle.standardError.write(Data(warning.utf8))
        }
        if insecure {
            FileHandle.standardError.write(Data("WARNING: --insecure set — upstream TLS verification is DISABLED\n".utf8))
        } else if let caCert = caCert {
            FileHandle.standardError.write(Data("upstream-ca-cert: \(caCert)\n".utf8))
        }
        FileHandle.standardError.write(Data("\nusage:\n".utf8))
        FileHandle.standardError.write(Data("  ANTHROPIC_BASE_URL=http://127.0.0.1:\(port) claude\n".utf8))
        FileHandle.standardError.write(Data("\nctrl-c to stop\n\n".utf8))

        // Ignore SIGPIPE — client disconnects must not kill the proxy.
        // Without this, send() to a closed socket delivers SIGPIPE which
        // terminates the process silently (no error, no log).
        signal(SIGPIPE, SIG_IGN)

        // WO-234: the SIGINT handler must not call server.stop() directly — logQueue.sync
        // uses pthread_mutex and is not async-signal-safe (WO-231). Signal the global
        // semaphore (signal-safe) to wake a normal thread that calls stop(), draining
        // pending audit log writes (WO-225) before exit.
        // WO-240/WO-298: SIGINT can arrive between signal() installation and listen()
        // completing inside server.start(). Use a second semaphore that opens only after
        // listen() succeeds, so early SIGINT does not call stop() on an unstarted server.
        let startedGate = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            proxyShutdownSemaphore.wait()
            // WO-308: cover the tiny running=true -> onListening signal window without
            // calling stop() when listen() never completed.
            let didStart = startedGate.wait(timeout: .now() + .milliseconds(proxyStartupSignalGraceMilliseconds)) == .success
            if didStart {
                FileHandle.standardError.write(Data("\nstopped.\n".utf8))
                server.stop()
            }
            let exitCode = proxyShutdownExitCode(didStart: didStart)
            #if canImport(Darwin)
            Darwin.exit(exitCode)
            #elseif canImport(Glibc)
            Glibc.exit(exitCode)
            #endif
        }
        signal(SIGINT) { _ in
            proxyShutdownSemaphore.signal()
        }

        try server.start {
            startedGate.signal()
        }
    }
}
