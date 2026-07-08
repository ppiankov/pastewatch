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

        var forwardProxyURL: URL?
        if let fp = forwardProxy {
            guard let url = URL(string: fp) else {
                FileHandle.standardError.write(Data("error: invalid forward proxy URL: \(fp)\n".utf8))
                throw ExitCode(rawValue: 2)
            }
            forwardProxyURL = url
        }

        let config = PastewatchConfig.resolve()
        let server = ProxyServer(
            port: port,
            upstream: upstreamURL,
            forwardProxy: forwardProxyURL,
            config: config,
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
        // WO-240: SIGINT can arrive in the ~4-instruction window between signal() installation
        // and listen() completing inside server.start(). Use a second semaphore (startedGate)
        // that the shutdown thread waits on briefly before deciding whether to print "stopped."
        // and call stop(). The gate is signaled just before server.start() — if SIGINT fires
        // before that, the shutdown thread races to wake and sees the gate still closed, so it
        // skips stop() and exits cleanly. If SIGINT fires after, the gate is open and stop() runs.
        let startedGate = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            proxyShutdownSemaphore.wait()
            // Non-blocking check: if start() hasn't been called yet, skip stop().
            if startedGate.wait(timeout: .now()) == .success {
                FileHandle.standardError.write(Data("\nstopped.\n".utf8))
                server.stop()
            }
            #if canImport(Darwin)
            Darwin.exit(0)
            #elseif canImport(Glibc)
            Glibc.exit(0)
            #endif
        }
        signal(SIGINT) { _ in
            proxyShutdownSemaphore.signal()
        }

        startedGate.signal()
        try server.start()
    }
}
