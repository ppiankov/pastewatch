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

// WO-696@v3: discovery consumes only the public operator-output identity fields.
struct WireProxyRecord: Decodable {
    let alive: Bool
    let listenAddr: String
    let proxyID: String

    enum CodingKeys: String, CodingKey {
        case alive
        case listenAddr = "listen_addr"
        case proxyID = "proxy_id"
    }
}

// WO-696@v3: startup and doctor share one bounded, exit-code-based discovery command.
enum WireProxyDiscovery {
    static let timeoutSeconds: TimeInterval = 1
    private static let maximumOutputBytes = 64 * 1024

    // WO-696@v3: PATH lookup is shared with curl but has no preferred system executable.
    static func discover(
        searchPath: String? = ProcessInfo.processInfo.environment["PATH"],
        timeout: TimeInterval = timeoutSeconds
    ) -> [WireProxyRecord] {
        guard let executable = PathExecutable.resolve(name: "nr", searchPath: searchPath) else { return [] }
        let outputURL = FileManager.default.temporaryDirectory.appendingPathComponent("pastewatch-discovery-" + UUID().uuidString)
        guard FileManager.default.createFile(atPath: outputURL.path, contents: nil,
                                              attributes: [.posixPermissions: 0o600]),
              let output = try? FileHandle(forWritingTo: outputURL) else { return [] }
        defer {
            try? output.close()
            try? FileManager.default.removeItem(at: outputURL)
        }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = ["proxies", "--json", "--output-mode", "operator"]
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        let terminated = DispatchSemaphore(value: 0)
        process.terminationHandler = { _ in terminated.signal() }
        do { try process.run() } catch { return [] }
        guard terminated.wait(timeout: .now() + timeout) == .success else {
            process.terminate()
            if terminated.wait(timeout: .now() + .milliseconds(100)) != .success, process.isRunning {
                kill(process.processIdentifier, SIGKILL)
            }
            process.waitUntilExit()
            return []
        }
        process.waitUntilExit()
        // Exit 1 and 3 are capability/availability outcomes, regardless of any printed text.
        guard process.terminationReason == .exit, process.terminationStatus == 0,
              let size = try? output.seekToEnd(), size <= maximumOutputBytes,
              let data = try? Data(contentsOf: outputURL) else { return [] }
        return decode(data)
    }

    // WO-696@v3: unknown or malformed discovery output never creates a guessed proxy identity.
    private static func decode(_ data: Data) -> [WireProxyRecord] {
        if let records = try? JSONDecoder().decode([WireProxyRecord].self, from: data) { return records.filter(\.alive) }
        struct Envelope: Decodable { let proxies: [WireProxyRecord] }
        return (try? JSONDecoder().decode(Envelope.self, from: data))?.proxies.filter(\.alive) ?? []
    }

    // WO-696@v3: local aliases and wildcard listeners share an endpoint only at the same port, without DNS.
    static func matches(_ record: WireProxyRecord, upstream: URL) -> Bool {
        let emptyListenHost = record.listenAddr.hasPrefix(":")
        let listenAddress = emptyListenHost ? "localhost" + record.listenAddr : record.listenAddr
        let port = upstream.port ?? (upstream.scheme?.lowercased() == "https" ? 443 : 80)
        guard record.alive, let address = URL(string: "http://" + listenAddress), address.port == port,
              let host = upstream.host, let recordHost = address.host else { return false }
        let upstreamHost = literalHost(host)
        let listenHost = emptyListenHost ? "" : literalHost(recordHost)
        if listenHost == upstreamHost { return true }
        return isLoopbackHost(upstreamHost) &&
            (isLoopbackHost(listenHost) || ["", "0.0.0.0", "::"].contains(listenHost))
    }

    // WO-696@v3: Foundation may retain IPv6 brackets, so normalize only literal presentation.
    private static func literalHost(_ host: String) -> String {
        host.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
    }

    // WO-696@v3: only explicit localhost and IPv4/IPv6 loopback literals share the local endpoint identity.
    private static func isLoopbackHost(_ host: String) -> Bool {
        if host == "localhost" || host == "::1" { return true }
        let octets = host.split(separator: ".", omittingEmptySubsequences: false)
        return octets.count == 4 && octets.first == "127" && octets.allSatisfy { UInt8($0) != nil }
    }

    // WO-696@v3: one wire owner is a supported-configuration requirement, not an input authorization marker.
    static func refusal(upstream: URL, records: [WireProxyRecord]) -> String? {
        guard let record = records.first(where: { matches($0, upstream: upstream) }) else { return nil }
        return "error: upstream is wire proxy \(record.proxyID); use one wire proxy per session and connect directly to the provider."
    }
}

// WO-696@v3: proxy and routed launch refuse known upstream proxy identities before starting a listener.
func requireSingleWireOwner(upstream: URL?, discover: () -> [WireProxyRecord] = { WireProxyDiscovery.discover() }) throws {
    guard let upstream else { return }
    if let refusal = WireProxyDiscovery.refusal(upstream: upstream, records: discover()) {
        FileHandle.standardError.write(Data((refusal + "\n").utf8))
        throw ExitCode(rawValue: 2)
    }
}

// WO-573@v4: proxy and launch share one strict startup gate for config and shared rules.
func compileProxyCustomRules(_ config: PastewatchConfig) throws -> [CustomRule] {
    try SharedSecretPatternSource.proxyRuleSet(for: config)
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

// WO-514: raw stream capture must remain conspicuous even when normal logs are quiet.
func streamDebugDumpWarning(path: String?) -> String? {
    guard let path else { return nil }
    return "WARNING: --debug-stream-dump writes raw streaming data with secrets to local file: \(path)\n"
}

// WO-649@v1: dependency checks complete before Linux creates a listening server.
func requireProxyCurl(
    lookup: () -> String? = { CurlExecutable.resolve() },
    diagnostic: (String) -> Void = { FileHandle.standardError.write(Data(($0 + "\n").utf8)) }
) throws -> String {
    guard let path = lookup() else {
        diagnostic(CurlExecutable.missingDependencyMessage)
        throw ExitCode(rawValue: 2)
    }
    diagnostic("curl: \(path)")
    return path
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

    // WO-559@v2: direct proxy runs use the named guard threshold by default.
    @Option(name: .long, help: "Minimum severity to redact: critical, high, medium, low")
    var severity: Severity = .defaultGuardThreshold

    @Option(name: .long, help: "Audit log file path")
    var auditLog: String?

    // WO-514: raw capture requires an explicit CLI path and has no config default.
    @Option(name: .long, help: "Write raw streaming frames and redaction decisions to a local file")
    var debugStreamDump: String?

    @Flag(name: .long, inversion: .prefixedNo, help: "Inject alert into response when secrets are redacted")
    var alert: Bool = true

    @Flag(name: .long, help: "Suppress redaction log to stderr (write to audit log only)")
    var quiet: Bool = false

    @Option(name: .long, help: "PEM CA bundle to trust for the upstream TLS handshake (in addition to system roots)")
    var caCert: String?

    @Flag(name: .long, help: "Skip upstream TLS verification (insecure; for private-CA gateways only)")
    var insecure: Bool = false

    // WO-649@v1: command decoding retains its existing fields and delegates transport lookup.
    func run() throws {
        try run(curlLookup: { CurlExecutable.resolve() })
    }

    // WO-649@v1: inject lookup through execution, not a non-Decodable command field.
    func run(curlLookup: () -> String?) throws {
        guard let upstreamURL = URL(string: upstream) else {
            FileHandle.standardError.write(Data("error: invalid upstream URL: \(upstream)\n".utf8))
            throw ExitCode(rawValue: 2)
        }
        guard ProxyServer.upstreamHostHeader(for: upstreamURL) != nil else {
            // WO-310: fail fast instead of starting a proxy that forwards `Host: `.
            FileHandle.standardError.write(Data("error: upstream URL has no host component: \(upstream)\n".utf8))
            throw ExitCode(rawValue: 2)
        }

        // WO-649@v1: macOS retains its existing URLSession startup path.
        #if os(Linux)
        _ = try requireProxyCurl(lookup: curlLookup)
        #endif

        var forwardProxyURL: URL?
        if let fp = forwardProxy {
            guard let url = URL(string: fp) else {
                FileHandle.standardError.write(Data("error: invalid forward proxy URL: \(fp)\n".utf8))
                throw ExitCode(rawValue: 2)
            }
            forwardProxyURL = url
        }

        // WO-574@v4: refuse to listen when the active config cannot be trusted.
        let config = try requireValidatedConfig()
        let compiledCustomRules = try requireValidProxyCustomRules(config)
        // WO-696@v3: discovery cannot affect the scanner or rewrite the request body.
        try requireSingleWireOwner(upstream: upstreamURL)
        let streamDebugSink = try debugStreamDump.map { try StreamDebugSink(path: $0) }
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
            insecureTLS: insecure,
            streamDebugSink: streamDebugSink
        )

        FileHandle.standardError.write(Data("pastewatch proxy listening on http://127.0.0.1:\(port)\n".utf8))
        FileHandle.standardError.write(Data("upstream: \(upstream)\n".utf8))
        if let fp = forwardProxy {
            FileHandle.standardError.write(Data("forward-proxy: \(fp)\n".utf8))
        }
        FileHandle.standardError.write(Data("severity: \(severity.rawValue)\n".utf8))
        FileHandle.standardError.write(Data("alert-injection: \(alert ? "on" : "off")\n".utf8))
        if let warning = streamDebugDumpWarning(path: debugStreamDump) {
            FileHandle.standardError.write(Data(warning.utf8))
        }
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
