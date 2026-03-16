import ArgumentParser
import Foundation
import PastewatchCore
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

struct Proxy: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Start API proxy that scans and redacts secrets from outbound requests"
    )

    @Option(name: .long, help: "Port to listen on")
    var port: UInt16 = 8443

    @Option(name: .long, help: "Upstream API URL")
    var upstream: String = "https://api.anthropic.com"

    @Option(name: .long, help: "Minimum severity to redact: critical, high, medium, low")
    var severity: Severity = .high

    @Option(name: .long, help: "Audit log file path")
    var auditLog: String?

    func run() throws {
        guard let upstreamURL = URL(string: upstream) else {
            FileHandle.standardError.write(Data("error: invalid upstream URL: \(upstream)\n".utf8))
            throw ExitCode(rawValue: 2)
        }

        let config = PastewatchConfig.resolve()
        let server = ProxyServer(
            port: port,
            upstream: upstreamURL,
            config: config,
            severity: severity,
            auditLogPath: auditLog
        )

        FileHandle.standardError.write(Data("pastewatch proxy listening on http://127.0.0.1:\(port)\n".utf8))
        FileHandle.standardError.write(Data("upstream: \(upstream)\n".utf8))
        FileHandle.standardError.write(Data("severity: \(severity.rawValue)\n".utf8))
        FileHandle.standardError.write(Data("\nusage:\n".utf8))
        FileHandle.standardError.write(Data("  ANTHROPIC_BASE_URL=http://127.0.0.1:\(port) claude\n".utf8))
        FileHandle.standardError.write(Data("\nctrl-c to stop\n\n".utf8))

        signal(SIGINT) { _ in
            FileHandle.standardError.write(Data("\nstopped.\n".utf8))
            _exit(0)
        }

        try server.start()
    }
}
