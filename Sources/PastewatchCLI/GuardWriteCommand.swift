import ArgumentParser
import Foundation
import PastewatchCore

// WO-561: logic extracted to FileGuard.check in GuardReadCommand.swift.
struct GuardWrite: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "guard-write",
        abstract: "Check if a file contains secrets before allowing Write tool access"
    )

    @Argument(help: "File path to check")
    var filePath: String

    @Option(name: .long, help: "Minimum severity to block: critical, high, medium, low")
    var failOnSeverity: Severity = .defaultThreshold

    func run() throws {
        try FileGuard.check(filePath: filePath, failOnSeverity: failOnSeverity, operation: .write)
    }
}
