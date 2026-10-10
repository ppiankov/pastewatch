import ArgumentParser
import Foundation
import PastewatchCore

// WO-673@v2: only an operator shell may create a content-bound binary transfer grant.
struct AllowBinary: ParsableCommand {
    static let configuration = CommandConfiguration(commandName: "allow-binary",
        abstract: "Operator-only binary transfer grant, bound to path, content and expiry")

    @Argument(help: "File the operator authorizes for binary transfer")
    var file: String // WO-673@v2: exact files only, never wildcard grant patterns.

    @Option(name: .long, help: "Positive duration with s, m or h suffix (default 1h, maximum 24h)")
    var ttl = "1h" // WO-673@v2: the command cannot request permanent authorization.

    // WO-673@v2: grant failures never echo file content or re-encode config.json.
    func run() throws {
        guard let duration = BinaryTransferGrants.parseTTL(ttl) else {
            throw ValidationError("TTL must be positive, use s/m/h, and not exceed 24h")
        }
        do {
            try BinaryTransferGrants.record(path: file, ttl: duration)
        } catch {
            throw ValidationError("Cannot record binary transfer grant; inspect the file and doctor grant-store warning")
        }
        print("Binary transfer grant recorded; content changes or expiry revoke admission.")
    }
}
