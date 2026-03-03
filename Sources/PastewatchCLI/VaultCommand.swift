import ArgumentParser
import Foundation
import PastewatchCore

struct VaultGroup: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "vault",
        abstract: "Encrypted secret vault management",
        subcommands: [Decrypt.self, Export.self, RotateKey.self, List.self]
    )
}

extension VaultGroup {
    struct Decrypt: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Decrypt vault to .env file"
        )

        @Option(name: .long, help: "Path to vault file (default: .pastewatch-vault)")
        var vault: String = ".pastewatch-vault"

        @Option(name: .long, help: "Path to key file (default: .pastewatch-key)")
        var key: String = ".pastewatch-key"

        @Option(name: .long, help: "Output .env file path (default: .env)")
        var output: String = ".env"

        func run() throws {
            let keyHex = try Vault.readKey(from: key)
            let vaultFile = try Vault.load(from: vault)
            let entries = try Vault.decryptAll(vault: vaultFile, keyHex: keyHex)

            var lines: [String] = []
            for (name, value) in entries {
                lines.append("\(name)=\(value)")
            }
            let content = lines.joined(separator: "\n") + "\n"
            try content.write(toFile: output, atomically: true, encoding: .utf8)
            print("Decrypted \(entries.count) entries → \(output)")
        }
    }

    struct Export: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Export vault as shell environment variables"
        )

        @Option(name: .long, help: "Path to vault file (default: .pastewatch-vault)")
        var vault: String = ".pastewatch-vault"

        @Option(name: .long, help: "Path to key file (default: .pastewatch-key)")
        var key: String = ".pastewatch-key"

        func run() throws {
            let keyHex = try Vault.readKey(from: key)
            let vaultFile = try Vault.load(from: vault)
            let entries = try Vault.decryptAll(vault: vaultFile, keyHex: keyHex)

            for (name, value) in entries {
                // Shell-safe quoting: single quotes, escape embedded single quotes
                let escaped = value.replacingOccurrences(of: "'", with: "'\\''")
                print("export \(name)='\(escaped)'")
            }
        }
    }

    struct RotateKey: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "rotate-key",
            abstract: "Re-encrypt vault with a new key"
        )

        @Option(name: .long, help: "Path to vault file (default: .pastewatch-vault)")
        var vault: String = ".pastewatch-vault"

        @Option(name: .long, help: "Path to key file (default: .pastewatch-key)")
        var key: String = ".pastewatch-key"

        func run() throws {
            let oldKeyHex = try Vault.readKey(from: key)
            let vaultFile = try Vault.load(from: vault)
            let entries = try Vault.decryptAll(vault: vaultFile, keyHex: oldKeyHex)

            let newKeyHex = Vault.generateKey()

            var newEntries: [VaultEntry] = []
            for (idx, (name, value)) in entries.enumerated() {
                let original = vaultFile.entries[idx]
                let encrypted = try Vault.encrypt(value: value, keyHex: newKeyHex)
                newEntries.append(VaultEntry(
                    varName: name,
                    type: original.type,
                    sourceFile: original.sourceFile,
                    sourceLine: original.sourceLine,
                    nonce: encrypted.nonce,
                    ciphertext: encrypted.ciphertext
                ))
            }

            let newVault = VaultFile(
                version: 1,
                keyFingerprint: Vault.keyFingerprint(newKeyHex),
                entries: newEntries
            )

            try Vault.save(newVault, to: vault)
            try Vault.writeKey(newKeyHex, to: key)
            print("Rotated key and re-encrypted \(entries.count) entries.")
        }
    }

    struct List: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "List vault entries (no decryption)"
        )

        @Option(name: .long, help: "Path to vault file (default: .pastewatch-vault)")
        var vault: String = ".pastewatch-vault"

        func run() throws {
            let vaultFile = try Vault.load(from: vault)
            print("Vault: \(vaultFile.entries.count) entries (key: \(vaultFile.keyFingerprint))")
            for entry in vaultFile.entries {
                print("  \(entry.varName)  [\(entry.type)]  from \(entry.sourceFile):\(entry.sourceLine)")
            }
        }
    }
}
