#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import Foundation

// MARK: - Types

public struct VaultEntry: Codable {
    public let varName: String
    public let type: String
    public let sourceFile: String
    public let sourceLine: Int
    public let nonce: String
    public let ciphertext: String

    public init(
        varName: String, type: String, sourceFile: String,
        sourceLine: Int, nonce: String, ciphertext: String
    ) {
        self.varName = varName
        self.type = type
        self.sourceFile = sourceFile
        self.sourceLine = sourceLine
        self.nonce = nonce
        self.ciphertext = ciphertext
    }
}

public struct VaultFile: Codable {
    public let version: Int
    public let keyFingerprint: String
    public var entries: [VaultEntry]

    public init(version: Int, keyFingerprint: String, entries: [VaultEntry]) {
        self.version = version
        self.keyFingerprint = keyFingerprint
        self.entries = entries
    }
}

// MARK: - Vault Operations

public enum VaultError: Error, CustomStringConvertible {
    case invalidKeyFormat
    case decryptionFailed
    case keyFingerprintMismatch(expected: String, got: String)
    case keyFileNotFound(String)
    case vaultFileNotFound(String)

    public var description: String {
        switch self {
        case .invalidKeyFormat:
            return "invalid key format: expected 64 hex characters"
        case .decryptionFailed:
            return "decryption failed: wrong key or corrupted data"
        case .keyFingerprintMismatch(let expected, let got):
            return "key fingerprint mismatch: vault expects \(expected), got \(got)"
        case .keyFileNotFound(let path):
            return "key file not found: \(path) (use --init-key to generate)"
        case .vaultFileNotFound(let path):
            return "vault file not found: \(path)"
        }
    }
}

public enum Vault {

    // MARK: - Key Management

    public static func generateKey() -> String {
        let key = SymmetricKey(size: .bits256)
        return key.withUnsafeBytes { bytes in
            bytes.map { String(format: "%02x", $0) }.joined()
        }
    }

    public static func keyFingerprint(_ keyHex: String) -> String {
        let digest = SHA256.hash(data: Data(keyHex.utf8))
        return digest.prefix(8).map { String(format: "%02x", $0) }.joined()
    }

    public static func readKey(from path: String) throws -> String {
        guard FileManager.default.fileExists(atPath: path) else {
            throw VaultError.keyFileNotFound(path)
        }
        let content = try String(contentsOfFile: path, encoding: .utf8)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard content.count == 64, content.allSatisfy({ $0.isHexDigit }) else {
            throw VaultError.invalidKeyFormat
        }
        return content
    }

    public static func writeKey(_ keyHex: String, to path: String) throws {
        let dir = (path as NSString).deletingLastPathComponent
        if !dir.isEmpty {
            try FileManager.default.createDirectory(
                atPath: dir, withIntermediateDirectories: true
            )
        }
        try keyHex.write(toFile: path, atomically: true, encoding: .utf8)
        // Set file permissions to owner-only (0600)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600], ofItemAtPath: path
        )
    }

    // MARK: - Encrypt / Decrypt

    public static func encrypt(
        value: String, keyHex: String
    ) throws -> (nonce: String, ciphertext: String) {
        let symmetricKey = try parseKey(keyHex)
        let plaintext = Data(value.utf8)
        let sealedBox = try ChaChaPoly.seal(plaintext, using: symmetricKey)
        let nonceData = Data(sealedBox.nonce)
        let combined = sealedBox.ciphertext + sealedBox.tag
        return (
            nonce: nonceData.base64EncodedString(),
            ciphertext: combined.base64EncodedString()
        )
    }

    public static func decrypt(
        nonce nonceB64: String, ciphertext ciphertextB64: String, keyHex: String
    ) throws -> String {
        let symmetricKey = try parseKey(keyHex)
        guard let nonceData = Data(base64Encoded: nonceB64),
              let combined = Data(base64Encoded: ciphertextB64) else {
            throw VaultError.decryptionFailed
        }
        do {
            let nonce = try ChaChaPoly.Nonce(data: nonceData)
            let tagSize = 16
            guard combined.count >= tagSize else { throw VaultError.decryptionFailed }
            let ciphertext = combined.prefix(combined.count - tagSize)
            let tag = combined.suffix(tagSize)
            let sealedBox = try ChaChaPoly.SealedBox(
                nonce: nonce, ciphertext: ciphertext, tag: tag
            )
            let plaintext = try ChaChaPoly.open(sealedBox, using: symmetricKey)
            guard let str = String(data: plaintext, encoding: .utf8) else {
                throw VaultError.decryptionFailed
            }
            return str
        } catch is VaultError {
            throw VaultError.decryptionFailed
        } catch {
            throw VaultError.decryptionFailed
        }
    }

    // MARK: - Vault File I/O

    public static func load(from path: String) throws -> VaultFile {
        guard FileManager.default.fileExists(atPath: path) else {
            throw VaultError.vaultFileNotFound(path)
        }
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        return try JSONDecoder().decode(VaultFile.self, from: data)
    }

    public static func save(_ vault: VaultFile, to path: String) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try encoder.encode(vault)
        try data.write(to: URL(fileURLWithPath: path))
    }

    // MARK: - Build & Decrypt All

    public static func buildVault(
        plan: FixPlan, keyHex: String
    ) throws -> VaultFile {
        let fp = keyFingerprint(keyHex)
        var entries: [VaultEntry] = []

        var seen = Set<String>()
        for action in plan.actions {
            guard !seen.contains(action.envVarName) else { continue }
            seen.insert(action.envVarName)

            let encrypted = try encrypt(value: action.secretValue, keyHex: keyHex)
            entries.append(VaultEntry(
                varName: action.envVarName,
                type: action.type.rawValue,
                sourceFile: action.filePath,
                sourceLine: action.line,
                nonce: encrypted.nonce,
                ciphertext: encrypted.ciphertext
            ))
        }

        return VaultFile(version: 1, keyFingerprint: fp, entries: entries)
    }

    public static func decryptAll(
        vault: VaultFile, keyHex: String
    ) throws -> [(String, String)] {
        let fp = keyFingerprint(keyHex)
        if vault.keyFingerprint != fp {
            throw VaultError.keyFingerprintMismatch(
                expected: vault.keyFingerprint, got: fp
            )
        }

        return try vault.entries.map { entry in
            let value = try decrypt(
                nonce: entry.nonce,
                ciphertext: entry.ciphertext,
                keyHex: keyHex
            )
            return (entry.varName, value)
        }
    }

    /// Merge new entries into existing vault, skipping duplicates by varName.
    public static func merge(
        existing: VaultFile, new: VaultFile
    ) -> VaultFile {
        let existingNames = Set(existing.entries.map { $0.varName })
        let newEntries = new.entries.filter { !existingNames.contains($0.varName) }
        var merged = existing
        merged.entries.append(contentsOf: newEntries)
        return merged
    }

    // MARK: - Private

    private static func parseKey(_ keyHex: String) throws -> SymmetricKey {
        guard keyHex.count == 64 else { throw VaultError.invalidKeyFormat }
        var bytes: [UInt8] = []
        var index = keyHex.startIndex
        for _ in 0..<32 {
            let nextIndex = keyHex.index(index, offsetBy: 2)
            guard let byte = UInt8(keyHex[index..<nextIndex], radix: 16) else {
                throw VaultError.invalidKeyFormat
            }
            bytes.append(byte)
            index = nextIndex
        }
        return SymmetricKey(data: bytes)
    }
}
