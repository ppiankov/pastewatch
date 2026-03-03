import XCTest
@testable import PastewatchCore

final class VaultTests: XCTestCase {

    // MARK: - Key Management

    func testGenerateKey() {
        let key = Vault.generateKey()
        XCTAssertEqual(key.count, 64)
        XCTAssertTrue(key.allSatisfy { $0.isHexDigit })
    }

    func testGenerateKeyUniqueness() {
        let key1 = Vault.generateKey()
        let key2 = Vault.generateKey()
        XCTAssertNotEqual(key1, key2)
    }

    func testKeyFingerprint() {
        let key = Vault.generateKey()
        let fp = Vault.keyFingerprint(key)
        XCTAssertEqual(fp.count, 16)
        XCTAssertTrue(fp.allSatisfy { $0.isHexDigit })
    }

    func testKeyFingerprintDeterministic() {
        let key = Vault.generateKey()
        let fp1 = Vault.keyFingerprint(key)
        let fp2 = Vault.keyFingerprint(key)
        XCTAssertEqual(fp1, fp2)
    }

    // MARK: - Encrypt / Decrypt

    func testEncryptDecryptRoundtrip() throws {
        let key = Vault.generateKey()
        let secret = "sk_test_abc123def456"
        let encrypted = try Vault.encrypt(value: secret, keyHex: key)

        XCTAssertFalse(encrypted.nonce.isEmpty)
        XCTAssertFalse(encrypted.ciphertext.isEmpty)

        let decrypted = try Vault.decrypt(
            nonce: encrypted.nonce,
            ciphertext: encrypted.ciphertext,
            keyHex: key
        )
        XCTAssertEqual(decrypted, secret)
    }

    func testDecryptWrongKey() throws {
        let key1 = Vault.generateKey()
        let key2 = Vault.generateKey()
        let encrypted = try Vault.encrypt(value: "secret_value", keyHex: key1)

        XCTAssertThrowsError(try Vault.decrypt(
            nonce: encrypted.nonce,
            ciphertext: encrypted.ciphertext,
            keyHex: key2
        ))
    }

    func testDecryptCorruptedNonce() throws {
        let key = Vault.generateKey()
        let encrypted = try Vault.encrypt(value: "secret_value", keyHex: key)

        XCTAssertThrowsError(try Vault.decrypt(
            nonce: "invalidbase64==",
            ciphertext: encrypted.ciphertext,
            keyHex: key
        ))
    }

    func testInvalidKeyFormat() {
        XCTAssertThrowsError(try Vault.encrypt(value: "test", keyHex: "short"))
        XCTAssertThrowsError(try Vault.encrypt(value: "test", keyHex: "zzzz" + String(repeating: "0", count: 60)))
    }

    // MARK: - Vault File I/O

    func testVaultFileRoundtrip() throws {
        let tmpDir = NSTemporaryDirectory()
        let vaultPath = (tmpDir as NSString).appendingPathComponent("test-vault-\(UUID().uuidString).json")
        defer { try? FileManager.default.removeItem(atPath: vaultPath) }

        let vault = VaultFile(
            version: 1,
            keyFingerprint: "abcdef0123456789",
            entries: [
                VaultEntry(
                    varName: "TEST_KEY",
                    type: "API Key",
                    sourceFile: "config.py",
                    sourceLine: 5,
                    nonce: "dGVzdG5vbmNl",
                    ciphertext: "dGVzdGNpcGhlcg=="
                )
            ]
        )

        try Vault.save(vault, to: vaultPath)
        let loaded = try Vault.load(from: vaultPath)

        XCTAssertEqual(loaded.version, 1)
        XCTAssertEqual(loaded.keyFingerprint, "abcdef0123456789")
        XCTAssertEqual(loaded.entries.count, 1)
        XCTAssertEqual(loaded.entries[0].varName, "TEST_KEY")
        XCTAssertEqual(loaded.entries[0].type, "API Key")
        XCTAssertEqual(loaded.entries[0].sourceFile, "config.py")
        XCTAssertEqual(loaded.entries[0].sourceLine, 5)
    }

    // MARK: - Key File I/O

    func testKeyFileRoundtrip() throws {
        let tmpDir = NSTemporaryDirectory()
        let keyPath = (tmpDir as NSString).appendingPathComponent("test-key-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(atPath: keyPath) }

        let key = Vault.generateKey()
        try Vault.writeKey(key, to: keyPath)
        let loaded = try Vault.readKey(from: keyPath)

        XCTAssertEqual(loaded, key)
    }

    func testKeyFilePermissions() throws {
        let tmpDir = NSTemporaryDirectory()
        let keyPath = (tmpDir as NSString).appendingPathComponent("test-key-perm-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(atPath: keyPath) }

        let key = Vault.generateKey()
        try Vault.writeKey(key, to: keyPath)

        let attrs = try FileManager.default.attributesOfItem(atPath: keyPath)
        let perms = attrs[.posixPermissions] as? Int
        XCTAssertEqual(perms, 0o600)
    }

    func testReadKeyInvalidFormat() throws {
        let tmpDir = NSTemporaryDirectory()
        let keyPath = (tmpDir as NSString).appendingPathComponent("test-key-bad-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(atPath: keyPath) }

        try "not-a-valid-key".write(toFile: keyPath, atomically: true, encoding: .utf8)
        XCTAssertThrowsError(try Vault.readKey(from: keyPath))
    }

    func testReadKeyFileNotFound() {
        XCTAssertThrowsError(try Vault.readKey(from: "/nonexistent/path"))
    }

    // MARK: - Build Vault from Plan

    func testBuildVaultFromPlan() throws {
        let key = Vault.generateKey()
        let plan = FixPlan(
            actions: [
                FixAction(
                    filePath: "config.py",
                    line: 10,
                    secretValue: "sk_test_abc123",
                    envVarName: "API_KEY",
                    replacement: "os.environ[\"API_KEY\"]",
                    type: .genericApiKey,
                    severity: .high
                ),
                FixAction(
                    filePath: "app.py",
                    line: 5,
                    secretValue: ["AKIA", "IOSFODNN7EXAMPLE"].joined(),
                    envVarName: "AWS_ACCESS_KEY_ID",
                    replacement: "os.environ[\"AWS_ACCESS_KEY_ID\"]",
                    type: .awsKey,
                    severity: .critical
                )
            ]
        )

        let vault = try Vault.buildVault(plan: plan, keyHex: key)
        XCTAssertEqual(vault.version, 1)
        XCTAssertEqual(vault.keyFingerprint, Vault.keyFingerprint(key))
        XCTAssertEqual(vault.entries.count, 2)
        XCTAssertEqual(vault.entries[0].varName, "API_KEY")
        XCTAssertEqual(vault.entries[1].varName, "AWS_ACCESS_KEY_ID")
    }

    func testBuildVaultDeduplicates() throws {
        let key = Vault.generateKey()
        let plan = FixPlan(
            actions: [
                FixAction(
                    filePath: "a.py", line: 1,
                    secretValue: "same_secret", envVarName: "SHARED_KEY",
                    replacement: "os.environ[\"SHARED_KEY\"]",
                    type: .genericApiKey, severity: .high
                ),
                FixAction(
                    filePath: "b.py", line: 2,
                    secretValue: "same_secret", envVarName: "SHARED_KEY",
                    replacement: "os.environ[\"SHARED_KEY\"]",
                    type: .genericApiKey, severity: .high
                )
            ]
        )

        let vault = try Vault.buildVault(plan: plan, keyHex: key)
        XCTAssertEqual(vault.entries.count, 1, "Duplicate varName should be deduplicated")
    }

    // MARK: - Decrypt All

    func testDecryptAll() throws {
        let key = Vault.generateKey()
        let secrets = ["secret_one", "secret_two", "secret_three"]
        var entries: [VaultEntry] = []

        for (idx, secret) in secrets.enumerated() {
            let encrypted = try Vault.encrypt(value: secret, keyHex: key)
            entries.append(VaultEntry(
                varName: "VAR_\(idx)",
                type: "API Key",
                sourceFile: "test.py",
                sourceLine: idx + 1,
                nonce: encrypted.nonce,
                ciphertext: encrypted.ciphertext
            ))
        }

        let vault = VaultFile(
            version: 1,
            keyFingerprint: Vault.keyFingerprint(key),
            entries: entries
        )

        let decrypted = try Vault.decryptAll(vault: vault, keyHex: key)
        XCTAssertEqual(decrypted.count, 3)
        for (idx, (name, value)) in decrypted.enumerated() {
            XCTAssertEqual(name, "VAR_\(idx)")
            XCTAssertEqual(value, secrets[idx])
        }
    }

    func testDecryptAllKeyFingerprintMismatch() throws {
        let key1 = Vault.generateKey()
        let key2 = Vault.generateKey()

        let encrypted = try Vault.encrypt(value: "test", keyHex: key1)
        let vault = VaultFile(
            version: 1,
            keyFingerprint: Vault.keyFingerprint(key1),
            entries: [
                VaultEntry(
                    varName: "TEST", type: "API Key",
                    sourceFile: "t.py", sourceLine: 1,
                    nonce: encrypted.nonce, ciphertext: encrypted.ciphertext
                )
            ]
        )

        XCTAssertThrowsError(try Vault.decryptAll(vault: vault, keyHex: key2)) { error in
            let desc = String(describing: error)
            XCTAssertTrue(desc.contains("fingerprint"), "Should mention fingerprint mismatch: \(desc)")
        }
    }

    // MARK: - Merge

    func testMergeVaults() throws {
        let existing = VaultFile(
            version: 1,
            keyFingerprint: "abc",
            entries: [
                VaultEntry(varName: "KEY_A", type: "API Key", sourceFile: "a.py", sourceLine: 1, nonce: "n1", ciphertext: "c1")
            ]
        )

        let new = VaultFile(
            version: 1,
            keyFingerprint: "abc",
            entries: [
                VaultEntry(varName: "KEY_A", type: "API Key", sourceFile: "a.py", sourceLine: 1, nonce: "n2", ciphertext: "c2"),
                VaultEntry(varName: "KEY_B", type: "AWS Key", sourceFile: "b.py", sourceLine: 5, nonce: "n3", ciphertext: "c3")
            ]
        )

        let merged = Vault.merge(existing: existing, new: new)
        XCTAssertEqual(merged.entries.count, 2)
        XCTAssertEqual(merged.entries[0].varName, "KEY_A")
        XCTAssertEqual(merged.entries[0].ciphertext, "c1", "Existing entry should be preserved")
        XCTAssertEqual(merged.entries[1].varName, "KEY_B")
    }

    func testMergeEmptyExisting() {
        let existing = VaultFile(version: 1, keyFingerprint: "abc", entries: [])
        let new = VaultFile(
            version: 1,
            keyFingerprint: "abc",
            entries: [
                VaultEntry(varName: "KEY_A", type: "API Key", sourceFile: "a.py", sourceLine: 1, nonce: "n1", ciphertext: "c1")
            ]
        )

        let merged = Vault.merge(existing: existing, new: new)
        XCTAssertEqual(merged.entries.count, 1)
    }

    // MARK: - Vault Errors

    func testLoadVaultFileNotFound() {
        XCTAssertThrowsError(try Vault.load(from: "/nonexistent/vault.json")) { error in
            XCTAssertTrue(error is VaultError)
        }
    }

    func testVaultErrorDescriptions() {
        let errors: [VaultError] = [
            .invalidKeyFormat,
            .decryptionFailed,
            .keyFingerprintMismatch(expected: "aaa", got: "bbb"),
            .keyFileNotFound("/tmp/key"),
            .vaultFileNotFound("/tmp/vault")
        ]
        for error in errors {
            XCTAssertFalse(error.description.isEmpty)
        }
    }
}
