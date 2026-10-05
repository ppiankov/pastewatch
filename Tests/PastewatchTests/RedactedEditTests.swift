import Foundation
import XCTest
@testable import PastewatchCore
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

// WO-647@v2: exercise edits against isolated policy and byte-preserving temporary files.
final class RedactedEditTests: XCTestCase {
    // WO-647@v2: whole-view tokens do not reveal secret-only changes or depend on selected line windows.
    func testConsistencyTokenDependsOnlyOnWholeRedactedView() throws {
        let original = "key=" + intrinsicFixture() + "\ntitle=before\n"
        try fixture(original) { path, store, config in
            let first = try RedactedEdit.read(filePath: path.path, store: store, config: config)
            let other = path.deletingLastPathComponent().appendingPathComponent("other.env")
            let secondSecret = ["AKIA", String(repeating: "R", count: 16)].joined()
            try Data(("key=" + secondSecret + "\ntitle=before\n").utf8).write(to: other)
            let second = try RedactedEdit.read(filePath: other.path, store: RedactionStore(), config: config)
            XCTAssertTrue(first.content.utf8.elementsEqual(second.content.utf8))
            XCTAssertTrue(first.viewToken == second.viewToken, "Secret-only changes must not affect the exposed token")
            let rawDigest = SHA256.hash(data: Data(original.utf8)).map { String(format: "%02x", $0) }.joined()
            XCTAssertFalse(first.viewToken == rawDigest, "Raw-byte digests must remain private")
            let window = try RedactedEdit.read(filePath: path.path, store: RedactionStore(), config: config,
                                               startLine: 2, lineCount: 1)
            XCTAssertEqual(window.content, "title=before\n")
            XCTAssertTrue(window.viewToken == first.viewToken)
        }
    }

    // WO-647@v2: structural changes invalidate the view token before any placeholder-based edit writes bytes.
    func testStructuralChangeInvalidatesViewTokenAndRefusesEdit() throws {
        let original = "key=" + intrinsicFixture() + "\ntitle=before\n"
        try fixture(original) { path, store, config in
            let before = try RedactedEdit.read(filePath: path.path, store: store, config: config)
            let changed = "heading=added\n" + original
            try Data(changed.utf8).write(to: path)
            let after = try RedactedEdit.read(filePath: path.path, store: RedactionStore(), config: config)
            XCTAssertFalse(before.viewToken == after.viewToken)
            let request = RedactedEditRequest(filePath: path.path, oldString: "title=before", newString: "title=after",
                                               expectedViewToken: before.viewToken)
            XCTAssertThrowsError(try RedactedEdit.edit(request, store: RedactionStore(), config: config)) { error in
                guard let refusal = error as? RedactedEditError, case .changedSinceRead = refusal else {
                    return XCTFail("Expected a stale-view refusal")
                }
            }
            XCTAssertTrue(try Data(contentsOf: path).elementsEqual(Data(changed.utf8)))
        }
    }

    // WO-647@v2: independently safe edit fragments must not assemble an intrinsic secret across a boundary.
    func testEditBoundaryCannotAssemblePlaintextSecret() throws {
        let prefix = ["AK", "IA"].joined()
        let suffix = String(repeating: "Q", count: 16)
        let original = "key=" + prefix + "FILL-HERE\n"
        try fixture(original) { path, store, config in
            XCTAssertThrowsError(try RedactedEdit.edit(filePath: path.path, oldString: "FILL-HERE", newString: suffix,
                                                       store: store, config: config)) { error in
                XCTAssertTrue(error.localizedDescription.contains("AWS Key"))
                XCTAssertTrue(error.localizedDescription.contains("line 1"))
                XCTAssertFalse(error.localizedDescription.contains(prefix + suffix))
            }
            XCTAssertTrue(try Data(contentsOf: path).elementsEqual(Data(original.utf8)))
        }
    }

    // WO-647@v2: a unique edit preserves every surrounding byte, including CRLF and multibyte context.
    func testUniqueEditPreservesOutsideBytesAndMode() throws {
        try fixture("prefix\r\ntitle=before\r\nfooter=keep\r\n") { path, store, config in
            try FileManager.default.setAttributes([.posixPermissions: 0o640], ofItemAtPath: path.path)
            let result = try RedactedEdit.edit(filePath: path.path, oldString: "title=before", newString: "title=after",
                                               store: store, config: config)
            XCTAssertEqual(result.linesChanged, 1)
            XCTAssertTrue(try Data(contentsOf: path).elementsEqual(Data("prefix\r\ntitle=after\r\nfooter=keep\r\n".utf8)))
            XCTAssertEqual(try FileManager.default.attributesOfItem(atPath: path.path)[.posixPermissions] as? NSNumber,
                           NSNumber(value: 0o640))
        }
    }

    // WO-647@v2: zero matches and overlapping duplicate matches both refuse without changing the file.
    func testMissingAndNonUniqueMatchesRefuse() throws {
        try fixture("aaaa\n") { path, store, config in
            for (old, expected) in [("absent", "not found"), ("aaa", "2 locations")] {
                XCTAssertThrowsError(try RedactedEdit.edit(filePath: path.path, oldString: old, newString: "change",
                                                          store: store, config: config)) { error in
                    XCTAssertTrue(error.localizedDescription.contains(expected))
                    XCTAssertFalse(error.localizedDescription.contains(old))
                }
                XCTAssertTrue(try Data(contentsOf: path).elementsEqual(Data("aaaa\n".utf8)))
            }
        }
    }

    // WO-647@v2: placeholders copied from an earlier read restore their original bytes in a small edit.
    func testPlaceholderContextAndEarlierReadRestore() throws {
        let secret = intrinsicFixture()
        let original = "key=" + secret + "\ntitle=before\nfooter=keep\n"
        try fixture(original) { path, store, config in
            let view = try RedactedEdit.read(filePath: path.path, store: store, config: config)
            XCTAssertFalse(view.content.contains(secret))
            XCTAssertEqual(view.redactions.count, 1)
            let replacement = view.content.replacingOccurrences(of: "title=before", with: "title=after")
            let summary = try RedactedEdit.edit(filePath: path.path, oldString: view.content, newString: replacement,
                                                store: store, config: config)
            XCTAssertEqual(summary.redactions, 1)
            XCTAssertEqual(summary.linesChanged, 1)
            XCTAssertTrue(try Data(contentsOf: path).elementsEqual(Data(original.replacingOccurrences(
                of: "title=before", with: "title=after").utf8)))
            let marker = try XCTUnwrap(view.redactions.first?.placeholder)
            _ = try RedactedEdit.edit(filePath: path.path, oldString: "footer=keep", newString: "footer=" + marker,
                                      store: store, config: config)
            let expected = "key=" + secret + "\ntitle=after\nfooter=" + secret + "\n"
            XCTAssertTrue(try Data(contentsOf: path).elementsEqual(Data(expected.utf8)))
        }
    }

    // WO-647@v2: neither selecting nor authoring a fragment of a restorable marker may corrupt a secret.
    func testPartialPlaceholdersRefuse() throws {
        let secret = intrinsicFixture()
        try fixture("key=" + secret + "\ntitle=before\n") { path, store, config in
            let view = try RedactedEdit.read(filePath: path.path, store: store, config: config)
            let marker = try XCTUnwrap(view.redactions.first?.placeholder)
            let fragments = [String(marker.dropLast()), String(marker.dropFirst(5))]
            for fragment in fragments {
                XCTAssertThrowsError(try RedactedEdit.edit(filePath: path.path, oldString: fragment, newString: "changed",
                                                          store: store, config: config)) { error in
                    XCTAssertTrue(error.localizedDescription.contains("partial placeholder"))
                    XCTAssertFalse(error.localizedDescription.contains(secret))
                }
                XCTAssertThrowsError(try RedactedEdit.edit(filePath: path.path, oldString: "title=before", newString: fragment,
                                                          store: store, config: config)) { error in
                    XCTAssertTrue(error.localizedDescription.contains("partial placeholder"))
                }
            }
        }
    }

    // WO-647@v2: custom-prefix markers obey the same partial-token checks and byte-exact restoration.
    func testCustomPrefixRestorationAndPartialRefusal() throws {
        let secret = intrinsicFixture()
        try fixture("key=" + secret + "\ntitle=before\n", prefix: "REDACTED_") { path, store, config in
            let view = try RedactedEdit.read(filePath: path.path, store: store, config: config)
            let marker = try XCTUnwrap(view.redactions.first?.placeholder)
            XCTAssertThrowsError(try RedactedEdit.edit(filePath: path.path, oldString: "title=before",
                                                      newString: String(marker.dropLast()), store: store, config: config))
            let changed = view.content.replacingOccurrences(of: "title=before", with: "title=after")
            _ = try RedactedEdit.edit(filePath: path.path, oldString: view.content, newString: changed,
                                      store: store, config: config)
            XCTAssertTrue(try Data(contentsOf: path).elementsEqual(Data(("key=" + secret + "\ntitle=after\n").utf8)))
        }
    }

    // WO-647@v2: fresh agent-authored secrets refuse with metadata only and cannot write their bytes.
    func testPlaintextSecretRefusesWithoutLeaking() throws {
        let secret = intrinsicFixture()
        try fixture("title=before\n") { path, store, config in
            XCTAssertThrowsError(try RedactedEdit.edit(filePath: path.path, oldString: "title=before", newString: "key=" + secret,
                                                      store: store, config: config)) { error in
                XCTAssertTrue(error.localizedDescription.contains("AWS Key"))
                XCTAssertTrue(error.localizedDescription.contains("line 1"))
                XCTAssertFalse(error.localizedDescription.contains(secret))
            }
            XCTAssertTrue(try Data(contentsOf: path).elementsEqual(Data("title=before\n".utf8)))
        }
    }

    // WO-647@v2: an injected rename failure cannot leave a partial destination or private staging file.
    func testAtomicReplacementFailureLeavesOriginal() throws {
        try fixture("title=before\n") { path, store, config in
            let request = RedactedEditRequest(filePath: path.path, oldString: "title=before", newString: "title=after")
            XCTAssertThrowsError(try RedactedEdit.edit(request, store: store, config: config, replace: { _, _ in
                throw POSIXError(.EIO)
            })) { error in
                XCTAssertTrue(error.localizedDescription.contains("atomic replacement failed"))
            }
            XCTAssertTrue(try Data(contentsOf: path).elementsEqual(Data("title=before\n".utf8)))
            XCTAssertFalse(try FileManager.default.contentsOfDirectory(atPath: path.deletingLastPathComponent().path)
                .contains { $0.hasPrefix(".pastewatch-edit-") })
        }
    }

    // WO-647@v2: a line-window edit still resolves the whole file and preserves off-window secret context.
    func testLineWindowEditPreservesWholeFile() throws {
        let secret = intrinsicFixture()
        let original = "key=" + secret + "\ntitle=before\nfooter=keep\n"
        try fixture(original) { path, store, config in
            let window = try RedactedEdit.read(filePath: path.path, store: store, config: config, startLine: 2, lineCount: 1)
            XCTAssertEqual(window.content, "title=before\n")
            _ = try RedactedEdit.edit(filePath: path.path, oldString: window.content, newString: "title=after\n",
                                      store: store, config: config)
            XCTAssertTrue(try Data(contentsOf: path).elementsEqual(Data(original.replacingOccurrences(
                of: "title=before", with: "title=after").utf8)))
        }
    }

    // WO-647@v2: a whole-file consistency token prevents replay after the redacted structure or marker numbering change.
    func testStaleSnapshotRefusesAndExactSnapshotAllows() throws {
        try fixture("title=before\n") { path, store, config in
            let view = try RedactedEdit.read(filePath: path.path, store: store, config: config)
            XCTAssertEqual(view.viewToken.count, 64)
            try Data("title=changed\n".utf8).write(to: path)
            let stale = RedactedEditRequest(filePath: path.path, oldString: "title=changed", newString: "title=after",
                                             expectedViewToken: view.viewToken)
            XCTAssertThrowsError(try RedactedEdit.edit(stale, store: store, config: config))
            XCTAssertTrue(try Data(contentsOf: path).elementsEqual(Data("title=changed\n".utf8)))
            let current = try RedactedEdit.read(filePath: path.path, store: store, config: config)
            let fresh = RedactedEditRequest(filePath: path.path, oldString: "title=changed", newString: "title=after",
                                             expectedViewToken: current.viewToken)
            _ = try RedactedEdit.edit(fresh, store: store, config: config)
        }
    }

    // WO-647@v2: byte-literal matching must not silently edit a canonically equivalent but different UTF-8 sequence.
    func testByteLiteralMatchingAndOrdinaryIdentifiers() throws {
        try fixture("caf\u{00e9}\n__init__\n") { path, store, config in
            XCTAssertThrowsError(try RedactedEdit.edit(filePath: path.path, oldString: "cafe\u{0301}", newString: "changed",
                                                      store: store, config: config))
            _ = try RedactedEdit.edit(filePath: path.path, oldString: "__init__", newString: "__name__",
                                      store: store, config: config)
        }
    }

    // WO-647@v2: repeated known markers cannot allocate a restoration larger than the caller's file limit.
    func testRestorationBoundsExpansionBeforeAllocation() throws {
        let secret = intrinsicFixture()
        try fixture("key=" + secret + "\n") { path, store, config in
            let view = try RedactedEdit.read(filePath: path.path, store: store, config: config)
            let marker = try XCTUnwrap(view.redactions.first?.placeholder)
            let repeated = Array(repeating: marker, count: 4).joined(separator: "\n")
            let outputLimit = repeated.utf8.count
            XCTAssertThrowsError(try store.resolveChecked(content: repeated, filePath: path.path,
                                                          maximumBytes: outputLimit))
            let allowed = try store.resolveChecked(content: marker, filePath: path.path, maximumBytes: secret.utf8.count)
            XCTAssertTrue(allowed.content.utf8.elementsEqual(secret.utf8))
        }
    }

    // WO-647@v2: deterministic fragments avoid committed intrinsic secret literals.
    private func intrinsicFixture() -> String {
        ["AKIA", String(repeating: "Q", count: 16)].joined()
    }

    // WO-647@v2: each engine test gets a private regular file and scoped policy independent of operator config.
    private func fixture(
        _ content: String, prefix: String? = nil,
        body: (URL, RedactionStore, PastewatchConfig) throws -> Void
    ) throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let path = root.appendingPathComponent("fixture.env")
            try Data(content.utf8).write(to: path)
            try body(path, RedactionStore(placeholderPrefix: prefix), .defaultConfig)
        }
    }
}
