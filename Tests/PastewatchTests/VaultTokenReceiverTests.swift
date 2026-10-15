import XCTest
@testable import PastewatchCore

final class VaultTokenReceiverTests: XCTestCase {
    // WO-684@v1: receiver-field assignments are syntax, not legacy token evidence.
    func testReceiverFieldAssignmentsAreNotVaultTokens() {
        let member = ["heartbeat", "Protocol", "Probe", "At"].joined()
        for receiver in ["s", "b", "r"] {
            for rhs in ["now", "time.Time{}"] {
                let content = "\(receiver).\(member) = \(rhs)"
                XCTAssertEqual(vaultMatches(in: content).count, 0)
            }
        }
    }

    // WO-684@v1: chained method and bare field reads distinguish a selector from an opaque token.
    func testReceiverSelectorReadsAreNotVaultTokens() {
        let member = ["heartbeat", "Protocol", "Probe", "At"].joined()
        for receiver in ["s", "b", "r"] {
            let reference = receiver + "." + member
            for content in [reference + ".IsZero()", "return " + reference + ".Location",
                            "if " + reference + ".IsZero() { }"] {
                XCTAssertEqual(vaultMatches(in: content).count, 0)
            }
        }
    }

    // WO-684@v1: the earlier receiver-call and nil-comparison exclusions stay intact.
    func testExistingReceiverCallsAndNilChecksRemainExcluded() {
        let member = ["refresh", "Pending", "Cache", "State"].joined()
        for receiver in ["s", "b", "r"] {
            let reference = receiver + "." + member
            for content in [reference + "()", reference + " (context.Background())",
                            "if " + reference + " == nil { }", "if " + reference + " != nil { }"] {
                XCTAssertEqual(vaultMatches(in: content).count, 0)
            }
        }
    }

    // WO-684@v1: standalone tokens and quoted/commented data retain intrinsic detection.
    func testLegacyVaultTokensRemainIntrinsicFindings() {
        let suffixes = [String(repeating: "A1", count: 12), ["heartbeat", "Protocol", "Probe", "At"].joined()]
        for receiver in ["s", "b", "r"] {
            for suffix in suffixes {
                let token = receiver + "." + suffix
                let contexts = [token, "var credential = \"" + token + "\"",
                                "var text = `" + token + " = now`", "// " + token + " = now",
                                "/* " + token + " = time.Time{} */"]
                for content in contexts {
                    let matches = vaultMatches(in: content)
                    XCTAssertEqual(matches.count, 1)
                    XCTAssertTrue(matches.allSatisfy { $0.value == token && $0.mutationSafe })
                }
            }
        }
    }

    // WO-684@v1: legacy tokens keep the existing exact-length base62 grammar and token boundaries.
    func testLegacyVaultGrammarStillRejectsNonTokenIdentifiers() {
        let token = "s." + ["opaque", "-", String(repeating: "A1", count: 12)].joined()
        for content in [token + " = now", token + ".IsZero()"] {
            XCTAssertEqual(vaultMatches(in: content).count, 0)
        }
    }

    // WO-684@v1: assertions report counts and evidence flags without exposing matched values.
    private func vaultMatches(in content: String) -> [DetectedMatch] {
        DetectionRules.scan(content, config: .defaultConfig).filter { $0.type == .vaultToken }
    }
}
