import Foundation

// WO-706@v1: executable identity uses complete basenames and one case rule across diagnostics and command parsing.
public enum ExecutableIdentityNames {
    // WO-706@v1: package-product and installed CLI spellings are compared case-insensitively, never by prefix.
    public static let basenames: Set<String> = ["pastewatch-cli", "pastewatchcli"]

    // WO-706@v1: path presentation does not change whether an executable has a supported basename.
    public static func isOwnBinary(_ executable: String) -> Bool {
        basenames.contains(URL(fileURLWithPath: executable).lastPathComponent.lowercased())
    }
}
