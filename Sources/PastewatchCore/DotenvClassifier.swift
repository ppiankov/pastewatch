import Foundation

/// WO-504: the case-sensitive dotenv filename contract shared by every scanner.
public enum DotenvClassifier {
    public static func isDotenvFile(_ fileName: String) -> Bool {
        fileName == ".env" || fileName.hasSuffix(".env")
    }
}
