import Foundation

// WO-576@v3: stream parsers share one strict RFC 3629 lead-byte classifier.
enum UTF8ScalarWidth {
    static func forLeadByte(_ byte: UInt8) -> Int? {
        switch byte {
        case 0x00...0x7F:
            return 1
        case 0xC2...0xDF:
            return 2
        case 0xE0...0xEF:
            return 3
        case 0xF0...0xF4:
            return 4
        default:
            return nil
        }
    }
}
