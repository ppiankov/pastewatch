import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

// WO-704@v1: literal loopback identity is shared without broadening it to private networks or doing DNS.
public func isLoopbackDestination(_ host: String) -> Bool {
    let normalized = normalizedHostLiteral(host)
    guard !normalized.isEmpty, !normalized.utf8.contains(0),
          !normalized.contains(where: \.isWhitespace) else { return false }
    if normalized == "localhost" { return true }
    var ipv4 = in_addr()
    if inet_aton(normalized, &ipv4) == 1 {
        return UInt32(bigEndian: ipv4.s_addr) >> 24 == 127
    }
    var ipv6 = in6_addr()
    guard let literal = normalized.split(separator: "%", maxSplits: 1).first else { return false }
    let address = String(literal)
    guard inet_pton(AF_INET6, address, &ipv6) == 1 else { return false }
    let bytes = withUnsafeBytes(of: ipv6) { Array($0) }
    if bytes.prefix(15).allSatisfy({ $0 == 0 }), bytes[15] == 1 { return true }
    return bytes.prefix(10).allSatisfy({ $0 == 0 }) && bytes[10] == 0xff && bytes[11] == 0xff && bytes[12] == 127
}

// WO-704@v1: unspecified listen addresses are separate from valid loopback destinations.
public func isWildcardListenAddress(_ host: String) -> Bool {
    let normalized = normalizedHostLiteral(host)
    guard !normalized.utf8.contains(0), !normalized.contains(where: \.isWhitespace) else { return false }
    if normalized.isEmpty { return true }
    var ipv4 = in_addr()
    if inet_aton(normalized, &ipv4) == 1 { return ipv4.s_addr == 0 }
    var ipv6 = in6_addr()
    guard inet_pton(AF_INET6, normalized, &ipv6) == 1 else { return false }
    return withUnsafeBytes(of: ipv6) { $0.allSatisfy { $0 == 0 } }
}

// WO-704@v1: bracket and case normalization must not depend on Foundation's URL presentation.
private func normalizedHostLiteral(_ host: String) -> String {
    let normalized = host.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
    // WO-704@v1: mapped inet_aton spellings preserve IPv4 loopback and wildcard identity, including short forms.
    guard normalized.hasPrefix("::ffff:") else { return normalized }
    let suffix = String(normalized.dropFirst("::ffff:".count))
    var ipv4 = in_addr()
    return inet_aton(suffix, &ipv4) == 1 ? suffix : normalized
}
