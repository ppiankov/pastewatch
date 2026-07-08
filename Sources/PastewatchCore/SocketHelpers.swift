import Foundation

/// WO-206: shared socket send-all helper used by both the macOS URLSession path
/// (SSEStreamRelay) and the Linux curl path (CurlHTTPClient).
/// Retries until all bytes are written or a hard error (EPIPE / closed socket) occurs.
/// Returns false when a hard error terminates the loop early; true when all bytes are sent.
@discardableResult
func sendAll(_ data: Data, to socket: Int32, flags: Int32) -> Bool {
    var sent = true
    data.withUnsafeBytes { ptr in
        guard let base = ptr.baseAddress else { return }
        var remaining = ptr.count
        var offset = 0
        while remaining > 0 {
            let n = send(socket, base.advanced(by: offset), remaining, flags)
            if n <= 0 { sent = false; break }
            offset += n
            remaining -= n
        }
    }
    return sent
}
