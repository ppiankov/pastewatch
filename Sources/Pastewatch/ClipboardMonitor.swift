import AppKit
import Foundation

/// Monitors the macOS clipboard for changes.
///
/// Design:
/// - Polls clipboard at regular intervals (macOS doesn't provide push notifications)
/// - Detects changes by comparing change count
/// - Scans new content for sensitive data
/// - Replaces clipboard content with obfuscated version if matches found
final class ClipboardMonitor: ObservableObject {

    /// Current application state.
    @Published var state: AppState = .idle

    /// Last scan result (for UI display).
    @Published var lastScanResult: ScanResult?

    /// Total obfuscations performed this session.
    @Published var sessionObfuscationCount: Int = 0

    /// Configuration.
    @Published var config: PastewatchConfig

    /// Callback when obfuscation occurs.
    var onObfuscation: ((ScanResult) -> Void)?

    private var timer: Timer?
    private var lastChangeCount: Int = 0
    private let pollInterval: TimeInterval = 0.5

    init(config: PastewatchConfig = .load(), autoStart: Bool = true) {
        self.config = config

        // Auto-start monitoring if enabled in config
        if autoStart && config.enabled {
            // Defer start to after init completes
            DispatchQueue.main.async { [weak self] in
                self?.start()
                // Set up notification callback
                self?.onObfuscation = { result in
                    if self?.config.showNotifications == true {
                        NotificationManager.shared.showObfuscationNotification(result)
                    }
                }
            }
        }
    }

    /// Start monitoring the clipboard.
    func start() {
        guard state != .monitoring else { return }

        lastChangeCount = NSPasteboard.general.changeCount
        state = .monitoring

        timer = Timer.scheduledTimer(withTimeInterval: pollInterval, repeats: true) { [weak self] _ in
            self?.checkClipboard()
        }

        // Also add to RunLoop to ensure it fires during UI events
        if let timer = timer {
            RunLoop.current.add(timer, forMode: .common)
        }
    }

    /// Stop monitoring the clipboard.
    func stop() {
        timer?.invalidate()
        timer = nil
        state = .idle
    }

    /// Pause monitoring temporarily.
    func pause() {
        guard state == .monitoring else { return }
        timer?.invalidate()
        timer = nil
        state = .paused
    }

    /// Resume monitoring after pause.
    func resume() {
        guard state == .paused else { return }
        start()
    }

    /// Toggle monitoring state.
    func toggle() {
        switch state {
        case .idle:
            start()
        case .monitoring:
            pause()
        case .paused:
            resume()
        }
    }

    /// Check clipboard for changes and process if needed.
    private func checkClipboard() {
        let pasteboard = NSPasteboard.general
        let currentChangeCount = pasteboard.changeCount

        // No change since last check
        guard currentChangeCount != lastChangeCount else { return }
        lastChangeCount = currentChangeCount

        // Only process string content
        guard let content = pasteboard.string(forType: .string) else { return }

        // Skip empty content
        guard !content.isEmpty else { return }

        // Skip if monitoring is disabled in config
        guard config.enabled else { return }

        // Scan for sensitive data
        let matches = DetectionRules.scan(content, config: config)

        // No matches — nothing to do
        guard !matches.isEmpty else { return }

        // Obfuscate and replace clipboard content
        let obfuscatedContent = Obfuscator.obfuscate(content, matches: matches)

        // Create scan result
        let result = ScanResult(
            originalContent: content,
            matches: matches,
            obfuscatedContent: obfuscatedContent,
            timestamp: Date()
        )

        // Replace clipboard content
        pasteboard.clearContents()
        pasteboard.setString(obfuscatedContent, forType: .string)

        // Update last change count to avoid re-processing our own change
        lastChangeCount = pasteboard.changeCount

        // Update state
        DispatchQueue.main.async { [weak self] in
            self?.lastScanResult = result
            self?.sessionObfuscationCount += matches.count
            self?.onObfuscation?(result)
        }
    }

    /// Manually scan current clipboard content without modifying it.
    /// Useful for preview/testing.
    func previewScan() -> ScanResult? {
        guard let content = NSPasteboard.general.string(forType: .string) else { return nil }
        guard !content.isEmpty else { return nil }

        let matches = DetectionRules.scan(content, config: config)
        let obfuscatedContent = Obfuscator.obfuscate(content, matches: matches)

        return ScanResult(
            originalContent: content,
            matches: matches,
            obfuscatedContent: obfuscatedContent,
            timestamp: Date()
        )
    }

    /// Update configuration.
    func updateConfig(_ newConfig: PastewatchConfig) {
        config = newConfig
        try? config.save()
    }
}
