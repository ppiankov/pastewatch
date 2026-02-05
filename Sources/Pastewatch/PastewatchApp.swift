import SwiftUI

/// Pastewatch — Local macOS utility that obfuscates sensitive data before paste.
///
/// Core principle: Principiis obsta — resist the beginnings.
/// If sensitive data never enters the prompt, the incident does not exist.
@main
struct PastewatchApp: App {
    @StateObject private var monitor = ClipboardMonitor()
    @State private var menuBarIcon: String = "eye.trianglebadge.exclamationmark"

    var body: some Scene {
        MenuBarExtra {
            MenuBarView(monitor: monitor)
        } label: {
            Image(systemName: menuBarIcon)
                .symbolRenderingMode(.hierarchical)
        }
        .menuBarExtraStyle(.window)
        .onChange(of: monitor.state) { _, newState in
            updateIcon(for: newState)
        }
        .onChange(of: monitor.lastScanResult?.timestamp) { _, _ in
            flashIcon()
        }
    }

    init() {
        // Request notification permissions on launch
        NotificationManager.shared.requestPermissions()
    }

    private func updateIcon(for state: AppState) {
        switch state {
        case .idle:
            menuBarIcon = "eye.slash"
        case .monitoring:
            menuBarIcon = "eye.trianglebadge.exclamationmark"
        case .paused:
            menuBarIcon = "pause.circle"
        }
    }

    private func flashIcon() {
        // Brief visual feedback when obfuscation occurs
        let originalIcon = menuBarIcon
        menuBarIcon = "checkmark.shield"

        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
            menuBarIcon = originalIcon
        }
    }
}
