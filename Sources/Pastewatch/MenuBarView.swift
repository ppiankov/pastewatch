import SwiftUI

/// Main menubar view for Pastewatch.
struct MenuBarView: View {
    @ObservedObject var monitor: ClipboardMonitor
    @State private var showingSettings = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            // Header
            headerSection

            Divider()

            // Status
            statusSection

            // Last scan result
            if let result = monitor.lastScanResult, result.hasMatches {
                Divider()
                lastScanSection(result)
            }

            Divider()

            // Actions
            actionsSection

            Divider()

            // Footer
            footerSection
        }
        .frame(width: 280)
    }

    // MARK: - Sections

    private var headerSection: some View {
        HStack {
            Image(systemName: "eye.trianglebadge.exclamationmark")
                .foregroundColor(stateColor)
            Text("Pastewatch")
                .font(.headline)
            Spacer()
            Text(stateText)
                .font(.caption)
                .foregroundColor(.secondary)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
    }

    private var statusSection: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Circle()
                    .fill(stateColor)
                    .frame(width: 8, height: 8)
                Text(stateDescription)
                    .font(.subheadline)
                Spacer()
            }

            if monitor.sessionObfuscationCount > 0 {
                Text("Session: \(monitor.sessionObfuscationCount) items obfuscated")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
    }

    private func lastScanSection(_ result: ScanResult) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Last obfuscation")
                .font(.caption)
                .foregroundColor(.secondary)

            Text(result.summary)
                .font(.subheadline)

            Text(result.timestamp, style: .relative)
                .font(.caption2)
                .foregroundColor(.secondary)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
    }

    private var actionsSection: some View {
        VStack(spacing: 0) {
            Button(action: { monitor.toggle() }) {
                HStack {
                    Image(systemName: toggleIcon)
                    Text(toggleText)
                    Spacer()
                }
            }
            .buttonStyle(.plain)
            .padding(.horizontal, 12)
            .padding(.vertical, 6)

            Button(action: { showingSettings.toggle() }) {
                HStack {
                    Image(systemName: "gear")
                    Text("Settings...")
                    Spacer()
                }
            }
            .buttonStyle(.plain)
            .padding(.horizontal, 12)
            .padding(.vertical, 6)
            .popover(isPresented: $showingSettings) {
                SettingsView(monitor: monitor)
            }
        }
    }

    private var footerSection: some View {
        Button(action: { NSApplication.shared.terminate(nil) }) {
            HStack {
                Image(systemName: "power")
                Text("Quit Pastewatch")
                Spacer()
            }
        }
        .buttonStyle(.plain)
        .padding(.horizontal, 12)
        .padding(.vertical, 6)
    }

    // MARK: - Computed Properties

    private var stateColor: Color {
        switch monitor.state {
        case .idle:
            return .gray
        case .monitoring:
            return .green
        case .paused:
            return .orange
        }
    }

    private var stateText: String {
        switch monitor.state {
        case .idle:
            return "Idle"
        case .monitoring:
            return "Active"
        case .paused:
            return "Paused"
        }
    }

    private var stateDescription: String {
        switch monitor.state {
        case .idle:
            return "Not monitoring"
        case .monitoring:
            return "Monitoring clipboard"
        case .paused:
            return "Monitoring paused"
        }
    }

    private var toggleIcon: String {
        monitor.state == .monitoring ? "pause.circle" : "play.circle"
    }

    private var toggleText: String {
        monitor.state == .monitoring ? "Pause Monitoring" : "Start Monitoring"
    }
}

/// Settings view for configuration.
struct SettingsView: View {
    @ObservedObject var monitor: ClipboardMonitor
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Settings")
                .font(.headline)

            Divider()

            Toggle("Enable Pastewatch", isOn: Binding(
                get: { monitor.config.enabled },
                set: { newValue in
                    var config = monitor.config
                    config.enabled = newValue
                    monitor.updateConfig(config)
                }
            ))

            Toggle("Show notifications", isOn: Binding(
                get: { monitor.config.showNotifications },
                set: { newValue in
                    var config = monitor.config
                    config.showNotifications = newValue
                    monitor.updateConfig(config)
                }
            ))

            Divider()

            Text("Detection Types")
                .font(.subheadline)
                .foregroundColor(.secondary)

            ForEach(SensitiveDataType.allCases, id: \.rawValue) { type in
                Toggle(type.rawValue, isOn: Binding(
                    get: { monitor.config.isTypeEnabled(type) },
                    set: { newValue in
                        var config = monitor.config
                        if newValue {
                            if !config.enabledTypes.contains(type.rawValue) {
                                config.enabledTypes.append(type.rawValue)
                            }
                        } else {
                            config.enabledTypes.removeAll { $0 == type.rawValue }
                        }
                        monitor.updateConfig(config)
                    }
                ))
                .font(.caption)
            }

            Divider()

            HStack {
                Spacer()
                Button("Done") {
                    dismiss()
                }
            }
        }
        .padding()
        .frame(width: 250)
    }
}
