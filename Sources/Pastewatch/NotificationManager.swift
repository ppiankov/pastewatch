import Foundation
import UserNotifications

/// Manages system notifications for Pastewatch.
///
/// Design:
/// - Minimal, non-intrusive notifications
/// - Only notifies when obfuscation actually occurs
/// - No animation, no dopamine, no celebration
final class NotificationManager: NSObject {

    static let shared = NotificationManager()

    private override init() {
        super.init()
    }

    /// Request notification permissions.
    func requestPermissions() {
        let center = UNUserNotificationCenter.current()
        center.requestAuthorization(options: [.alert, .sound]) { granted, error in
            if let error = error {
                print("Notification permission error: \(error.localizedDescription)")
            }
        }
        center.delegate = self
    }

    /// Show notification for obfuscation result.
    func showObfuscationNotification(_ result: ScanResult) {
        guard result.hasMatches else { return }

        let content = UNMutableNotificationContent()
        content.title = "Pastewatch"
        content.body = "Obfuscated: \(result.summary)"
        content.sound = nil // Silent by default

        let request = UNNotificationRequest(
            identifier: UUID().uuidString,
            content: content,
            trigger: nil
        )

        UNUserNotificationCenter.current().add(request) { error in
            if let error = error {
                print("Notification error: \(error.localizedDescription)")
            }
        }
    }
}

extension NotificationManager: UNUserNotificationCenterDelegate {
    func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification,
        withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void
    ) {
        // Show banner even when app is in foreground
        completionHandler([.banner])
    }
}
