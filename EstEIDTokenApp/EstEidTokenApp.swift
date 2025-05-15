/*
 * EstEIDTokenApp
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

import SwiftUI
import UserNotifications

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationWillUpdate(_ notification: Notification) {
        if let menu = NSApplication.shared.mainMenu {
            let list = ["File", "Edit", "Window", "View", "Help"]
            for item in menu.items where list.contains(item.title) {
                menu.removeItem(item)
            }
        }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        return true
    }
}

@main
struct EstEidTokenApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var delegate

    var body: some Scene {
        WindowGroup {
            ContentView().onAppear { NSWindow.allowsAutomaticWindowTabbing = false }
        }
    }
}

struct ContentView: View {
    @State private var text = ""
    @State private var notifications = UNAuthorizationStatus.authorized

    var body: some View {
        VStack {
            switch notifications {
            case .denied:
                Text("Failed to send ID-card notification. To receive notifications,\nplease enable EstEIDTokenApp notifications in [System Settings](x-apple.systempreferences:com.apple.notifications) → Notifications.")
                    .multilineTextAlignment(.center)
                    .padding(10)
                    .foregroundColor(.black)
                    .background(Color(red: 251 / 255, green: 174 / 255, blue: 56 / 255))
                    .cornerRadius(4)
                    .padding(5)
            case .notDetermined:
                Text("Enable EstEIDTokenApp notifications to receive ID-card related notifications.")
                    .padding(10)
                    .foregroundColor(.black)
                    .background(Color.yellow.opacity(0.7))
                    .cornerRadius(4)
                    .padding(5)
            default:
                EmptyView()
            }
            Text("In case of questions please contact our support via https://www.id.ee")
            Text("Version: \(Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.0.0").\(Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "0")")
            TextEditor(text: .constant(text))
        }
        .padding()
        .task {
            notifications = await UNUserNotificationCenter.current().notificationSettings().authorizationStatus
            if notifications != .authorized {
                UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .badge, .timeSensitive]) { success, error in
                    NSLog("EstEIDTokenNotify: requestAuthorizationWithOptions \(success) \(String(describing: error))")
                    notifications = success ? .authorized : .denied
                }
            }
            let pipe = Pipe()
            let task = Process()
            task.executableURL = URL(fileURLWithPath: "/usr/sbin/system_profiler")
            task.arguments = ["SPSmartCardsDataType"]
            task.standardOutput = pipe
            do {
                try task.run()
                task.waitUntilExit()
                if let data = try pipe.fileHandleForReading.readToEnd() {
                    text = String(data: data, encoding: .utf8) ?? "Failed to read diagnostic information\n";
                }
            } catch {
                text = "Failed to read diagnostic information: \(error)\n"
            }

            let find = [
                kSecClass: kSecClassKey,
                kSecReturnAttributes: true,
                kSecMatchLimit: kSecMatchLimitAll,
            ] as [CFString : Any]
            var result: CFTypeRef?
            if SecItemCopyMatching(find as CFDictionary, &result) == errSecSuccess,
                let items = result as? [Dictionary<CFString, Any>] {
                for item in items {
                    if let value = item[kSecAttrTokenID] as? String,
                       value.contains("ee.ria.EstEIDTokenApp.EstEIDToken") {
                        text.append("\nKey: \(item as NSDictionary)")
                    }
                }
            }

            let settings = NSDictionary(contentsOfFile: "/Library/Preferences/com.apple.security.smartcard.plist")
            text.append("\nSettings: \(settings ?? NSDictionary())")
        }
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}
