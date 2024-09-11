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

import Cocoa
import SwiftUI

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationWillUpdate(_ notification: Notification) {
        if let menu = NSApplication.shared.mainMenu {
            let list = ["File", "Edit", "Window", "View", "Help"]
            for item in menu.items {
                if list.contains(item.title) {
                    menu.removeItem(item)
                }
            }
        }
    }
}

@main
struct EstEidTokenApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var delegate

    var body: some Scene {
        WindowGroup {
            ContentView()
                .onAppear {
                    NSWindow.allowsAutomaticWindowTabbing = false
                }
        }
    }
}

struct ContentView: View {
    @State private var version = "1.0.0.0"
    @State private var text = ""

    var body: some View {
        VStack {
            Text("In case of questions please contact our support via https://www.id.ee")
            Text("Version: \(version)")
            TextEditor(text: .constant(text))
        }
        .padding()
        .onAppear {
            version = "\(Bundle.main.infoDictionary?["CFBundleShortVersionString"] ?? "1.0.0").\(Bundle.main.infoDictionary?["CFBundleVersion"] ?? 0)"

            let pipe = Pipe()
            let task = Process()
            task.launchPath = "/usr/sbin/system_profiler"
            task.arguments = ["SPSmartCardsDataType"]
            task.standardOutput = pipe
            try! task.run()
            task.waitUntilExit()

            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            text = String(data: data, encoding: .utf8) ?? "";

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
