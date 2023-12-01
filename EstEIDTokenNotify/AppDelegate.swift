/*
 * EstEIDTokenNotify
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
import UserNotifications
import OSLog

@main
class AppDelegate: NSObject, NSApplicationDelegate {

    func applicationDidFinishLaunching(_ aNotification: Notification) {
        let center = UNUserNotificationCenter.current()
        center.requestAuthorization(options: [.alert, .sound, .badge]) { success, error in
            os_log("EstEIDTokenNotify: requestAuthorizationWithOptions \(success) \(error)")
        }
        DistributedNotificationCenter.default()
            .addObserver(self, selector: #selector(self.notificationEvent(_:)), name: Notification.Name("EstEIDTokenNotify"), object: nil)
    }

    @objc func notificationEvent(_ notification: Notification) {
        let message = notification.object as? String
        os_log("EstEIDTokenNotify: notificationEvent \(message ?? "nil")")
        let center = UNUserNotificationCenter.current()
        if (message != nil) {
            let list = message!.split(separator: "\n")
            let ui = UNMutableNotificationContent()
            ui.title = String(list[0])
            if (list.count > 1) {
                ui.subtitle = String(list[1])
            }
            ui.sound = .default
            let request = UNNotificationRequest(identifier: UUID().uuidString, content: ui, trigger: nil)
            center.add(request) { error in
                os_log("EstEIDTokenNotify: addNotificationRequest \(error)")
            }
        } else {
            center.removeAllDeliveredNotifications()
        }
    }

}

