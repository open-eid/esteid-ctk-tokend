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

#import <Cocoa/Cocoa.h>

@interface AppDelegate : NSObject <NSApplicationDelegate,NSUserNotificationCenterDelegate>
@end

@implementation AppDelegate

- (void)applicationDidFinishLaunching:(NSNotification *)notification
{
    [NSDistributedNotificationCenter.defaultCenter addObserver:self selector:@selector(notificationEvent:) name:@"EstEIDTokenNotify" object:nil];
}

-(void)notificationEvent:(NSNotification *)notification {

    NSLog(@"EstEIDTokenNotify: notificationEvent %@", notification.object);
    NSUserNotificationCenter *center = NSUserNotificationCenter.defaultUserNotificationCenter;
    if (notification.object != nil) {
        NSUserNotification *ui = [NSUserNotification new];
        ui.title = notification.object;
        ui.hasActionButton = NO;
        ui.soundName = NSUserNotificationDefaultSoundName;
        center.delegate = self;
        [center deliverNotification:ui];
    } else {
        [center removeAllDeliveredNotifications];
    }
}

- (void)userNotificationCenter:(NSUserNotificationCenter *)center didDeliverNotification:(NSUserNotification *)notification
{
    NSLog(@"EstEIDTokenNotify: didDeliverNotification %d", notification.isPresented);
}

- (void)userNotificationCenter:(NSUserNotificationCenter *)center didActivateNotification:(NSUserNotification *)notification
{
    NSLog(@"EstEIDTokenNotify: didActivateNotification");
}

- (BOOL)userNotificationCenter:(NSUserNotificationCenter *)center shouldPresentNotification:(NSUserNotification *)notification
{
    NSLog(@"EstEIDTokenNotify: shouldPresentNotification");
    return YES;
}

@end
