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

#import <Cocoa/Cocoa.h>

@interface AppDelegate : NSObject <NSApplicationDelegate>
@property (weak) IBOutlet NSTextField *version;
@property (weak) IBOutlet NSTextView *text;
@property (weak) IBOutlet NSWindow *window;
@end

@implementation AppDelegate

- (void)applicationDidFinishLaunching:(NSNotification *)notification
{
    self.version.stringValue = [NSString stringWithFormat:@"Version: %@.%@", NSBundle.mainBundle.infoDictionary[@"CFBundleShortVersionString"], NSBundle.mainBundle.infoDictionary[@"CFBundleVersion"]];

    NSPipe *pipe = [NSPipe pipe];
    NSFileHandle *file = pipe.fileHandleForReading;

    NSTask *task = [[NSTask alloc] init];
    task.launchPath = @"/usr/sbin/system_profiler";
    task.arguments = @[@"SPSmartCardsDataType"];
    task.standardOutput = pipe;
    [task launch];

    NSData *data = [file readDataToEndOfFile];
    [file closeFile];

    NSMutableAttributedString *text = [[NSMutableAttributedString alloc] initWithString:[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding]
                                                                             attributes:@{NSForegroundColorAttributeName : NSColor.controlTextColor}];
    self.text.textStorage.attributedString = text;

    NSDictionary *find = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassKey,
        (__bridge id)kSecReturnAttributes: (__bridge id)kCFBooleanTrue,
        (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitAll,
    };
    CFArrayRef itemsTemp = nil;
    SecItemCopyMatching((__bridge CFDictionaryRef)find, (CFTypeRef *)&itemsTemp);
    NSArray *items = CFBridgingRelease(itemsTemp);
    NSMutableString *string = text.mutableString;
    for (NSDictionary *key in items) {
        if ([(NSString*)key[(__bridge id)kSecAttrTokenID] containsString:@"ee.ria.EstEIDTokenApp.EstEIDToken"]) {
            [string appendFormat:@"\nKey: %@", key];
            self.text.textStorage.attributedString = text;
        }
    }
}

@end
