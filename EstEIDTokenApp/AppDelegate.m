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

    self.text.string = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
}

@end
