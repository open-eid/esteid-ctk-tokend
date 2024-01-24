/*
 * EstEIDToken
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

#import "Token.h"

#import <AppKit/AppKit.h>

@implementation TKSmartCard(EstEID)

- (NSData*)selectFile:(UInt8)p1 p2:(UInt8)p2 file:(nullable NSData *)file error:(NSError **)error {
    UInt16 sw = 0;
    NSData *data = [self sendIns:0xA4 p1:p1 p2:p2 data:file le:@0 sw:&sw error:error];
    if (sw == 0x9000) {
        return data;
    }
    NSLog(@"EstEIDToken selectFile failed to select: %@", file);
    if (error != nil) {
        *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeObjectNotFound userInfo:nil];
    }
    return nil;
}

- (nullable NSData*)readBinary:(NSUInteger)pos error:(NSError **) error {
    UInt16 sw = 0;
    NSData *data = [self sendIns:0xB0 p1:(pos >> 8) p2:pos data:nil le:@0 sw:&sw error:error];
    if (sw == 0x9000) {
        return data;
    }
    NSLog(@"EstEIDToken readBinary failed to read binary at pos %@", @(pos));
    if (error != nil) {
        *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeObjectNotFound userInfo:nil];
    }
    return nil;
}

- (nullable NSData*)readCert:(NSData*)file error:(NSError **) error {
    NSData *data = [self selectFile:0x02 p2:0x0C file:file error:error];
    if (data == nil) {
        return nil;
    }

    data = [self readBinary:0 error:error];
    if (data == nil) {
        return nil;
    }
    const UInt8 *byteData = (const UInt8*)data.bytes;
    if (byteData[0] != (UInt8) 0x30 || byteData[1] != (UInt8) 0x82) {
        return nil;
    }
    UInt16 length = (((byteData[2] & 0xFF) << 8) | (byteData[3] & 0xFF)) + 4;

    NSMutableData *fileData = [[NSMutableData alloc] init];
    [fileData appendData:data];
    while (fileData.length < length) {
        data = [self readBinary:fileData.length error:error];
        if (data == nil) {
            return nil;
        }
        [fileData appendData:data];
    }
    return fileData;
}

@end

@implementation TKTokenKeychainItem(EstEIDDataFormat)

- (void)setName:(NSString *)name {
    if (self.label != nil) {
        self.label = [NSString stringWithFormat:@"%@ (%@)", name, self.label];
    } else {
        self.label = name;
    }
}

@end

@implementation Token

- (TKTokenSession *)token:(TKToken *)token createSessionWithError:(NSError **)error {
    NSLog(@"Token createSessionWithError not implemented %@", self.AID);
    return nil;
}

- (void)token:(TKToken *)token terminateSession:(TKTokenSession *)session {
    NSLog(@"Token terminateSession");
}

- (BOOL)populateIdentity:(NSData*)certificateData certificateID:(NSData*)certificateID keyID:(NSData*)keyID auth:(BOOL)auth error:(NSError **)error {
    NSLog(@"Token populateIdentityFromSmartCard cert (%@) key (%@)", certificateID, keyID);
    // Create certificate item.
    if (certificateData == nil) {
        return NO;
    }

    id certificate = CFBridgingRelease(SecCertificateCreateWithData(kCFAllocatorDefault, (__bridge CFDataRef)certificateData));
    if (certificate == nil) {
        if (error != nil) {
            *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeCorruptedData userInfo:nil];
        }
        return NO;
    }
    TKTokenKeychainCertificate *certificateItem = [[TKTokenKeychainCertificate alloc] initWithCertificate:(__bridge SecCertificateRef)certificate objectID:certificateID];
    if (certificateItem == nil) {
        if (error != nil) {
            *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeCorruptedData userInfo:nil];
        }
        return NO;
    }
    [certificateItem setName:NSLocalizedString(auth ? @"AUTH_CERT" : @"SIGN_CERT", nil)];

    // Create key item.
    TKTokenKeychainKey *keyItem = [[TKTokenKeychainKey alloc] initWithCertificate:(__bridge SecCertificateRef)certificate objectID:keyID];
    if (keyItem == nil) {
        if (error != nil) {
            *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeCorruptedData userInfo:nil];
        }
        return NO;
    }
    [keyItem setName:NSLocalizedString(auth ? @"AUTH_KEY" : @"SIGN_KEY", nil)];
    keyItem.canSign = YES;
    keyItem.canDecrypt = NO;
    keyItem.suitableForLogin = NO; //auth; FIXME: implement login
    keyItem.canPerformKeyExchange = NO; //auth; FIXME: implement derive
    keyItem.constraints = @{ @(TKTokenOperationSignData): EstEIDConstraintPIN };
    // keyItem.constraints = constraints[@(TKTokenOperationPerformKeyExchange)] = EstEIDConstraintPIN; //auth; FIXME: implement derive
    // Populate keychain state with keys.
    [self.keychainContents fillWithItems:@[certificateItem, keyItem]];
    return YES;
}

@end

@implementation IDEMIAToken

- (nullable instancetype)initWithSmartCard:(TKSmartCard *)smartCard AID:(nullable NSData *)AID tokenDriver:(TKSmartCardTokenDriver *)tokenDriver error:(NSError **)error {
    NSLog(@"IDEMIAToken initWithSmartCard AID %@", AID);
    NSData *data;
    if ([smartCard selectFile:0x00 p2:0x0C file:nil error:error] == nil ||
        [smartCard selectFile:0x01 p2:0x0C file:NSDATA(2, 0xD0, 0x03) error:error] == nil ||
        (data = [smartCard readBinary:0 error:error]) == nil) {
        NSLog(@"IDEMIAToken initWithSmartCard failed to read card");
        return nil;
    }
    NSString *instanceID = [[NSString alloc] initWithBytes:data.bytes + 2 length:data.length - 2 encoding:NSUTF8StringEncoding];
    NSLog(@"IDEMIAToken initWithSmartCard %@", instanceID);
    if (self = [super initWithSmartCard:smartCard AID:AID instanceID:instanceID tokenDriver:tokenDriver]) {
        NSData *certificateID = NSDATA(2, 0xAD, 0xF1);
        NSData *keyID = NSDATA(2, 0x34, 0x01);
        if ([smartCard selectFile:0x00 p2:0x0C file:nil error:error] == nil ||
            [smartCard selectFile:0x01 p2:0x0C file:certificateID error:error] == nil ||
            ![super populateIdentity:[smartCard readCert:keyID error:error] certificateID:certificateID keyID:keyID auth:YES error:error]) {
            return nil;
        }
    }
    return self;
}

- (TKTokenSession *)token:(TKToken *)token createSessionWithError:(NSError **)error {
    NSLog(@"IDEMIAToken createSessionWithError %@", self.AID);
    return [[IDEMIATokenSession alloc] initWithToken:self];
}

@end

@implementation EstEIDTokenDriver

- (TKSmartCardToken *)tokenDriver:(TKSmartCardTokenDriver *)driver createTokenForSmartCard:(TKSmartCard *)smartCard AID:(NSData *)AID error:(NSError **)error {
    NSBundle *bundle = [NSBundle bundleForClass:EstEIDTokenDriver.class];
    NSLog(@"EstEIDTokenDriver createTokenForSmartCard AID %@ version %@.%@", AID, bundle.infoDictionary[@"CFBundleShortVersionString"], bundle.infoDictionary[@"CFBundleVersion"]);
    [EstEIDTokenDriver showNotification:nil];
    return [[IDEMIAToken alloc] initWithSmartCard:smartCard AID:AID tokenDriver:self error:error];
}

+ (void)showNotification:(NSString*__nullable)msg {
    BOOL isRunning = NO;
    for (NSRunningApplication *app in NSWorkspace.sharedWorkspace.runningApplications) {
        if ([app.bundleIdentifier containsString:@"EstEIDTokenNotify"]) {
            isRunning = YES;
            break;
        }
    }
    NSLog(@"EstEIDTokenDriver showNotification isRunning: %d", isRunning);
    if (!isRunning) {
        NSBundle *bundle = [NSBundle bundleForClass:EstEIDTokenDriver.class];
        NSString *path = [bundle.bundlePath.stringByDeletingLastPathComponent.stringByDeletingLastPathComponent stringByAppendingString:@"/Resources/EstEIDTokenNotify.app"];
        NSLog(@"EstEIDTokenDriver showNotification path: %@", path);
        [NSWorkspace.sharedWorkspace openApplicationAtURL:[NSURL fileURLWithPath:path isDirectory:YES] configuration:NSWorkspaceOpenConfiguration.configuration completionHandler:^(NSRunningApplication *app, NSError *error) {
            NSLog(@"EstEIDTokenDriver showNotification openApplicationAtURL: %@", error);
        }];
    }
    [NSDistributedNotificationCenter.defaultCenter postNotificationName:@"EstEIDTokenNotify" object:msg userInfo:nil deliverImmediately:YES];
}

@end
