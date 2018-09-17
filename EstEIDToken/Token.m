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

- (NSData*)selectFile:(UInt8)ins p1:(UInt8)p1 p2:(UInt8)p2 file:(nullable NSData *)file error:(NSError **)error {
    UInt16 sw = 0;
    NSData *data = [self sendIns:ins p1:p1 p2:p2 data:file le:@0 sw:&sw error:error];
    if (sw == 0x9000) {
        return data;
    }
    NSLog(@"EstEIDToken selectFile failed to select: %@", file);
    if (error != nil) {
        *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeObjectNotFound userInfo:nil];
    }
    return nil;
}

- (nullable NSData*)readFile:(NSData*)file error:(NSError **) error {
    NSData *data = [self selectFile:0xA4 p1:0x02 p2:0x04 file:file error:error];
    if (data == nil) {
        return nil;
    }

    __block UInt16 length = 0x0600;
    TKBERTLVRecord *record = [TKBERTLVRecord recordFromData:data];
    if (record != nil) {
        NSArray<TKTLVRecord *> *records = [TKBERTLVRecord sequenceOfRecordsFromData:record.value];
        if (records != nil) {
            [records enumerateObjectsUsingBlock:^(TKTLVRecord *obj, NSUInteger idx, BOOL *stop) {
                if (obj.tag == 0x85) {
                    length = CFSwapInt16BigToHost(*(UInt16*)obj.value.bytes);
                    *stop = YES;
                }
            }];
        }
    }

    NSMutableData *fileData = [[NSMutableData alloc] init];
    while (fileData.length < length) {
        UInt16 sw = 0;
        NSData *data = [self sendIns:0xB0 p1:(fileData.length >> 8) p2:fileData.length data:nil le:@0 sw:&sw error:error];
        if (sw == 0x9000) {
            [fileData appendData:data];
            continue;
        }
        NSLog(@"EstEIDToken readFile failed to read file: %@", file);
        if (error != nil) {
            *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeObjectNotFound userInfo:nil];
        }
        return nil;
    }
    return fileData;
}

- (nullable NSString*)readRecord:(UInt8)record error:(NSError **) error {
    UInt16 sw = 0;
    NSData *data = [self sendIns:0xB2 p1:record p2:0x04 data:nil le:@0 sw:&sw error:error];
    if (sw == 0x9000) {
        return [[NSString alloc] initWithData:data encoding:NSWindowsCP1252StringEncoding];
    }
    NSLog(@"EstEIDToken readRecord failed to read record %@", @(record));
    if (error != nil) {
        *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeObjectNotFound userInfo:nil];
    }
    return nil;
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

@implementation EstEIDToken

- (BOOL)populateIdentity:(NSMutableArray<TKTokenKeychainItem *> *)items smartcard:(TKSmartCard *)smartCard certificateID:(NSData*)certificateID name:(NSString *)certificateName keyID:(NSData*)keyID name:(NSString *)keyName auth:(BOOL)auth error:(NSError **)error {
    NSLog(@"EstEIDToken populateIdentityFromSmartCard cert %@ (%@) key %@ (%@)", certificateName, certificateID, keyName, keyID);

    // Create certificate item.
    NSData *certificateData = [smartCard readFile:certificateID error:error];
    if (certificateData == nil) {
        return NO;
    }
    id certificate = CFBridgingRelease(SecCertificateCreateWithData(kCFAllocatorDefault, (CFDataRef)certificateData));
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
    [certificateItem setName:certificateName];

    // Create key item.
    TKTokenKeychainKey *keyItem = [[TKTokenKeychainKey alloc] initWithCertificate:(__bridge SecCertificateRef)certificate objectID:keyID];
    if (keyItem == nil) {
        if (error != nil) {
            *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeCorruptedData userInfo:nil];
        }
        return NO;
    }
    [keyItem setName:keyName];

    keyItem.canSign = YES;
    keyItem.canDecrypt = NO; //auth; FIXME: implement decryption
    keyItem.suitableForLogin = NO; //auth; FIXME: implement login
    keyItem.canPerformKeyExchange = NO; //auth; FIXME: implement derive
    NSMutableDictionary<NSNumber *, TKTokenOperationConstraint> *constraints = [NSMutableDictionary dictionary];
    constraints[@(TKTokenOperationSignData)] = EstEIDConstraintPIN;
    if (auth) {
        constraints[@(TKTokenOperationDecryptData)] = EstEIDConstraintPIN;
        constraints[@(TKTokenOperationPerformKeyExchange)] = EstEIDConstraintPIN;
    }
    keyItem.constraints = constraints;

    [items addObject:certificateItem];
    [items addObject:keyItem];
    return YES;
}

- (nullable instancetype)initWithSmartCard:(TKSmartCard *)smartCard AID:(nullable NSData *)AID tokenDriver:(TKSmartCardTokenDriver *)tokenDriver error:(NSError **)error {
    NSLog(@"EstEIDToken initWithSmartCard AID %@", AID);
    NSString *instanceID;
    if ([smartCard selectFile:0xA4 p1:0x00 p2:0x0C file:nil error:error] == nil ||
        [smartCard selectFile:0xA4 p1:0x01 p2:0x0C file:NSDATA(2, 0xEE, 0xEE) error:error] == nil ||
        [smartCard selectFile:0xA4 p1:0x02 p2:0x0C file:NSDATA(2, 0x50, 0x44) error:error] == nil ||
        (instanceID = [smartCard readRecord:0x08 error:error]) == nil) {
        NSLog(@"EstEIDToken initWithSmartCard failed to read card");
        return nil;
    }
    NSLog(@"EstEIDToken initWithSmartCard %@", instanceID);
    if (self = [super initWithSmartCard:smartCard AID:AID instanceID:instanceID tokenDriver:tokenDriver]) {
        // Prepare array with keychain items representing on card objects.
        NSMutableArray<TKTokenKeychainItem *> *items = [NSMutableArray arrayWithCapacity:2];
        if (![self populateIdentity:items smartcard:smartCard
                      certificateID:NSDATA(2, 0xAA, 0xCE) name:NSLocalizedString(@"AUTH_CERT", nil)
                              keyID:NSDATA(2, 0x11, 0x00) name:NSLocalizedString(@"AUTH_KEY", nil) auth:YES error:error]/* ||
            ![self populateIdentity:items smartcard:smartCard // FIXME: Sign cert disabled
                      certificateID:NSDATA(2, 0xDD, 0xCE) name:NSLocalizedString(@"SIGN_CERT", nil)
                              keyID:NSDATA(2, 0x01, 0x00) name:NSLocalizedString(@"SIGN_KEY", nil) auth:NO error:error]*/) {
            return nil;
        }
        // Populate keychain state with keys.
        [self.keychainContents fillWithItems:items];
    }
    return self;
}

- (TKTokenSession *)token:(TKToken *)token createSessionWithError:(NSError **)error {
    NSLog(@"EstEIDToken createSessionWithError %@", self.AID);
    return [[EstEIDTokenSession alloc] initWithToken:self];
}

- (void)token:(TKToken *)token terminateSession:(TKTokenSession *)session {
    NSLog(@"EstEIDToken terminateSession");
}

@end

@implementation EstEIDTokenDriver

- (TKSmartCardToken *)tokenDriver:(TKSmartCardTokenDriver *)driver createTokenForSmartCard:(TKSmartCard *)smartCard AID:(NSData *)AID error:(NSError **)error {
    NSBundle *bundle = [NSBundle bundleForClass:EstEIDTokenDriver.class];
    NSLog(@"EstEIDTokenDriver createTokenForSmartCard AID %@ version %@.%@", AID, bundle.infoDictionary[@"CFBundleShortVersionString"], bundle.infoDictionary[@"CFBundleVersion"]);
    [EstEIDTokenDriver showNotification:nil];
    return [[EstEIDToken alloc] initWithSmartCard:smartCard AID:AID tokenDriver:self error:error];
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
        BOOL isLaunched = [NSWorkspace.sharedWorkspace launchApplication:path];
        NSLog(@"EstEIDTokenDriver showNotification launchApplication: %d", isLaunched);
    }
    [NSDistributedNotificationCenter.defaultCenter postNotificationName:@"EstEIDTokenNotify" object:msg userInfo:nil deliverImmediately:YES];
}

@end
