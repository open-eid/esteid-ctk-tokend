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

@implementation EstEIDAuthOperation

- (BOOL)finishWithError:(NSError **)error {
    NSLog(@"EstEIDAuthOperation finishWithError %@", *error);

    UInt16 sw = 0;
#if 0
    TKSmartCardUserInteractionForSecurePINVerification *pinpad = [self.smartCard userInteractionForSecurePINVerificationWithPINFormat:self.PINFormat APDU:self.APDUTemplate PINByteOffset:self.PINByteOffset];

    if (pinpad != nil) {
        dispatch_semaphore_t sem = dispatch_semaphore_create(0);
        pinpad.initialTimeout = 30;
        pinpad.interactionTimeout = 30;
        [pinpad runWithReply:^(BOOL success, NSError *error) {
            NSLog(@"EstEIDAuthOperation finishWithError %@ %@", @(success), error);
            dispatch_semaphore_signal(sem);
        }];
        dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
        sw = pinpad.resultSW;
    }
    else
#endif
    [self.smartCard sendIns:0x20 p1:0x00 p2:0x01 data:[self.PIN dataUsingEncoding:NSUTF8StringEncoding] le:nil sw:&sw error:error];
    NSLog(@"EstEIDAuthOperation finishWithError %@", [NSData dataWithBytes:&sw length:sizeof(sw)]);
    if ((sw & 0xff00) == 0x6300) {
        int triesLeft = sw & 0x3f;
        NSLog(@"EstEIDAuthOperation finishWithError Failed to verify PIN sw:0x%04x retries: %d", sw, triesLeft);
        if (error != nil) {
            *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeAuthenticationFailed userInfo:
                      @{NSLocalizedDescriptionKey: [NSString localizedStringWithFormat: NSLocalizedString(@"VERIFY_TRY_LEFT", nil), triesLeft]}];
        }
        return NO;
    } else if (sw != 0x9000) {
        NSLog(@"EstEIDAuthOperation finishWithError Failed to verify PIN sw: 0x%04x", sw);
        if (error != nil) {
            *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeAuthenticationFailed userInfo:
                      @{NSLocalizedDescriptionKey: [NSString localizedStringWithFormat: NSLocalizedString(@"VERIFY_TRY_LEFT", nil), 0]}];
        }
        return NO;
    }

    // Mark card session sensitive, because we entered PIN into it and no session should access it in this state.
    self.smartCard.sensitive = YES;

    // Remember in card context that the card is authenticated.
    self.smartCard.context = @(YES);

    return YES;
}

@end

@implementation EstEIDTokenSession

- (TKTokenAuthOperation *)tokenSession:(TKTokenSession *)session beginAuthForOperation:(TKTokenOperation)operation constraint:(TKTokenOperationConstraint)constraint error:(NSError **)error {
    NSLog(@"EstEIDTokenSession beginAuthForOperation");
    if ([constraint isEqual:EstEIDConstraintPIN]) {
        EstEIDAuthOperation *auth = [[EstEIDAuthOperation alloc] init];
        auth.smartCard = self.smartCard;
        auth.APDUTemplate = [NSData dataWithBytes:(const UInt8[]){self.smartCard.cla, 0x20, 0x00, 0x01, 0x00} length:5];
        auth.PINByteOffset = 5;
        auth.PINFormat.maxPINLength = 12;
        auth.PINFormat.PINBlockByteLength = 0;
        return auth;
    }
    NSLog(@"EstEIDTokenSession beginAuthForOperation attempt to evaluate unsupported constraint %@", constraint);
    if (error != nil) {
        *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeBadParameter userInfo:@{NSLocalizedDescriptionKey: NSLocalizedString(@"WRONG_CONSTR", nil)}];
    }
    return nil;
}

- (BOOL)tokenSession:(TKTokenSession *)session supportsOperation:(TKTokenOperation)operation usingKey:(TKTokenObjectID)keyObjectID algorithm:(TKTokenKeyAlgorithm *)algorithm {
    NSLog(@"EstEIDTokenSession supportsOperation %@ keyID %@", @(operation), keyObjectID);
    TKTokenKeychainKey *keyItem = [self.token.keychainContents keyForObjectID:keyObjectID error:nil];
    if (keyItem == nil) {
        NSLog(@"EstEIDTokenSession supportsOperation key not found");
        return NO;
    }

    BOOL supports = NO;
    switch (operation) {
        case TKTokenOperationSignData:
            supports = keyItem.canSign && [algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureRaw];
            break;
        case TKTokenOperationDecryptData:
            //supports = keyItem.canDecrypt && [algorithm isAlgorithm:kSecKeyAlgorithmRSAEncryptionRaw]; // FIXME: implement encryption
            break;
        default:
            break;
    }
    NSLog(@"EstEIDTokenSession supportsOperation key supports: %@", @(supports));
    return supports;
}

- (NSData *)tokenSession:(TKTokenSession *)session signData:(NSData *)dataToSign usingKey:(TKTokenObjectID)keyObjectID algorithm:(TKTokenKeyAlgorithm *)algorithm error:(NSError **)error {
    NSLog(@"EstEIDTokenSession signData %@", keyObjectID);

    TKTokenKeychainKey *keyItem = [self.token.keychainContents keyForObjectID:keyObjectID error:error];
    if (keyItem == nil) {
        NSLog(@"EstEIDTokenSession signData key not found");
        if (error != nil) {
            *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeTokenNotFound userInfo:nil];
        }
        return nil;
    }

    if (self.smartCard.context == nil) {
        NSLog(@"EstEIDTokenSession signData unauthicated");
        if (error != nil) {
            *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeAuthenticationNeeded userInfo:nil];
        }
        return nil;
    }

    UInt16 sw;
    NSData *DEFAULT = [NSData dataWithBytes:(const UInt8[]){ 0x83, 0x00 } length:2]; //Key reference, 8303801100

    [self.smartCard sendIns:0x22 p1:0xF3 p2:0x01 data:nil le:@0 sw:&sw error:error];
    if (sw != 0x9000) {
        NSLog(@"EstEIDTokenSession signData failed to set sec env");
        if (error != nil) {
            *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeCorruptedData userInfo:nil];
        }
        return nil;
    }

    [self.smartCard sendIns:0x22 p1:0x41 p2:0xB8 data:DEFAULT le:nil sw:&sw error:error];
    if (sw != 0x9000) {
        NSLog(@"EstEIDTokenSession signData failed to select default key");
        if (error != nil) {
            *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeCorruptedData userInfo:nil];
        }
        return nil;
    }

    // Remove PKCS1 1.5 padding 00 01 FF FF 00 ....
    const char *string = dataToSign.bytes;
    char *e = strchr(&string[3], '\0'); // Start at pos 3
    NSUInteger pos = (NSUInteger)(e - string) + 1;
    NSData *sign = [dataToSign subdataWithRange:NSMakeRange(pos, dataToSign.length - pos)];

    self.smartCard.useExtendedLength = NO;
    NSData *response = [self.smartCard sendIns:0x88 p1:0x00 p2:0x00 data:sign le:@0 sw:&sw error:error];
    if (sw == 0x9000) {
        self.smartCard.sensitive = NO;
        self.smartCard.context = nil;
        return response;
    }

    NSLog(@"EstEIDTokenSession signData failed to sign");
    if (error != nil) {
        *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeCorruptedData userInfo:nil];
    }
    return nil;
}

- (NSData *)tokenSession:(TKTokenSession *)session decryptData:(NSData *)ciphertext usingKey:(TKTokenObjectID)keyObjectID algorithm:(TKTokenKeyAlgorithm *)algorithm error:(NSError **)error {
    NSLog(@"EstEIDTokenSession decryptData %@", keyObjectID);
    // FIXME: implement decrypt
    return [self tokenSession:session signData:ciphertext usingKey:keyObjectID algorithm:algorithm error:error];
}

@end
