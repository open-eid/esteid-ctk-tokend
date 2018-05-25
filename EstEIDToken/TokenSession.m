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
#import <Security/SecAsn1Coder.h>

@implementation EstEIDAuthOperation

- (nullable instancetype)initWithSmartCard:(TKSmartCard *)smartCard {
    if (self = [super init]) {
        self.smartCard = smartCard;
        self.APDUTemplate = NSDATA(5, self.smartCard.cla, 0x20, 0x00, 0x01, 0x00);
        self.PINByteOffset = 5;
        self.PINFormat.maxPINLength = 12;
        self.PINFormat.PINBlockByteLength = 0;
    }
    return self;
}

- (BOOL)finishWithError:(NSError **)error {
    NSLog(@"EstEIDAuthOperation finishWithError %@", *error);
    UInt16 sw = 0;
    [self.smartCard sendIns:0x20 p1:0x00 p2:0x01 data:[self.PIN dataUsingEncoding:NSUTF8StringEncoding] le:nil sw:&sw error:error];
    NSLog(@"EstEIDAuthOperation finishWithError %@", *error);
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
    self.smartCard.sensitive = YES;
    self.smartCard.context = @(YES);
    return YES;
}

@end

@implementation EstEIDTokenSession

- (TKTokenAuthOperation *)tokenSession:(TKTokenSession *)session beginAuthForOperation:(TKTokenOperation)operation constraint:(TKTokenOperationConstraint)constraint error:(NSError **)error {
    NSLog(@"EstEIDTokenSession beginAuthForOperation %@ constraint %@", @(operation), constraint);
    if (![constraint isEqual:EstEIDConstraintPIN]) {
        NSLog(@"EstEIDTokenSession beginAuthForOperation attempt to evaluate unsupported constraint %@", constraint);
        if (error != nil) {
            *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeBadParameter userInfo:@{NSLocalizedDescriptionKey: NSLocalizedString(@"WRONG_CONSTR", nil)}];
        }
        return nil;
    }

    // Begin session to avoid deauth before sign operation
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    [self.smartCard beginSessionWithReply:^(BOOL success, NSError *error) {
        NSLog(@"EstEIDTokenSession beginAuthForOperation beginSessionWithReply %@ %@", @(success), error);
        dispatch_semaphore_signal(sem);
    }];
    dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);

    TKTokenSmartCardPINAuthOperation *tokenAuth = [[EstEIDAuthOperation alloc] initWithSmartCard:self.smartCard];

    // workaround: macOS does not support PINPad templates
    TKSmartCardUserInteractionForSecurePINVerification *pinpad = [self.smartCard userInteractionForSecurePINVerificationWithPINFormat:tokenAuth.PINFormat APDU:tokenAuth.APDUTemplate PINByteOffset:tokenAuth.PINByteOffset];
    if (pinpad != nil) {
        NSLog(@"EstEIDTokenSession beginAuthForOperation PINPad");
        pinpad.PINMessageIndices = @[@0];

        // Open application for PinPAD notification
        BOOL isRunning = NO;
        for (NSRunningApplication *app in NSWorkspace.sharedWorkspace.runningApplications) {
            if ([app.bundleIdentifier containsString:@"EstEIDTokenNotify"]) {
                isRunning = YES;
                break;
            }
        }
        NSLog(@"EstEIDTokenSession beginAuthForOperation isRunning: %d", isRunning);
        if (!isRunning) {
            NSBundle *bundle = [NSBundle bundleForClass:EstEIDTokenDriver.class];
            NSString *path = [bundle.bundlePath.stringByDeletingLastPathComponent.stringByDeletingLastPathComponent stringByAppendingString:@"/Resources/EstEIDTokenNotify.app"];
            NSLog(@"EstEIDTokenSession beginAuthForOperation path: %@", path);
            BOOL isLaunched = [NSWorkspace.sharedWorkspace launchApplication:path];
            NSLog(@"EstEIDTokenSession beginAuthForOperation launchApplication: %d", isLaunched);
        }
        [NSDistributedNotificationCenter.defaultCenter postNotificationName:@"EstEIDTokenNotify" object:NSLocalizedString(@"ENTER_PINPAD", nil) userInfo:nil deliverImmediately:YES];

        __block BOOL isCanceled = NO;
        [pinpad runWithReply:^(BOOL success, NSError *error) {
            NSLog(@"EstEIDTokenSession beginAuthForOperation PINPad completed %@ %@ %04X", @(success), error, pinpad.resultSW);
            switch (pinpad.resultSW)
            {
                case 0x9000:
                    self.smartCard.sensitive = YES;
                    self.smartCard.context = @(YES);
                    break;
                case 0x6401:
                    isCanceled = YES;
                default:
                    self.smartCard.sensitive = NO;
                    self.smartCard.context = nil;
                    break;
            }
            [NSDistributedNotificationCenter.defaultCenter postNotificationName:@"EstEIDTokenNotify" object:nil userInfo:nil deliverImmediately:YES];
            dispatch_semaphore_signal(sem);
        }];
        dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
        NSLog(@"EstEIDTokenSession beginAuthForOperation PINPad completed");
        if (isCanceled) {
            if (error != nil) {
                *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeCanceledByUser userInfo:nil];
            }
            return nil;
        }
        return [[TKTokenAuthOperation alloc] init];
    }
    return tokenAuth;
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
            supports = keyItem.canSign && (
#if ENABLE_RSA
                [algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureRaw] ||
#endif
                [algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureRFC4754] ||
                [algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureDigestX962] ||
                [algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureDigestX962SHA1] ||
                [algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureDigestX962SHA224] ||
                [algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureDigestX962SHA256] ||
                [algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureDigestX962SHA384] ||
                [algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureDigestX962SHA512]);
            break;
        case TKTokenOperationDecryptData:
            //supports = keyItem.canDecrypt && [algorithm isAlgorithm:kSecKeyAlgorithmRSAEncryptionRaw]; // FIXME: implement decryption
            break;
        case TKTokenOperationPerformKeyExchange:
            //supports = keyItem.canPerformKeyExchange && [algorithm isAlgorithm:kSecKeyAlgorithmECDHKeyExchangeStandard]; // FIXME: implement derive
            break;
        default:
            break;
    }
    NSLog(@"EstEIDTokenSession supportsOperation key supports: %@", @(supports));
    return supports;
}

- (NSData *)tokenSession:(TKTokenSession *)session signData:(NSData *)dataToSign usingKey:(TKTokenObjectID)keyObjectID algorithm:(TKTokenKeyAlgorithm *)algorithm error:(NSError **)error {
    NSLog(@"EstEIDTokenSession signData %@ %@", keyObjectID, dataToSign);

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
    [self.smartCard sendIns:0x22 p1:0xF3 p2:0x01 data:nil le:@0 sw:&sw error:error];
    if (sw != 0x9000) {
        NSLog(@"EstEIDTokenSession signData failed to set sec env");
        if (error != nil) {
            *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeCorruptedData userInfo:nil];
        }
        return nil;
    }

    [self.smartCard sendIns:0x22 p1:0x41 p2:0xB8 data:NSDATA(2, 0x83, 0x00) le:nil sw:&sw error:error]; //Key reference, 8303801100
    if (sw != 0x9000) {
        NSLog(@"EstEIDTokenSession signData failed to select default key");
        if (error != nil) {
            *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeCorruptedData userInfo:nil];
        }
        return nil;
    }

    NSData *sign = dataToSign;
#if ENABLE_RSA
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureRaw]) {
        NSLog(@"EstEIDToken Remove PKCS1 1.5 padding");
        //  00 01 FF FF 00 ....
        const char *string = dataToSign.bytes;
        char *e = strchr(&string[3], '\0'); // Start at pos 3
        NSUInteger pos = (NSUInteger)(e - string) + 1;
        sign = [dataToSign subdataWithRange:NSMakeRange(pos, dataToSign.length - pos)];
    }
#endif

    self.smartCard.useExtendedLength = NO;
    NSData *response = [self.smartCard sendIns:0x88 p1:0x00 p2:0x00 data:sign le:@0 sw:&sw error:error];
    if (sw != 0x9000 || response == nil) {
        NSLog(@"EstEIDTokenSession signData failed to sign");
        return nil;
    }

    // Deauth and release session
    self.smartCard.sensitive = NO;
    self.smartCard.context = nil;
    [self.smartCard endSession];

    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureDigestX962] ||
        [algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureDigestX962SHA1] ||
        [algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureDigestX962SHA224] ||
        [algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureDigestX962SHA256] ||
        [algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureDigestX962SHA384] ||
        [algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureDigestX962SHA512]) {
        NSLog(@"EstEIDToken encoding to ASN1 sequence %@", response);

        typedef struct {
            SecAsn1Item r;
            SecAsn1Item s;
        } ECDSA;

        static const SecAsn1Template ECDSATemplate[] = {
            { SEC_ASN1_SEQUENCE, 0, NULL, sizeof(ECDSA) },
            { SEC_ASN1_INTEGER, offsetof(ECDSA, r) },
            { SEC_ASN1_INTEGER, offsetof(ECDSA, s) },
            { 0 }
        };

        uint8 *bytes = (uint8*)response.bytes;
        ECDSA ecdsa = {
            { response.length / 2, bytes },
            { response.length / 2, &bytes[response.length / 2] },
        };

        SecAsn1CoderRef coder;
        SecAsn1CoderCreate(&coder);
        SecAsn1Item ber = {0, nil};
        OSStatus ortn = SecAsn1EncodeItem(coder, &ecdsa, ECDSATemplate, &ber);
        response = [NSData dataWithBytes:ber.Data length:ber.Length];
        SecAsn1CoderRelease(coder);
        NSLog(@"EstEIDToken SecAsn1EncodeItem %i %@", ortn, response);
    }
    return response;
}

- (NSData *)tokenSession:(TKTokenSession *)session decryptData:(NSData *)ciphertext usingKey:(TKTokenObjectID)keyObjectID algorithm:(TKTokenKeyAlgorithm *)algorithm error:(NSError **)error {
    NSLog(@"EstEIDTokenSession decryptData %@", keyObjectID);
    return nil; // FIXME: implement decrypt
}

- (NSData *)tokenSession:(TKTokenSession *)session performKeyExchangeWithPublicKey:(NSData *)otherPartyPublicKeyData usingKey:(TKTokenObjectID)keyObjectID algorithm:(TKTokenKeyAlgorithm *)algorithm parameters:(TKTokenKeyExchangeParameters *)parameters error:(NSError **)error {
    NSLog(@"EstEIDTokenSession performKeyExchangeWithPublicKey %@", keyObjectID);
    return nil; // FIXME: implement derive
}

@end
