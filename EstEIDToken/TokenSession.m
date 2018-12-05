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

#import <Security/SecAsn1Coder.h>

@implementation EstEIDAuthOperation {
    EstEIDTokenSession *session;
}

- (nullable instancetype)initWithSmartCard:(TKSmartCard *)smartCard tokenSession:(EstEIDTokenSession *)esteidsession {
    if (self = [super init]) {
        self.smartCard = smartCard;
        self.APDUTemplate = NSDATA(5, self.smartCard.cla, 0x20, 0x00, 0x01, 0x00);
        self.PINByteOffset = 5;
        self.PINFormat.maxPINLength = 12;
        self.PINFormat.PINBlockByteLength = 0;
        session = esteidsession;
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
        [EstEIDTokenDriver showNotification:[NSString localizedStringWithFormat:NSLocalizedString(@"VERIFY_TRY_LEFT", nil), triesLeft]];
        if (triesLeft == 0) {
            [session closeSession];
        }
        if (error != nil) {
            *error = [NSError errorWithDomain:TKErrorDomain code:triesLeft == 0 ? TKErrorCodeCanceledByUser : TKErrorCodeAuthenticationFailed userInfo:
                      @{NSLocalizedDescriptionKey:[NSString localizedStringWithFormat:NSLocalizedString(@"VERIFY_TRY_LEFT", nil), triesLeft]}];
        }
        return NO;
    } else if (sw != 0x9000) {
        NSLog(@"EstEIDAuthOperation finishWithError Failed to verify PIN sw: 0x%04x", sw);
        [EstEIDTokenDriver showNotification:nil];
        if (error != nil) {
            *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeAuthenticationFailed userInfo:
                      @{NSLocalizedDescriptionKey:[NSString localizedStringWithFormat:NSLocalizedString(@"VERIFY_TRY_LEFT", nil), 0]}];
        }
        return NO;
    }
    self.smartCard.sensitive = YES;
    return YES;
}

@end

@implementation EstEIDTokenSession {
    BOOL isSessionActive;
}

- (void)closeSession {
    if (isSessionActive) {
        [self.smartCard endSession];
    }
    isSessionActive = NO;
    self.smartCard.sensitive = NO;
}

- (TKTokenAuthOperation *)tokenSession:(TKTokenSession *)session beginAuthForOperation:(TKTokenOperation)operation constraint:(TKTokenOperationConstraint)constraint error:(NSError **)error {
    NSLog(@"EstEIDTokenSession beginAuthForOperation %@ constraint %@ isSessionActive %d", @(operation), constraint, isSessionActive);
    if (![constraint isEqual:EstEIDConstraintPIN]) {
        NSLog(@"EstEIDTokenSession beginAuthForOperation attempt to evaluate unsupported constraint %@", constraint);
        if (error != nil) {
            *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeBadParameter userInfo:@{NSLocalizedDescriptionKey: NSLocalizedString(@"WRONG_CONSTR", nil)}];
        }
        return nil;
    }

    // Begin session to avoid deauth before sign operation
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    if (!isSessionActive) {
        [self.smartCard beginSessionWithReply:^(BOOL success, NSError *error) {
            NSLog(@"EstEIDTokenSession beginAuthForOperation beginSessionWithReply %@ %@", @(success), error);
            dispatch_semaphore_signal(sem);
        }];
        dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
        isSessionActive = YES;
    }

    UInt16 sw;
    NSData *pinStatus;
    if ([self.smartCard sendIns:0xA4 p1:0x00 p2:0x0C data:nil le:@0 sw:&sw  error:error] == nil ||
        [self.smartCard sendIns:0xA4 p1:0x02 p2:0x0C data:NSDATA(2, 0x00, 0x16) le:@0 sw:&sw error:error] == nil ||
        (pinStatus = [self.smartCard sendIns:0xB2 p1:0x01 p2:0x04 data:nil le:@0 sw:&sw error:error]) == nil) {
        NSLog(@"EstEIDTokenSession beginAuthForOperation beginSessionWithReply %d", sw);
        [self closeSession];
        if (error != nil) {
            *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeAuthenticationFailed userInfo:@{NSLocalizedDescriptionKey:NSLocalizedString(@"WRONG_CONSTR", nil)}];
        }
        return nil;
    }
    UInt8 count = 0;
    [pinStatus getBytes:&count range:NSMakeRange(5, sizeof(count))];
    if (count == 0) {
        NSLog(@"EstEIDTokenSession beginAuthForOperation beginSessionWithReply locked %d %@", count, pinStatus);
        [self closeSession];
        [EstEIDTokenDriver showNotification:[NSString localizedStringWithFormat:NSLocalizedString(@"VERIFY_TRY_LEFT", nil), 0]];
        if (error != nil) {
            *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeCanceledByUser
                                     userInfo:@{NSLocalizedDescriptionKey:[NSString localizedStringWithFormat:NSLocalizedString(@"VERIFY_TRY_LEFT", nil), 0]}];
        }
        return nil;
    }

    TKTokenSmartCardPINAuthOperation *tokenAuth = [[EstEIDAuthOperation alloc] initWithSmartCard:self.smartCard tokenSession:self];
    if ([self.smartCard.slot.name containsString:@"HID Global OMNIKEY 3x21 Smart Card Reader"] ||
        [self.smartCard.slot.name containsString:@"HID Global OMNIKEY 6121 Smart Card Reader"])
    {
        NSLog(@"EstEIDTokenSession beginAuthForOperation '%@' is not PinPad reader", self.smartCard.slot.name);
        return tokenAuth;
    }

    // workaround: macOS does not support PINPad templates
    TKSmartCardUserInteractionForSecurePINVerification *pinpad = [self.smartCard userInteractionForSecurePINVerificationWithPINFormat:tokenAuth.PINFormat APDU:tokenAuth.APDUTemplate PINByteOffset:tokenAuth.PINByteOffset];
    if (pinpad == nil) {
        return tokenAuth;
    }

    NSLog(@"EstEIDTokenSession beginAuthForOperation PINPad");
    pinpad.PINMessageIndices = @[@0];
    [EstEIDTokenDriver showNotification:NSLocalizedString(@"ENTER_PINPAD", nil)];
    __block BOOL isCanceled = NO;
    [pinpad runWithReply:^(BOOL success, NSError *error) {
        NSLog(@"EstEIDTokenSession beginAuthForOperation PINPad completed %@ %@ %04X", @(success), error, pinpad.resultSW);
        switch (pinpad.resultSW)
        {
            case 0x9000:
                [EstEIDTokenDriver showNotification:nil];
                self.smartCard.sensitive = YES;
                break;
            case 0x63C0:
            case 0x63C1:
            case 0x63C2:
            {
                int triesLeft = pinpad.resultSW & 0x3f;
                isCanceled = triesLeft == 0;
                [EstEIDTokenDriver showNotification:[NSString localizedStringWithFormat:NSLocalizedString(@"VERIFY_TRY_LEFT", nil), triesLeft]];
                self.smartCard.sensitive = NO;
                break;
            }
            case 0x6400: // Timeout
            case 0x6401: // Cancel
                isCanceled = YES;
            default:
                [EstEIDTokenDriver showNotification:nil];
                self.smartCard.sensitive = NO;
                break;
        }
        dispatch_semaphore_signal(sem);
    }];
    dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
    NSLog(@"EstEIDTokenSession beginAuthForOperation PINPad completed: %d", isCanceled);
    if (isCanceled) {
        [self closeSession];
        if (error != nil) {
            *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeCanceledByUser userInfo:nil];
        }
        return nil;
    }
    return [[TKTokenAuthOperation alloc] init];
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
                [algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureRaw] ||
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
        [self closeSession];
        return nil;
    }

    UInt16 sw;
    [self.smartCard sendIns:0x22 p1:0xF3 p2:0x01 data:nil le:@0 sw:&sw error:error];
    if (sw != 0x9000) {
        NSLog(@"EstEIDTokenSession signData failed to set sec env");
        if (error != nil) {
            *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeCorruptedData userInfo:nil];
        }
        [self closeSession];
        return nil;
    }

    [self.smartCard sendIns:0x22 p1:0x41 p2:0xB8 data:NSDATA(2, 0x83, 0x00) le:nil sw:&sw error:error]; //Key reference, 8303801100
    if (sw != 0x9000) {
        NSLog(@"EstEIDTokenSession signData failed to select default key");
        if (error != nil) {
            *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeCorruptedData userInfo:nil];
        }
        [self closeSession];
        return nil;
    }

    NSData *sign = dataToSign;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureRaw]) {
        NSLog(@"EstEIDToken Remove PKCS1 1.5 padding");
        //  00 01 FF FF 00 ....
        const char *string = dataToSign.bytes;
        char *e = strchr(&string[3], '\0'); // Start at pos 3
        NSUInteger pos = (NSUInteger)(e - string) + 1;
        sign = [dataToSign subdataWithRange:NSMakeRange(pos, dataToSign.length - pos)];
    }

    NSData *response = [self.smartCard sendIns:0x88 p1:0x00 p2:0x00 data:sign le:@0 sw:&sw error:error];
    // Deauth and release session
    [self closeSession];
    switch (sw)
    {
        case 0x6982:
            NSLog(@"EstEIDTokenSession signData unauthicated");
            if (error != nil) {
                *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeAuthenticationNeeded userInfo:nil];
            }
            return nil;
        case 0x9000:
            if (response != nil)
                break;
        default:
            NSLog(@"EstEIDTokenSession signData failed to sign sw: %04x", sw);
            return nil;
    }

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
            { SEC_ASN1_SEQUENCE, 0, nil, sizeof(ECDSA) },
            { SEC_ASN1_INTEGER, offsetof(ECDSA, r) },
            { SEC_ASN1_INTEGER, offsetof(ECDSA, s) },
            { 0 }
        };

        uint8 *bytes = (uint8*)response.bytes;
        ECDSA ecdsa = {
            { response.length / 2, bytes },
            { response.length / 2, bytes + (response.length / 2) },
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
