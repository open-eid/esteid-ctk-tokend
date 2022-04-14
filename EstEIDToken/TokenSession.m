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

@interface TokenSession (EstEIDAuthOperation)
- (void)closeSession;
- (NSData*)pinTemplate:(NSString*)pin;
- (void)pinPadTemplate:(AuthOperation*)auth;
@end

@implementation AuthOperation {
    TokenSession *session;
}

- (BOOL)isAllDigits:(NSString*)data {
    NSCharacterSet* nonNumbers = [[NSCharacterSet decimalDigitCharacterSet] invertedSet];
    NSRange r = [data rangeOfCharacterFromSet: nonNumbers];
    return r.location == NSNotFound && data.length > 0;
}

- (nullable instancetype)initWithSmartCard:(TKSmartCard *)smartCard tokenSession:(TokenSession *)eidsession {
    if (self = [super init]) {
        self.smartCard = smartCard;
        [eidsession pinPadTemplate:self];
        session = eidsession;
    }
    return self;
}

- (BOOL)finishWithError:(NSError **)error {
    NSLog(@"AuthOperation finishWithError %@", *error);
    if (self.PIN.length < self.PINFormat.minPINLength || self.PIN.length > self.PINFormat.maxPINLength ||
        ![self isAllDigits:self.PIN]) {
        NSLog(@"AuthOperation finishWithError invalid PIN lenght: %lu min: %lu max: %lu", self.PIN.length, self.PINFormat.minPINLength, self.PINFormat.maxPINLength);
        [EstEIDTokenDriver showNotification:[NSString localizedStringWithFormat:NSLocalizedString(@"INVALID_PIN", nil)]];
        if (error != nil) {
            *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeAuthenticationFailed userInfo:
                      @{NSLocalizedDescriptionKey:[NSString localizedStringWithFormat:NSLocalizedString(@"INVALID_PIN", nil)]}];
        }
        return NO;
    }
    UInt16 sw = 0;
    [self.smartCard sendIns:0x20 p1:0x00 p2:0x01 data:[session pinTemplate:self.PIN] le:nil sw:&sw error:error];
    NSLog(@"AuthOperation finishWithError %@", *error);
    if ((sw & 0xff00) == 0x6300 || sw == 0x6983) {
        int triesLeft = sw == 0x6983 ? 0 : sw & 0x3f;
        NSLog(@"EstEIDAuthOperation finishWithError Failed to verify PIN sw:0x%04x retries: %d", sw, triesLeft);
        if (@available(macOS 12, *)) {
            if (triesLeft == 0) {
                [EstEIDTokenDriver showNotification:[NSString localizedStringWithFormat:NSLocalizedString(@"VERIFY_TRY_LEFT", nil), triesLeft]];
            }
        } else {
            [EstEIDTokenDriver showNotification:[NSString localizedStringWithFormat:NSLocalizedString(@"VERIFY_TRY_LEFT", nil), triesLeft]];
        }
        if (triesLeft == 0) {
            [session closeSession];
        }
        if (error != nil) {
            *error = [NSError errorWithDomain:TKErrorDomain code:triesLeft == 0 ? TKErrorCodeCanceledByUser : TKErrorCodeAuthenticationFailed userInfo:
                      @{NSLocalizedDescriptionKey:[NSString localizedStringWithFormat:NSLocalizedString(@"VERIFY_TRY_LEFT", nil), triesLeft]}];
        }
        return NO;
    } else if (sw != 0x9000) {
        NSLog(@"AuthOperation finishWithError Failed to verify PIN sw: 0x%04x", sw);
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

@implementation TokenSession {
    BOOL isSessionActive;
    BOOL hasFailedAttempt;
}

- (void)closeSession {
    NSLog(@"TokenSession closeSession");
    if (isSessionActive) {
        [self.smartCard endSession];
    }
    isSessionActive = NO;
    self.smartCard.sensitive = NO;
}

- (UInt8)triesLeft:(NSError **)error {
    NSLog(@"TokenSession triesLeft not mplemented");
    return 0;
}

- (NSData*)pinTemplate:(NSString*)pin {
    return [pin dataUsingEncoding:NSUTF8StringEncoding];
}

- (void)pinPadTemplate:(AuthOperation*)auth {
    NSLog(@"TokenSession pinPadTemplate");
    auth.APDUTemplate = NSDATA(5, self.smartCard.cla, 0x20, 0x00, 0x01, 0x00);
    auth.PINByteOffset = 5;
    auth.PINFormat.maxPINLength = 12;
    auth.PINFormat.PINBlockByteLength = 0;
}

- (BOOL)initSignEnv:(NSError **)error {
    NSLog(@"TokenSession initSignEnv not mplemented");
    return NO;
}

- (TKTokenAuthOperation *)tokenSession:(TKTokenSession *)session beginAuthForOperation:(TKTokenOperation)operation constraint:(TKTokenOperationConstraint)constraint error:(NSError **)error {
    NSLog(@"TokenSession beginAuthForOperation %@ constraint %@ isSessionActive %d", @(operation), constraint, isSessionActive);
    if (![constraint isEqual:EstEIDConstraintPIN]) {
        NSLog(@"TokenSession beginAuthForOperation attempt to evaluate unsupported constraint %@", constraint);
        if (error != nil) {
            *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeBadParameter userInfo:@{NSLocalizedDescriptionKey: NSLocalizedString(@"WRONG_CONSTR", nil)}];
        }
        return nil;
    }

    // Begin session to avoid deauth before sign operation
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    if (!isSessionActive) {
        [self.smartCard beginSessionWithReply:^(BOOL success, NSError *error) {
            NSLog(@"TokenSession beginAuthForOperation beginSessionWithReply %@ %@", @(success), error);
            dispatch_semaphore_signal(sem);
        }];
        dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
        isSessionActive = YES;
    }

    UInt8 triesLeft = [self triesLeft:error];
    if (*error != nil) {
        return nil;
    }
    if (triesLeft == 0) {
        NSLog(@"TokenSession beginAuthForOperation locked %d", triesLeft);
        [self closeSession];
        [EstEIDTokenDriver showNotification:[NSString localizedStringWithFormat:NSLocalizedString(@"VERIFY_TRY_LEFT", nil), triesLeft]];
        if (error != nil) {
            *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeCanceledByUser
                                     userInfo:@{NSLocalizedDescriptionKey:[NSString localizedStringWithFormat:NSLocalizedString(@"VERIFY_TRY_LEFT", nil), 0]}];
        }
        return nil;
    }

    TKTokenSmartCardPINAuthOperation *tokenAuth = [[AuthOperation alloc] initWithSmartCard:self.smartCard tokenSession:self];
    if ([self.smartCard.slot.name containsString:@"HID Global OMNIKEY 3x21 Smart Card Reader"] ||
        [self.smartCard.slot.name containsString:@"HID Global OMNIKEY 6121 Smart Card Reader"])
    {
        NSLog(@"TokenSession beginAuthForOperation '%@' is not PinPad reader", self.smartCard.slot.name);
        return tokenAuth;
    }

    // workaround: macOS does not support PINPad templates
    TKSmartCardUserInteractionForSecurePINVerification *pinpad = [self.smartCard userInteractionForSecurePINVerificationWithPINFormat:tokenAuth.PINFormat APDU:tokenAuth.APDUTemplate PINByteOffset:tokenAuth.PINByteOffset];
    if (pinpad == nil) {
        return tokenAuth;
    }

    NSLog(@"TokenSession beginAuthForOperation PINPad");
    pinpad.PINMessageIndices = @[@0];
    NSString *msg = NSLocalizedString(@"ENTER_PINPAD", nil);
    if (self->hasFailedAttempt) {
        msg = [NSString stringWithFormat:@"%@\n%@", msg, [NSString localizedStringWithFormat:NSLocalizedString(@"VERIFY_TRY_LEFT", nil), triesLeft]];
    }
    [EstEIDTokenDriver showNotification:msg];
    __block BOOL isCanceled = NO;
    [pinpad runWithReply:^(BOOL success, NSError *error) {
        NSLog(@"TokenSession beginAuthForOperation PINPad completed %@ %@ %04X", @(success), error, pinpad.resultSW);
        switch (pinpad.resultSW)
        {
            case 0x9000:
                [EstEIDTokenDriver showNotification:nil];
                self.smartCard.sensitive = YES;
                break;
            case 0x63C0:
            case 0x63C1:
            case 0x63C2:
            case 0x6983:
            {
                int triesLeft = pinpad.resultSW == 0x6983 ? 0 : pinpad.resultSW & 0x3f;
                isCanceled = triesLeft == 0;
                self->hasFailedAttempt = triesLeft > 0;
                if (triesLeft == 0) {
                    [EstEIDTokenDriver showNotification:[NSString localizedStringWithFormat:NSLocalizedString(@"VERIFY_TRY_LEFT", nil), triesLeft]];
                }
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
    NSLog(@"TokenSession beginAuthForOperation PINPad completed: %d", isCanceled);
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
    NSLog(@"TokenSession supportsOperation %@ keyID %@", @(operation), keyObjectID);
    TKTokenKeychainKey *keyItem = [self.token.keychainContents keyForObjectID:keyObjectID error:nil];
    if (keyItem == nil) {
        NSLog(@"TokenSession supportsOperation key not found");
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
    NSLog(@"TokenSession supportsOperation key supports: %@", @(supports));
    return supports;
}

- (NSData *)tokenSession:(TKTokenSession *)session signData:(NSData *)dataToSign usingKey:(TKTokenObjectID)keyObjectID algorithm:(TKTokenKeyAlgorithm *)algorithm error:(NSError **)error {
    NSLog(@"TokenSession signData %@ %@", keyObjectID, dataToSign);

    TKTokenKeychainKey *keyItem = [self.token.keychainContents keyForObjectID:keyObjectID error:error];
    if (keyItem == nil) {
        NSLog(@"TokenSession signData key not found");
        if (error != nil) {
            *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeTokenNotFound userInfo:nil];
        }
        [self closeSession];
        return nil;
    }

    if(![self initSignEnv:error]) {
        return nil;
    }

    NSData *sign = dataToSign;
    if ([algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureRaw]) {
        NSLog(@"TokenSession Remove PKCS1 1.5 padding");
        //  00 01 FF FF 00 ....
        const char *string = dataToSign.bytes;
        char *e = strchr(&string[3], '\0'); // Start at pos 3
        NSUInteger pos = (NSUInteger)(e - string) + 1;
        sign = [dataToSign subdataWithRange:NSMakeRange(pos, dataToSign.length - pos)];
    }

    UInt16 sw = 0;
    NSData *response = [self.smartCard sendIns:0x88 p1:0x00 p2:0x00 data:sign le:@0 sw:&sw error:error];
    // Deauth and release session
    [self closeSession];
    switch (sw)
    {
        case 0x6982:
            NSLog(@"TokenSession signData unauthenticated");
            if (error != nil) {
                *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeAuthenticationNeeded userInfo:nil];
            }
            return nil;
        case 0x9000:
            if (response != nil)
                break;
        default:
            NSLog(@"TokenSession signData failed to sign sw: %04x", sw);
            return nil;
    }

    if ([algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureDigestX962] ||
        [algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureDigestX962SHA1] ||
        [algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureDigestX962SHA224] ||
        [algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureDigestX962SHA256] ||
        [algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureDigestX962SHA384] ||
        [algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureDigestX962SHA512]) {
        NSLog(@"TokenSession encoding to ASN1 sequence %@", response);

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
        NSLog(@"TokenSession SecAsn1EncodeItem %i %@", ortn, response);
    }
    return response;
}

@end

@implementation EstEIDTokenSession

- (BOOL)initSignEnv:(NSError **)error {
    NSLog(@"EstEIDTokenSession initSignEnv");
    UInt16 sw;
    [self.smartCard sendIns:0x22 p1:0xF3 p2:0x01 data:nil le:@0 sw:&sw error:error];
    if (sw != 0x9000) {
        NSLog(@"EstEIDTokenSession signData failed to set sec env");
        if (error != nil) {
            *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeCorruptedData userInfo:nil];
        }
        [self closeSession];
        return NO;
    }

    [self.smartCard sendIns:0x22 p1:0x41 p2:0xB8 data:NSDATA(2, 0x83, 0x00) le:nil sw:&sw error:error]; //Key reference, 8303801100
    if (sw != 0x9000) {
        NSLog(@"EstEIDTokenSession signData failed to select default key");
        if (error != nil) {
            *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeCorruptedData userInfo:nil];
        }
        [self closeSession];
        return NO;
    }
    return YES;
}

- (UInt8)triesLeft:(NSError **)error {
    NSLog(@"EstEIDTokenSession triesLeft");
    UInt16 sw;
    NSData *pinStatus;
    if ([self.smartCard sendIns:0xA4 p1:0x00 p2:0x0C data:nil le:@0 sw:&sw error:error] == nil ||
        [self.smartCard sendIns:0xA4 p1:0x02 p2:0x0C data:NSDATA(2, 0x00, 0x16) le:@0 sw:&sw error:error] == nil ||
        (pinStatus = [self.smartCard sendIns:0xB2 p1:0x01 p2:0x04 data:nil le:@0 sw:&sw error:error]) == nil) {
        NSLog(@"EstEIDTokenSession triesLeft %d %@", sw, pinStatus);
        [self closeSession];
        if (error != nil) {
            *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeAuthenticationFailed userInfo:@{NSLocalizedDescriptionKey:NSLocalizedString(@"WRONG_CONSTR", nil)}];
        }
        return 0;
    }
    UInt8 triesLeft = 0;
    [pinStatus getBytes:&triesLeft range:NSMakeRange(5, sizeof(triesLeft))];
    return triesLeft;
}

@end

@implementation IDEMIATokenSession

- (BOOL)initSignEnv:(NSError **)error {
    NSLog(@"IDEMIATokenSession initSignEnv");
    UInt16 sw;
    [self.smartCard sendIns:0xA4 p1:0x04 p2:0x0C data:NSDATA(13, 0xE8, 0x28, 0xBD, 0x08, 0x0F, 0xF2, 0x50, 0x4F, 0x54, 0x20, 0x41, 0x57, 0x50) le:nil sw:&sw error:error];
    if (sw != 0x9000) {
        NSLog(@"IDEMIATokenSession signData failed to select OT AID");
        if (error != nil) {
            *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeCorruptedData userInfo:nil];
        }
        [self closeSession];
        return NO;
    }

    [self.smartCard sendIns:0x22 p1:0x41 p2:0xA4 data:NSDATA(9, 0x80, 0x04, 0xFF, 0x20, 0x08, 0x00, 0x84, 0x01, 0x81) le:@0 sw:&sw error:error];
    if (sw != 0x9000) {
        NSLog(@"IDEMIATokenSession signData failed to set sec env");
        if (error != nil) {
            *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeCorruptedData userInfo:nil];
        }
        [self closeSession];
        return NO;
    }
    return YES;
}

- (NSData*)pinTemplate:(NSString*)pin {
    NSLog(@"IDEMIATokenSession pinTemplate");
    NSMutableData *data = [NSMutableData dataWithData:[super pinTemplate:pin]];
    NSUInteger i = data.length;
    data.length = 12;
    UInt8 *byteData = (UInt8*) data.mutableBytes;
    for (; i < data.length; ++i) {
        byteData[i] = 0xFF;
    }
    return data;
}

- (void)pinPadTemplate:(AuthOperation*)auth {
    NSLog(@"IDEMIATokenSession pinPadTemplate");
    auth.APDUTemplate = NSDATA(5 + 12, self.smartCard.cla, 0x20, 0x00, 0x01, 0x0C, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
    auth.PINByteOffset = 5;
    auth.PINFormat.maxPINLength = 12;
    auth.PINFormat.PINBlockByteLength = 12;
}

- (UInt8)triesLeft:(NSError **)error {
    NSLog(@"IDEMIATokenSession triesLeft");
    UInt16 sw;
    NSData *pinStatus;
    TKSmartCardToken *smtoken = (TKSmartCardToken*) self.token;
    if ([self.smartCard sendIns:0xA4 p1:0x04 p2:0x0C data:smtoken.AID le:@0 sw:&sw error:error] == nil ||
        (pinStatus = [self.smartCard sendIns:0xCB p1:0x3F p2:0xFF data:NSDATA(10, 0x4D, 0x08, 0x70, 0x06, 0xBF, 0x81, 0x01, 0x02, 0xA0, 0x80) le:@0 sw:&sw error:error]) == nil) {
        NSLog(@"IDEMIATokenSession triesLeft %d %@", sw, pinStatus);
        [self closeSession];
        if (error != nil) {
            *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeAuthenticationFailed userInfo:@{NSLocalizedDescriptionKey:NSLocalizedString(@"WRONG_CONSTR", nil)}];
        }
        return 0;
    }
    UInt8 triesLeft = 0;
    [pinStatus getBytes:&triesLeft range:NSMakeRange(13, sizeof(triesLeft))];
    return triesLeft;
}

@end
