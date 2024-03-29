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

#import <CryptoTokenKit/CryptoTokenKit.h>
#import <CryptoTokenKit/TKSmartCardToken.h>

NS_ASSUME_NONNULL_BEGIN

#pragma mark EstEID implementation of TKToken classes

#define NSDATA(LEN, ...) [NSData dataWithBytes:(const UInt8[]){__VA_ARGS__} length:LEN]

static const TKTokenOperationConstraint EstEIDConstraintPIN = @"PIN";

@interface EstEIDTokenDriver : TKSmartCardTokenDriver<TKSmartCardTokenDriverDelegate>
+ (void)showNotification:(NSString*__nullable)msg;
@end

@interface Token : TKSmartCardToken<TKTokenDelegate>
@end

@interface IDEMIAToken : Token
@end

@interface TokenSession : TKSmartCardTokenSession<TKTokenSessionDelegate>
@end

@interface IDEMIATokenSession : TokenSession
@end

@interface AuthOperation : TKTokenSmartCardPINAuthOperation
@end

NS_ASSUME_NONNULL_END
