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

import CryptoTokenKit

class AuthOperation: TKTokenSmartCardPINAuthOperation {
    private let session: TokenSession

    init(smartCard: TKSmartCard, tokenSession: TokenSession) {
        NSLog("AuthOperation init")
        session = tokenSession
        super.init()
        self.smartCard = smartCard
        pinByteOffset = 5
        pinFormat.minPINLength = 4
        pinFormat.maxPINLength = 12
        pinFormat.pinBlockByteLength = 12
        apduTemplate = Data([smartCard.cla, 0x20, 0x00, session.pinId, UInt8(pinFormat.pinBlockByteLength)]) + Data(repeating: session.fillChar, count: 12)
    }

    required init?(coder: NSCoder) {
        fatalError("AuthOperation init(coder:) has not been implemented")
    }

    deinit {
        NSLog("AuthOperation deinit")
    }

    private func isAllDigits(_ data: String) -> Bool {
        let nonNumbers = CharacterSet.decimalDigits.inverted
        return data.rangeOfCharacter(from: nonNumbers) == nil && !data.isEmpty
    }

    override func finish() throws {
        NSLog("AuthOperation finish")

        guard pin != nil && smartCard != nil else {
            NSLog("AuthOperation finish invalid condition")
            throw TKError(.canceledByUser)
        }

        if pin!.count < pinFormat.minPINLength ||
           pin!.count > pinFormat.maxPINLength ||
           !isAllDigits(pin!) {
            NSLog("AuthOperation finish invalid PIN length: \(pin!.count) min: \(pinFormat.minPINLength) max: \(pinFormat.maxPINLength)")
            let msg = String(localized: "Invalid PIN entered")
            EstEIDTokenDriver.showNotification(msg)
            throw NSError(domain: TKErrorDomain, code: TKError.Code.authenticationFailed.rawValue, userInfo: [NSLocalizedDescriptionKey: msg])
        }

        var pinData = Data(repeating: session.fillChar, count: pinFormat.pinBlockByteLength)
        pinData.replaceSubrange(0..<pin!.count, with: pin!.utf8)
        switch try? smartCard!.send(ins: 0x20, p1: 0x00, p2: session.pinId, data: pinData) {
        case (0x9000, _)?:
            NSLog("AuthOperation finish success")
            return
        case (0x6983, _)?, (0x63C0, _)?:
            NSLog("AuthOperation finish Failed to verify PIN blocked")
            EstEIDTokenDriver.showNotification(String(format: String(localized: "VERIFY_TRY_LEFT"), 0))
        case (let sw, _)? where (sw & 0xfff0) == 0x63C0:
            let triesLeft = Int(sw & 0x000f)
            NSLog("AuthOperation finish Failed to verify PIN sw: 0x\(String(format: "%04x", sw)) retries: \(triesLeft)")
            let msg = String(format: String(localized: "VERIFY_TRY_LEFT"), triesLeft)
            // Do not close session, It will retry
            throw NSError(domain: TKErrorDomain, code: TKError.Code.authenticationFailed.rawValue, userInfo: [NSLocalizedDescriptionKey: msg])
        case (let sw, _)?:
            NSLog("AuthOperation finish Failed to verify PIN sw: 0x\(String(format: "%04x", sw))")
        default:
            NSLog("AuthOperation finish failed")
        }
        session.closeSession()
        throw TKError(.canceledByUser)
    }
}

class TokenSession: TKSmartCardTokenSession, TKTokenSessionDelegate {
    var pinId: UInt8 = 0x01
    var fillChar: UInt8 = 0xFF

    private var hasFailedAttempt = false
    private var isSessionActive = false

    required override init(token: TKToken) {
        NSLog("TokenSession init")
        super.init(token: token)
    }

    deinit {
        NSLog("TokenSession deinit")
    }

    func closeSession() {
        NSLog("TokenSession closeSession isSessionActive \(isSessionActive)")
        if isSessionActive {
            smartCard.endSession()
        }
        isSessionActive = false
    }

    func triesLeft() throws -> UInt8 {
        NSLog("TokenSession triesLeft not implemented")
        throw TKError(.notImplemented)
    }

    func signData(keyId: UInt8, sign dataToSign: Data) throws -> (UInt16, Data) {
        NSLog("TokenSession signData not implemented")
        throw TKError(.notImplemented)
    }

    func tokenSession(_ session: TKTokenSession, beginAuthFor operation: TKTokenOperation, constraint: Any) throws -> TKTokenAuthOperation {
        NSLog("TokenSession beginAuthFor \(operation) constraint \(constraint)")

        guard EstEIDTokenDriver.ConstraintPIN.isEqual(constraint) else {
            throw NSError(domain: TKErrorDomain, code: TKError.Code.badParameter.rawValue, userInfo: [NSLocalizedDescriptionKey: "Unexpected constraint"])
        }

        let triesLeft = try triesLeft()
        if triesLeft == 0 {
            NSLog("TokenSession beginAuthFor locked")
            EstEIDTokenDriver.showNotification(String(format: String(localized: "VERIFY_TRY_LEFT"), triesLeft))
            throw TKError(.canceledByUser)
        }

        let semaphore = DispatchSemaphore(value: 0)
        if !isSessionActive {
            smartCard.beginSession() { result, error in
                NSLog("TokenSession beginAuthFor beginSession \(result) \(String(describing: error))")
                self.isSessionActive = result
                semaphore.signal()
            }
            semaphore.wait()
        }

        let tokenAuth = AuthOperation(smartCard: smartCard, tokenSession: self)
        if smartCard.slot.name.contains("HID Global OMNIKEY") {
            NSLog("TokenSession beginAuthFor '\(smartCard.slot.name)' is not a PinPad reader")
            return tokenAuth
        }

        guard let pinpad = smartCard.userInteractionForSecurePINVerification(
            tokenAuth.pinFormat,
            apdu: tokenAuth.apduTemplate ?? Data(),
            pinByteOffset: tokenAuth.pinByteOffset) else {
            NSLog("TokenSession beginAuthFor '\(smartCard.slot.name)' is regular reader")
            return tokenAuth
        }

        pinpad.pinMessageIndices = [0]
        EstEIDTokenDriver.showNotification(
            String(localized: "Please enter PIN code on PinPAD"),
            subtitle: hasFailedAttempt ? String(format: String(localized: "VERIFY_TRY_LEFT"), triesLeft) : .init())

        var result: Error?
        pinpad.run { isRunning, error in
            NSLog("TokenSession beginAuthFor PINPad completed \(isRunning) \(String(describing: error)) \(String(format: "%04X", pinpad.resultSW))")
            if isRunning {
                switch pinpad.resultSW {
                case 0x9000:
                    EstEIDTokenDriver.showNotification(nil)
                case 0x6983, 0x63C0:
                    self.hasFailedAttempt = false
                    EstEIDTokenDriver.showNotification(String(format: String(localized: "VERIFY_TRY_LEFT"), 0))
                    result = TKError(.canceledByUser)
                case let sw where (sw & 0xfff0) == 0x63C0:
                    let triesLeft = Int(sw & 0x000f)
                    self.hasFailedAttempt = true
                    EstEIDTokenDriver.showNotification(String(format: String(localized: "VERIFY_TRY_LEFT"), triesLeft))
                    // Do not throw error here, sign will then re-trigger beginAuthFor
                case 0x6400, 0x6401: // Timeout, Cancel
                    result = TKError(.canceledByUser)
                default:
                    result = TKError(.canceledByUser)
                }
            } else {
                result = TKError(.canceledByUser)
            }
            semaphore.signal()
        }
        semaphore.wait()
        if let result {
            self.closeSession()
            throw result
        }
        return TKTokenAuthOperation()
    }

    func tokenSession(_ session: TKTokenSession, supports operation: TKTokenOperation, keyObjectID: TKToken.ObjectID, algorithm: TKTokenKeyAlgorithm) -> Bool {
        NSLog("TokenSession supports \(operation) keyID \(keyObjectID)")
        guard let keyItem = try? token.keychainContents?.key(forObjectID: keyObjectID) else {
            NSLog("TokenSession supports key not found")
            return false
        }
        return operation == .signData && keyItem.canSign && (
            algorithm.isAlgorithm(.ecdsaSignatureRFC4754) ||
            algorithm.isAlgorithm(.ecdsaSignatureDigestX962) ||
            algorithm.isAlgorithm(.ecdsaSignatureDigestX962SHA256) ||
            algorithm.isAlgorithm(.ecdsaSignatureDigestX962SHA384) ||
            algorithm.isAlgorithm(.ecdsaSignatureDigestX962SHA512)
        )
    }

    func tokenSession(_ session: TKTokenSession, sign dataToSign: Data, keyObjectID: TKToken.ObjectID, algorithm: TKTokenKeyAlgorithm) throws -> Data {
        NSLog("TokenSession sign \(keyObjectID) \(dataToSign)")
        guard ((try? token.keychainContents?.key(forObjectID: keyObjectID)) != nil) else {
            throw TKError(.tokenNotFound)
        }
        defer { closeSession() }
        switch try signData(keyId: keyObjectID as! UInt8, sign: dataToSign) {
        case (0x9000, var data):
            NSLog("TokenSession sign success: \(data as NSData)")
            if algorithm.isAlgorithm(.ecdsaSignatureRFC4754) {
                NSLog("TokenSession sign raw")
                return data
            }
            let halfLength = data.count / 2
            let r = TLV(tag: 0x02, bigInt: data.prefix(halfLength))
            let s = TLV(tag: 0x02, bigInt: data.suffix(halfLength))
            data = TLV(tag: 0x30, records: [r, s]).data
            NSLog("TokenSession sign encoded: \(data as NSData)")
            return data
        case (0x6982, _):
            NSLog("TokenSession sign needs auth")
            throw TKError(.authenticationNeeded)
        case (let sw, _):
            NSLog("TokenSession sign failed to sign sw: \(String(format: "%04X", sw))")
            throw TKError(.corruptedData)
        }
    }
}

class IdemiaTokenSession : TokenSession {
    required init(token: TKToken) {
        NSLog("IdemiaTokenSession init")
        super.init(token: token)
    }

    override func signData(keyId: UInt8, sign dataToSign: Data) throws -> (UInt16, Data) {
        NSLog("IdemiaTokenSession signData \(String(format: "%02X", keyId))")
        _ = try smartCard.selectFile(p1:0x00, file: 0x3F00) // Make sure we select from root path file, for second sign attempt
        _ = try smartCard.selectFile(p1:0x01, file: 0xADF1)
        _ = try smartCard.send(ins: 0x22, p1: 0x41, p2: 0xA4, records: [
            TLV(tag: 0x80, bytes: [0xFF, 0x20, 0x08, 0x00]),
            TLV(tag: 0x84, bytes: [keyId])
        ])
        return try smartCard.send(ins: 0x88, p1: 0x00, p2: 0x00, data: dataToSign, le: 0)
    }

    override func triesLeft() throws -> UInt8 {
        NSLog("IdemiaTokenSession triesLeft")
        _ = try smartCard.selectFile(p1: 0x04, file: (token as! TKSmartCardToken).aid)
        let data = try smartCard.send(ins: 0xCB, p1: 0x3F, p2: 0xFF,
                                      tlv: TLV(tag: 0x4D, tlv: TLV(tag: 0x70, tlv: TLV(tag: 0xBF8101, bytes: [0xA0, 0x80]))), le: 0)
        if let pinInfo = TLV(from: data), pinInfo.tag == 0x70 ,
            let capsule = TLV(from: pinInfo.value), capsule.tag == 0xBF8101,
            let info = TLV(from: capsule.value), info.tag == 0xA0 {
            for tlv in TLV.sequenceOfRecords(from: info.value) ?? [] where tlv.tag == 0x9B {
                return tlv.value[0]
            }
        }
        NSLog("IdemiaTokenSession triesLeft failed to fetch")
        throw TKError(.authenticationFailed)
    }
}

class ThalesTokenSession : TokenSession {
    required init(token: TKToken) {
        NSLog("ThalesTokenSession init")
        super.init(token: token)
        fillChar = 0x00
        pinId = 0x81
    }

    override func signData(keyId: UInt8, sign dataToSign: Data) throws -> (UInt16, Data) {
        let algo = UInt8(dataToSign.count) + 0x20 + 0x04
        NSLog("ThalesTokenSession signData \(String(format: "%02X", keyId)) \(String(format: "%02X", algo))")
        _ = try smartCard.send(ins: 0x22, p1: 0x41, p2: 0xB6, records: [
            TLV(tag: 0x80, bytes: [algo]),
            TLV(tag: 0x84, bytes: [keyId])
        ])
        let (sw, data) = try smartCard.send(ins: 0x2A, p1: 0x90, p2: 0xA0, data: TLV(tag: 0x90, value: dataToSign).data)
        guard sw == 0x9000 else {
            return (sw, data)
        }
        return try smartCard.send(ins: 0x2A, p1: 0x9E, p2: 0x9A, le: 0)
    }

    override func triesLeft() throws -> UInt8 {
        NSLog("ThalesTokenSession triesLeft")
        let data = try smartCard.send(ins: 0xCB, p1: 0x00, p2: 0xFF,
                                      tlv: TLV(tag: 0xA0, tlv: TLV(tag: 0x83, bytes: [0x81])), le: 0)
        if let pinInfo = TLV(from: data), pinInfo.tag == 0xA0 {
            NSLog("ThalesTokenSession triesLeft \(pinInfo.value as NSData)")
            for tlv in TLV.sequenceOfRecords(from: pinInfo.value) ?? [] where tlv.tag == 0xDF21 {
                return tlv.value[0]
            }
        }
        NSLog("ThalesTokenSession triesLeft failed to fetch")
        throw TKError(.authenticationFailed)
    }
}
