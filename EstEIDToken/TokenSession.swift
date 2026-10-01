// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

import CryptoKit
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

    // Best effort: the framework-owned PIN String and APDU buffers cannot be wiped
    private static func wipe(_ buffer: UnsafeMutableRawBufferPointer) {
        guard let baseAddress = buffer.baseAddress else { return }
        _ = memset_s(baseAddress, buffer.count, 0, buffer.count)
    }

    override func finish() throws {
        NSLog("AuthOperation finish")

        let pin = self.pin
        self.pin = nil
        guard let pin, let smartCard else {
            NSLog("AuthOperation finish invalid condition")
            session.closeSession()
            throw TKError(.canceledByUser)
        }

        var pinBytes = Array(pin.utf8)
        defer { pinBytes.withUnsafeMutableBytes(Self.wipe) }
        guard pinBytes.count >= pinFormat.minPINLength,
              pinBytes.count <= min(pinFormat.maxPINLength, pinFormat.pinBlockByteLength),
              pinBytes.allSatisfy({ (0x30...0x39).contains($0) }) else {
            NSLog("AuthOperation finish invalid PIN length: \(pinBytes.count) min: \(pinFormat.minPINLength) max: \(pinFormat.maxPINLength)")
            let msg = String(localized: "Invalid PIN entered")
            EstEIDTokenDriver.showNotification(msg)
            throw NSError(domain: TKErrorDomain, code: TKError.Code.authenticationFailed.rawValue, userInfo: [NSLocalizedDescriptionKey: msg])
        }

        var pinData = Data(repeating: session.fillChar, count: pinFormat.pinBlockByteLength)
        defer { pinData.withUnsafeMutableBytes(Self.wipe) }
        pinData.replaceSubrange(0..<pinBytes.count, with: pinBytes)
        // Hold the card only from VERIFY to the end of the auth window: a cancelled dialog never calls finish()
        guard session.beginSession(smartCard) else {
            throw TKError(.communicationError)
        }
        switch try? smartCard.send(ins: 0x20, p1: 0x00, p2: session.pinId, data: pinData) {
        case (0x9000, _)?:
            NSLog("AuthOperation finish success")
            session.authenticated(smartCard)
            return
        case (0x6983, _)?, (0x63C0, _)?:
            NSLog("AuthOperation finish Failed to verify PIN blocked")
            EstEIDTokenDriver.showNotification(String(format: String(localized: "VERIFY_TRY_LEFT"), 0))
        case (let sw, _)? where (sw & 0xfff0) == 0x63C0:
            let triesLeft = Int(sw & 0x000f)
            NSLog("AuthOperation finish Failed to verify PIN sw: 0x\(String(format: "%04x", sw)) retries: \(triesLeft)")
            let msg = String(format: String(localized: "VERIFY_TRY_LEFT"), triesLeft)
            // Release the card while the dialog asks again; the retry calls finish() again, a cancel does not
            session.closeSession()
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

    // PIN stays verified for this session while signatures keep arriving (e.g. Safari signs twice per TLS login),
    // then it is devalidated before the card is released, so the verified state never reaches another card user
    private static let authWindow: TimeInterval = 2
    private static let maxAuthWindow: TimeInterval = 30

    private enum CardState {
        case idle
        case held(TKSmartCard)
        case verified(TKSmartCard, deadline: Date)
    }

    private var hasFailedAttempt = false
    private var cardState = CardState.idle
    private var releaseGeneration = 0
    private let lock = NSLock()

    required override init(token: TKToken) {
        NSLog("TokenSession init")
        super.init(token: token)
    }

    deinit {
        NSLog("TokenSession deinit")
        // Fail-safe, the auth window timer normally keeps the session alive until release()
        switch cardState {
        case .idle:
            break
        case let .held(card), let .verified(card, _):
            card.endSession()
        }
    }

    func authenticated(_ card: TKSmartCard) {
        lock.withLock {
            NSLog("TokenSession authenticated")
            cardState = .verified(card, deadline: Date(timeIntervalSinceNow: Self.maxAuthWindow))
            scheduleRelease()
        }
    }

    func beginSession(_ card: TKSmartCard) -> Bool {
        if lock.withLock({
            if case .idle = cardState { return false }
            return true
        }) {
            return true
        }
        let semaphore = DispatchSemaphore(value: 0)
        var began = false
        card.beginSession { result, error in
            NSLog("TokenSession beginSession \(result) \(String(describing: error))")
            began = result
            semaphore.signal()
        }
        semaphore.wait()
        if began {
            lock.withLock { cardState = .held(card) }
        }
        return began
    }

    func closeSession() {
        lock.withLock { release() }
    }

    // Caller holds lock
    private func scheduleRelease() {
        guard case let .verified(_, deadline) = cardState else { return }
        releaseGeneration += 1
        let generation = releaseGeneration
        let delay = min(Self.authWindow, deadline.timeIntervalSinceNow)
        DispatchQueue.global().asyncAfter(deadline: .now() + max(delay, 0)) { [self] in
            lock.withLock {
                guard generation == releaseGeneration else { return }
                NSLog("TokenSession auth window expired")
                release()
            }
        }
    }

    // Caller holds lock
    private func release() {
        NSLog("TokenSession release")
        releaseGeneration += 1
        let card: TKSmartCard
        switch cardState {
        case .idle:
            return
        case let .held(heldCard), let .verified(heldCard, _):
            card = heldCard
        }
        // Devalidate PIN after any authentication attempt (VERIFY response may have been lost).
        // isSensitive is a last resort only: once set during a token request it keeps resetting the card on hand-off
        // even after being cleared, which breaks other applications' card sessions (IB-8374)
        let devalidated = (try? card.send(ins: 0x20, p1: 0xFF, p2: pinId))?.sw == 0x9000
        if !devalidated, case .verified = cardState {
            NSLog("TokenSession release failed to devalidate PIN, marking card sensitive")
            card.isSensitive = true
        }
        card.endSession()
        cardState = .idle
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

        let tokenAuth = AuthOperation(smartCard: smartCard, tokenSession: self)
        // OMNIKEY readers wrongly report PIN pad support (hardware issue, reappeared with Apple's own CCID driver)
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
        return try authenticateWithPINPad(pinpad, triesLeft: triesLeft)
    }

    private func authenticateWithPINPad(_ pinpad: TKSmartCardUserInteractionForSecurePINVerification, triesLeft: UInt8) throws -> TKTokenAuthOperation {
        // Keypad entry holds the card and cannot be cancelled from software, only these timeouts end it.
        // ifd-ccid ignores interactionTimeout (reader default applies)
        pinpad.initialTimeout = 30
        pinpad.interactionTimeout = 15
        pinpad.pinMessageIndices = [0]
        let card = smartCard
        guard beginSession(card) else {
            throw TKError(.communicationError)
        }
        EstEIDTokenDriver.showNotification(
            String(localized: "Please enter PIN code on PinPAD"),
            subtitle: hasFailedAttempt ? String(format: String(localized: "VERIFY_TRY_LEFT"), triesLeft) : .init())
        // The reply only records the outcome, so a late reply after a timeout cannot change the session state
        var reply: (success: Bool, error: Error?)?
        let semaphore = DispatchSemaphore(value: 0)
        pinpad.run { success, error in
            self.lock.withLock { reply = (success, error) }
            semaphore.signal()
        }
        // Last resort if the reply never arrives, longer than ifd-ccid's own minimum 90 s read timeout
        let completed = semaphore.wait(timeout: .now() + 100) == .success
        EstEIDTokenDriver.showNotification(nil)
        guard completed, let reply = lock.withLock({ reply }) else {
            NSLog("TokenSession beginAuthFor PINPad did not complete in 100s")
            closeSession()
            throw TKError(.canceledByUser)
        }
        NSLog("TokenSession beginAuthFor PINPad completed \(reply.success) \(String(describing: reply.error)) \(String(format: "%04X", pinpad.resultSW))")
        guard reply.success else {
            // Entry did not complete: Cancel, timeout, card or reader removal. Apple's CCID driver reports these
            // without a status word and an uninformative error (nil on macOS 26, CryptoTokenKit -3 on macOS 27)
            closeSession()
            throw TKError(.canceledByUser)
        }

        switch pinpad.resultSW {
        case 0x9000:
            hasFailedAttempt = false
            authenticated(card)
            return TKTokenAuthOperation()
        case 0x6983, 0x63C0:
            hasFailedAttempt = false
            EstEIDTokenDriver.showNotification(String(format: String(localized: "VERIFY_TRY_LEFT"), 0))
            closeSession()
            throw TKError(.canceledByUser)
        case let sw where (sw & 0xfff0) == 0x63C0:
            let triesLeft = Int(sw & 0x000f)
            hasFailedAttempt = true
            EstEIDTokenDriver.showNotification(String(format: String(localized: "VERIFY_TRY_LEFT"), triesLeft))
            // Wrong PIN: release the card until sign re-triggers beginAuthFor
            closeSession()
            return TKTokenAuthOperation()
        case 0x6400, 0x6401: // Timeout, Cancel
            closeSession()
            throw TKError(.canceledByUser)
        default:
            closeSession()
            throw reply.error ?? TKError(.canceledByUser)
        }
    }

    #if hasAttribute(diagnose)
    @diagnose(DeprecatedDeclaration, as: ignored)
    #endif
    private func isRFC4754(_ algorithm: TKTokenKeyAlgorithm) -> Bool {
        algorithm.isAlgorithm(.ecdsaSignatureRFC4754) ||
        algorithm.isAlgorithm(.ecdsaSignatureDigestRFC4754) ||
        algorithm.isAlgorithm(.ecdsaSignatureDigestRFC4754SHA256) ||
        algorithm.isAlgorithm(.ecdsaSignatureDigestRFC4754SHA384) ||
        algorithm.isAlgorithm(.ecdsaSignatureDigestRFC4754SHA512)
    }

    func tokenSession(_ session: TKTokenSession, supports operation: TKTokenOperation, keyObjectID: TKToken.ObjectID, algorithm: TKTokenKeyAlgorithm) -> Bool {
        NSLog("TokenSession supports \(operation) keyID \(keyObjectID)")
        guard let keyItem = try? token.keychainContents?.key(forObjectID: keyObjectID) else {
            NSLog("TokenSession supports key not found")
            return false
        }
        return operation == .signData && keyItem.canSign && (
            isRFC4754(algorithm) ||
            algorithm.isAlgorithm(.ecdsaSignatureDigestX962) ||
            algorithm.isAlgorithm(.ecdsaSignatureDigestX962SHA256) ||
            algorithm.isAlgorithm(.ecdsaSignatureDigestX962SHA384) ||
            algorithm.isAlgorithm(.ecdsaSignatureDigestX962SHA512)
        )
    }

    func tokenSession(_ session: TKTokenSession, sign dataToSign: Data, keyObjectID: TKToken.ObjectID, algorithm: TKTokenKeyAlgorithm) throws -> Data {
        NSLog("TokenSession sign \(keyObjectID) \(dataToSign)")
        guard let keyItem = try? token.keychainContents?.key(forObjectID: keyObjectID) else {
            throw TKError(.tokenNotFound)
        }
        guard let keyId = keyObjectID as? UInt8 else {
            throw TKError(.badParameter)
        }
        let response = try lock.withLock {
            // PIN verified by another session must not be reused
            guard case let .verified(_, deadline) = cardState else {
                NSLog("TokenSession sign not authenticated")
                throw TKError(.authenticationNeeded)
            }
            do {
                let response = try signData(keyId: keyId, sign: dataToSign)
                if response.0 == 0x9000 && deadline.timeIntervalSinceNow > 0 {
                    scheduleRelease()
                } else {
                    release()
                }
                return response
            } catch {
                release()
                throw error
            }
        }
        switch response {
        case (0x9000, let data):
            NSLog("TokenSession sign success: \(data as NSData)")
            let der: Data
            do {
                switch keyItem.keySizeInBits {
                case 256: der = try P256.Signing.ECDSASignature(rawRepresentation: data).derRepresentation
                case 384: der = try P384.Signing.ECDSASignature(rawRepresentation: data).derRepresentation
                case 521: der = try P521.Signing.ECDSASignature(rawRepresentation: data).derRepresentation
                default: throw TKError(.corruptedData)
                }
            } catch {
                NSLog("TokenSession sign invalid signature length \(data.count) for key size \(keyItem.keySizeInBits)")
                throw TKError(.corruptedData)
            }
            if isRFC4754(algorithm) {
                NSLog("TokenSession sign raw")
                return data
            }
            NSLog("TokenSession sign encoded: \(der as NSData)")
            return der
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
        return try smartCard.send(ins: 0x88, p1: 0x00, p2: 0x00, data: dataToSign.prefix(48), le: 0)
    }

    override func triesLeft() throws -> UInt8 {
        NSLog("IdemiaTokenSession triesLeft")
        _ = try smartCard.selectFile(p1: 0x04, file: (token as! TKSmartCardToken).aid)
        let data = try smartCard.send(ins: 0xCB, p1: 0x3F, p2: 0xFF,
                                      tlv: TLV(tag: 0x4D, tlv: TLV(tag: 0x70, tlv: TLV(tag: 0xBF8101, bytes: [0xA0, 0x80]))), le: 0)
        if let pinInfo = TLV(from: data), pinInfo.tag == 0x70 ,
            let capsule = TLV(from: pinInfo.value), capsule.tag == 0xBF8101,
            let info = TLV(from: capsule.value), info.tag == 0xA0 {
            for tlv in TLV.sequenceOfRecords(from: info.value) ?? [] where tlv.tag == 0x9B && !tlv.value.isEmpty {
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
        let algo: UInt8
        switch dataToSign.count {
        case 32: algo = 0x44 // SHA-256
        case 48: algo = 0x54 // SHA-384
        case 64: algo = 0x64 // SHA-512
        default:
            NSLog("ThalesTokenSession signData unsupported digest length \(dataToSign.count)")
            throw TKError(.badParameter)
        }
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
            for tlv in TLV.sequenceOfRecords(from: pinInfo.value) ?? [] where tlv.tag == 0xDF21 && !tlv.value.isEmpty {
                return tlv.value[0]
            }
        }
        NSLog("ThalesTokenSession triesLeft failed to fetch")
        throw TKError(.authenticationFailed)
    }
}
