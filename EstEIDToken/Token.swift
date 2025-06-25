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
import UserNotifications
import AppKit

typealias TLV = TKBERTLVRecord

extension TLV {
    convenience init(tag: UInt64, bytes: [UInt8]) {
        self.init(tag: tag, value: Data(bytes))
    }
    convenience init(tag: UInt64, tlv: TLV) {
        self.init(tag: tag, value: tlv.data)
    }
    convenience init(tag: UInt64, bigInt: Data) {
        if let firstByte = bigInt.first,
           firstByte > 0x80 {
            self.init(tag: tag, value: [0x00] + bigInt)
        } else {
            self.init(tag: tag, value: bigInt)
        }
    }
}

extension TKTokenKeychainItem {
    func setName(_ name: String) {
        if label == nil {
            label = name
        } else {
            label = "\(name) \(label ?? "")"
        }
    }
}

extension TKSmartCard {
    func sendCheck(ins: UInt8, p1: UInt8, p2: UInt8, data: Data? = nil, le: Int? = nil) throws -> Data {
        switch try? send(ins: ins, p1: p1, p2: p2, data: data, le: le) {
        case (0x9000, let data)?: return data
        case (let sw, _)?:
            NSLog("EstEIDToken sendCheck failed: \((data ?? Data()) as NSData) sw: \(String(format: "%04X", sw))")
            throw TKError(.objectNotFound)
        default:
            NSLog("EstEIDToken sendCheck failed: \((data ?? Data()) as NSData)")
            throw TKError(.objectNotFound)
        }
    }

    func send(ins: UInt8, p1: UInt8, p2: UInt8, tlv: TLV, le: Int? = nil) throws -> Data {
        try sendCheck(ins: ins, p1: p1, p2: p2, data: tlv.data, le: le)
    }

    func send(ins: UInt8, p1: UInt8, p2: UInt8, records: [TLV], le: Int? = nil) throws -> Data {
        let data = records.reduce(Data()) { partialResult, record in
            partialResult + record.data
        }
        return try sendCheck(ins: ins, p1: p1, p2: p2, data: data, le: le)
    }

    func selectFile(p1: UInt8, p2: UInt8 = 0x0C, file: Data? = nil, le: Int? = nil) throws -> Data {
        try sendCheck(ins: 0xA4, p1: p1, p2: p2, data: file, le: le)
    }

    func selectFile(p1: UInt8, p2: UInt8 = 0x0C, file: UInt16, le: Int? = nil) throws -> Data {
        try selectFile(p1: p1, p2: p2, file: withUnsafeBytes(of: file.bigEndian) { Data($0) }, le: le)
    }

    func readFile(file: UInt16, le: Int = 0) throws -> Data {
        guard let fci = TLV(from: try selectFile(p1: 0x02, p2: 0x04, file: file, le: 0)) else {
            NSLog("EstEIDToken readBinary failed to parse FCI record")
            throw TKError(.corruptedData)
        }

        var size: UInt16 = 0
        for tlv in TLV.sequenceOfRecords(from: fci.value)! where tlv.tag == 0x80 || tlv.tag == 0x81 {
            size = UInt16(tlv.value[0]) << 8 | UInt16(tlv.value[1])
        }

        if size == 0 {
            NSLog("EstEIDToken readBinary failed to missing size in FCI record")
            throw TKError(.corruptedData)
        }

        var data = Data()
        do {
            while data.count < size {
                data.append(try sendCheck(ins: 0xB0, p1: UInt8(data.count >> 8), p2: UInt8(truncatingIfNeeded: data.count), le: min(le, Int(size) - data.count)))
            }
            return data
        } catch {
            NSLog("EstEIDToken readBinary failed to read binary at pos \(data.count)")
            throw error
        }
    }
}


class Token<T : TokenSession> : TKSmartCardToken, TKTokenDelegate {
    func createSession(_ token: TKToken) throws -> TKTokenSession {
        NSLog("Token createSessionWithError \(aid! as NSData)")
        return T(token: self)
    }

    func token(_ token: TKToken, terminateSession session: TKTokenSession) {
        NSLog("Token terminateSession")
        if let sess = session as? TokenSession {
            sess.smartCard.isSensitive = false
        }
    }

    init(smartCard: TKSmartCard, aid AID: Data?, instanceID: String, tokenDriver: TKSmartCardTokenDriver, certificateID: UInt16, keyID: UInt8) throws {
        NSLog("Token initWithSmartCard cert \(String(format: "%04X", certificateID)) key \(String(format: "%02X", keyID))")
        super.init(smartCard: smartCard, aid: AID, instanceID: instanceID, tokenDriver: tokenDriver)

        let certificateData: Data
        do {
            certificateData = try smartCard.readFile(file: certificateID, le: 0xC0)
        } catch {
            NSLog("Token initWithSmartCard failed to read certificate")
            throw TKError(.corruptedData)
        }
        guard let certificate = SecCertificateCreateWithData(kCFAllocatorDefault, certificateData as CFData) else {
            NSLog("Token initWithSmartCard failed to parse certificate")
            throw TKError(.corruptedData)
        }
        guard let certificateItem = TKTokenKeychainCertificate(certificate: certificate, objectID: certificateID) else {
            NSLog("Token initWithSmartCard failed to create certificate item")
            throw TKError(.corruptedData)
        }
        certificateItem.setName(NSLocalizedString("AUTH_CERT", comment: "Cert label"))
        guard let keyItem = TKTokenKeychainKey(certificate: certificate, objectID: keyID) else {
            NSLog("Token initWithSmartCard failed to create key item")
            throw TKError(.corruptedData)
        }
        keyItem.setName(NSLocalizedString("AUTH_KEY", comment: "Key label"))
        keyItem.canSign = true
        keyItem.canDecrypt = false
        keyItem.isSuitableForLogin = false
        keyItem.canPerformKeyExchange = false
        keyItem.constraints = [TKTokenOperation.signData.rawValue: EstEIDTokenDriver.ConstraintPIN] as [NSNumber: Any]
        // keyItem.constraints = constraints[@(TKTokenOperationPerformKeyExchange)] = EstEIDConstraintPIN
        keychainContents?.fill(with: [certificateItem, keyItem])
    }
}

class IdemiaToken : Token<IdemiaTokenSession> {
    init(smartCard: TKSmartCard, aid AID: Data?, tokenDriver: TKSmartCardTokenDriver) throws {
        NSLog("IdemiaToken initWithSmartCard AID \(AID! as NSData)")
        do {
            let data = try smartCard.readFile(file: 0xD003)
            guard let tlv = TLV(from: data) else {
                throw TKError(.corruptedData)
            }
            let instanceID = String(decoding: tlv.value, as: UTF8.self)
            NSLog("IdemiaToken initWithSmartCard \(instanceID)")
            _ = try smartCard.selectFile(p1: 0x01, file: 0xADF1)
            try super.init(smartCard: smartCard, aid: AID, instanceID: instanceID, tokenDriver: tokenDriver, certificateID: 0x3401, keyID: 0x81)
        } catch {
            NSLog("IdemiaToken initWithSmartCard failed to read card")
            throw error
        }
    }
}

class ThalesToken : Token<ThalesTokenSession> {
    init(smartCard: TKSmartCard, aid AID: Data?, tokenDriver: TKSmartCardTokenDriver) throws {
        NSLog("ThalesToken initWithSmartCard AID \(AID! as NSData)")
        do {
            _ = try smartCard.selectFile(p1: 0x08, file: 0xDFDD)
            let data = try smartCard.readFile(file: 0x5007)
            let instanceID = String(decoding: data, as: UTF8.self)
            NSLog("ThalesToken initWithSmartCard \(instanceID)")
            _ = try smartCard.selectFile(p1: 0x08, file: 0xADF1)
            try super.init(smartCard: smartCard, aid: AID, instanceID: instanceID, tokenDriver: tokenDriver, certificateID: 0x3411, keyID: 0x01)
        } catch {
            NSLog("ThalesToken initWithSmartCard failed to read card")
            throw error
        }
    }
}


class EstEIDTokenDriver : TKSmartCardTokenDriver, TKSmartCardTokenDriverDelegate {
    static let ConstraintPIN: String = "PIN"

    func tokenDriver(_ driver: TKSmartCardTokenDriver, createTokenFor smartCard: TKSmartCard, aid AID: Data?) throws -> TKSmartCardToken {
        let info = Bundle(for: EstEIDTokenDriver.self).infoDictionary
        let ver = info?["CFBundleShortVersionString"] ?? 0
        let build = info?["CFBundleVersion"] ?? 0
        NSLog("EstEIDTokenDriver createTokenForSmartCard AID \(AID! as NSData) version \(ver).\(build)")
        EstEIDTokenDriver.showNotification(nil)
        if AID != nil && AID!.elementsEqual([0xA0, 0x00, 0x00, 0x00, 0x63, 0x50, 0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35]) {
            return try ThalesToken(smartCard: smartCard, aid: AID, tokenDriver: self)
        }
        return try IdemiaToken(smartCard: smartCard, aid: AID, tokenDriver: self)
    }

    static func showNotification(_ title: String?, subtitle: String = .init()) {
        NSLog("EstEIDTokenDriver showNotification")
        let center = UNUserNotificationCenter.current()

        center.getNotificationSettings { settings in
            NSLog("EstEIDTokenDriver showNotification status \(settings.authorizationStatus)")
            if settings.authorizationStatus == .authorized { return }
            var path = Bundle(for: EstEIDTokenDriver.self).bundleURL
            path.deleteLastPathComponent()
            path.deleteLastPathComponent()
            path.deleteLastPathComponent()
            NSLog("EstEIDTokenDriver showNotification path: \(path)")
            NSWorkspace.shared.openApplication(at: path, configuration: NSWorkspace.OpenConfiguration()) { app, error in
                NSLog("EstEIDTokenDriver showNotification openApplicationAtURL: \(error?.localizedDescription ?? "")")
            }
        }

        guard title != nil else {
            return center.removeAllDeliveredNotifications()
        }
        let ui = UNMutableNotificationContent()
        ui.title = title!
        ui.subtitle = subtitle
        ui.sound = .default
        ui.interruptionLevel = .timeSensitive
        let request = UNNotificationRequest(identifier: UUID().uuidString, content: ui, trigger: nil)
        center.add(request) { error in
            NSLog("EstEIDTokenNotify: addNotificationRequest \(error?.localizedDescription ?? "")")
        }
    }
}
