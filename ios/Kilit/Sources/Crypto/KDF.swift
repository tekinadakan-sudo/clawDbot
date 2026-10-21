import Foundation
import CryptoKit

/// Every domain-separation string of the protocol (DESIGN.md §3), byte-exact.
enum KilitInfo {
    static let x3dh: String = "Kilit_X3DH_v1_X25519_SHA256_ChaChaPoly"
    static let wmSecret: String = "Kilit_WM_Secret_v1"
    static let sid: String = "Kilit_SID_v1"
    static let rootChain: String = "Kilit_DR_v1_RootChain"
    static let messageKeys: String = "Kilit_DR_v1_MessageKeys"
    static let attachV1: String = "Kilit_Attach_v1"
    static let attachV2: String = "Kilit_Attach_v2"
    static let watermark: String = "Kilit_WM_v1"
    static let safetyNumber: String = "Kilit_SafetyNumber_v1"
    static let localStore: String = "Kilit_LocalStore_v1"
    static let localStoreDoc: String = "Kilit_LocalStoreDoc_v1"
    static let ikBind: String = "Kilit_IKBind_v1"
    static let spk: String = "Kilit_SPK_v1"
    static let opkBatch: String = "Kilit_OPKBatch_v1"
    static let register: String = "Kilit_Register_v1"
    static let auth: String = "Kilit_Auth_v1"
    static let delete: String = "Kilit_Delete_v1"
    static let safetyQRPrefix: String = "kilit-sn:v1:"
}

/// HKDF-SHA256 / HMAC-SHA256 / SHA-256 wrappers and the ratchet KDFs of §3.3.
enum KDF {
    /// 32 zero bytes (equal to an empty salt per RFC 5869).
    static let zeros32: Data = Data(repeating: 0, count: 32)

    static func hkdf(ikm: Data, salt: Data, info: Data, length: Int) -> Data {
        let okm: SymmetricKey = HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: ikm),
                                                       salt: salt,
                                                       info: info,
                                                       outputByteCount: length)
        return okm.withUnsafeBytes { Data($0) }
    }

    static func hkdf(ikm: Data, salt: Data, info: String, length: Int) -> Data {
        hkdf(ikm: ikm, salt: salt, info: Data(info.utf8), length: length)
    }

    static func hmacSHA256(key: Data, message: Data) -> Data {
        let mac = HMAC<SHA256>.authenticationCode(for: message, using: SymmetricKey(data: key))
        return Data(mac)
    }

    static func sha256(_ data: Data) -> Data {
        Data(SHA256.hash(data: data))
    }

    /// `KDF_RK(rk, dh)`: HKDF(ikm = dh, salt = rk, info = "Kilit_DR_v1_RootChain", L = 64) → (rk', ck).
    static func kdfRK(rk: Data, dh: Data) -> (rk: Data, ck: Data) {
        let out: Data = hkdf(ikm: dh, salt: rk, info: KilitInfo.rootChain, length: 64)
        return (Bytes.copy(out.prefix(32)), Bytes.copy(out.suffix(32)))
    }

    /// `KDF_CK(ck)`: mk = HMAC(ck, 0x01), ck' = HMAC(ck, 0x02).
    static func kdfCK(ck: Data) -> (ck: Data, mk: Data) {
        let mk: Data = hmacSHA256(key: ck, message: Data([0x01]))
        let next: Data = hmacSHA256(key: ck, message: Data([0x02]))
        return (next, mk)
    }

    /// Message keys: HKDF(ikm = mk, salt = zeros, info = "Kilit_DR_v1_MessageKeys", L = 44) → key(32) || nonce(12).
    static func messageKeys(mk: Data) -> (key: Data, nonce: Data) {
        let out: Data = hkdf(ikm: mk, salt: zeros32, info: KilitInfo.messageKeys, length: 44)
        return (Bytes.copy(out.prefix(32)), Bytes.copy(out.suffix(12)))
    }

    /// Watermark secret: HKDF(ikm = SK, salt = zeros, info = "Kilit_WM_Secret_v1", L = 32).
    static func watermarkSecret(sk: Data) -> Data {
        hkdf(ikm: sk, salt: zeros32, info: KilitInfo.wmSecret, length: 32)
    }
}
