import Foundation
import CryptoKit

/// `GENERATE_DH` and every other random draw of the crypto layer go through this protocol
/// (`RandomKeySource` in the app, `ScriptedKeySource` in tests). Consumption order is normative (§3.8):
/// `X3DH.initiate` draws `EK` first, then `RatchetInitAlice` draws the first `DHs`; each `DHRatchet`
/// draws one key; the responder side draws nothing. `AttachmentCrypto.seal` draws `blob_id` (16 bytes)
/// and then `fileKey` (32 bytes) through `bytes(count:)`.
protocol KeySource: AnyObject {
    func x25519() -> Curve25519.KeyAgreement.PrivateKey
    func bytes(count: Int) -> Data
}

final class RandomKeySource: KeySource {
    init() {}

    func x25519() -> Curve25519.KeyAgreement.PrivateKey {
        Curve25519.KeyAgreement.PrivateKey()
    }

    func bytes(count: Int) -> Data {
        Bytes.random(count)
    }
}

/// Replays a fixed list of 32-byte X25519 private keys and a fixed list of byte strings.
/// When a list is exhausted it falls back to random material and counts the overdraw, so a test
/// can assert that the scripted budget was exactly consumed.
final class ScriptedKeySource: KeySource {
    private var keys: [Data]
    private var byteStrings: [Data]
    private(set) var keysDrawn: Int = 0
    private(set) var bytesDrawn: Int = 0
    private(set) var overdrawnKeys: Int = 0
    private(set) var overdrawnBytes: Int = 0

    init(keys: [Data], bytes: [Data] = []) {
        self.keys = keys
        self.byteStrings = bytes
    }

    var remainingKeys: Int { keys.count }

    /// The public key of the next scripted private key without consuming it (nil when exhausted or malformed).
    func peekNextPublicKey() -> Data? {
        guard let raw = keys.first, let k = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: raw) else { return nil }
        return k.publicKey.rawRepresentation
    }

    func x25519() -> Curve25519.KeyAgreement.PrivateKey {
        keysDrawn += 1
        if !keys.isEmpty {
            let raw: Data = keys.removeFirst()
            if let k = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: raw) {
                return k
            }
        }
        overdrawnKeys += 1
        return Curve25519.KeyAgreement.PrivateKey()
    }

    func bytes(count: Int) -> Data {
        bytesDrawn += 1
        if !byteStrings.isEmpty {
            let b: Data = byteStrings.removeFirst()
            if b.count == count { return b }
        }
        overdrawnBytes += 1
        return Bytes.random(count)
    }
}
