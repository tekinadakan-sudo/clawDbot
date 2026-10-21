import Foundation
import CryptoKit

/// ChaCha20-Poly1305 with an implicit (derived) nonce; wire = ciphertext || tag(16).
enum AEAD {
    static let tagLength: Int = 16

    /// Throws `CryptoKitError.incorrectKeySize` for a key that is not 32 bytes and
    /// `CryptoKitError.incorrectParameterSize` for a nonce that is not 12 bytes.
    static func seal(plaintext: Data, key: Data, nonce: Data, aad: Data) throws -> Data {
        let n: ChaChaPoly.Nonce = try ChaChaPoly.Nonce(data: nonce)
        let box: ChaChaPoly.SealedBox = try ChaChaPoly.seal(plaintext, using: SymmetricKey(data: key), nonce: n, authenticating: aad)
        return box.ciphertext + box.tag
    }

    /// Throws `CryptoKitError.authenticationFailure` on a bad tag or AAD.
    static func open(wire: Data, key: Data, nonce: Data, aad: Data) throws -> Data {
        guard wire.count >= tagLength else { throw CryptoKitError.incorrectParameterSize }
        let n: ChaChaPoly.Nonce = try ChaChaPoly.Nonce(data: nonce)
        let ciphertext: Data = Bytes.copy(wire.prefix(wire.count - tagLength))
        let tag: Data = Bytes.copy(wire.suffix(tagLength))
        let box: ChaChaPoly.SealedBox = try ChaChaPoly.SealedBox(nonce: n, ciphertext: ciphertext, tag: tag)
        return try ChaChaPoly.open(box, using: SymmetricKey(data: key), authenticating: aad)
    }
}

/// ISO/IEC 7816-4 padding to a multiple of 256 bytes (DESIGN.md §3.3).
enum Padding {
    static let block: Int = 256
    /// Inner JSON size limit before padding.
    static let maxInner: Int = 40960
    /// Smallest valid `ct` on the wire: one padded block plus the tag.
    static let minWire: Int = block + AEAD.tagLength

    /// `json || 0x80 || 0x00*k` to the next multiple of 256; at least one byte is always added.
    static func pad(_ json: Data) throws -> Data {
        guard json.count <= maxInner else { throw KilitCryptoError.sizeLimit }
        let total: Int = (json.count / block + 1) * block
        var out: Data = Data(capacity: total)
        out.append(json)
        out.append(0x80)
        out.append(Data(repeating: 0, count: total - json.count - 1))
        return out
    }

    /// Rejects an empty block, a length that is not a multiple of 256, an all-zero block,
    /// and a block whose last non-zero byte is not 0x80.
    static func unpad(_ padded: Data) throws -> Data {
        guard padded.count > 0, padded.count % block == 0 else { throw KilitCryptoError.badPadding }
        var i: Int = padded.count - 1
        while i >= 0 {
            let b: UInt8 = padded[padded.startIndex + i]
            if b == 0x80 {
                return Bytes.copy(padded.prefix(i))
            }
            if b != 0 {
                throw KilitCryptoError.badPadding
            }
            i -= 1
        }
        throw KilitCryptoError.badPadding
    }
}
