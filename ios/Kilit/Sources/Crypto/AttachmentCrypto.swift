import Foundation
import CryptoKit

/// Decrypted attachment bytes in an owned buffer that is scrubbed with `memset_s` and freed on deinit.
final class OwnedPlaintextBuffer {
    private var buffer: UnsafeMutableRawBufferPointer?
    let count: Int

    init(copying data: Data) {
        let n: Int = data.count
        self.count = n
        let buf: UnsafeMutableRawBufferPointer = UnsafeMutableRawBufferPointer.allocate(byteCount: Swift.max(n, 1), alignment: 1)
        data.withUnsafeBytes { (src: UnsafeRawBufferPointer) in
            if n > 0, let base = src.baseAddress {
                buf.baseAddress?.copyMemory(from: base, byteCount: n)
            }
        }
        self.buffer = buf
    }

    /// Read access to the plaintext (invalid after `clear()`).
    func withBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        guard let buf = buffer else {
            return try body(UnsafeRawBufferPointer(start: nil, count: 0))
        }
        return try body(UnsafeRawBufferPointer(start: buf.baseAddress, count: count))
    }

    /// `memset_s` over the buffer, then deallocate. Idempotent.
    func clear() {
        guard let buf = buffer else { return }
        if let base = buf.baseAddress {
            _ = memset_s(base, buf.count, 0, buf.count)
        }
        buf.deallocate()
        buffer = nil
    }

    deinit {
        clear()
    }
}

/// Result of `AttachmentCrypto.seal`: the blob file bytes and the fields of the inner `att` object.
struct SealedAttachment: Equatable {
    let blobId: Data
    let fileKey: Data
    let mime: String
    let len: UInt64
    let blob: Data
    let sha256: Data

    /// `blob_id` as hex32 (the wire form).
    var blobIdHex: String { blobId.hex }
}

/// Single-shot attachment encryption (§3.5): `"KATT" || 0x01 || ciphertext || tag`.
enum AttachmentCrypto {
    static let magic: Data = Data("KATT".utf8)
    static let version: UInt8 = 0x01
    static let headerLength: Int = 5
    static let maxPlaintext: Int = 8 * 1024 * 1024

    /// `HKDF(ikm = fileKey, salt = zeros, info = "Kilit_Attach_v1", L = 44)` → key(32) || nonce(12).
    static func deriveKeys(fileKey: Data) -> (key: Data, nonce: Data) {
        let out: Data = KDF.hkdf(ikm: fileKey, salt: KDF.zeros32, info: KilitInfo.attachV1, length: 44)
        return (Bytes.copy(out.prefix(32)), Bytes.copy(out.suffix(12)))
    }

    /// `AAD = "Kilit_Attach_v1" || 0x01 || blob_id(16) || u16BE(len(mime)) || mime || u64BE(plaintext_len)`.
    static func aad(blobId: Data, mime: String, len: UInt64) -> Data {
        let m: Data = Data(mime.utf8)
        var out: Data = Data(KilitInfo.attachV1.utf8)
        out.append(version)
        out.append(blobId)
        out.append(BE.u16(UInt16(m.count)))
        out.append(m)
        out.append(BE.u64(len))
        return out
    }

    /// Draws `blob_id` (16 bytes) and then a fresh `fileKey` (32 bytes) from `keySource` on every call —
    /// a `fileKey` is never used for more than one seal. Throws `sizeLimit` above 8 MiB.
    static func seal(plaintext: Data, mime: String, keySource: KeySource) throws -> SealedAttachment {
        guard plaintext.count <= maxPlaintext else { throw KilitCryptoError.sizeLimit }
        let blobId: Data = keySource.bytes(count: 16)
        let fileKey: Data = keySource.bytes(count: 32)
        guard blobId.count == 16, fileKey.count == 32 else { throw KilitCryptoError.badKeyLength }
        let len: UInt64 = UInt64(plaintext.count)
        let (key, nonce) = deriveKeys(fileKey: fileKey)
        let wire: Data = try AEAD.seal(plaintext: plaintext, key: key, nonce: nonce,
                                       aad: aad(blobId: blobId, mime: mime, len: len))
        var blob: Data = magic
        blob.append(version)
        blob.append(wire)
        return SealedAttachment(blobId: blobId, fileKey: fileKey, mime: mime, len: len, blob: blob, sha256: KDF.sha256(blob))
    }

    /// Verifies `att.sha256` over the whole blob file (header included).
    static func verifyDigest(blob: Data, expected: Data) -> Bool {
        KDF.sha256(blob) == expected
    }

    /// Opens a blob file into an owned buffer; the receiver must find exactly `len` bytes.
    /// Go `OpenAttachment` order: a `fileKey` that is not 32 bytes → `badKeyLength`; a blob shorter than
    /// 21 bytes or without the `KATT 0x01` header, and every AEAD/length failure →
    /// `CryptoKitError.authenticationFailure`.
    static func open(blob: Data, fileKey: Data, blobId: Data, mime: String, len: UInt64) throws -> OwnedPlaintextBuffer {
        guard fileKey.count == 32 else { throw KilitCryptoError.badKeyLength }
        guard blob.count >= headerLength + AEAD.tagLength else { throw CryptoKitError.authenticationFailure }
        let header: Data = Bytes.copy(blob.prefix(headerLength))
        guard header.prefix(4) == magic, header[4] == version else { throw CryptoKitError.authenticationFailure }
        let wire: Data = Bytes.copy(blob.suffix(blob.count - headerLength))
        let (key, nonce) = deriveKeys(fileKey: fileKey)
        let pt: Data = try AEAD.open(wire: wire, key: key, nonce: nonce, aad: aad(blobId: blobId, mime: mime, len: len))
        guard UInt64(pt.count) == len else { throw CryptoKitError.authenticationFailure }
        return OwnedPlaintextBuffer(copying: pt)
    }
}
