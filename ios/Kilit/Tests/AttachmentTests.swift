import XCTest
import CryptoKit
@testable import Kilit

final class AttachmentTests: XCTestCase {
    private var root: [String: Any] = [:]

    override func setUpWithError() throws {
        root = try Vec.object(KilitVectors.attachment)
    }

    func testVectorCases() throws {
        let cases: [[String: Any]] = try Vec.dicts(root, "cases")
        XCTAssertFalse(cases.isEmpty)
        for c in cases {
            let blobId: Data = try Vec.hex(c, "blob_id")
            let fileKey: Data = try Vec.hex(c, "file_key")
            let mime: String = try Vec.str(c, "mime")
            let pt: Data = try Vec.hex(c, "pt")
            let (key, nonce) = AttachmentCrypto.deriveKeys(fileKey: fileKey)
            XCTAssertEqual(key, try Vec.hex(c, "key"))
            XCTAssertEqual(nonce, try Vec.hex(c, "nonce"))
            XCTAssertEqual(AttachmentCrypto.aad(blobId: blobId, mime: mime, len: UInt64(pt.count)), try Vec.hex(c, "aad"))
            // seal draws blob_id then fileKey from the injected source.
            let ks: ScriptedKeySource = ScriptedKeySource(keys: [], bytes: [blobId, fileKey])
            let sealed: SealedAttachment = try AttachmentCrypto.seal(plaintext: pt, mime: mime, keySource: ks)
            XCTAssertEqual(ks.overdrawnBytes, 0)
            XCTAssertEqual(sealed.blobId, blobId)
            XCTAssertEqual(sealed.fileKey, fileKey)
            XCTAssertEqual(sealed.len, UInt64(pt.count))
            XCTAssertEqual(sealed.blob, try Vec.hex(c, "blob"))
            XCTAssertEqual(sealed.sha256, try Vec.hex(c, "sha256"))
            XCTAssertEqual(sealed.blob.prefix(5), Data("KATT".utf8) + Data([0x01]))
            XCTAssertEqual(sealed.blob.count, pt.count + 21)
            XCTAssertTrue(AttachmentCrypto.verifyDigest(blob: sealed.blob, expected: sealed.sha256))
            // Open into the owned buffer.
            let buf: OwnedPlaintextBuffer = try AttachmentCrypto.open(blob: sealed.blob, fileKey: fileKey, blobId: blobId,
                                                                      mime: mime, len: UInt64(pt.count))
            XCTAssertEqual(buf.count, pt.count)
            let copy: Data = buf.withBytes { Data($0) }
            XCTAssertEqual(copy, pt)
            buf.clear()
            XCTAssertEqual(buf.withBytes { $0.count }, 0)
        }
    }

    func testWrongLenNegative() throws {
        for n in try Vec.dicts(root, "negative") {
            let blobId: Data = try Vec.hex(n, "blob_id")
            let fileKey: Data = try Vec.hex(n, "file_key")
            let mime: String = try Vec.str(n, "mime")
            let len: UInt64 = try Vec.u64(n, "len")
            let blob: Data = try Vec.hex(n, "blob")
            let err: String? = Vec.errorName {
                _ = try AttachmentCrypto.open(blob: blob, fileKey: fileKey, blobId: blobId, mime: mime, len: len)
            }
            let caseName: String = try Vec.str(n, "name")
            XCTAssertEqual(err, try Vec.str(n, "error"), caseName)
        }
    }

    func testMismatchedAADAndTamperRejected() throws {
        let pt: Data = Bytes.random(100)
        let sealed: SealedAttachment = try AttachmentCrypto.seal(plaintext: pt, mime: "image/jpeg", keySource: RandomKeySource())
        // Wrong mime.
        XCTAssertThrowsError(try AttachmentCrypto.open(blob: sealed.blob, fileKey: sealed.fileKey, blobId: sealed.blobId,
                                                       mime: "image/png", len: sealed.len))
        // Wrong blob id.
        XCTAssertThrowsError(try AttachmentCrypto.open(blob: sealed.blob, fileKey: sealed.fileKey, blobId: Bytes.random(16),
                                                       mime: "image/jpeg", len: sealed.len))
        // Wrong length.
        XCTAssertThrowsError(try AttachmentCrypto.open(blob: sealed.blob, fileKey: sealed.fileKey, blobId: sealed.blobId,
                                                       mime: "image/jpeg", len: sealed.len + 1)) { e in
            XCTAssertEqual(KilitErrorName.of(e), "authenticationFailure")
        }
        // Flipped ciphertext byte.
        var tampered: Data = sealed.blob
        tampered[tampered.startIndex + 10] ^= 0x01
        XCTAssertThrowsError(try AttachmentCrypto.open(blob: tampered, fileKey: sealed.fileKey, blobId: sealed.blobId,
                                                       mime: "image/jpeg", len: sealed.len)) { e in
            XCTAssertEqual(KilitErrorName.of(e), "authenticationFailure")
        }
        XCTAssertFalse(AttachmentCrypto.verifyDigest(blob: tampered, expected: sealed.sha256))
        // Wrong header.
        var badHeader: Data = sealed.blob
        badHeader[badHeader.startIndex + 4] = 0x02
        XCTAssertThrowsError(try AttachmentCrypto.open(blob: badHeader, fileKey: sealed.fileKey, blobId: sealed.blobId,
                                                       mime: "image/jpeg", len: sealed.len)) { e in
            XCTAssertEqual(KilitErrorName.of(e), "badHeader")
        }
    }

    /// Two seals of the same plaintext draw distinct `fileKey`s and therefore distinct `(key, nonce)`.
    func testFreshFileKeyPerSeal() throws {
        let pt: Data = Data("same plaintext".utf8)
        let ks: RandomKeySource = RandomKeySource()
        let a: SealedAttachment = try AttachmentCrypto.seal(plaintext: pt, mime: "image/jpeg", keySource: ks)
        let b: SealedAttachment = try AttachmentCrypto.seal(plaintext: pt, mime: "image/jpeg", keySource: ks)
        XCTAssertNotEqual(a.fileKey, b.fileKey)
        XCTAssertNotEqual(a.blobId, b.blobId)
        let ka = AttachmentCrypto.deriveKeys(fileKey: a.fileKey)
        let kb = AttachmentCrypto.deriveKeys(fileKey: b.fileKey)
        XCTAssertNotEqual(ka.key, kb.key)
        XCTAssertNotEqual(ka.nonce, kb.nonce)
        XCTAssertNotEqual(a.sha256, b.sha256)
    }

    func testSizeLimit() {
        let big: Data = Data(repeating: 0, count: AttachmentCrypto.maxPlaintext + 1)
        XCTAssertThrowsError(try AttachmentCrypto.seal(plaintext: big, mime: "image/jpeg", keySource: RandomKeySource())) { e in
            XCTAssertEqual(KilitErrorName.of(e), "sizeLimit")
        }
    }
}
