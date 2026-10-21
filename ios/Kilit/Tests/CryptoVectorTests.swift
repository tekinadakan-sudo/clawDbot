import XCTest
import CryptoKit
@testable import Kilit

// MARK: - Shared vector-file helpers (used by every WP5 test file)

struct VecError: Error, CustomStringConvertible {
    let description: String
    init(_ d: String) { description = d }
}

/// Small typed accessors over `JSONSerialization` output (schema: docs/VECTOR_SCHEMA.md).
enum Vec {
    static func object(_ json: String) throws -> [String: Any] {
        let any: Any = try JSONSerialization.jsonObject(with: Data(json.utf8), options: [])
        guard let d = any as? [String: Any] else { throw VecError("top-level is not an object") }
        return d
    }

    static func dict(_ d: [String: Any], _ key: String) throws -> [String: Any] {
        guard let v = d[key] as? [String: Any] else { throw VecError("missing object \(key)") }
        return v
    }

    static func optDict(_ d: [String: Any], _ key: String) -> [String: Any]? {
        d[key] as? [String: Any]
    }

    static func dicts(_ d: [String: Any], _ key: String) throws -> [[String: Any]] {
        guard let v = d[key] as? [[String: Any]] else { throw VecError("missing array \(key)") }
        return v
    }

    static func optDicts(_ d: [String: Any], _ key: String) -> [[String: Any]] {
        (d[key] as? [[String: Any]]) ?? []
    }

    static func str(_ d: [String: Any], _ key: String) throws -> String {
        guard let v = d[key] as? String else { throw VecError("missing string \(key)") }
        return v
    }

    static func optStr(_ d: [String: Any], _ key: String) -> String? {
        d[key] as? String
    }

    static func strs(_ d: [String: Any], _ key: String) throws -> [String] {
        guard let v = d[key] as? [String] else { throw VecError("missing string array \(key)") }
        return v
    }

    static func int(_ d: [String: Any], _ key: String) throws -> Int {
        guard let v = d[key] as? NSNumber else { throw VecError("missing number \(key)") }
        return v.intValue
    }

    static func optInt(_ d: [String: Any], _ key: String) -> Int? {
        (d[key] as? NSNumber)?.intValue
    }

    static func u64(_ d: [String: Any], _ key: String) throws -> UInt64 {
        guard let v = d[key] as? NSNumber else { throw VecError("missing number \(key)") }
        return v.uint64Value
    }

    static func bool(_ d: [String: Any], _ key: String) -> Bool {
        (d[key] as? NSNumber)?.boolValue ?? false
    }

    static func hex(_ d: [String: Any], _ key: String) throws -> Data {
        let s: String = try str(d, key)
        guard let v = Data(hex: s) else { throw VecError("bad hex in \(key)") }
        return v
    }

    /// nil for an absent key or an explicit JSON null.
    static func optHex(_ d: [String: Any], _ key: String) throws -> Data? {
        guard let s = d[key] as? String else { return nil }
        guard let v = Data(hex: s) else { throw VecError("bad hex in \(key)") }
        return v
    }

    static func hexes(_ d: [String: Any], _ key: String) throws -> [Data] {
        let list: [String] = try strs(d, key)
        var out: [Data] = []
        for s in list {
            guard let v = Data(hex: s) else { throw VecError("bad hex in \(key)") }
            out.append(v)
        }
        return out
    }

    /// Re-serialises a wire JSON object (any key order is fine: the parser decodes it again).
    static func jsonBytes(_ obj: Any) throws -> Data {
        try JSONSerialization.data(withJSONObject: obj, options: [])
    }

    static func errorName(_ body: () throws -> Void) -> String? {
        do {
            try body()
            return nil
        } catch {
            return KilitErrorName.of(error)
        }
    }
}

// MARK: - primitives.json

final class CryptoVectorTests: XCTestCase {
    private var root: [String: Any] = [:]

    override func setUpWithError() throws {
        root = try Vec.object(KilitVectors.primitives)
    }

    func testX25519Vectors() throws {
        for v in try Vec.dicts(root, "x25519") {
            let caseName: String = try Vec.str(v, "name")
            let priv = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: try Vec.hex(v, "priv"))
            XCTAssertEqual(priv.publicKey.rawRepresentation, try Vec.hex(v, "pub"), caseName)
            let shared: Data = try X3DH.dh(priv, try Vec.hex(v, "peer_pub"))
            XCTAssertEqual(shared, try Vec.hex(v, "shared"), caseName)
        }
    }

    func testX25519Negatives() throws {
        for v in try Vec.dicts(root, "x25519_negative") {
            let caseName: String = try Vec.str(v, "name")
            let priv = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: try Vec.hex(v, "priv"))
            let peer: Data = try Vec.hex(v, "peer_pub")
            let name: String? = Vec.errorName { _ = try X3DH.dh(priv, peer) }
            XCTAssertEqual(name, try Vec.str(v, "error"), caseName)
        }
    }

    func testEd25519Vectors() throws {
        for v in try Vec.dicts(root, "ed25519") {
            let seed: Data = try Vec.hex(v, "seed")
            let priv = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
            let pub: Data = try Vec.hex(v, "pub")
            let msg: Data = try Vec.hex(v, "msg")
            XCTAssertEqual(priv.publicKey.rawRepresentation, pub)
            // Go's deterministic signature verifies under the strict rules …
            XCTAssertNoThrow(try Ed25519Strict.verify(signature: try Vec.hex(v, "go_sig"), message: msg, publicKey: pub))
            // … and so does a fresh (randomised) CryptoKit signature.
            let own: Data = try priv.signature(for: msg)
            XCTAssertNoThrow(try Ed25519Strict.verify(signature: own, message: msg, publicKey: pub))
            // A flipped message byte fails.
            var bad: Data = msg
            if bad.isEmpty { bad.append(0x01) } else { bad[bad.startIndex] ^= 0x01 }
            XCTAssertThrowsError(try Ed25519Strict.verify(signature: own, message: bad, publicKey: pub))
        }
    }

    func testEd25519StrictNegatives() throws {
        for v in try Vec.dicts(root, "ed25519_negative") {
            let caseName: String = try Vec.str(v, "name")
            let pub: Data = try Vec.hex(v, "pub")
            let msg: Data = try Vec.hex(v, "msg")
            let sig: Data = try Vec.hex(v, "sig")
            let name: String? = Vec.errorName { try Ed25519Strict.verify(signature: sig, message: msg, publicKey: pub) }
            XCTAssertEqual(name, try Vec.str(v, "error"), caseName)
        }
    }

    func testSmallOrderTableMatchesVectorFile() throws {
        let table: [Data] = try Vec.hexes(root, "ed25519_small_order_points")
        XCTAssertEqual(table.count, 14)
        XCTAssertEqual(Set(table), Set(Ed25519Strict.smallOrderPoints))
        for p in table {
            XCTAssertTrue(Ed25519Strict.isSmallOrder(p))
            XCTAssertThrowsError(try Ed25519Strict.publicKey(p)) { e in
                XCTAssertEqual(KilitErrorName.of(e), "badPublicKey")
            }
        }
    }

    func testScalarBound() {
        // S == L is rejected, S == L − 1 accepted, S with the top byte 0x11 rejected.
        let l: Data = Data(Ed25519Strict.lBytes)
        XCTAssertFalse(Ed25519Strict.scalarIsCanonical(l))
        var lMinus: [UInt8] = Ed25519Strict.lBytes
        lMinus[0] -= 1
        XCTAssertTrue(Ed25519Strict.scalarIsCanonical(Data(lMinus)))
        var big: [UInt8] = Array(repeating: 0, count: 32)
        big[31] = 0x11
        XCTAssertFalse(Ed25519Strict.scalarIsCanonical(Data(big)))
        XCTAssertFalse(Ed25519Strict.scalarIsCanonical(Data(repeating: 0xFF, count: 32)))
        XCTAssertTrue(Ed25519Strict.scalarIsCanonical(Data(repeating: 0, count: 32)))
    }

    func testHKDFVectors() throws {
        for v in try Vec.dicts(root, "hkdf") {
            let caseName: String = try Vec.str(v, "name")
            let ikm: Data = try Vec.hex(v, "ikm")
            let info: Data = try Vec.hex(v, "info")
            let len: Int = try Vec.int(v, "len")
            let okm: Data = try Vec.hex(v, "okm")
            if let saltA = try Vec.optHex(v, "salt_a"), let saltB = try Vec.optHex(v, "salt_b") {
                let a: Data = KDF.hkdf(ikm: ikm, salt: saltA, info: info, length: len)
                let b: Data = KDF.hkdf(ikm: ikm, salt: saltB, info: info, length: len)
                XCTAssertEqual(a, b, "empty salt must equal 32 zero bytes")
                XCTAssertEqual(a, okm, caseName)
            } else {
                let salt: Data = try Vec.hex(v, "salt")
                XCTAssertEqual(KDF.hkdf(ikm: ikm, salt: salt, info: info, length: len), okm, caseName)
            }
        }
    }

    func testKdfCKVectors() throws {
        for v in try Vec.dicts(root, "hmac_kdf_ck") {
            let (next, mk) = KDF.kdfCK(ck: try Vec.hex(v, "ck"))
            XCTAssertEqual(mk, try Vec.hex(v, "mk"))
            XCTAssertEqual(next, try Vec.hex(v, "ck_next"))
        }
    }

    func testChaChaPolyVectors() throws {
        for v in try Vec.dicts(root, "chachapoly") {
            let caseName: String = try Vec.str(v, "name")
            let key: Data = try Vec.hex(v, "key")
            let nonce: Data = try Vec.hex(v, "nonce")
            let aad: Data = try Vec.hex(v, "aad")
            let pt: Data = try Vec.hex(v, "pt")
            let wire: Data = try Vec.hex(v, "wire")
            XCTAssertEqual(try AEAD.seal(plaintext: pt, key: key, nonce: nonce, aad: aad), wire, caseName)
            XCTAssertEqual(try AEAD.open(wire: wire, key: key, nonce: nonce, aad: aad), pt)
        }
    }

    func testChaChaPolyNegatives() throws {
        for v in try Vec.dicts(root, "chachapoly_negative") {
            let caseName: String = try Vec.str(v, "name")
            let key: Data = try Vec.hex(v, "key")
            let expected: String = try Vec.str(v, "error")
            if let wire = try Vec.optHex(v, "wire") {
                let nonce: Data = try Vec.hex(v, "nonce")
                let aad: Data = try Vec.hex(v, "aad")
                let name: String? = Vec.errorName { _ = try AEAD.open(wire: wire, key: key, nonce: nonce, aad: aad) }
                XCTAssertEqual(name, expected, caseName)
            } else {
                let nonce: Data = Data(repeating: 0, count: 12)
                let name: String? = Vec.errorName { _ = try AEAD.seal(plaintext: Data(), key: key, nonce: nonce, aad: Data()) }
                XCTAssertEqual(name, expected, caseName)
            }
        }
    }

    func testIncorrectKeySizeOnImport() {
        let short: Data = Data(repeating: 1, count: 31)
        XCTAssertThrowsError(try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: short)) { e in
            XCTAssertEqual(KilitErrorName.of(e), "incorrectKeySize")
        }
    }

    func testZeroizingKeyRoundTrip() throws {
        let raw: Data = Bytes.random(32)
        let k: ZeroizingKey = ZeroizingKey(data: raw)
        XCTAssertEqual(k.count, 32)
        XCTAssertEqual(k.dataCopy, raw)
        let encoded: Data = try KilitJSON.encoder().encode(k)
        let decoded: ZeroizingKey = try KilitJSON.decoder().decode(ZeroizingKey.self, from: encoded)
        XCTAssertEqual(decoded, k)
        XCTAssertEqual(try k.x25519PrivateKey().rawRepresentation, raw)
    }

    func testBigEndianHelpers() {
        XCTAssertEqual(BE.u16(0x0102).hex, "0102")
        XCTAssertEqual(BE.u32(0x01020304).hex, "01020304")
        XCTAssertEqual(BE.u64(0x0102030405060708).hex, "0102030405060708")
        XCTAssertEqual(BE.readU32(Data([0xAA, 0x01, 0x02, 0x03, 0x04]), at: 1), 0x01020304)
        XCTAssertTrue(Bytes.isAllZero(Data(repeating: 0, count: 32)))
        XCTAssertFalse(Bytes.isAllZero(Data([0, 0, 1])))
        XCTAssertTrue(Bytes.lexLess(Data([0, 1]), Data([0, 2])))
        XCTAssertTrue(Bytes.lexLess(Data([0]), Data([0, 0])))
        XCTAssertFalse(Bytes.lexLess(Data([1]), Data([0, 9])))
    }
}
