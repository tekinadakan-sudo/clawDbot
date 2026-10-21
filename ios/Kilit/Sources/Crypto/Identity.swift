import Foundation
import CryptoKit

// MARK: - Public identity

/// The two public identity keys of a party (raw 32 bytes each).
struct IdentityPublicKeys: Codable, Equatable {
    let ikSig: Data
    let ikDh: Data

    enum CodingKeys: String, CodingKey {
        case ikSig = "ik_sig"
        case ikDh = "ik_dh"
    }

    var isWellFormed: Bool {
        ikSig.count == 32 && ikDh.count == 32
    }
}

/// Username canonical form `^[a-z0-9_]{3,32}$` and the lowercase UUIDv4 `device_id` rule of §3.
enum Canonical {
    /// Lowercases ASCII letters; returns nil when the result does not match `^[a-z0-9_]{3,32}$`.
    static func username(_ raw: String) -> String? {
        let lowered: String = raw.lowercased()
        let bytes: [UInt8] = Array(lowered.utf8)
        guard bytes.count >= 3, bytes.count <= 32 else { return nil }
        for b in bytes {
            let ok: Bool = (b >= 0x61 && b <= 0x7A) || (b >= 0x30 && b <= 0x39) || b == 0x5F
            if !ok { return nil }
        }
        return lowered
    }

    static func isDeviceId(_ s: String) -> Bool {
        let bytes: [UInt8] = Array(s.utf8)
        guard bytes.count == 36 else { return false }
        for (i, b) in bytes.enumerated() {
            switch i {
            case 8, 13, 18, 23:
                if b != 0x2D { return false }
            case 14:
                if b != 0x34 { return false }
            case 19:
                if !(b == 0x38 || b == 0x39 || b == 0x61 || b == 0x62) { return false }
            default:
                let hex: Bool = (b >= 0x30 && b <= 0x39) || (b >= 0x61 && b <= 0x66)
                if !hex { return false }
            }
        }
        return true
    }
}

// MARK: - Identity private keys

/// `IK_sig` (Ed25519, 32-byte seed) and `IK_dh` (X25519). The seeds are the transport/storage form.
final class IdentityKeys {
    let signing: Curve25519.Signing.PrivateKey
    let agreement: Curve25519.KeyAgreement.PrivateKey

    init() {
        self.signing = Curve25519.Signing.PrivateKey()
        self.agreement = Curve25519.KeyAgreement.PrivateKey()
    }

    init(sigSeed: Data, dhPriv: Data) throws {
        self.signing = try Curve25519.Signing.PrivateKey(rawRepresentation: sigSeed)
        self.agreement = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: dhPriv)
    }

    var publicKeys: IdentityPublicKeys {
        IdentityPublicKeys(ikSig: signing.publicKey.rawRepresentation, ikDh: agreement.publicKey.rawRepresentation)
    }

    var sigSeed: Data { signing.rawRepresentation }
    var dhPriv: Data { agreement.rawRepresentation }

    func sign(_ message: Data) throws -> Data {
        try signing.signature(for: message)
    }

    func ikBindSig() throws -> Data {
        try sign(SignedMessages.ikBind(ikDh: agreement.publicKey.rawRepresentation))
    }
}

// MARK: - Strict Ed25519

/// Pre-checks that both `crypto/ed25519` and CryptoKit lack (DESIGN.md §3): run before the library verify.
enum Ed25519Strict {
    /// L = 2^252 + 27742317777372353535851937790883648493 as 32 little-endian bytes.
    static let lBytes: [UInt8] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
    ]

    /// libsodium's 7 small-order encodings expanded to both sign-bit values (14 entries).
    static let smallOrderPoints: [Data] = {
        let hexes: [String] = [
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000080",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "0100000000000000000000000000000000000000000000000000000000000080",
            "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
            "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        ]
        var out: [Data] = []
        for h in hexes {
            if let d = Data(hex: h) { out.append(d) }
        }
        return out
    }()

    static func isSmallOrder(_ encoding: Data) -> Bool {
        smallOrderPoints.contains(encoding)
    }

    /// `S = sig[32:64]` (little-endian) must be `< L`: compare from index 31 downwards; equal → false.
    static func scalarIsCanonical(_ s: Data) -> Bool {
        guard s.count == 32 else { return false }
        var i: Int = 31
        while i >= 0 {
            let x: UInt8 = s[s.startIndex + i]
            let y: UInt8 = lBytes[i]
            if x != y { return x < y }
            i -= 1
        }
        return false
    }

    /// Imports a public key: 32 bytes, not small-order, accepted by CryptoKit; otherwise `badPublicKey`.
    static func publicKey(_ raw: Data) throws -> Curve25519.Signing.PublicKey {
        guard raw.count == 32, !isSmallOrder(raw) else { throw KilitCryptoError.badPublicKey }
        guard let pk = try? Curve25519.Signing.PublicKey(rawRepresentation: raw) else {
            throw KilitCryptoError.badPublicKey
        }
        return pk
    }

    /// Full strict verification; throws `badSignature` (or `badPublicKey` for a bad key).
    static func verify(signature: Data, message: Data, publicKey raw: Data) throws {
        let pk: Curve25519.Signing.PublicKey = try publicKey(raw)
        guard signature.count == 64 else { throw KilitCryptoError.badSignature }
        let r: Data = Bytes.copy(signature.prefix(32))
        let s: Data = Bytes.copy(signature.suffix(32))
        guard scalarIsCanonical(s) else { throw KilitCryptoError.badSignature }
        guard !isSmallOrder(r) else { throw KilitCryptoError.badSignature }
        guard pk.isValidSignature(signature, for: message) else { throw KilitCryptoError.badSignature }
    }
}

// MARK: - Prekeys

/// Published form of the signed prekey (`spk` object of the bundle).
struct SignedPrekeyPublic: Equatable {
    let id: UInt32
    let pub: Data
    let sig: Data
    let createdAt: UInt64
}

/// A stored signed prekey with its private key (§3.1; deleted 28 d after `createdAt` by the store).
struct SignedPrekey: Codable, Equatable {
    let id: UInt32
    let createdAt: UInt64
    let privateKey: ZeroizingKey
    let publicKey: Data

    enum CodingKeys: String, CodingKey {
        case id
        case createdAt = "created_at"
        case privateKey = "priv"
        case publicKey = "pub"
    }

    init(id: UInt32, createdAt: UInt64, privateKey: Curve25519.KeyAgreement.PrivateKey) {
        self.id = id
        self.createdAt = createdAt
        self.privateKey = ZeroizingKey(data: privateKey.rawRepresentation)
        self.publicKey = privateKey.publicKey.rawRepresentation
    }

    init(id: UInt32, createdAt: UInt64, rawPrivate: Data) throws {
        let key: Curve25519.KeyAgreement.PrivateKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: rawPrivate)
        self.init(id: id, createdAt: createdAt, privateKey: key)
    }

    func signed(by identity: IdentityKeys) throws -> SignedPrekeyPublic {
        let sig: Data = try identity.sign(SignedMessages.spk(id: id, createdAt: createdAt, pub: publicKey))
        return SignedPrekeyPublic(id: id, pub: publicKey, sig: sig, createdAt: createdAt)
    }
}

/// A stored one-time prekey with its private key.
struct OneTimePrekey: Codable, Equatable {
    let id: UInt32
    let privateKey: ZeroizingKey
    let publicKey: Data

    enum CodingKeys: String, CodingKey {
        case id
        case privateKey = "priv"
        case publicKey = "pub"
    }

    init(id: UInt32, privateKey: Curve25519.KeyAgreement.PrivateKey) {
        self.id = id
        self.privateKey = ZeroizingKey(data: privateKey.rawRepresentation)
        self.publicKey = privateKey.publicKey.rawRepresentation
    }

    init(id: UInt32, rawPrivate: Data) throws {
        let key: Curve25519.KeyAgreement.PrivateKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: rawPrivate)
        self.init(id: id, privateKey: key)
    }
}

/// `{username, ik_sig, ik_dh, ik_bind_sig, spk:{id,pub,sig,created_at}, opk:{id,pub}|null}` as fetched.
struct PrekeyBundle: Equatable {
    let username: String
    let identity: IdentityPublicKeys
    let ikBindSig: Data
    let spk: SignedPrekeyPublic
    let opkId: UInt32?
    let opkPub: Data?
}

// MARK: - Signed messages (§3.1), byte-exact

enum SignedMessages {
    private static let sep: Data = Data([0x00])

    static func ikBind(ikDh: Data) -> Data {
        Bytes.utf8(KilitInfo.ikBind) + ikDh
    }

    static func spk(id: UInt32, createdAt: UInt64, pub: Data) -> Data {
        var out: Data = Bytes.utf8(KilitInfo.spk)
        out.append(BE.u32(id))
        out.append(BE.u64(createdAt))
        out.append(pub)
        return out
    }

    /// Over the batch in request order: `u32BE(count) || (u32BE(id) || pub)…`.
    static func opkBatch(_ opks: [(id: UInt32, pub: Data)]) -> Data {
        var out: Data = Bytes.utf8(KilitInfo.opkBatch) + BE.u32(UInt32(opks.count))
        for o in opks {
            out.append(BE.u32(o.id))
            out.append(o.pub)
        }
        return out
    }

    /// `prefix || 0x00 || part1 || 0x00 || part2 …` (single-byte separators).
    private static func separated(_ prefix: String, _ parts: [Data]) -> Data {
        var out: Data = Bytes.utf8(prefix)
        for p in parts {
            out.append(sep)
            out.append(p)
        }
        return out
    }

    static func registerProof(username: String, ikDh: Data, deviceId: String, nonce: Data, ts: UInt64, serverOrigin: String) -> Data {
        separated(KilitInfo.register, [Bytes.utf8(username), ikDh, Bytes.utf8(deviceId), nonce, BE.u64(ts), Bytes.utf8(serverOrigin)])
    }

    static func login(username: String, nonce: Data, ts: UInt64, deviceId: String, serverOrigin: String) -> Data {
        separated(KilitInfo.auth, [Bytes.utf8(username), nonce, BE.u64(ts), Bytes.utf8(deviceId), Bytes.utf8(serverOrigin)])
    }

    static func delete(username: String, nonce: Data, ts: UInt64, serverOrigin: String) -> Data {
        separated(KilitInfo.delete, [Bytes.utf8(username), nonce, BE.u64(ts), Bytes.utf8(serverOrigin)])
    }
}

/// Bundle verification performed by clients on fetch (§3.1): `ik_bind_sig` and `spk.sig`.
enum BundleVerifier {
    static func verify(_ bundle: PrekeyBundle) throws {
        guard bundle.identity.isWellFormed, bundle.spk.pub.count == 32 else { throw KilitCryptoError.badKeyLength }
        if let opk = bundle.opkPub, opk.count != 32 { throw KilitCryptoError.badKeyLength }
        try Ed25519Strict.verify(signature: bundle.ikBindSig,
                                 message: SignedMessages.ikBind(ikDh: bundle.identity.ikDh),
                                 publicKey: bundle.identity.ikSig)
        try Ed25519Strict.verify(signature: bundle.spk.sig,
                                 message: SignedMessages.spk(id: bundle.spk.id, createdAt: bundle.spk.createdAt, pub: bundle.spk.pub),
                                 publicKey: bundle.identity.ikSig)
    }
}
