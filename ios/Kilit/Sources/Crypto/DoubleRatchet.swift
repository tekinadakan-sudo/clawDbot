import Foundation
import CryptoKit

/// 41-byte header `0x01 || dh_pub(32) || u32BE(pn) || u32BE(n)`.
struct MessageHeader: Equatable {
    static let length: Int = 41
    static let version: UInt8 = 0x01

    let dhPub: Data
    let pn: UInt32
    let n: UInt32

    init(dhPub: Data, pn: UInt32, n: UInt32) {
        self.dhPub = dhPub
        self.pn = pn
        self.n = n
    }

    /// Parses the wire form; `badHeader` for any length other than 41 or a version byte other than 0x01.
    init(bytes: Data) throws {
        guard bytes.count == MessageHeader.length else { throw KilitCryptoError.badHeader }
        let b: Data = Bytes.copy(bytes)
        guard b[0] == MessageHeader.version else { throw KilitCryptoError.badHeader }
        dhPub = Bytes.copy(b[1..<33])
        pn = BE.readU32(b, at: 33)
        n = BE.readU32(b, at: 37)
    }

    var bytes: Data {
        var out: Data = Data([MessageHeader.version])
        out.append(dhPub)
        out.append(BE.u32(pn))
        out.append(BE.u32(n))
        return out
    }
}

/// Everything a `RatchetEncrypt` produced (the vector files expose `mk`, `key`, `nonce` and `aad`).
struct RatchetEncryption {
    let header: MessageHeader
    let wire: Data
    let aad: Data
    let mk: Data
    let key: Data
    let nonce: Data
}

/// Signal Double Ratchet (§3.3) over value-type state. `decrypt` takes the state by value and returns
/// the advanced copy only on success, so a caller commits exactly the copy-commit discipline of §3.2b.
enum DoubleRatchet {
    /// `CONCAT(ad, sid, h) = u16BE(len(ad)) || ad || sid(8) || h`.
    static func concat(ad: Data, sid: Data, header: Data) -> Data {
        var out: Data = BE.u16(UInt16(ad.count))
        out.append(ad)
        out.append(sid)
        out.append(header)
        return out
    }

    /// `RatchetInitAlice`: draws the first `DHs` from `keySource` (second draw of the §3.8 order).
    static func initAlice(sk: Data, peerDhPub: Data, keySource: KeySource) throws -> RatchetState {
        guard peerDhPub.count == 32 else { throw KilitCryptoError.badKeyLength }
        let dhs: Curve25519.KeyAgreement.PrivateKey = keySource.x25519()
        let shared: Data = try X3DH.dh(dhs, peerDhPub)
        let (rk, cks) = KDF.kdfRK(rk: sk, dh: shared)
        return RatchetState(dhs: dhs, dhr: peerDhPub, rk: rk, cks: cks, ckr: nil)
    }

    /// `RatchetInitBob`: `DHs` is the SPK keypair (a copy; replaced by the first `DHRatchet`).
    static func initBob(sk: Data, dhs: Curve25519.KeyAgreement.PrivateKey) -> RatchetState {
        RatchetState(dhs: dhs, dhr: nil, rk: sk, cks: nil, ckr: nil)
    }

    /// `RatchetEncrypt`; `plaintext` is the padded block. The caller persists `state` before the wire leaves.
    static func encrypt(state: inout RatchetState, plaintext: Data, ad: Data, sid: Data) throws -> RatchetEncryption {
        guard let cks = state.cks else { throw KilitCryptoError.unknownSession }
        let (nextCK, mk) = KDF.kdfCK(ck: cks)
        let header: MessageHeader = MessageHeader(dhPub: state.dhsPub, pn: state.pn, n: state.ns)
        let aad: Data = concat(ad: ad, sid: sid, header: header.bytes)
        let (key, nonce) = KDF.messageKeys(mk: mk)
        let wire: Data = try AEAD.seal(plaintext: plaintext, key: key, nonce: nonce, aad: aad)
        state.cks = nextCK
        state.ns += 1
        return RatchetEncryption(header: header, wire: wire, aad: aad, mk: mk, key: key, nonce: nonce)
    }

    /// `RatchetDecrypt` on a copy. Throws `badKeyLength` for a header whose `dh_pub` is not 32 bytes
    /// (before any KDF), `tooManySkipped`, or `CryptoKitError.authenticationFailure`.
    static func decrypt(state: RatchetState, header: MessageHeader, wire: Data, ad: Data, sid: Data,
                        keySource: KeySource, now: UInt64) throws -> (plaintext: Data, state: RatchetState) {
        guard header.dhPub.count == 32 else { throw KilitCryptoError.badKeyLength }
        var s: RatchetState = state
        let aad: Data = concat(ad: ad, sid: sid, header: header.bytes)
        if let mk = s.takeSkipped(dh: header.dhPub, n: header.n) {
            let pt: Data = try open(mk: mk, wire: wire, aad: aad)
            return (pt, s)
        }
        if header.dhPub != s.dhr {
            try skipMessageKeys(&s, until: header.pn, now: now)
            try dhRatchet(&s, header: header, keySource: keySource)
        }
        try skipMessageKeys(&s, until: header.n, now: now)
        guard let ckr = s.ckr else { throw CryptoKitError.authenticationFailure }
        let (nextCK, mk) = KDF.kdfCK(ck: ckr)
        s.ckr = nextCK
        s.nr += 1
        let pt: Data = try open(mk: mk, wire: wire, aad: aad)
        return (pt, s)
    }

    private static func open(mk: Data, wire: Data, aad: Data) throws -> Data {
        let (key, nonce) = KDF.messageKeys(mk: mk)
        return try AEAD.open(wire: wire, key: key, nonce: nonce, aad: aad)
    }

    /// `SkipMessageKeys`: `Nr + MAX_SKIP < until` → `tooManySkipped`; stores the skipped keys with one
    /// `insertedAt` per call and runs the eviction.
    static func skipMessageKeys(_ s: inout RatchetState, until: UInt32, now: UInt64) throws {
        if s.nr &+ RatchetState.maxSkip < until { throw KilitCryptoError.tooManySkipped }
        guard var ckr = s.ckr, let dhr = s.dhr else { return }
        var entries: [SkippedKey] = []
        while s.nr < until {
            let (next, mk) = KDF.kdfCK(ck: ckr)
            entries.append(SkippedKey(dh: dhr, n: s.nr, mk: mk, insertedAt: now))
            ckr = next
            s.nr += 1
        }
        s.ckr = ckr
        if !entries.isEmpty {
            s.insertSkipped(entries, now: now)
        }
    }

    /// `DHRatchet`: two `KDF_RK` steps, a fresh `DHs` from `keySource` (one draw), old `DHs` released.
    static func dhRatchet(_ s: inout RatchetState, header: MessageHeader, keySource: KeySource) throws {
        s.pn = s.ns
        s.ns = 0
        s.nr = 0
        s.dhr = header.dhPub
        let oldDHs: Curve25519.KeyAgreement.PrivateKey = try s.dhsPriv.x25519PrivateKey()
        let shared1: Data = try X3DH.dh(oldDHs, header.dhPub)
        let (rk1, ckr) = KDF.kdfRK(rk: s.rk, dh: shared1)
        s.rk = rk1
        s.ckr = ckr
        let newDHs: Curve25519.KeyAgreement.PrivateKey = keySource.x25519()
        s.replaceDHs(with: newDHs)
        let shared2: Data = try X3DH.dh(newDHs, header.dhPub)
        let (rk2, cks) = KDF.kdfRK(rk: s.rk, dh: shared2)
        s.rk = rk2
        s.cks = cks
    }
}
