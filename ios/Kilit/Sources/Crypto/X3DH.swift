import Foundation
import CryptoKit

/// Copied into every outgoing envelope of an initiator session until the first peer message decrypts (§3.2).
struct PendingX3DH: Codable, Equatable {
    let ekPub: Data
    let spkId: UInt32
    let opkId: UInt32?

    enum CodingKeys: String, CodingKey {
        case ekPub = "ek_pub"
        case spkId = "spk_id"
        case opkId = "opk_id"
    }
}

/// The shared outputs of an X3DH run.
struct X3DHResult: Equatable {
    let sk: Data
    let ws: Data
    let sid: Data
    let ad: Data
}

/// Initiator-side outputs: the shared values plus what the session must remember.
struct X3DHInitiation {
    let result: X3DHResult
    let pending: PendingX3DH
    /// Bob's SPK public key (the first `DHr` of the initiator ratchet).
    let peerSpkPub: Data
}

enum X3DH {
    /// A bundle whose SPK is older than this is rejected with `staleSPK`.
    static let spkMaxAge: UInt64 = 21 * 86400

    /// `SID = SHA256("Kilit_SID_v1" || EK_A_pub)[0:8]`.
    static func sid(ek: Data) -> Data {
        Bytes.copy(KDF.sha256(Bytes.utf8(KilitInfo.sid) + ek).prefix(8))
    }

    /// `AD = IK_sig_A || IK_dh_A || IK_sig_B || IK_dh_B || u16BE(len(uA)) || uA || u16BE(len(uB)) || uB` (initiator first).
    static func ad(initiator: IdentityPublicKeys, initiatorUsername: String,
                   responder: IdentityPublicKeys, responderUsername: String) -> Data {
        let uA: Data = Bytes.utf8(initiatorUsername)
        let uB: Data = Bytes.utf8(responderUsername)
        var out: Data = Data()
        out.append(initiator.ikSig)
        out.append(initiator.ikDh)
        out.append(responder.ikSig)
        out.append(responder.ikDh)
        out.append(BE.u16(UInt16(uA.count)))
        out.append(uA)
        out.append(BE.u16(UInt16(uB.count)))
        out.append(uB)
        return out
    }

    /// X25519 with the two protocol checks: peer key exactly 32 bytes, output not all zero.
    static func dh(_ priv: Curve25519.KeyAgreement.PrivateKey, _ peerPub: Data) throws -> Data {
        guard peerPub.count == 32 else { throw KilitCryptoError.badKeyLength }
        let pub: Curve25519.KeyAgreement.PublicKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: peerPub)
        let shared: SharedSecret = try priv.sharedSecretFromKeyAgreement(with: pub)
        let out: Data = shared.withUnsafeBytes { Data($0) }
        guard !Bytes.isAllZero(out) else { throw KilitCryptoError.lowOrderPoint }
        return out
    }

    /// `SK = HKDF(0xFF*32 || DH1 || DH2 || DH3 [|| DH4], zeros, info, 32)`.
    static func deriveSK(dh1: Data, dh2: Data, dh3: Data, dh4: Data?) -> Data {
        var ikm: Data = Data(repeating: 0xFF, count: 32)
        ikm.append(dh1)
        ikm.append(dh2)
        ikm.append(dh3)
        if let d4 = dh4 { ikm.append(d4) }
        return KDF.hkdf(ikm: ikm, salt: KDF.zeros32, info: KilitInfo.x3dh, length: 32)
    }

    /// Identity binding (§3.2 step 1): the envelope's identity keys must be byte-equal to the record.
    static func checkIdentity(_ block: X3DHBlock, against record: IdentityPublicKeys) throws {
        guard block.ikSig == record.ikSig, block.ikDh == record.ikDh else { throw KilitCryptoError.identityMismatch }
    }

    private static func finish(sk: Data, ek: Data, ad: Data) -> X3DHResult {
        X3DHResult(sk: sk, ws: KDF.watermarkSecret(sk: sk), sid: sid(ek: ek), ad: ad)
    }

    /// Alice → Bob. Verifies the bundle, rejects a stale SPK, draws `EK` from `keySource` (the first draw
    /// of the §3.8 order; `RatchetInitAlice` draws next). The EK private key and the DH outputs die with the call.
    static func initiate(bundle: PrekeyBundle, local: IdentityKeys, localUsername: String,
                         now: UInt64, keySource: KeySource) throws -> X3DHInitiation {
        try BundleVerifier.verify(bundle)
        if now > bundle.spk.createdAt, now - bundle.spk.createdAt > spkMaxAge {
            throw KilitCryptoError.staleSPK
        }
        let ek: Curve25519.KeyAgreement.PrivateKey = keySource.x25519()
        let dh1: Data = try dh(local.agreement, bundle.spk.pub)
        let dh2: Data = try dh(ek, bundle.identity.ikDh)
        let dh3: Data = try dh(ek, bundle.spk.pub)
        var dh4: Data? = nil
        if let opkPub = bundle.opkPub {
            dh4 = try dh(ek, opkPub)
        }
        let sk: Data = deriveSK(dh1: dh1, dh2: dh2, dh3: dh3, dh4: dh4)
        let ad: Data = X3DH.ad(initiator: local.publicKeys, initiatorUsername: localUsername,
                               responder: bundle.identity, responderUsername: bundle.username)
        let ekPub: Data = ek.publicKey.rawRepresentation
        let pending: PendingX3DH = PendingX3DH(ekPub: ekPub, spkId: bundle.spk.id, opkId: bundle.opkPub == nil ? nil : bundle.opkId)
        return X3DHInitiation(result: finish(sk: sk, ek: ekPub, ad: ad), pending: pending, peerSpkPub: bundle.spk.pub)
    }

    /// Bob's mirror of the DHs for a `prekey` envelope from `from`. The caller has already resolved
    /// `spk`/`opk` by id (`spk_gone`/`opk_gone` otherwise). Verifies the identity binding in Go's order
    /// (`ik_sig` import check, `ik_dh` length, `ik_bind_sig`) and the `ek` length.
    static func respond(x3dh: X3DHBlock, from: String, local: IdentityKeys, localUsername: String,
                        spk: SignedPrekey, opk: OneTimePrekey?) throws -> X3DHResult {
        try BundleVerifier.verifyIdentityBinding(x3dh.identity, ikBindSig: x3dh.ikBindSig)
        guard x3dh.ek.count == 32 else { throw KilitCryptoError.badKeyLength }
        let spkPriv: Curve25519.KeyAgreement.PrivateKey = try spk.privateKey.x25519PrivateKey()
        let dh1: Data = try dh(spkPriv, x3dh.ikDh)
        let dh2: Data = try dh(local.agreement, x3dh.ek)
        let dh3: Data = try dh(spkPriv, x3dh.ek)
        var dh4: Data? = nil
        if let o = opk {
            let opkPriv: Curve25519.KeyAgreement.PrivateKey = try o.privateKey.x25519PrivateKey()
            dh4 = try dh(opkPriv, x3dh.ek)
        }
        let sk: Data = deriveSK(dh1: dh1, dh2: dh2, dh3: dh3, dh4: dh4)
        let peer: IdentityPublicKeys = IdentityPublicKeys(ikSig: x3dh.ikSig, ikDh: x3dh.ikDh)
        let ad: Data = X3DH.ad(initiator: peer, initiatorUsername: from,
                               responder: local.publicKeys, responderUsername: localUsername)
        return finish(sk: sk, ek: x3dh.ek, ad: ad)
    }
}
