import XCTest
import CryptoKit
@testable import Kilit

final class X3DHVectorTests: XCTestCase {
    private var root: [String: Any] = [:]
    private var inputs: [String: Any] = [:]
    private var alice: IdentityKeys = IdentityKeys()
    private var bob: IdentityKeys = IdentityKeys()
    private var bobSPK: SignedPrekey = SignedPrekey(id: 0, createdAt: 0, privateKey: Curve25519.KeyAgreement.PrivateKey())
    private var bobOPKs: [OneTimePrekey] = []
    private var ekPriv: Data = Data()

    override func setUpWithError() throws {
        root = try Vec.object(KilitVectors.x3dh)
        inputs = try Vec.dict(root, "inputs")
        let a: [String: Any] = try Vec.dict(inputs, "alice")
        let b: [String: Any] = try Vec.dict(inputs, "bob")
        alice = try IdentityKeys(sigSeed: try Vec.hex(a, "ik_sig_seed"), dhPriv: try Vec.hex(a, "ik_dh_priv"))
        bob = try IdentityKeys(sigSeed: try Vec.hex(b, "ik_sig_seed"), dhPriv: try Vec.hex(b, "ik_dh_priv"))
        ekPriv = try Vec.hex(a, "ek_priv")
        bobSPK = try SignedPrekey(id: UInt32(try Vec.int(b, "spk_id")), createdAt: try Vec.u64(b, "spk_created_at"),
                                  rawPrivate: try Vec.hex(b, "spk_priv"))
        bobOPKs = []
        for o in try Vec.dicts(b, "opks") {
            bobOPKs.append(try OneTimePrekey(id: UInt32(try Vec.int(o, "id")), rawPrivate: try Vec.hex(o, "priv")))
        }
    }

    private func bundle(withOPK: Bool, spkCreatedAt: UInt64? = nil) throws -> PrekeyBundle {
        var spk: SignedPrekey = bobSPK
        if let c = spkCreatedAt {
            spk = SignedPrekey(id: bobSPK.id, createdAt: c, privateKey: try bobSPK.privateKey.x25519PrivateKey())
        }
        let signedSPK: SignedPrekeyPublic = try spk.signed(by: bob)
        let opk: OneTimePrekey? = withOPK ? bobOPKs.first : nil
        return PrekeyBundle(username: try Vec.str(try Vec.dict(inputs, "bob"), "username"),
                            identity: bob.publicKeys, ikBindSig: try bob.ikBindSig(), spk: signedSPK,
                            opkId: opk?.id, opkPub: opk?.publicKey)
    }

    func testPublicKeys() throws {
        let pub: [String: Any] = try Vec.dict(root, "public")
        let a: [String: Any] = try Vec.dict(pub, "alice")
        let b: [String: Any] = try Vec.dict(pub, "bob")
        XCTAssertEqual(alice.publicKeys.ikSig, try Vec.hex(a, "ik_sig"))
        XCTAssertEqual(alice.publicKeys.ikDh, try Vec.hex(a, "ik_dh"))
        let ek = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: ekPriv)
        XCTAssertEqual(ek.publicKey.rawRepresentation, try Vec.hex(a, "ek"))
        XCTAssertEqual(bob.publicKeys.ikSig, try Vec.hex(b, "ik_sig"))
        XCTAssertEqual(bob.publicKeys.ikDh, try Vec.hex(b, "ik_dh"))
        XCTAssertEqual(bobSPK.publicKey, try Vec.hex(b, "spk"))
        for o in try Vec.dicts(b, "opks") {
            let id: UInt32 = UInt32(try Vec.int(o, "id"))
            let match: OneTimePrekey? = bobOPKs.first(where: { $0.id == id })
            XCTAssertEqual(match?.publicKey, try Vec.hex(o, "pub"))
        }
    }

    /// Every signed message is rebuilt byte-exact, Go's signature verifies, and so does a fresh one.
    func testSignatures() throws {
        let sigs: [String: Any] = try Vec.dict(root, "signatures")
        let deviceId: String = try Vec.str(inputs, "device_id")
        let nonce: Data = try Vec.hex(inputs, "nonce")
        let ts: UInt64 = try Vec.u64(inputs, "ts")
        let origin: String = try Vec.str(inputs, "server_origin")
        let aliceName: String = try Vec.str(try Vec.dict(inputs, "alice"), "username")
        let b: [String: Any] = try Vec.dict(inputs, "bob")
        var opkList: [(id: UInt32, pub: Data)] = []
        for o in bobOPKs { opkList.append((o.id, o.publicKey)) }
        let expected: [String: Data] = [
            "ik_bind_sig": SignedMessages.ikBind(ikDh: bob.publicKeys.ikDh),
            "spk_sig": SignedMessages.spk(id: bobSPK.id, createdAt: bobSPK.createdAt, pub: bobSPK.publicKey),
            "opks_sig": SignedMessages.opkBatch(opkList),
            "register_proof": SignedMessages.registerProof(username: aliceName, ikDh: alice.publicKeys.ikDh, deviceId: deviceId,
                                                           nonce: nonce, ts: ts, serverOrigin: origin),
            "login_sig": SignedMessages.login(username: aliceName, nonce: nonce, ts: ts, deviceId: deviceId, serverOrigin: origin),
            "delete_sig": SignedMessages.delete(username: aliceName, nonce: nonce, ts: ts, serverOrigin: origin),
        ]
        XCTAssertTrue(Canonical.isDeviceId(deviceId))
        XCTAssertEqual(Canonical.username(try Vec.str(b, "username")), "bob")
        for (name, msg) in expected {
            let entry: [String: Any] = try Vec.dict(sigs, name)
            let signerName: String = try Vec.str(entry, "signer")
            let signer: IdentityKeys = signerName == "alice" ? alice : bob
            XCTAssertEqual(try Vec.hex(entry, "msg"), msg, "\(name) message bytes")
            let goSig: Data = try Vec.hex(entry, "sig")
            XCTAssertNoThrow(try Ed25519Strict.verify(signature: goSig, message: msg, publicKey: signer.publicKeys.ikSig), name)
            let own: Data = try signer.sign(msg)
            XCTAssertNoThrow(try Ed25519Strict.verify(signature: own, message: msg, publicKey: signer.publicKeys.ikSig), name)
            let other: IdentityKeys = signerName == "alice" ? bob : alice
            XCTAssertThrowsError(try Ed25519Strict.verify(signature: goSig, message: msg, publicKey: other.publicKeys.ikSig))
        }
    }

    func testInitiatorAndResponderAgree() throws {
        let x: [String: Any] = try Vec.dict(root, "x3dh")
        let now: UInt64 = try Vec.u64(inputs, "ts")
        let aliceName: String = try Vec.str(try Vec.dict(inputs, "alice"), "username")
        let bobName: String = try Vec.str(try Vec.dict(inputs, "bob"), "username")
        let ks: ScriptedKeySource = ScriptedKeySource(keys: [ekPriv])
        let init1: X3DHInitiation = try X3DH.initiate(bundle: try bundle(withOPK: true), local: alice,
                                                      localUsername: aliceName, now: now, keySource: ks)
        XCTAssertEqual(ks.remainingKeys, 0)
        XCTAssertEqual(init1.result.sk, try Vec.hex(x, "sk"))
        XCTAssertEqual(init1.result.ws, try Vec.hex(x, "ws"))
        XCTAssertEqual(init1.result.sid, try Vec.hex(x, "sid"))
        XCTAssertEqual(init1.result.ad, try Vec.hex(x, "ad"))
        XCTAssertEqual(init1.pending.opkId, bobOPKs.first?.id)
        XCTAssertEqual(init1.pending.spkId, bobSPK.id)
        // Individual DH outputs.
        let ek = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: ekPriv)
        XCTAssertEqual(try X3DH.dh(alice.agreement, bobSPK.publicKey), try Vec.hex(x, "dh1"))
        XCTAssertEqual(try X3DH.dh(ek, bob.publicKeys.ikDh), try Vec.hex(x, "dh2"))
        XCTAssertEqual(try X3DH.dh(ek, bobSPK.publicKey), try Vec.hex(x, "dh3"))
        if let opk = bobOPKs.first {
            XCTAssertEqual(try X3DH.dh(ek, opk.publicKey), try Vec.hex(x, "dh4"))
        }
        // Responder with OPK.
        let block: X3DHBlock = X3DHBlock(ikSig: alice.publicKeys.ikSig, ikDh: alice.publicKeys.ikDh,
                                         ikBindSig: try alice.ikBindSig(), ek: init1.pending.ekPub,
                                         spkId: bobSPK.id, opkId: init1.pending.opkId)
        let resp: X3DHResult = try X3DH.respond(x3dh: block, from: aliceName, local: bob, localUsername: bobName,
                                                spk: bobSPK, opk: bobOPKs.first)
        XCTAssertEqual(resp, init1.result)
        // Without OPK: sk differs, ad unchanged.
        let ks2: ScriptedKeySource = ScriptedKeySource(keys: [ekPriv])
        let init2: X3DHInitiation = try X3DH.initiate(bundle: try bundle(withOPK: false), local: alice,
                                                      localUsername: aliceName, now: now, keySource: ks2)
        XCTAssertEqual(init2.result.sk, try Vec.hex(x, "sk_no_opk"))
        XCTAssertEqual(init2.result.ad, try Vec.hex(x, "ad"))
        XCTAssertNil(init2.pending.opkId)
        let block2: X3DHBlock = X3DHBlock(ikSig: alice.publicKeys.ikSig, ikDh: alice.publicKeys.ikDh,
                                          ikBindSig: try alice.ikBindSig(), ek: init2.pending.ekPub,
                                          spkId: bobSPK.id, opkId: nil)
        let resp2: X3DHResult = try X3DH.respond(x3dh: block2, from: aliceName, local: bob, localUsername: bobName,
                                                 spk: bobSPK, opk: nil)
        XCTAssertEqual(resp2, init2.result)
    }

    func testFirstEnvelopeParses() throws {
        let env: [String: Any] = try Vec.dict(root, "first_envelope")
        let parsed: ParsedEnvelope = try EnvelopeParser.parse(try Vec.jsonBytes(env))
        XCTAssertEqual(parsed.outer.kind, .prekey)
        XCTAssertEqual(parsed.sid, try Vec.hex(try Vec.dict(root, "x3dh"), "sid"))
        XCTAssertEqual(parsed.outer.x3dh?.identity, alice.publicKeys)
        XCTAssertEqual(parsed.outer.x3dh?.spkId, bobSPK.id)
        XCTAssertEqual(parsed.header.dhPub.count, 32)
        XCTAssertGreaterThanOrEqual(parsed.outer.ct.count, Padding.minWire)
        // Round trip through the Codable keeps every field.
        let again: ParsedEnvelope = try EnvelopeParser.parse(try parsed.outer.encoded())
        XCTAssertEqual(again, parsed)
    }

    func testNegatives() throws {
        let now: UInt64 = try Vec.u64(inputs, "ts")
        let aliceName: String = try Vec.str(try Vec.dict(inputs, "alice"), "username")
        let bobName: String = try Vec.str(try Vec.dict(inputs, "bob"), "username")
        for n in try Vec.dicts(root, "negative") {
            let name: String = try Vec.str(n, "name")
            let expected: String = try Vec.str(n, "error")
            switch name {
            case "ik_dh_swapped":
                // A prekey envelope whose ik_dh is another key than the contact record's → identityMismatch.
                let other: IdentityKeys = IdentityKeys()
                let bind: Data = try other.ikBindSig()
                let block: X3DHBlock = X3DHBlock(ikSig: other.publicKeys.ikSig, ikDh: other.publicKeys.ikDh,
                                                 ikBindSig: bind, ek: Bytes.random(32), spkId: bobSPK.id, opkId: nil)
                XCTAssertNoThrow(try X3DH.checkIdentity(block, against: other.publicKeys))
                let err: String? = Vec.errorName { try X3DH.checkIdentity(block, against: alice.publicKeys) }
                XCTAssertEqual(err, expected, name)
            case "bad_bind_sig":
                let other: IdentityKeys = IdentityKeys()
                let bad: Data = try other.ikBindSig()
                let block: X3DHBlock = X3DHBlock(ikSig: alice.publicKeys.ikSig, ikDh: alice.publicKeys.ikDh,
                                                 ikBindSig: bad, ek: Bytes.random(32), spkId: bobSPK.id, opkId: nil)
                let err: String? = Vec.errorName {
                    _ = try X3DH.respond(x3dh: block, from: aliceName, local: bob, localUsername: bobName, spk: bobSPK, opk: nil)
                }
                XCTAssertEqual(err, expected, name)
            case "stale_spk":
                let createdAt: UInt64 = try Vec.u64(n, "spk_created_at")
                let b: PrekeyBundle = try bundle(withOPK: true, spkCreatedAt: createdAt)
                let err: String? = Vec.errorName {
                    _ = try X3DH.initiate(bundle: b, local: alice, localUsername: aliceName, now: now,
                                          keySource: ScriptedKeySource(keys: [ekPriv]))
                }
                XCTAssertEqual(err, expected, name)
            default:
                XCTFail("unknown negative \(name)")
            }
        }
    }

    func testBundleVerifierRejectsTamperedSPKSig() throws {
        let good: PrekeyBundle = try bundle(withOPK: true)
        XCTAssertNoThrow(try BundleVerifier.verify(good))
        var sig: Data = good.spk.sig
        sig[sig.startIndex] ^= 0x01
        let bad: PrekeyBundle = PrekeyBundle(username: good.username, identity: good.identity, ikBindSig: good.ikBindSig,
                                             spk: SignedPrekeyPublic(id: good.spk.id, pub: good.spk.pub, sig: sig, createdAt: good.spk.createdAt),
                                             opkId: good.opkId, opkPub: good.opkPub)
        XCTAssertThrowsError(try BundleVerifier.verify(bad)) { e in
            XCTAssertEqual(KilitErrorName.of(e), "badSignature")
        }
    }
}
