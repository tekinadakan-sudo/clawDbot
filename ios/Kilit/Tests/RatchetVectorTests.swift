import XCTest
import CryptoKit
@testable import Kilit

// MARK: - Direct ratchet-API ops of the scenario runner

extension ScenarioRunner {
    /// Finds the ratchet behind a label: a direct-API session, else the app session (whose state is committed back).
    private func withRatchet(_ s: ScenarioSide, label: String, _ body: (inout RawRatchet) throws -> Void) throws {
        if var raw = s.rawSessions[label] {
            try body(&raw)
            s.rawSessions[label] = raw
            return
        }
        let sid: Data = try s.sid(forLabel: label)
        guard let i = s.sessions.index(of: sid) else { throw VecError("\(context): no session \(label)") }
        var raw: RawRatchet = RawRatchet(sid: sid, ad: s.sessions.sessions[i].ad, state: s.sessions.sessions[i].state)
        try body(&raw)
        s.sessions.sessions[i].state = raw.state
    }

    func opInitAlice(_ op: [String: Any]) throws {
        let s: ScenarioSide = try side(of: op)
        let sid: Data = try Vec.hex(op, "sid")
        // `X3DH.initiate` draws EK before `RatchetInitAlice` draws DHs (§3.8): consume the EK entry when the
        // scripted list starts with it (its sid matches the op), so the first DHs is the second entry.
        if let next = s.keySource.peekNextPublicKey(), X3DH.sid(ek: next) == sid {
            _ = s.keySource.x25519()
        }
        let state: RatchetState = try DoubleRatchet.initAlice(sk: try Vec.hex(op, "sk"), peerDhPub: try Vec.hex(op, "peer_pub"),
                                                              keySource: s.keySource)
        let label: String = try Vec.str(op, "session")
        s.rawSessions[label] = RawRatchet(sid: sid, ad: try Vec.hex(op, "ad"), state: state)
        s.labels[label] = sid
        if let expected = Vec.optDict(op, "state_after") { try checkState(state, expected) }
    }

    func opInitBob(_ op: [String: Any]) throws {
        let s: ScenarioSide = try side(of: op)
        let sid: Data = try Vec.hex(op, "sid")
        let dhs: Curve25519.KeyAgreement.PrivateKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: try Vec.hex(op, "dhs_priv"))
        let state: RatchetState = DoubleRatchet.initBob(sk: try Vec.hex(op, "sk"), dhs: dhs)
        let label: String = try Vec.str(op, "session")
        s.rawSessions[label] = RawRatchet(sid: sid, ad: try Vec.hex(op, "ad"), state: state)
        s.labels[label] = sid
        if let expected = Vec.optDict(op, "state_after") { try checkState(state, expected) }
    }

    func opEncrypt(_ op: [String: Any]) throws {
        let s: ScenarioSide = try side(of: op)
        let label: String = Vec.optStr(op, "label") ?? ""
        try withRatchet(s, label: try Vec.str(op, "session")) { raw in
            let enc: RatchetEncryption = try DoubleRatchet.encrypt(state: &raw.state, plaintext: try Vec.hex(op, "pt_padded"),
                                                                   ad: raw.ad, sid: raw.sid)
            XCTAssertEqual(enc.header.bytes, try Vec.hex(op, "hdr"), "\(self.context) \(label): hdr")
            XCTAssertEqual(enc.aad, try Vec.hex(op, "aad"), "\(self.context) \(label): aad")
            XCTAssertEqual(enc.mk, try Vec.hex(op, "mk"), "\(self.context) \(label): mk")
            XCTAssertEqual(enc.key, try Vec.hex(op, "key"), "\(self.context) \(label): key")
            XCTAssertEqual(enc.nonce, try Vec.hex(op, "nonce"), "\(self.context) \(label): nonce")
            XCTAssertEqual(enc.wire, try Vec.hex(op, "wire"), "\(self.context) \(label): wire")
            // The AAD carries the sid between the length-prefixed AD and the header.
            XCTAssertEqual(enc.aad, DoubleRatchet.concat(ad: raw.ad, sid: raw.sid, header: enc.header.bytes))
            if let expected = Vec.optDict(op, "state_after") { try self.checkState(raw.state, expected) }
        }
    }

    func opDecrypt(_ op: [String: Any]) throws {
        let s: ScenarioSide = try side(of: op)
        let label: String = Vec.optStr(op, "label") ?? ""
        try withRatchet(s, label: try Vec.str(op, "session")) { raw in
            let header: MessageHeader = try MessageHeader(bytes: try Vec.hex(op, "hdr"))
            let r = try DoubleRatchet.decrypt(state: raw.state, header: header, wire: try Vec.hex(op, "wire"), ad: raw.ad,
                                              sid: raw.sid, keySource: s.keySource, now: self.clock)
            XCTAssertEqual(r.plaintext, try Vec.hex(op, "pt_padded"), "\(self.context) \(label): plaintext")
            raw.state = r.state
            if let expected = Vec.optDict(op, "state_after") { try self.checkState(raw.state, expected) }
        }
    }

    func opDecryptExpectError(_ op: [String: Any]) throws {
        let s: ScenarioSide = try side(of: op)
        let expected: String = try Vec.str(op, "error")
        try withRatchet(s, label: try Vec.str(op, "session")) { raw in
            let before: RatchetState = raw.state
            let wire: Data = try Vec.hex(op, "wire")
            let name: String? = Vec.errorName {
                let header: MessageHeader
                if let hdr = try Vec.optHex(op, "hdr") {
                    header = try MessageHeader(bytes: hdr)
                } else {
                    header = MessageHeader(dhPub: try Vec.hex(op, "dh_pub"), pn: UInt32(Vec.optInt(op, "pn") ?? 0),
                                           n: UInt32(Vec.optInt(op, "n") ?? 0))
                }
                _ = try DoubleRatchet.decrypt(state: raw.state, header: header, wire: wire, ad: raw.ad, sid: raw.sid,
                                              keySource: s.keySource, now: self.clock)
            }
            XCTAssertEqual(name, expected, "\(self.context): expected error")
            XCTAssertEqual(raw.state, before, "\(self.context): state unchanged")
        }
    }

    /// STATE = {rk, cks|null, ckr|null, ns, nr, pn, dhs_priv, dhr|null, mkskipped:[{dh,n,mk}] | mkskipped_count + mkskipped_sha256}.
    func checkState(_ state: RatchetState, _ e: [String: Any]) throws {
        XCTAssertEqual(state.rk, try Vec.hex(e, "rk"), "\(context): rk")
        XCTAssertEqual(state.cks, try Vec.optHex(e, "cks"), "\(context): cks")
        XCTAssertEqual(state.ckr, try Vec.optHex(e, "ckr"), "\(context): ckr")
        XCTAssertEqual(Int(state.ns), try Vec.int(e, "ns"), "\(context): ns")
        XCTAssertEqual(Int(state.nr), try Vec.int(e, "nr"), "\(context): nr")
        XCTAssertEqual(Int(state.pn), try Vec.int(e, "pn"), "\(context): pn")
        XCTAssertEqual(state.dhsPriv.dataCopy, try Vec.hex(e, "dhs_priv"), "\(context): dhs_priv")
        XCTAssertEqual(state.dhr, try Vec.optHex(e, "dhr"), "\(context): dhr")
        if let list = e["mkskipped"] as? [[String: Any]] {
            var expected: Set<String> = []
            for k in list {
                let dh: String = try Vec.str(k, "dh")
                let n: Int = try Vec.int(k, "n")
                let mk: String = try Vec.str(k, "mk")
                expected.insert("\(dh):\(n):\(mk)")
            }
            let actual: Set<String> = Set(state.mkskipped.map { "\($0.dh.hex):\($0.n):\($0.mk.hex)" })
            XCTAssertEqual(actual, expected, "\(context): mkskipped")
        } else if let count = Vec.optInt(e, "mkskipped_count") {
            XCTAssertEqual(state.mkskipped.count, count, "\(context): mkskipped_count")
            XCTAssertEqual(state.mkskippedSHA256(), try Vec.hex(e, "mkskipped_sha256"), "\(context): mkskipped_sha256")
        }
    }
}

// MARK: - RatchetVectorTests (§5.12)

final class RatchetVectorTests: XCTestCase {
    func testBasicScenario() throws {
        let r: ScenarioRunner = try Scenarios.run("basic")
        XCTAssertFalse(r.a.rawSessions.isEmpty, "basic drives the ratchet through the direct-API ops")
    }

    func testEvictionScenario() throws {
        _ = try Scenarios.run("eviction", in: KilitVectors.eviction)
    }

    // Unit-level checks that do not need the vector file.

    private func pair() throws -> (alice: RatchetState, bob: RatchetState, ad: Data, sid: Data, ksA: KeySource, ksB: KeySource) {
        let sk: Data = Bytes.random(32)
        let spk: Curve25519.KeyAgreement.PrivateKey = Curve25519.KeyAgreement.PrivateKey()
        let ksA: RandomKeySource = RandomKeySource()
        let ksB: RandomKeySource = RandomKeySource()
        let alice: RatchetState = try DoubleRatchet.initAlice(sk: sk, peerDhPub: spk.publicKey.rawRepresentation, keySource: ksA)
        let bob: RatchetState = DoubleRatchet.initBob(sk: sk, dhs: spk)
        return (alice, bob, Bytes.random(40), Bytes.random(8), ksA, ksB)
    }

    func testRoundTripSkippedKeysAndSPKRemoval() throws {
        var p = try pair()
        let spkPriv: Data = p.bob.dhsPriv.dataCopy
        var sent: [(MessageHeader, Data)] = []
        for i in 0..<4 {
            let pt: Data = try Padding.pad(Data("m\(i)".utf8))
            let enc: RatchetEncryption = try DoubleRatchet.encrypt(state: &p.alice, plaintext: pt, ad: p.ad, sid: p.sid)
            sent.append((enc.header, enc.wire))
        }
        // Deliver 3 before 1 and 2: skipped keys are stored, then consumed and deleted.
        let d3 = try DoubleRatchet.decrypt(state: p.bob, header: sent[3].0, wire: sent[3].1, ad: p.ad, sid: p.sid, keySource: p.ksB, now: 100)
        XCTAssertEqual(try Padding.unpad(d3.plaintext), Data("m3".utf8))
        XCTAssertEqual(d3.state.mkskipped.count, 3)
        XCTAssertFalse(d3.state.contains(secret: spkPriv), "SPK private key gone after the first DH ratchet")
        XCTAssertTrue(p.bob.contains(secret: spkPriv), "the pre-decrypt copy is the caller's to drop")
        p.bob = d3.state
        let d1 = try DoubleRatchet.decrypt(state: p.bob, header: sent[1].0, wire: sent[1].1, ad: p.ad, sid: p.sid, keySource: p.ksB, now: 100)
        XCTAssertEqual(d1.state.mkskipped.count, 2)
        p.bob = d1.state
        // Bob replies (no DH step for Bob's first send after the ratchet), Alice decrypts and performs a DH step.
        let reply: RatchetEncryption = try DoubleRatchet.encrypt(state: &p.bob, plaintext: try Padding.pad(Data("r".utf8)), ad: p.ad, sid: p.sid)
        let dA = try DoubleRatchet.decrypt(state: p.alice, header: reply.header, wire: reply.wire, ad: p.ad, sid: p.sid, keySource: p.ksA, now: 100)
        XCTAssertEqual(try Padding.unpad(dA.plaintext), Data("r".utf8))
        XCTAssertEqual(dA.state.pn, 4)
        XCTAssertEqual(dA.state.ns, 0)
        // Wrong sid in the AAD → authenticationFailure, nothing committed.
        XCTAssertThrowsError(try DoubleRatchet.decrypt(state: p.bob, header: sent[0].0, wire: sent[0].1, ad: p.ad, sid: Bytes.random(8), keySource: p.ksB, now: 100)) { e in
            XCTAssertEqual(KilitErrorName.of(e), "authenticationFailure")
        }
    }

    func testErrorsAndStateUnchanged() throws {
        let p = try pair()
        var alice: RatchetState = p.alice
        let enc: RatchetEncryption = try DoubleRatchet.encrypt(state: &alice, plaintext: try Padding.pad(Data("x".utf8)), ad: p.ad, sid: p.sid)
        // Tamper → authenticationFailure.
        var bad: Data = enc.wire
        bad[bad.startIndex + bad.count - 1] ^= 0x01
        let e1: String? = Vec.errorName { _ = try DoubleRatchet.decrypt(state: p.bob, header: enc.header, wire: bad, ad: p.ad, sid: p.sid, keySource: p.ksB, now: 1) }
        XCTAssertEqual(e1, "authenticationFailure")
        // n jump of 1001 → tooManySkipped.
        let far: MessageHeader = MessageHeader(dhPub: enc.header.dhPub, pn: 0, n: 1001)
        let e2: String? = Vec.errorName { _ = try DoubleRatchet.decrypt(state: p.bob, header: far, wire: enc.wire, ad: p.ad, sid: p.sid, keySource: p.ksB, now: 1) }
        XCTAssertEqual(e2, "tooManySkipped")
        let ok: MessageHeader = MessageHeader(dhPub: enc.header.dhPub, pn: 0, n: 1000)
        let e2b: String? = Vec.errorName { _ = try DoubleRatchet.decrypt(state: p.bob, header: ok, wire: enc.wire, ad: p.ad, sid: p.sid, keySource: p.ksB, now: 1) }
        XCTAssertEqual(e2b, "authenticationFailure", "1000 skipped is allowed; the tag then fails")
        // 31-byte dh_pub fed directly → badKeyLength before any KDF.
        let short: MessageHeader = MessageHeader(dhPub: Bytes.copy(enc.header.dhPub.prefix(31)), pn: 0, n: 0)
        let e3: String? = Vec.errorName { _ = try DoubleRatchet.decrypt(state: p.bob, header: short, wire: enc.wire, ad: p.ad, sid: p.sid, keySource: p.ksB, now: 1) }
        XCTAssertEqual(e3, "badKeyLength")
        // The same bytes at the envelope level are a 40-byte hdr → badHeader; hdr[0] = 0x02 → badHeader.
        XCTAssertEqual(Vec.errorName { _ = try MessageHeader(bytes: short.bytes.prefix(40)) }, "badHeader")
        var v2: Data = enc.header.bytes
        v2[v2.startIndex] = 0x02
        XCTAssertEqual(Vec.errorName { _ = try MessageHeader(bytes: v2) }, "badHeader")
        XCTAssertEqual(try MessageHeader(bytes: enc.header.bytes), enc.header)
        XCTAssertEqual(enc.header.bytes.count, 41)
        XCTAssertEqual(enc.header.bytes[enc.header.bytes.startIndex], 0x01)
        // Encrypting without a sending chain (fresh Bob) is refused.
        var bob: RatchetState = p.bob
        XCTAssertThrowsError(try DoubleRatchet.encrypt(state: &bob, plaintext: Data(repeating: 0, count: 256), ad: p.ad, sid: p.sid))
    }

    func testEvictionOrderAndTies() {
        var s: RatchetState = DoubleRatchet.initBob(sk: Data(repeating: 1, count: 32), dhs: Curve25519.KeyAgreement.PrivateKey())
        func key(_ chain: UInt8, _ n: UInt32, _ t: UInt64) -> SkippedKey {
            SkippedKey(dh: Data(repeating: chain, count: 32), n: n, mk: Data(repeating: UInt8(n & 0xFF), count: 32), insertedAt: t)
        }
        // 6 chains: chain 0x06 inserted with the same insertedAt as chain 0x05 (tie → dh bytes decide).
        for c: UInt8 in 1...5 { s.insertSkipped([key(c, 0, UInt64(c))], now: 10) }
        s.insertSkipped([key(6, 0, 5)], now: 10)
        XCTAssertEqual(Set(s.mkskipped.map { $0.dh }).count, 5)
        XCTAssertNil(s.skippedIndex(dh: Data(repeating: 1, count: 32), n: 0), "chain with the smallest newest entry dropped")
        XCTAssertNotNil(s.skippedIndex(dh: Data(repeating: 5, count: 32), n: 0))
        XCTAssertNotNil(s.skippedIndex(dh: Data(repeating: 6, count: 32), n: 0))
        // Age: entries older than 7 days go first.
        let late: UInt64 = 10 + 7 * 86400 + 1
        s.insertSkipped([key(7, 0, late)], now: late)
        XCTAssertEqual(s.mkskipped.count, 1)
        // Count: more than 2000 → the first entries in (insertedAt, dh, n) order are dropped.
        var many: [SkippedKey] = []
        for n in 0..<2100 { many.append(key(9, UInt32(n), 100)) }
        s.insertSkipped(many, now: 100)
        XCTAssertEqual(s.mkskipped.count, 2000)
        XCTAssertNotNil(s.skippedIndex(dh: Data(repeating: 7, count: 32), n: 0), "newer insertedAt survives")
        XCTAssertNil(s.skippedIndex(dh: Data(repeating: 9, count: 32), n: 100))
        XCTAssertNotNil(s.skippedIndex(dh: Data(repeating: 9, count: 32), n: 101))
        // Used → deleted; hash form is order-independent.
        let h1: Data = s.mkskippedSHA256()
        s.mkskipped.shuffle()
        XCTAssertEqual(s.mkskippedSHA256(), h1)
        XCTAssertNotNil(s.takeSkipped(dh: Data(repeating: 9, count: 32), n: 101))
        XCTAssertNil(s.takeSkipped(dh: Data(repeating: 9, count: 32), n: 101))
        XCTAssertEqual(s.mkskipped.count, 1999)
    }

    func testStateCodableRoundTrip() throws {
        let p = try pair()
        var alice: RatchetState = p.alice
        _ = try DoubleRatchet.encrypt(state: &alice, plaintext: Data(repeating: 0, count: 256), ad: p.ad, sid: p.sid)
        alice.insertSkipped([SkippedKey(dh: Data(repeating: 3, count: 32), n: 2, mk: Data(repeating: 4, count: 32), insertedAt: 7)], now: 7)
        let data: Data = try KilitJSON.encoder().encode(alice)
        let back: RatchetState = try KilitJSON.decoder().decode(RatchetState.self, from: data)
        XCTAssertEqual(back, alice)
        let json: String = String(decoding: data, as: UTF8.self)
        XCTAssertTrue(json.contains("\"dhs_priv\""))
        XCTAssertTrue(json.contains("\"inserted_at\""))
    }
}
