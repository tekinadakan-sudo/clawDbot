import XCTest
import CryptoKit
@testable import Kilit

// MARK: - Scenario op dispatcher (§3.9 step ops)

extension ScenarioRunner {
    func run(_ steps: [[String: Any]]) throws {
        for (i, op) in steps.enumerated() {
            stepIndex = i
            try perform(op)
        }
    }

    func perform(_ op: [String: Any]) throws {
        let kind: String = try Vec.str(op, "op")
        switch kind {
        case "init_alice": try opInitAlice(op)
        case "init_bob": try opInitBob(op)
        case "encrypt": try opEncrypt(op)
        case "decrypt": try opDecrypt(op)
        case "decrypt_expect_error": try opDecryptExpectError(op)
        case "advance_clock": clock += try Vec.u64(op, "seconds")
        case "deliver_envelope": try opDeliver(op)
        case "send": try opSend(op)
        case "expect_sending_sid": try checkSendingSid(op)
        case "expect_messages": try opExpectMessages(op)
        case "rotate_identity": try opRotateIdentity(op)
        case "accept_message_request": try opAcceptMessageRequest(op)
        case "lookup_result": try opLookupResult(op)
        case "consumed_report": try opConsumedReport(op)
        case "inject_rollback": try opInjectRollback(op)
        case "delete_session": try opDeleteSession(op)
        case "accept_key_change": try opAcceptKeyChange(op)
        case "expect_mkskipped": try opExpectMKSkipped(op)
        case "expect_state_excludes": try opExpectStateExcludes(op)
        default: throw VecError("\(context): unknown op \(kind)")
        }
    }

    // MARK: app-level ops

    func opDeliver(_ op: [String: Any]) throws {
        let s: ScenarioSide = try side(of: op)
        try applyTimers(s)
        let msgId: String = try Vec.str(op, "msg_id")
        guard let envObj = op["envelope"] else { throw VecError("\(context): deliver_envelope without envelope") }
        let bytes: Data
        if let str = envObj as? String {
            bytes = Data(str.utf8)
        } else {
            bytes = try Vec.jsonBytes(envObj)
        }
        let before: PeerSessions = s.sessions
        let result: InboundResult = try deliver(to: s, msgId: msgId, envelope: bytes)
        let expect: String = try Vec.str(op, "expect")
        let reason: String? = Vec.optStr(op, "reason")
        let outcome: InboundOutcome = result.outcome
        if expect == "classified", reason == InboundReason.alreadyProcessed.rawValue {
            XCTAssertEqual(outcome, .alreadyProcessed, context)
        } else if expect == "already_processed" {
            XCTAssertEqual(outcome, .alreadyProcessed, context)
        } else {
            XCTAssertEqual(outcome.kindString, expect, "\(context): outcome \(outcome)")
            if let r = reason {
                XCTAssertEqual(outcome.reasonString, r, "\(context): reason")
            }
        }
        if outcome.kindString == "classified" || outcome == .alreadyProcessed {
            // A classification never changes any ratchet state.
            for sess in before.sessions {
                XCTAssertEqual(s.sessions.session(sid: sess.sid)?.state, sess.state, "\(context): state unchanged on \(sess.sid.hex)")
            }
            XCTAssertTrue(s.ledger.pendingAcks.contains(msgId), "\(context): ack pending with the cursor")
        }
        if case .stored = outcome {
            XCTAssertTrue(s.ledger.pendingAcks.contains(msgId), "\(context): stored ack pending")
        }
        if case .parked = outcome {
            XCTAssertFalse(s.ledger.pendingAcks.contains(msgId), "\(context): never ack while parked")
        }
        if let exp = Vec.optDict(op, "expect_sending_sid") {
            try checkSendingSid(exp)
        }
        if let expectedRecoveries = Vec.optInt(op, "expect_recoveries") {
            XCTAssertEqual(s.recoveryCount, expectedRecoveries, "\(context): recoveries")
        }
        checkResendIds(op, s)
    }

    func opSend(_ op: [String: Any]) throws {
        let s: ScenarioSide = try side(of: op)
        let inner: InnerMessage = try InnerMessage.decode(try Vec.jsonBytes(try Vec.dict(op, "inner")))
        let env: OutboundEnvelope = try send(s, inner: inner)
        if let sid = try Vec.optHex(op, "expect_sid") {
            XCTAssertEqual(env.sid, sid, "\(context): sending sid")
        }
        if let kind = Vec.optStr(op, "expect_kind") {
            XCTAssertEqual(env.kind.rawValue, kind, "\(context): envelope kind")
        }
        // The produced envelope must pass the step-1 parser.
        XCTAssertNoThrow(try EnvelopeParser.parse(env.bytes), context)
        checkResendIds(op, s)
    }

    func opExpectMessages(_ op: [String: Any]) throws {
        let s: ScenarioSide = try side(of: op)
        guard let ids = op["ids"] as? [[String]] else { throw VecError("\(context): ids") }
        let expected: [String] = ids.map { $0.joined(separator: ":") }
        let actual: [String] = s.messages.map { "\($0.author.rawValue):\($0.id)" }
        XCTAssertEqual(actual, expected, "\(context): message set of \(s.name)")
    }

    func opRotateIdentity(_ op: [String: Any]) throws {
        let s: ScenarioSide = try side(of: op)
        s.identity = try IdentityKeys(sigSeed: try Vec.hex(op, "new_ik_sig_seed"), dhPriv: try Vec.hex(op, "new_ik_dh_priv"))
        if let spk = Vec.optDict(op, "new_spk") {
            s.spks = [try SignedPrekey(id: UInt32(try Vec.int(spk, "id")), createdAt: try Vec.u64(spk, "created_at"),
                                       rawPrivate: try Vec.hex(spk, "priv"))]
        }
        s.opks = []
        for o in Vec.optDicts(op, "new_opks") {
            s.opks.append(try OneTimePrekey(id: UInt32(try Vec.int(o, "id")), rawPrivate: try Vec.hex(o, "priv")))
        }
        s.claimedOpkIds = []
        // Re-registration: every existing session was bound to the old identity.
        for i in s.sessions.sessions.indices {
            s.sessions.sessions[i].supersede(.oldIdentity)
        }
    }

    func opAcceptMessageRequest(_ op: [String: Any]) throws {
        let s: ScenarioSide = try side(of: op)
        let p: ScenarioSide = peer(of: s)
        if s.contact == nil {
            s.contact = ContactRecord(username: p.username, identity: p.identity.publicKeys, verified: false, accepted: true)
        } else {
            s.contact?.accepted = true
        }
    }

    func opLookupResult(_ op: [String: Any]) throws {
        let s: ScenarioSide = try side(of: op)
        let p: ScenarioSide = peer(of: s)
        let result: String = try Vec.str(op, "result")
        switch result {
        case "ok": s.lookup = .ok(p.identity.publicKeys)
        case "mismatch": s.lookup = .mismatch
        case "not_found": s.lookup = .notFound
        case "transient": s.lookup = .transient
        default: throw VecError("\(context): lookup result \(result)")
        }
        if result != "transient" {
            try rerunParked(s) { $0.reason == .lookupDeferred }
        }
    }

    func opConsumedReport(_ op: [String: Any]) throws {
        let s: ScenarioSide = try side(of: op)
        guard let ids = op["ids"] as? [NSNumber] else { throw VecError("\(context): ids") }
        for id in ids {
            let key: UInt32 = id.uint32Value
            if s.consumedAt[key] == nil { s.consumedAt[key] = clock }
        }
    }

    /// S3 at once (the Go reference's `LoseSession`): delete with reason rollback and initiate `ctrl.resync`.
    func opInjectRollback(_ op: [String: Any]) throws {
        let s: ScenarioSide = try side(of: op)
        let sid: Data = try s.sid(forLabel: try Vec.str(op, "session"))
        guard s.sessions.session(sid: sid) != nil else { throw VecError("\(context): no session to roll back") }
        s.sessions.deleteSession(sid: sid, reason: .rollback, now: clock)
        s.rawSessions = s.rawSessions.filter { $0.value.sid != sid }
        if s.sessions.gateS3Recovery(now: clock) {
            try recover(s, lostSid: sid)
        }
    }

    /// `delete_session` with an optional `reason` (default `parse_failure`, which makes a later `msg` on it an S3 trigger).
    func opDeleteSession(_ op: [String: Any]) throws {
        let s: ScenarioSide = try side(of: op)
        let sid: Data = try s.sid(forLabel: try Vec.str(op, "session"))
        let reason: DeletedReason = DeletedReason(rawValue: Vec.optStr(op, "reason") ?? "") ?? .parseFailure
        s.sessions.deleteSession(sid: sid, reason: reason, now: clock)
        s.rawSessions = s.rawSessions.filter { $0.value.sid != sid }
    }

    func opAcceptKeyChange(_ op: [String: Any]) throws {
        let s: ScenarioSide = try side(of: op)
        let parkedKeyChange: [ParkedEnvelope] = s.conversation.parked(reason: .keyChange)
        var newIdentity: IdentityPublicKeys? = nil
        if let first = parkedKeyChange.first, let parsed = try? EnvelopeParser.parse(first.envelope), let x = parsed.outer.x3dh {
            newIdentity = x.identity
        }
        let identity: IdentityPublicKeys = newIdentity ?? peer(of: s).identity.publicKeys
        if s.contact == nil {
            s.contact = ContactRecord(username: peer(of: s).username, identity: identity, verified: false, accepted: true)
        } else {
            s.contact?.acceptKeyChange(identity)
        }
        s.sessions.applyS2(newPeerIdentity: identity)
        try rerunParked(s) { $0.reason == .keyChange }
    }

    func opExpectMKSkipped(_ op: [String: Any]) throws {
        let s: ScenarioSide = try side(of: op)
        let state: RatchetState = try ratchetState(s, label: try Vec.str(op, "session"))
        if let keys = op["keys"] as? [[String: Any]] {
            var expected: Set<String> = []
            for k in keys {
                let dh: String = try Vec.str(k, "dh")
                let n: Int = try Vec.int(k, "n")
                expected.insert("\(dh):\(n)")
            }
            let actual: Set<String> = Set(state.mkskipped.map { "\($0.dh.hex):\($0.n)" })
            XCTAssertEqual(actual, expected, "\(context): MKSKIPPED key set")
        } else {
            XCTAssertEqual(state.mkskipped.count, try Vec.int(op, "count"), "\(context): MKSKIPPED count")
            XCTAssertEqual(state.mkskippedSHA256(), try Vec.hex(op, "mkskipped_sha256"), "\(context): MKSKIPPED hash")
        }
    }

    func opExpectStateExcludes(_ op: [String: Any]) throws {
        let s: ScenarioSide = try side(of: op)
        let state: RatchetState = try ratchetState(s, label: try Vec.str(op, "session"))
        let bytes: Data = try Vec.hex(op, "bytes")
        XCTAssertFalse(state.contains(secret: bytes), "\(context): state still holds the excluded secret")
        XCTAssertNotEqual(state.dhsPriv.dataCopy, bytes, context)
    }

    /// The ratchet state behind a label: a direct-API session first, else the app session.
    func ratchetState(_ s: ScenarioSide, label: String) throws -> RatchetState {
        if let raw = s.rawSessions[label] { return raw.state }
        let sid: Data = try s.sid(forLabel: label)
        guard let session = s.sessions.session(sid: sid) else { throw VecError("\(context): no session \(label)") }
        return session.state
    }
}

// MARK: - InboundPolicyTests (§5.12)

final class InboundPolicyTests: XCTestCase {
    func testReplayScenario() throws {
        let r: ScenarioRunner = try Scenarios.run("replay")
        XCTAssertFalse(r.b.ledger.pendingAcks.isEmpty)
        XCTAssertGreaterThan(r.b.ledger.cursor, 0)
    }

    func testIdCollisionScenario() throws {
        _ = try Scenarios.run("id_collision")
    }

    func testOPKGraceScenario() throws {
        let r: ScenarioRunner = try Scenarios.run("opk_grace")
        XCTAssertTrue(r.b.sessions.knownSids.contains { $0.deletedReason == .rejectedInitiation })
    }

    // Unit-level policy checks independent of the vector file.

    private func makeParties() throws -> (ScenarioRunner, ScenarioSide, ScenarioSide) {
        let scenario: [String: Any] = ["name": "unit", "clock_start": NSNumber(value: 1_760_000_000)]
        let r: ScenarioRunner = try ScenarioRunner(scenario: scenario)
        r.a.spks = [SignedPrekey(id: 9, createdAt: 1_759_900_000, privateKey: Curve25519.KeyAgreement.PrivateKey())]
        r.b.spks = [SignedPrekey(id: 7, createdAt: 1_759_900_000, privateKey: Curve25519.KeyAgreement.PrivateKey())]
        r.a.opks = [OneTimePrekey(id: 2301, privateKey: Curve25519.KeyAgreement.PrivateKey())]
        r.b.opks = [OneTimePrekey(id: 1203, privateKey: Curve25519.KeyAgreement.PrivateKey())]
        return (r, r.a, r.b)
    }

    func testOuterDedupeParkingAndAcks() throws {
        let (r, alice, bob) = try makeParties()
        let env: OutboundEnvelope = try r.send(alice, inner: InnerMessage.text(id: "m1", ts: r.clock, ttl: 0, text: "hi"))
        XCTAssertEqual(env.kind, .prekey)
        // Stored, acked, cursor advanced, pendingAcks written.
        let first: InboundResult = try r.deliver(to: bob, msgId: "id-1", envelope: env.bytes)
        XCTAssertEqual(first.outcome.kindString, "stored")
        XCTAssertEqual(bob.ledger.pendingAcks, ["id-1"])
        XCTAssertEqual(bob.ledger.cursor, 1)
        XCTAssertEqual(bob.messages.count, 1)
        // Step 0: same msg_id → already_processed, acked again from the list, no KDF.
        let again: InboundResult = try r.deliver(to: bob, msgId: "id-1", envelope: env.bytes)
        XCTAssertEqual(again.outcome, .alreadyProcessed)
        XCTAssertEqual(bob.ledger.pendingAcks, ["id-1"])
        // New msg_id, same envelope: routed to the existing session by sid(ek) → decrypt_failed, state unchanged.
        let stateBefore: RatchetState? = bob.sessions.session(sid: env.sid)?.state
        let replayed: InboundResult = try r.deliver(to: bob, msgId: "id-2", envelope: env.bytes)
        XCTAssertEqual(replayed.outcome, .classified(.decryptFailed))
        XCTAssertEqual(bob.sessions.session(sid: env.sid)?.state, stateBefore)
        XCTAssertEqual(bob.ledger.pendingAcks, ["id-1", "id-2"])
        // After deleting the session the ek is in seen_ek → replay.
        bob.sessions.deleteSession(sid: env.sid, reason: .parseFailure, now: r.clock)
        let third: InboundResult = try r.deliver(to: bob, msgId: "id-3", envelope: env.bytes)
        XCTAssertEqual(third.outcome, .classified(.replay))
        // A msg with an unknown sid is parked (never acked) and, since the sid was lost (parse_failure), S3 fires once.
        var fake: Session = try XCTUnwrap(alice.sessions.session(sid: env.sid))
        let env2: OutboundEnvelope = try SessionOutbound.encrypt(session: &fake, inner: InnerMessage.text(id: "m2", ts: 1, ttl: 0, text: "x"), local: alice.identity)
        let msgOnly: OuterEnvelope = OuterEnvelope(kind: .msg, sid: env.sid, x3dh: nil, hdr: env2.header.bytes, ct: env2.wire)
        let recoveriesBefore: Int = bob.recoveryCount
        let parked: InboundResult = try r.deliver(to: bob, msgId: "id-4", envelope: try msgOnly.encoded())
        XCTAssertEqual(parked.outcome, .parked(.unknownSid))
        XCTAssertFalse(bob.ledger.pendingAcks.contains("id-4"))
        XCTAssertEqual(bob.recoveryCount, recoveriesBefore + 1)
        XCTAssertEqual(bob.conversation.parked.count, 1)
        // Second unknown-sid msg inside 10 min does not fire again.
        let parked2: InboundResult = try r.deliver(to: bob, msgId: "id-5", envelope: try msgOnly.encoded())
        XCTAssertEqual(parked2.outcome, .parked(.unknownSid))
        XCTAssertEqual(bob.recoveryCount, recoveriesBefore + 1)
        // Parked envelopes expire after 24 h with their reason and are acked then.
        var conv: ConversationState = bob.conversation
        XCTAssertTrue(conv.expireParked(now: r.clock + 3600).isEmpty)
        let expired = conv.expireParked(now: r.clock + 24 * 3600 + 1)
        XCTAssertEqual(expired.count, 2)
        XCTAssertEqual(expired.first?.reason, .unknownSid)
        XCTAssertTrue(conv.parked.isEmpty)
    }

    func testParkedOverflowAndBounds() {
        var conv: ConversationState = ConversationState()
        for i in 0..<101 {
            let p: ParkedEnvelope = ParkedEnvelope(msgId: "p\(i)", kind: .msg, sid: Data(repeating: 1, count: 8), envelope: Data(),
                                                   receivedAt: 1, reason: .unknownSid)
            let victim: ParkedEnvelope? = conv.park(p)
            XCTAssertEqual(victim != nil, i == 100)
            if let v = victim { XCTAssertEqual(v.msgId, "p0") }
        }
        XCTAssertEqual(conv.parked.count, 100)
        var ledger: AckLedger = AckLedger()
        for i in 0..<5100 { ledger.record(serverId: Int64(i), acks: ["a\(i)"]) }
        XCTAssertEqual(ledger.pendingAcks.count, 5000)
        XCTAssertEqual(ledger.cursor, 5099)
        ledger.confirm(["a5099"])
        XCTAssertFalse(ledger.pendingAcks.contains("a5099"))
        XCTAssertEqual(ParkReason.keyChange.lifetime, 7 * 86400)
        XCTAssertEqual(ParkReason.lookupDeferred.expiryReason, .lookupFailed)
        XCTAssertEqual(ParkReason.keyChange.expiryReason, .keyChangeExpired)
    }

    func testKeyChangeAndLookupPaths() throws {
        let (r, alice, bob) = try makeParties()
        let savedOPK: OneTimePrekey = try XCTUnwrap(bob.opks.first)
        // Unknown sender, transient lookup → parked lookup_deferred, no contact; then ok → stored.
        bob.lookup = .transient
        let env: OutboundEnvelope = try r.send(alice, inner: InnerMessage.text(id: "m1", ts: 1, ttl: 0, text: "hi"))
        let deferred: InboundResult = try r.deliver(to: bob, msgId: "k1", envelope: env.bytes)
        XCTAssertEqual(deferred.outcome, .parked(.lookupDeferred))
        XCTAssertNil(bob.contact)
        try r.opLookupResult(["op": "lookup_result", "side": "B", "peer": "alice", "result": "ok"])
        XCTAssertEqual(bob.contact?.identity, alice.identity.publicKeys)
        XCTAssertFalse(bob.contact?.accepted ?? true, "message request until Kabul et")
        XCTAssertEqual(bob.messages.count, 1)
        XCTAssertTrue(bob.ledger.pendingAcks.contains("k1"), "parked-then-resolved ack")
        // Identity mismatch on lookup for a different unknown sender.
        bob.contact = nil
        bob.sessions = PeerSessions()
        bob.lookup = .mismatch
        let env2: OutboundEnvelope = try r.send(alice, inner: InnerMessage.text(id: "m2", ts: 1, ttl: 0, text: "x"))
        let mism: InboundResult = try r.deliver(to: bob, msgId: "k2", envelope: env2.bytes)
        XCTAssertEqual(mism.outcome, .classified(.identityMismatch))
        // Key change: contact exists with other keys → parked key_change; accept → S2 + rerun → stored.
        bob.lookup = nil
        bob.opks = [savedOPK]
        let old: IdentityKeys = IdentityKeys()
        bob.contact = ContactRecord(username: "alice", identity: old.publicKeys, verified: true, accepted: true)
        let env3: OutboundEnvelope = try r.send(alice, inner: InnerMessage.text(id: "m3", ts: 1, ttl: 0, text: "y"))
        let kc: InboundResult = try r.deliver(to: bob, msgId: "k3", envelope: env3.bytes)
        XCTAssertEqual(kc.outcome, .parked(.keyChange))
        XCTAssertTrue(kc.actions.contains(.keyChangeDetected))
        try r.opAcceptKeyChange(["op": "accept_key_change", "side": "B", "peer": "alice"])
        XCTAssertEqual(bob.contact?.identity, alice.identity.publicKeys)
        XCTAssertTrue(bob.conversation.parked.isEmpty)
        XCTAssertTrue(bob.ledger.pendingAcks.contains("k3"))
    }

    func testRejectedInitiationTriggers() throws {
        let (r, alice, bob) = try makeParties()
        // Pending message request: opk_gone is classified only (Bob lost the claimed OPK after the grace period).
        let env: OutboundEnvelope = try r.send(alice, inner: InnerMessage.text(id: "m1", ts: 1, ttl: 0, text: "hi"))
        XCTAssertNotNil(try EnvelopeParser.parse(env.bytes).outer.x3dh?.opkId)
        bob.opks = []
        let pending: InboundResult = try r.deliver(to: bob, msgId: "r1", envelope: env.bytes)
        XCTAssertEqual(pending.outcome, .classified(.opkGone))
        XCTAssertEqual(bob.recoveryCount, 0)
        XCTAssertTrue(bob.sessions.knownSids.isEmpty)
        // Accepted contact: recovery fires once, sid recorded as rejected_initiation.
        bob.contact?.accepted = true
        let rec: InboundResult = try r.deliver(to: bob, msgId: "r2", envelope: env.bytes)
        XCTAssertEqual(rec.outcome, .classified(.opkGone))
        XCTAssertEqual(bob.recoveryCount, 1)
        XCTAssertEqual(bob.sessions.knownSid(env.sid)?.deletedReason, .rejectedInitiation)
        // Known sid: classified only, no second recovery.
        let rec2: InboundResult = try r.deliver(to: bob, msgId: "r3", envelope: env.bytes)
        XCTAssertEqual(rec2.outcome, .classified(.opkGone))
        XCTAssertEqual(bob.recoveryCount, 1)
        // AEAD failure on a fresh initiation never recovers.
        bob.opks = [OneTimePrekey(id: 1203, privateKey: Curve25519.KeyAgreement.PrivateKey())]
        bob.claimedOpkIds = []
        alice.sessions = PeerSessions()
        let fresh: OutboundEnvelope = try r.send(alice, inner: InnerMessage.text(id: "m2", ts: 1, ttl: 0, text: "z"))
        var ct: Data = fresh.wire
        ct[ct.startIndex + ct.count - 1] ^= 0x01
        let freshParsed: ParsedEnvelope = try EnvelopeParser.parse(fresh.bytes)
        let tampered: OuterEnvelope = OuterEnvelope(kind: .prekey, sid: fresh.sid, x3dh: freshParsed.outer.x3dh,
                                                    hdr: fresh.header.bytes, ct: ct)
        let bad: InboundResult = try r.deliver(to: bob, msgId: "r4", envelope: try tampered.encoded())
        XCTAssertEqual(bad.outcome, .classified(.decryptFailed))
        XCTAssertNil(bob.sessions.knownSid(fresh.sid))
        XCTAssertEqual(bob.recoveryCount, 1)
        XCTAssertNil(bob.sessions.session(sid: fresh.sid))
    }
}
