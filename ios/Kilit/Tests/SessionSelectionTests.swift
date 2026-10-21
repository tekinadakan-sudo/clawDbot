import XCTest
import CryptoKit
@testable import Kilit

// MARK: - Scenario runner (Set B / B′ of §3.8–3.9), shared by RatchetVector/SessionSelection/InboundPolicy tests

/// A ratchet state driven by the direct-API ops (`init_alice`, `init_bob`, `encrypt`, `decrypt`).
struct RawRatchet {
    let sid: Data
    let ad: Data
    var state: RatchetState
}

/// One party of a scenario: its identity, bundle keys, scripted `KeySource`, and the store snapshot values.
final class ScenarioSide {
    let name: String
    let username: String
    var identity: IdentityKeys
    let keySource: ScriptedKeySource
    var spks: [SignedPrekey] = []
    var opks: [OneTimePrekey] = []
    var sessions: PeerSessions = PeerSessions()
    var contact: ContactRecord? = nil
    var conversation: ConversationState = ConversationState()
    var ledger: AckLedger = AckLedger()
    var sentLog: [OwnSentMessage] = []
    var sentInners: [String: InnerMessage] = [:]
    var messages: [(author: MessageAuthor, id: String)] = []
    var labels: [String: Data] = [:]
    var creationOrder: [Data] = []
    var rawSessions: [String: RawRatchet] = [:]
    var lookup: LookupResult? = nil
    var consumedAt: [UInt32: UInt64] = [:]
    var claimedOpkIds: Set<UInt32> = []
    var pendingRollback: Set<Data> = []
    var resentIds: [String] = []
    var outbox: [OutboundEnvelope] = []
    var serverIdCounter: Int64 = 0
    var resyncCounter: Int = 0
    var recoveryCount: Int = 0

    init(name: String, username: String, identity: IdentityKeys, keys: [Data]) {
        self.name = name
        self.username = username
        self.identity = identity
        self.keySource = ScriptedKeySource(keys: keys)
    }

    func noteSessions() {
        for s in sessions.sessions where !creationOrder.contains(s.sid) {
            creationOrder.append(s.sid)
        }
    }

    func sid(forLabel label: String) throws -> Data {
        if let s = labels[label] { return s }
        if label.hasPrefix("S"), let n = Int(label.dropFirst()), n >= 1, n <= creationOrder.count {
            return creationOrder[n - 1]
        }
        throw VecError("\(name): unknown session label \(label)")
    }
}

final class ScenarioRunner {
    let name: String
    var clock: UInt64
    let a: ScenarioSide
    let b: ScenarioSide
    var stepIndex: Int = 0
    static let spkLifetime: UInt64 = 28 * 86400
    static let opkConsumedGrace: UInt64 = 7 * 86400

    init(scenario: [String: Any]) throws {
        name = try Vec.str(scenario, "name")
        clock = try Vec.u64(scenario, "clock_start")
        let (idA, idB, nameA, nameB) = try ScenarioRunner.identities(scenario)
        let sources: [String: Any] = Vec.optDict(scenario, "key_sources") ?? [:]
        a = ScenarioSide(name: "A", username: nameA, identity: idA, keys: try ScenarioRunner.hexList(sources, "A"))
        b = ScenarioSide(name: "B", username: nameB, identity: idB, keys: try ScenarioRunner.hexList(sources, "B"))
        let bundles: [String: Any] = Vec.optDict(scenario, "bundles") ?? [:]
        try ScenarioRunner.loadBundle(Vec.optDict(bundles, "A"), into: a)
        try ScenarioRunner.loadBundle(Vec.optDict(bundles, "B"), into: b)
    }

    private static func hexList(_ d: [String: Any], _ key: String) throws -> [Data] {
        guard d[key] != nil else { return [] }
        return try Vec.hexes(d, key)
    }

    /// Identity keys come from the scenario's `identities` object when present, else from Set A's inputs.
    private static func identities(_ scenario: [String: Any]) throws -> (IdentityKeys, IdentityKeys, String, String) {
        if let ids = Vec.optDict(scenario, "identities"), let ia = Vec.optDict(ids, "A"), let ib = Vec.optDict(ids, "B") {
            let ka: IdentityKeys = try IdentityKeys(sigSeed: try Vec.hex(ia, "ik_sig_seed"), dhPriv: try Vec.hex(ia, "ik_dh_priv"))
            let kb: IdentityKeys = try IdentityKeys(sigSeed: try Vec.hex(ib, "ik_sig_seed"), dhPriv: try Vec.hex(ib, "ik_dh_priv"))
            return (ka, kb, Vec.optStr(ia, "username") ?? "alice", Vec.optStr(ib, "username") ?? "bob")
        }
        let x: [String: Any] = try Vec.object(KilitVectors.x3dh)
        let inputs: [String: Any] = try Vec.dict(x, "inputs")
        let ia: [String: Any] = try Vec.dict(inputs, "alice")
        let ib: [String: Any] = try Vec.dict(inputs, "bob")
        let ka: IdentityKeys = try IdentityKeys(sigSeed: try Vec.hex(ia, "ik_sig_seed"), dhPriv: try Vec.hex(ia, "ik_dh_priv"))
        let kb: IdentityKeys = try IdentityKeys(sigSeed: try Vec.hex(ib, "ik_sig_seed"), dhPriv: try Vec.hex(ib, "ik_dh_priv"))
        return (ka, kb, try Vec.str(ia, "username"), try Vec.str(ib, "username"))
    }

    private static func loadBundle(_ d: [String: Any]?, into side: ScenarioSide) throws {
        guard let d = d else { return }
        let spk: SignedPrekey = try SignedPrekey(id: UInt32(try Vec.int(d, "spk_id")), createdAt: try Vec.u64(d, "spk_created_at"),
                                                 rawPrivate: try Vec.hex(d, "spk_priv"))
        side.spks = [spk]
        side.opks = []
        for o in Vec.optDicts(d, "opks") {
            side.opks.append(try OneTimePrekey(id: UInt32(try Vec.int(o, "id")), rawPrivate: try Vec.hex(o, "priv")))
        }
    }

    // MARK: sides

    func side(_ key: String) throws -> ScenarioSide {
        switch key {
        case "A": return a
        case "B": return b
        default: throw VecError("unknown side \(key)")
        }
    }

    func side(of op: [String: Any]) throws -> ScenarioSide {
        try side(try Vec.str(op, "side"))
    }

    func peer(of side: ScenarioSide) -> ScenarioSide {
        side === a ? b : a
    }

    var context: String { "\(name) step \(stepIndex)" }

    // MARK: store-side timers (what PrekeyStore / LocalStore do on load)

    func applyTimers(_ side: ScenarioSide) throws {
        let now: UInt64 = clock
        side.spks.removeAll { now > $0.createdAt && now - $0.createdAt > ScenarioRunner.spkLifetime }
        side.opks.removeAll { o in
            if let t = side.consumedAt[o.id], now > t, now - t > ScenarioRunner.opkConsumedGrace { return true }
            return false
        }
        side.sessions.prune(now: now)
        let rollbacks: Set<Data> = side.pendingRollback
        side.pendingRollback = []
        for sid in rollbacks where side.sessions.session(sid: sid) != nil {
            side.sessions.deleteSession(sid: sid, reason: .rollback, now: now)
            side.sessions.stampRecovery(now: now)
            try recover(side, lostSid: sid)
        }
    }

    // MARK: bundle fetch (server simulation) and initiation

    func makeBundle(for peer: ScenarioSide) throws -> PrekeyBundle {
        guard let spk = peer.spks.max(by: { $0.createdAt < $1.createdAt }) else { throw VecError("\(peer.name) has no SPK") }
        let signed: SignedPrekeyPublic = try spk.signed(by: peer.identity)
        let opk: OneTimePrekey? = peer.opks.first { !peer.claimedOpkIds.contains($0.id) }
        if let o = opk { peer.claimedOpkIds.insert(o.id) }
        let bind: Data = try peer.identity.ikBindSig()
        return PrekeyBundle(username: peer.username, identity: peer.identity.publicKeys, ikBindSig: bind, spk: signed,
                            opkId: opk?.id, opkPub: opk?.publicKey)
    }

    /// Fetch a bundle and initiate; returns the new (not yet advanced) session.
    func initiateSession(_ side: ScenarioSide) throws -> Session {
        let bundle: PrekeyBundle = try makeBundle(for: peer(of: side))
        let session: Session = try SessionOutbound.initiate(bundle: bundle, local: side.identity, localUsername: side.username,
                                                            now: clock, keySource: side.keySource)
        side.sessions.addSession(session)
        side.noteSessions()
        if side.contact == nil {
            side.contact = ContactRecord(username: peer(of: side).username, identity: bundle.identity, verified: false, accepted: true)
        }
        side.contact?.appendWMSecret(sid: session.sid, ws: session.ws)
        return session
    }

    /// S3 / rejected-initiation recovery: new session whose first inner message is `ctrl.resync{lost_sid}`.
    func recover(_ side: ScenarioSide, lostSid: Data) throws {
        side.recoveryCount += 1
        var session: Session = try initiateSession(side)
        side.resyncCounter += 1
        let inner: InnerMessage = InnerMessage.resync(id: "resync-\(side.name)-\(side.resyncCounter)", ts: clock, lostSid: lostSid)
        let env: OutboundEnvelope = try SessionOutbound.encrypt(session: &session, inner: inner, local: side.identity)
        side.sessions.addSession(session)
        side.outbox.append(env)
    }

    /// Receiver of `ctrl.resync`: re-send own messages sent on `lostSid` (≤ 7 d, oldest first, ≤ 50) on the new sending session.
    func resend(_ side: ScenarioSide, lostSid: Data) throws {
        let candidates: [OwnSentMessage] = SessionOutbound.resendCandidates(sent: side.sentLog, lostSid: lostSid, now: clock)
        for c in candidates {
            guard let inner = side.sentInners[c.id] else { continue }
            guard var session = side.sessions.sendingSession() else { throw VecError("\(context): no sending session for resend") }
            let env: OutboundEnvelope = try SessionOutbound.encrypt(session: &session, inner: inner, local: side.identity)
            side.sessions.addSession(session)
            side.outbox.append(env)
            side.sentLog.append(OwnSentMessage(id: c.id, sid: session.sid, sentAt: clock))
            side.resentIds.append(c.id)
        }
    }

    // MARK: inbound

    func deliver(to side: ScenarioSide, msgId: String, envelope: Data) throws -> InboundResult {
        let peerSide: ScenarioSide = peer(of: side)
        let input: InboundInput = InboundInput(from: peerSide.username, msgId: msgId, envelope: envelope, now: clock,
                                               local: side.identity, localUsername: side.username, contact: side.contact,
                                               sessions: side.sessions, conversation: side.conversation,
                                               prekeys: PrekeyLookup.from(spks: side.spks, opks: side.opks),
                                               lookup: side.lookup ?? .ok(peerSide.identity.publicKeys),
                                               keySource: side.keySource)
        let result: InboundResult = Inbound.process(input)
        try apply(result, to: side)
        return result
    }

    func apply(_ result: InboundResult, to side: ScenarioSide) throws {
        side.sessions = result.sessions
        side.conversation = result.conversation
        side.contact = result.contact
        side.noteSessions()
        side.serverIdCounter += 1
        side.ledger.record(serverId: side.serverIdCounter, acks: result.ackIds)
        if case .stored(let inner, _) = result.outcome {
            if inner.t == InnerMessageType.text || inner.t == InnerMessageType.image {
                side.messages.append((MessageAuthor.peer, inner.id))
            } else if inner.t == InnerMessageType.ctrlDelete, let refs = inner.ref {
                side.messages.removeAll { $0.author == .peer && refs.contains($0.id) }
            }
        }
        for action in result.actions {
            switch action {
            case .deleteOneTimePrekey(let id):
                side.opks.removeAll { $0.id == id }
            case .initiateRecovery(let lostSid, _):
                try recover(side, lostSid: lostSid)
            case .rerunParked(let sid):
                try rerunParked(side) { $0.sid == sid }
            case .resyncReceived(let lostSid, _):
                try resend(side, lostSid: lostSid)
            case .ack, .keyChangeDetected, .lookupIdentity, .contactCreated:
                break
            }
        }
    }

    func rerunParked(_ side: ScenarioSide, where filter: (ParkedEnvelope) -> Bool) throws {
        let items: [ParkedEnvelope] = side.conversation.parked.filter(filter)
        for p in items {
            side.conversation.unpark(msgId: p.msgId)
            _ = try deliver(to: side, msgId: p.msgId, envelope: p.envelope)
        }
    }

    // MARK: outbound

    func send(_ side: ScenarioSide, inner: InnerMessage) throws -> OutboundEnvelope {
        try applyTimers(side)
        var session: Session
        if let s = side.sessions.sendingSession() {
            session = s
        } else {
            session = try initiateSession(side)
        }
        let env: OutboundEnvelope = try SessionOutbound.encrypt(session: &session, inner: inner, local: side.identity)
        side.sessions.addSession(session)
        side.outbox.append(env)
        if inner.t == InnerMessageType.text || inner.t == InnerMessageType.image {
            side.sentLog.append(OwnSentMessage(id: inner.id, sid: session.sid, sentAt: clock))
            side.sentInners[inner.id] = inner
            side.messages.append((MessageAuthor.me, inner.id))
        }
        return env
    }

    // MARK: assertions

    func checkSendingSid(_ op: [String: Any]) throws {
        for key in ["A", "B"] {
            guard op[key] != nil else { continue }
            let s: ScenarioSide = try side(key)
            let expected: Data? = try Vec.optHex(op, key)
            XCTAssertEqual(s.sessions.sendingSession()?.sid, expected, "\(context): sending sid of \(key)")
        }
    }

    func checkResendIds(_ op: [String: Any], _ side: ScenarioSide) {
        guard let ids = op["expect_resend_ids"] as? [String] else { return }
        XCTAssertEqual(side.resentIds, ids, "\(context): resend set")
        side.resentIds = []
    }

    func assertNoOverdraw() {
        XCTAssertEqual(a.keySource.overdrawnKeys, 0, "\(name): A drew more keys than scripted")
        XCTAssertEqual(b.keySource.overdrawnKeys, 0, "\(name): B drew more keys than scripted")
    }
}

// MARK: - Loading scenarios

enum Scenarios {
    static func all(from json: String) throws -> [[String: Any]] {
        try Vec.dicts(try Vec.object(json), "scenarios")
    }

    static func named(_ name: String, in json: String) throws -> [String: Any] {
        for s in try all(from: json) {
            let n: String = try Vec.str(s, "name")
            if n == name { return s }
        }
        throw XCTSkip("scenario \(name) not present in the vector file")
    }

    static func run(_ name: String, in json: String = KilitVectors.ratchet) throws -> ScenarioRunner {
        let scenario: [String: Any] = try named(name, in: json)
        let runner: ScenarioRunner = try ScenarioRunner(scenario: scenario)
        try runner.run(try Vec.dicts(scenario, "steps"))
        runner.assertNoOverdraw()
        return runner
    }
}

// MARK: - SessionSelectionTests (§5.12)

final class SessionSelectionTests: XCTestCase {
    func testCrossed() throws {
        let r: ScenarioRunner = try Scenarios.run("crossed")
        // After convergence both sides send on the same sid and both sessions are known on both sides.
        XCTAssertEqual(r.a.sessions.sendingSession()?.sid, r.b.sessions.sendingSession()?.sid)
        XCTAssertEqual(r.a.contact?.canonicalWMSecret, r.b.contact?.canonicalWMSecret, "canonical wm_secret = smallest sid")
    }

    func testLostSession() throws {
        let r: ScenarioRunner = try Scenarios.run("lost_session")
        XCTAssertEqual(r.a.sessions.sendingSession()?.sid, r.b.sessions.sendingSession()?.sid)
        XCTAssertTrue(r.b.sessions.knownSids.contains { $0.deletedReason == .parseFailure || $0.deletedReason == .rollback })
    }

    func testReinitAfterRollback() throws {
        let r: ScenarioRunner = try Scenarios.run("reinit_after_rollback")
        XCTAssertTrue(r.b.sessions.knownSids.contains { $0.deletedReason == .rollback })
        XCTAssertEqual(r.a.sessions.sendingSession()?.sid, r.b.sessions.sendingSession()?.sid)
    }

    func testKeyChangeThenSend() throws {
        let r: ScenarioRunner = try Scenarios.run("key_change_then_send")
        XCTAssertTrue(r.b.sessions.sessions.contains { $0.superseded && $0.supersededReason == .oldIdentity })
        XCTAssertEqual(r.b.contact?.identity, r.a.identity.publicKeys)
        XCTAssertEqual(r.a.sessions.sendingSession()?.sid, r.b.sessions.sendingSession()?.sid)
    }

    func testRejectedInitiation() throws {
        let r: ScenarioRunner = try Scenarios.run("rejected_initiation")
        XCTAssertTrue(r.b.sessions.knownSids.contains { $0.deletedReason == .rejectedInitiation })
        XCTAssertTrue(r.a.sessions.sessions.contains { $0.superseded && $0.lastActivity == nil }, "superseded without lastActivity")
    }

    // Unit-level rules that do not need the vector file.

    private func session(sid: UInt8, role: SessionRole, createdAt: UInt64, lastActivity: UInt64?) -> Session {
        let state: RatchetState = DoubleRatchet.initBob(sk: Data(repeating: 1, count: 32), dhs: Curve25519.KeyAgreement.PrivateKey())
        let ids: IdentityPublicKeys = IdentityPublicKeys(ikSig: Data(repeating: 2, count: 32), ikDh: Data(repeating: 3, count: 32))
        var s: Session = Session(sid: Data(repeating: sid, count: 8), role: role, createdAt: createdAt, ws: Data(repeating: 4, count: 32),
                                 ad: Data(repeating: 5, count: 8), localIdentity: ids, peerIdentity: ids, state: state, pendingX3DH: nil)
        s.lastActivity = lastActivity
        return s
    }

    func testSendingSessionRule() {
        var p: PeerSessions = PeerSessions()
        XCTAssertNil(p.sendingSession())
        p.addSession(session(sid: 0x20, role: .initiator, createdAt: 10, lastActivity: nil))
        p.addSession(session(sid: 0x10, role: .initiator, createdAt: 20, lastActivity: nil))
        XCTAssertEqual(p.sendingSession()?.sid, Data(repeating: 0x10, count: 8), "newest own-initiated")
        p.addSession(session(sid: 0x30, role: .responder, createdAt: 5, lastActivity: 30))
        XCTAssertEqual(p.sendingSession()?.sid, Data(repeating: 0x30, count: 8), "only session with a decrypt")
        p.addSession(session(sid: 0x05, role: .responder, createdAt: 6, lastActivity: 31))
        XCTAssertEqual(p.sendingSession()?.sid, Data(repeating: 0x05, count: 8), "smallest sid among active")
        p.sessions[p.index(of: Data(repeating: 0x05, count: 8)) ?? 0].supersede(.resync)
        XCTAssertEqual(p.sendingSession()?.sid, Data(repeating: 0x30, count: 8), "superseded never sends")
    }

    func testS1S2S3AndBounds() {
        var p: PeerSessions = PeerSessions()
        p.addSession(session(sid: 0x01, role: .initiator, createdAt: 1, lastActivity: 5))
        p.addSession(session(sid: 0x02, role: .initiator, createdAt: 2, lastActivity: nil))
        p.addSession(session(sid: 0x03, role: .responder, createdAt: 3, lastActivity: 3))
        p.applyS1(committedSid: Data(repeating: 0x03, count: 8))
        XCTAssertTrue(p.session(sid: Data(repeating: 0x01, count: 8))?.superseded ?? false)
        XCTAssertFalse(p.session(sid: Data(repeating: 0x02, count: 8))?.superseded ?? true, "no decrypt → untouched")
        XCTAssertFalse(p.session(sid: Data(repeating: 0x03, count: 8))?.superseded ?? true)
        p.applyS2(newPeerIdentity: IdentityPublicKeys(ikSig: Data(repeating: 9, count: 32), ikDh: Data(repeating: 9, count: 32)))
        XCTAssertTrue(p.sessions.allSatisfy { $0.superseded })
        XCTAssertEqual(p.session(sid: Data(repeating: 0x02, count: 8))?.supersededReason, .oldIdentity)
        XCTAssertEqual(p.session(sid: Data(repeating: 0x01, count: 8))?.supersededReason, .peerMovedOn, "sticky")
        // S3 bound: only rollback / parse_failure trigger, once per 10 min.
        p.deleteSession(sid: Data(repeating: 0x02, count: 8), reason: .pruned, now: 100)
        XCTAssertEqual(p.knownSid(Data(repeating: 0x02, count: 8))?.deletedReason, .pruned)
        XCTAssertFalse(DeletedReason.pruned.triggersS3)
        XCTAssertFalse(DeletedReason.rejectedInitiation.triggersS3)
        XCTAssertTrue(DeletedReason.rollback.triggersS3)
        XCTAssertTrue(DeletedReason.parseFailure.triggersS3)
        XCTAssertTrue(p.gateS3Recovery(now: 1000))
        XCTAssertFalse(p.gateS3Recovery(now: 1000 + 599))
        XCTAssertTrue(p.gateS3Recovery(now: 1000 + 600))
        XCTAssertFalse(p.gateRejectedInitiationRecovery(now: 1600 + 599), "shared with S3")
        XCTAssertTrue(p.gateRejectedInitiationRecovery(now: 1600 + 600))
        XCTAssertFalse(p.gateS3Recovery(now: 1000), "a clock that went backwards keeps the bound closed (Go)")
        // ctrl.resync supersedes a session without lastActivity.
        p.addSession(session(sid: 0x04, role: .initiator, createdAt: 4, lastActivity: nil))
        XCTAssertTrue(p.supersede(lostSid: Data(repeating: 0x04, count: 8)))
        XCTAssertEqual(p.session(sid: Data(repeating: 0x04, count: 8))?.supersededReason, .resync)
        XCTAssertFalse(p.supersede(lostSid: Data(repeating: 0x77, count: 8)))
    }

    func testPruneAndWMSecret() {
        var p: PeerSessions = PeerSessions()
        for i in 1...6 {
            var s: Session = session(sid: UInt8(i), role: .initiator, createdAt: UInt64(i), lastActivity: UInt64(i))
            if i <= 5 { s.supersede(.peerMovedOn) }
            p.addSession(s)
        }
        p.prune(now: 10)
        XCTAssertEqual(p.sessions.count, 4, "cap 4 per peer, oldest superseded first")
        XCTAssertNotNil(p.session(sid: Data(repeating: 6, count: 8)))
        XCTAssertEqual(p.knownSids.count, 2)
        XCTAssertTrue(p.knownSids.allSatisfy { $0.deletedReason == .pruned })
        p.prune(now: 10 + 31 * 86400)
        XCTAssertEqual(p.sessions.count, 1, "superseded deleted 30 d after lastActivity")
        var c: ContactRecord = ContactRecord(username: "bob", identity: IdentityPublicKeys(ikSig: Data(), ikDh: Data()))
        c.appendWMSecret(sid: Data([9, 9, 9, 9, 9, 9, 9, 9]), ws: Data(repeating: 1, count: 32))
        c.appendWMSecret(sid: Data([1, 2, 3, 4, 5, 6, 7, 8]), ws: Data(repeating: 2, count: 32))
        c.appendWMSecret(sid: Data([1, 2, 3, 4, 5, 6, 7, 8]), ws: Data(repeating: 3, count: 32))
        XCTAssertEqual(c.wmSecrets.count, 2)
        XCTAssertEqual(c.canonicalWMSecret, Data(repeating: 2, count: 32))
        c.acceptKeyChange(IdentityPublicKeys(ikSig: Data(repeating: 1, count: 32), ikDh: Data(repeating: 1, count: 32)))
        XCTAssertTrue(c.wmSecrets.isEmpty)
    }

    func testResendCandidates() {
        let lost: Data = Data(repeating: 1, count: 8)
        var sent: [OwnSentMessage] = []
        for i in 0..<60 {
            sent.append(OwnSentMessage(id: "m\(i)", sid: lost, sentAt: 1000 + UInt64(60 - i)))
        }
        sent.append(OwnSentMessage(id: "old", sid: lost, sentAt: 1))
        sent.append(OwnSentMessage(id: "other", sid: Data(repeating: 2, count: 8), sentAt: 1050))
        let out: [OwnSentMessage] = SessionOutbound.resendCandidates(sent: sent, lostSid: lost, now: 7 * 86400 + 500)
        XCTAssertEqual(out.count, 50)
        XCTAssertEqual(out.first?.id, "m59", "oldest first")
        XCTAssertFalse(out.contains { $0.id == "old" || $0.id == "other" })
    }
}
