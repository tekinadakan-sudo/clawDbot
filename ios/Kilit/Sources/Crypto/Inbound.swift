import Foundation
import CryptoKit

// MARK: - Reason codes (§3.2b)

/// Classification / ack reason strings of §3.2b step 4 and 5, plus the two success reasons.
enum InboundReason: String, Codable, Equatable {
    case badEnvelope = "bad_envelope"
    case unknownSid = "unknown_sid"
    case identityMismatch = "identity_mismatch"
    case lookupFailed = "lookup_failed"
    case keyChangeExpired = "key_change_expired"
    case parkedOverflow = "parked_overflow"
    case replay
    case opkGone = "opk_gone"
    case spkGone = "spk_gone"
    case tooManySkipped = "too_many_skipped"
    case decryptFailed = "decrypt_failed"
    case alreadyProcessed = "already_processed"
    case duplicate
    case stored
}

enum ParkReason: String, Codable, Equatable {
    case keyChange = "key_change"
    case unknownSid = "unknown_sid"
    case lookupDeferred = "lookup_deferred"

    var lifetime: UInt64 {
        switch self {
        case .keyChange: return 7 * 86400
        case .unknownSid, .lookupDeferred: return 24 * 3600
        }
    }

    var expiryReason: InboundReason {
        switch self {
        case .keyChange: return .keyChangeExpired
        case .unknownSid: return .unknownSid
        case .lookupDeferred: return .lookupFailed
        }
    }
}

struct ParkedEnvelope: Codable, Equatable {
    let msgId: String
    let kind: EnvelopeKind
    let sid: Data
    let envelope: Data
    let receivedAt: UInt64
    let reason: ParkReason

    enum CodingKeys: String, CodingKey {
        case msgId = "msg_id"
        case kind, sid, envelope
        case receivedAt = "received_at"
        case reason
    }
}

struct ProcessedId: Codable, Equatable {
    let msgId: String
    let at: UInt64

    enum CodingKeys: String, CodingKey {
        case msgId = "msg_id"
        case at
    }
}

enum MessageAuthor: String, Codable, Equatable {
    case me
    case peer
}

struct DedupeEntry: Codable, Equatable {
    let author: MessageAuthor
    let id: String
    let at: UInt64
}

/// The policy-relevant part of `conv/<peer>.json`: outer dedupe, parked envelopes, inner `(author, id)` dedupe.
struct ConversationState: Codable, Equatable {
    static let processedMax: Int = 10_000
    static let processedTTL: UInt64 = 30 * 86400
    static let dedupeMax: Int = 10_000
    static let dedupeTTL: UInt64 = 45 * 86400
    static let parkedMax: Int = 100

    var processedMsgIds: [ProcessedId]
    var parked: [ParkedEnvelope]
    var seenMessageIds: [DedupeEntry]

    enum CodingKeys: String, CodingKey {
        case processedMsgIds = "processed_msg_ids"
        case parked
        case seenMessageIds = "seen_message_ids"
    }

    init() {
        processedMsgIds = []
        parked = []
        seenMessageIds = []
    }

    func isProcessed(msgId: String) -> Bool {
        processedMsgIds.contains { $0.msgId == msgId }
    }

    mutating func markProcessed(msgId: String, now: UInt64) {
        processedMsgIds.removeAll { $0.msgId == msgId || (now > $0.at && now - $0.at > ConversationState.processedTTL) }
        processedMsgIds.append(ProcessedId(msgId: msgId, at: now))
        if processedMsgIds.count > ConversationState.processedMax {
            processedMsgIds.removeFirst(processedMsgIds.count - ConversationState.processedMax)
        }
    }

    func isKnownMessage(author: MessageAuthor, id: String) -> Bool {
        seenMessageIds.contains { $0.author == author && $0.id == id }
    }

    /// Records `(author, id)`; returns false when it was already known (duplicate).
    mutating func rememberMessage(author: MessageAuthor, id: String, now: UInt64) -> Bool {
        if isKnownMessage(author: author, id: id) { return false }
        seenMessageIds.removeAll { now > $0.at && now - $0.at > ConversationState.dedupeTTL }
        seenMessageIds.append(DedupeEntry(author: author, id: id, at: now))
        if seenMessageIds.count > ConversationState.dedupeMax {
            seenMessageIds.removeFirst(seenMessageIds.count - ConversationState.dedupeMax)
        }
        return true
    }

    /// Parks an envelope; returns the oldest one when the 100-per-peer bound evicted it (`parked_overflow`).
    mutating func park(_ envelope: ParkedEnvelope) -> ParkedEnvelope? {
        parked.removeAll { $0.msgId == envelope.msgId }
        parked.append(envelope)
        if parked.count > ConversationState.parkedMax {
            return parked.removeFirst()
        }
        return nil
    }

    @discardableResult
    mutating func unpark(msgId: String) -> ParkedEnvelope? {
        guard let i = parked.firstIndex(where: { $0.msgId == msgId }) else { return nil }
        return parked.remove(at: i)
    }

    func parked(sid: Data) -> [ParkedEnvelope] {
        parked.filter { $0.sid == sid }
    }

    func parked(reason: ParkReason) -> [ParkedEnvelope] {
        parked.filter { $0.reason == reason }
    }

    /// Removes expired parked envelopes and returns them with the reason they are classified under.
    mutating func expireParked(now: UInt64) -> [(envelope: ParkedEnvelope, reason: InboundReason)] {
        var out: [(envelope: ParkedEnvelope, reason: InboundReason)] = []
        for p in parked where now > p.receivedAt && now - p.receivedAt > p.reason.lifetime {
            out.append((p, p.reason.expiryReason))
        }
        parked.removeAll { p in now > p.receivedAt && now - p.receivedAt > p.reason.lifetime }
        return out
    }
}

// MARK: - Inputs

/// Injected `GET /v1/users/{from}` answer for the trust-on-first-use lookup.
enum LookupResult: Equatable {
    case ok(IdentityPublicKeys)
    case mismatch
    case notFound
    case transient
}

/// Resolves stored prekeys by id (`spk_gone` / `opk_gone` when nil).
struct PrekeyLookup {
    let spk: (UInt32) -> SignedPrekey?
    let opk: (UInt32) -> OneTimePrekey?

    init(spk: @escaping (UInt32) -> SignedPrekey?, opk: @escaping (UInt32) -> OneTimePrekey?) {
        self.spk = spk
        self.opk = opk
    }

    static func from(spks: [SignedPrekey], opks: [OneTimePrekey]) -> PrekeyLookup {
        PrekeyLookup(spk: { id in spks.first { $0.id == id } }, opk: { id in opks.first { $0.id == id } })
    }
}

/// One fetched envelope plus the store snapshot it is processed against.
struct InboundInput {
    let from: String
    let msgId: String
    let envelope: Data
    let now: UInt64
    let local: IdentityKeys
    let localUsername: String
    let contact: ContactRecord?
    let sessions: PeerSessions
    let conversation: ConversationState
    let prekeys: PrekeyLookup
    let lookup: LookupResult?
    let keySource: KeySource
}

// MARK: - Outputs

enum InboundOutcome: Equatable {
    case stored(InnerMessage, sid: Data)
    case duplicate(sid: Data)
    case parked(ParkReason)
    case classified(InboundReason)
    case alreadyProcessed

    /// `stored|parked|classified|already_processed|duplicate` (the `expect` strings of the vector ops).
    var kindString: String {
        switch self {
        case .stored: return "stored"
        case .duplicate: return "duplicate"
        case .parked: return "parked"
        case .classified: return "classified"
        case .alreadyProcessed: return "already_processed"
        }
    }

    var reasonString: String? {
        switch self {
        case .stored, .duplicate: return nil
        case .parked(let r): return r.rawValue
        case .classified(let r): return r.rawValue
        case .alreadyProcessed: return InboundReason.alreadyProcessed.rawValue
        }
    }
}

enum RecoveryTrigger: String, Equatable {
    case rejectedInitiation = "rejected_initiation"
    case s3
}

enum InboundAction: Equatable {
    case ack(msgId: String, reason: InboundReason)
    case deleteOneTimePrekey(id: UInt32)
    /// Fetch a bundle and initiate a new session whose first inner message is `ctrl.resync{lost_sid}`.
    case initiateRecovery(lostSid: Data, trigger: RecoveryTrigger)
    /// A session with this `sid` was committed: re-run the pipeline for envelopes parked under it.
    case rerunParked(sid: Data)
    case keyChangeDetected
    case lookupIdentity(username: String)
    case contactCreated
    case resyncReceived(lostSid: Data, onSid: Data)
}

struct InboundResult {
    let outcome: InboundOutcome
    let sessions: PeerSessions
    let conversation: ConversationState
    let contact: ContactRecord?
    let actions: [InboundAction]

    var ackIds: [String] {
        var out: [String] = []
        for a in actions {
            if case .ack(let id, _) = a { out.append(id) }
        }
        return out
    }
}

// MARK: - Policy

/// §3.2b as a pure function over value types; the caller persists in the normative order
/// (plaintext → ratchet state → `index.json` with cursor + `pendingAcks`) and executes `actions`.
enum Inbound {
    private struct Context {
        let input: InboundInput
        var sessions: PeerSessions
        var conversation: ConversationState
        var contact: ContactRecord?
        var actions: [InboundAction]

        init(_ input: InboundInput) {
            self.input = input
            self.sessions = input.sessions
            self.conversation = input.conversation
            self.contact = input.contact
            self.actions = []
        }

        var now: UInt64 { input.now }

        func result(_ outcome: InboundOutcome) -> InboundResult {
            InboundResult(outcome: outcome, sessions: sessions, conversation: conversation, contact: contact, actions: actions)
        }

        mutating func classify(_ reason: InboundReason) -> InboundResult {
            actions.append(.ack(msgId: input.msgId, reason: reason))
            return result(.classified(reason))
        }

        mutating func park(_ reason: ParkReason, _ parsed: ParsedEnvelope) -> InboundResult {
            let p: ParkedEnvelope = ParkedEnvelope(msgId: input.msgId, kind: parsed.outer.kind, sid: parsed.sid,
                                                   envelope: input.envelope, receivedAt: now, reason: reason)
            if let victim = conversation.park(p) {
                actions.append(.ack(msgId: victim.msgId, reason: .parkedOverflow))
            }
            return result(.parked(reason))
        }
    }

    static func process(_ input: InboundInput) -> InboundResult {
        var ctx: Context = Context(input)
        // Step 0: outer dedupe before any KDF.
        if ctx.conversation.isProcessed(msgId: input.msgId) {
            ctx.actions.append(.ack(msgId: input.msgId, reason: .alreadyProcessed))
            return ctx.result(.alreadyProcessed)
        }
        // Step 1: parse and reject before any KDF.
        let parsed: ParsedEnvelope
        do {
            parsed = try EnvelopeParser.parse(input.envelope)
        } catch {
            return ctx.classify(.badEnvelope)
        }
        switch parsed.outer.kind {
        case .prekey:
            return processPrekey(&ctx, parsed)
        case .msg:
            return processMsg(&ctx, parsed)
        }
    }

    private static func processPrekey(_ ctx: inout Context, _ parsed: ParsedEnvelope) -> InboundResult {
        guard let x = parsed.outer.x3dh, x.ikSig.count == 32, x.ikDh.count == 32, x.ek.count == 32 else {
            return ctx.classify(.badEnvelope)
        }
        do {
            try Ed25519Strict.verify(signature: x.ikBindSig, message: SignedMessages.ikBind(ikDh: x.ikDh), publicKey: x.ikSig)
        } catch {
            return ctx.classify(.badEnvelope)
        }
        let peerIdentity: IdentityPublicKeys = x.identity
        // §3.2 step 1: identity binding.
        if let c = ctx.contact {
            if c.identity != peerIdentity {
                ctx.actions.append(.keyChangeDetected)
                return ctx.park(.keyChange, parsed)
            }
        } else {
            switch ctx.input.lookup {
            case .some(.ok(let fetched)):
                guard fetched == peerIdentity else { return ctx.classify(.identityMismatch) }
                ctx.contact = ContactRecord(username: ctx.input.from, identity: peerIdentity, verified: false, accepted: false)
                ctx.actions.append(.contactCreated)
            case .some(.mismatch), .some(.notFound):
                return ctx.classify(.identityMismatch)
            case .some(.transient), .none:
                ctx.actions.append(.lookupIdentity(username: ctx.input.from))
                return ctx.park(.lookupDeferred, parsed)
            }
        }
        // §3.2 step 2: routing by sid(ek) to any existing session, then seen_ek.
        if let session = ctx.sessions.session(sid: parsed.sid) {
            return decryptOn(&ctx, session: session, parsed: parsed)
        }
        if ctx.sessions.isSeen(ek: x.ek, now: ctx.now) {
            return ctx.classify(.replay)
        }
        // §3.2 step 3: fresh initiation.
        guard let spk = ctx.input.prekeys.spk(x.spkId) else { return rejected(&ctx, parsed, .spkGone) }
        var opk: OneTimePrekey? = nil
        if let oid = x.opkId {
            guard let o = ctx.input.prekeys.opk(oid) else { return rejected(&ctx, parsed, .opkGone) }
            opk = o
        }
        let shared: X3DHResult
        let spkKey: Curve25519.KeyAgreement.PrivateKey
        do {
            shared = try X3DH.respond(x3dh: x, from: ctx.input.from, local: ctx.input.local,
                                      localUsername: ctx.input.localUsername, spk: spk, opk: opk)
            spkKey = try spk.privateKey.x25519PrivateKey()
        } catch {
            return ctx.classify(.decryptFailed)
        }
        let candidate: RatchetState = DoubleRatchet.initBob(sk: shared.sk, dhs: spkKey)
        let plaintext: Data
        let advanced: RatchetState
        do {
            let r = try DoubleRatchet.decrypt(state: candidate, header: parsed.header, wire: parsed.outer.ct,
                                              ad: shared.ad, sid: parsed.sid, keySource: ctx.input.keySource, now: ctx.now)
            plaintext = r.plaintext
            advanced = r.state
        } catch KilitCryptoError.tooManySkipped {
            return ctx.classify(.tooManySkipped)
        } catch {
            return ctx.classify(.decryptFailed)
        }
        guard let inner = parseInner(plaintext) else { return ctx.classify(.badEnvelope) }
        var session: Session = Session(sid: parsed.sid, role: .responder, createdAt: ctx.now, ws: shared.ws, ad: shared.ad,
                                       localIdentity: ctx.input.local.publicKeys, peerIdentity: peerIdentity,
                                       state: advanced, pendingX3DH: nil)
        session.lastActivity = ctx.now
        ctx.sessions.addSession(session)
        ctx.sessions.rememberEk(x.ek, now: ctx.now)
        if let o = opk { ctx.actions.append(.deleteOneTimePrekey(id: o.id)) }
        ctx.sessions.applyS1(committedSid: parsed.sid)
        ctx.contact?.appendWMSecret(sid: parsed.sid, ws: shared.ws)
        ctx.actions.append(.rerunParked(sid: parsed.sid))
        return store(&ctx, inner: inner, sid: parsed.sid)
    }

    /// Rejected initiation (`spk_gone` / `opk_gone` only): recovery for an accepted contact, never for an
    /// existing or known `sid(ek)`, at most once per peer per 10 min; always classified.
    private static func rejected(_ ctx: inout Context, _ parsed: ParsedEnvelope, _ reason: InboundReason) -> InboundResult {
        if let c = ctx.contact, c.accepted,
           ctx.sessions.session(sid: parsed.sid) == nil,
           ctx.sessions.knownSid(parsed.sid) == nil,
           ctx.sessions.gateRejectedInitiationRecovery(now: ctx.now) {
            ctx.sessions.rememberDeleted(sid: parsed.sid, reason: .rejectedInitiation, now: ctx.now)
            ctx.actions.append(.initiateRecovery(lostSid: parsed.sid, trigger: .rejectedInitiation))
        }
        return ctx.classify(reason)
    }

    private static func processMsg(_ ctx: inout Context, _ parsed: ParsedEnvelope) -> InboundResult {
        if let session = ctx.sessions.session(sid: parsed.sid) {
            return decryptOn(&ctx, session: session, parsed: parsed)
        }
        if let known = ctx.sessions.knownSid(parsed.sid), known.deletedReason.triggersS3,
           ctx.sessions.gateS3Recovery(now: ctx.now) {
            ctx.actions.append(.initiateRecovery(lostSid: parsed.sid, trigger: .s3))
        }
        return ctx.park(.unknownSid, parsed)
    }

    private static func decryptOn(_ ctx: inout Context, session: Session, parsed: ParsedEnvelope) -> InboundResult {
        let plaintext: Data
        let advanced: RatchetState
        do {
            let r = try DoubleRatchet.decrypt(state: session.state, header: parsed.header, wire: parsed.outer.ct,
                                              ad: session.ad, sid: session.sid, keySource: ctx.input.keySource, now: ctx.now)
            plaintext = r.plaintext
            advanced = r.state
        } catch KilitCryptoError.tooManySkipped {
            return ctx.classify(.tooManySkipped)
        } catch {
            return ctx.classify(.decryptFailed)
        }
        guard let inner = parseInner(plaintext) else { return ctx.classify(.badEnvelope) }
        ctx.sessions.commitDecrypt(sid: session.sid, state: advanced, now: ctx.now)
        return store(&ctx, inner: inner, sid: session.sid)
    }

    private static func parseInner(_ padded: Data) -> InnerMessage? {
        guard let json = try? Padding.unpad(padded) else { return nil }
        return try? InnerMessage.decode(json)
    }

    /// Step 3: outer id recorded, inner `(peer, id)` dedupe, `ctrl.resync` applied, ack appended.
    private static func store(_ ctx: inout Context, inner: InnerMessage, sid: Data) -> InboundResult {
        ctx.conversation.markProcessed(msgId: ctx.input.msgId, now: ctx.now)
        let fresh: Bool = ctx.conversation.rememberMessage(author: .peer, id: inner.id, now: ctx.now)
        guard fresh else {
            ctx.actions.append(.ack(msgId: ctx.input.msgId, reason: .duplicate))
            return ctx.result(.duplicate(sid: sid))
        }
        if inner.t == InnerMessageType.ctrlResync, let lost = inner.lostSid {
            ctx.sessions.supersede(lostSid: lost)
            ctx.actions.append(.resyncReceived(lostSid: lost, onSid: sid))
        }
        ctx.actions.append(.ack(msgId: ctx.input.msgId, reason: .stored))
        return ctx.result(.stored(inner, sid: sid))
    }
}
