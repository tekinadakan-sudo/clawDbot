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

        /// Step 4 (Go `classify`): the outer id is recorded as processed, then the ack is appended.
        mutating func classify(_ reason: InboundReason) -> InboundResult {
            conversation.markProcessed(msgId: input.msgId, now: now)
            actions.append(.ack(msgId: input.msgId, reason: reason))
            return result(.classified(reason))
        }

        mutating func park(_ reason: ParkReason, _ parsed: ParsedEnvelope) -> InboundResult {
            parkEntry(reason, parsed)
            return result(.parked(reason))
        }

        /// Parks the current envelope. A `parked_overflow` victim is classified like Go does: its id is
        /// recorded as processed and it is acked with `.parkedOverflow` (the caller writes its system row).
        mutating func parkEntry(_ reason: ParkReason, _ parsed: ParsedEnvelope) {
            let p: ParkedEnvelope = ParkedEnvelope(msgId: input.msgId, kind: parsed.outer.kind, sid: parsed.sid,
                                                   envelope: input.envelope, receivedAt: now, reason: reason)
            if let victim = conversation.park(p) {
                conversation.markProcessed(msgId: victim.msgId, now: now)
                actions.append(.ack(msgId: victim.msgId, reason: .parkedOverflow))
            }
        }
    }

    static func process(_ input: InboundInput) -> InboundResult {
        var ctx: Context = Context(input)
        // Step 0: outer dedupe before any KDF.
        if ctx.conversation.isProcessed(msgId: input.msgId, now: input.now) {
            ctx.actions.append(.ack(msgId: input.msgId, reason: .alreadyProcessed))
            return ctx.result(.alreadyProcessed)
        }
        // The same row delivered again (WS + poll) while it is parked: no state change, never acked
        // while parked (Go `ActIgnored`). A parked re-run unparks before calling `process`.
        if let p = ctx.conversation.isParked(msgId: input.msgId) {
            return ctx.result(.parked(p.reason))
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
        // Unpad / inner-JSON failures after a successful decrypt are `decrypt_failed` (Go `decryptReason`).
        guard let inner = parseInner(plaintext) else { return ctx.classify(.decryptFailed) }
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
           ctx.sessions.knownSid(parsed.sid, now: ctx.now) == nil,
           ctx.sessions.gateRecovery(now: ctx.now) {
            ctx.sessions.rememberDeleted(sid: parsed.sid, reason: .rejectedInitiation, now: ctx.now)
            ctx.actions.append(.initiateRecovery(lostSid: parsed.sid, trigger: .rejectedInitiation))
        }
        return ctx.classify(reason)
    }

    private static func processMsg(_ ctx: inout Context, _ parsed: ParsedEnvelope) -> InboundResult {
        if let session = ctx.sessions.session(sid: parsed.sid) {
            return decryptOn(&ctx, session: session, parsed: parsed)
        }
        // Go order: park first, then the S3 trigger under the shared per-peer bound.
        ctx.parkEntry(.unknownSid, parsed)
        if let known = ctx.sessions.knownSid(parsed.sid, now: ctx.now), known.deletedReason.triggersS3,
           ctx.sessions.gateRecovery(now: ctx.now) {
            ctx.actions.append(.initiateRecovery(lostSid: parsed.sid, trigger: .s3))
        }
        return ctx.result(.parked(.unknownSid))
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
        guard let inner = parseInner(plaintext) else { return ctx.classify(.decryptFailed) }
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
