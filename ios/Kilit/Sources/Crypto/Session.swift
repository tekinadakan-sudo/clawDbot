import Foundation
import CryptoKit

// MARK: - Session (§3.2)

enum SessionRole: String, Codable, Equatable {
    case initiator
    case responder
}

enum SupersededReason: String, Codable, Equatable {
    /// S1: a newer responder session with the peer was committed.
    case peerMovedOn = "peer_moved_on"
    /// S2: the peer's identity keys changed and the new record was accepted.
    case oldIdentity
    /// The peer told us via `ctrl.resync{lost_sid}` that it lost this session.
    case resync
}

struct Session: Codable, Equatable {
    let sid: Data
    let role: SessionRole
    let createdAt: UInt64
    /// Timestamp of the last successful decrypt of a peer message (own sends do not count).
    var lastActivity: UInt64?
    /// Sticky, never cleared.
    var superseded: Bool
    var supersededReason: SupersededReason?
    let ws: Data
    let ad: Data
    let localIdentity: IdentityPublicKeys
    let peerIdentity: IdentityPublicKeys
    var state: RatchetState
    var pendingX3DH: PendingX3DH?

    enum CodingKeys: String, CodingKey {
        case sid, role
        case createdAt = "created_at"
        case lastActivity = "last_activity"
        case superseded
        case supersededReason = "superseded_reason"
        case ws, ad
        case localIdentity = "local_identity"
        case peerIdentity = "peer_identity"
        case state
        case pendingX3DH = "pending_x3dh"
    }

    init(sid: Data, role: SessionRole, createdAt: UInt64, ws: Data, ad: Data, localIdentity: IdentityPublicKeys,
         peerIdentity: IdentityPublicKeys, state: RatchetState, pendingX3DH: PendingX3DH?) {
        self.sid = sid
        self.role = role
        self.createdAt = createdAt
        self.lastActivity = nil
        self.superseded = false
        self.supersededReason = nil
        self.ws = ws
        self.ad = ad
        self.localIdentity = localIdentity
        self.peerIdentity = peerIdentity
        self.state = state
        self.pendingX3DH = pendingX3DH
    }

    mutating func supersede(_ reason: SupersededReason) {
        if !superseded {
            superseded = true
            supersededReason = reason
        }
    }
}

enum DeletedReason: String, Codable, Equatable {
    case rollback
    case parseFailure = "parse_failure"
    case rejectedInitiation = "rejected_initiation"
    case pruned

    /// Only these trigger S3 recovery on an inbound `msg` with an unknown `sid`.
    var triggersS3: Bool {
        self == .rollback || self == .parseFailure
    }
}

struct KnownSid: Codable, Equatable {
    let sid: Data
    let deletedReason: DeletedReason
    let deletedAt: UInt64

    enum CodingKeys: String, CodingKey {
        case sid
        case deletedReason = "deleted_reason"
        case deletedAt = "deleted_at"
    }
}

struct SeenEK: Codable, Equatable {
    let ek: Data
    let seenAt: UInt64

    enum CodingKeys: String, CodingKey {
        case ek
        case seenAt = "seen_at"
    }
}

/// `sessions/<peer>.json`: every session with one peer plus `seen_ek`, `known_sids` and the recovery gates.
struct PeerSessions: Codable, Equatable {
    static let seenEkTTL: UInt64 = 45 * 86400
    static let seenEkMax: Int = 64
    static let knownSidTTL: UInt64 = 90 * 86400
    static let supersededTTL: UInt64 = 30 * 86400
    static let maxSessions: Int = 4
    /// Minimum spacing of recovery initiations per peer (rejected-initiation path and S3), seconds.
    static let recoveryInterval: UInt64 = 600

    var sessions: [Session]
    var seenEk: [SeenEK]
    var knownSids: [KnownSid]
    var lastRejectedInitiationRecoveryAt: UInt64?
    var lastS3RecoveryAt: UInt64?

    enum CodingKeys: String, CodingKey {
        case sessions
        case seenEk = "seen_ek"
        case knownSids = "known_sids"
        case lastRejectedInitiationRecoveryAt = "last_rejected_initiation_recovery_at"
        case lastS3RecoveryAt = "last_s3_recovery_at"
    }

    init() {
        self.sessions = []
        self.seenEk = []
        self.knownSids = []
        self.lastRejectedInitiationRecoveryAt = nil
        self.lastS3RecoveryAt = nil
    }

    // MARK: lookup

    func index(of sid: Data) -> Int? {
        sessions.firstIndex { $0.sid == sid }
    }

    func session(sid: Data) -> Session? {
        sessions.first { $0.sid == sid }
    }

    func knownSid(_ sid: Data) -> KnownSid? {
        knownSids.first { $0.sid == sid }
    }

    func isSeen(ek: Data, now: UInt64) -> Bool {
        seenEk.contains { $0.ek == ek && !(now > $0.seenAt && now - $0.seenAt > PeerSessions.seenEkTTL) }
    }

    // MARK: mutation

    mutating func rememberEk(_ ek: Data, now: UInt64) {
        seenEk.removeAll { $0.ek == ek || (now > $0.seenAt && now - $0.seenAt > PeerSessions.seenEkTTL) }
        seenEk.append(SeenEK(ek: ek, seenAt: now))
        if seenEk.count > PeerSessions.seenEkMax {
            seenEk.removeFirst(seenEk.count - PeerSessions.seenEkMax)
        }
    }

    mutating func rememberDeleted(sid: Data, reason: DeletedReason, now: UInt64) {
        knownSids.removeAll { $0.sid == sid }
        knownSids.append(KnownSid(sid: sid, deletedReason: reason, deletedAt: now))
    }

    mutating func addSession(_ session: Session) {
        sessions.removeAll { $0.sid == session.sid }
        sessions.append(session)
    }

    /// Deletes a session (not supersession) and records its `sid` in `known_sids`.
    mutating func deleteSession(sid: Data, reason: DeletedReason, now: UInt64) {
        sessions.removeAll { $0.sid == sid }
        rememberDeleted(sid: sid, reason: reason, now: now)
    }

    /// Commits an advanced ratchet state after a successful peer decrypt: `lastActivity = now`,
    /// `pendingX3DH` cleared.
    mutating func commitDecrypt(sid: Data, state: RatchetState, now: UInt64) {
        guard let i = index(of: sid) else { return }
        sessions[i].state = state
        sessions[i].lastActivity = now
        sessions[i].pendingX3DH = nil
    }

    /// S1: when a new responder session is committed, every other session that already has a decrypt
    /// becomes superseded; sessions without a decrypt are untouched (crossed case).
    mutating func applyS1(committedSid: Data) {
        for i in sessions.indices where sessions[i].sid != committedSid && sessions[i].lastActivity != nil {
            sessions[i].supersede(.peerMovedOn)
        }
    }

    /// S2: on accepted key change every session whose AD identity keys differ from the new record is superseded.
    mutating func applyS2(newPeerIdentity: IdentityPublicKeys) {
        for i in sessions.indices where sessions[i].peerIdentity != newPeerIdentity {
            sessions[i].supersede(.oldIdentity)
        }
    }

    /// `ctrl.resync{lost_sid}` receiver: supersede even without `lastActivity`. Returns false if unknown.
    @discardableResult
    mutating func supersede(lostSid: Data) -> Bool {
        guard let i = index(of: lostSid) else { return false }
        sessions[i].supersede(.resync)
        return true
    }

    /// Superseded sessions are deleted 30 d after `lastActivity`, at most 4 sessions per peer (the oldest
    /// superseded goes first), `seen_ek` 45 d, `known_sids` 90 d.
    mutating func prune(now: UInt64) {
        var expired: [Data] = []
        for s in sessions where s.superseded {
            let last: UInt64 = s.lastActivity ?? s.createdAt
            if now > last && now - last > PeerSessions.supersededTTL { expired.append(s.sid) }
        }
        for sid in expired { deleteSession(sid: sid, reason: .pruned, now: now) }
        while sessions.count > PeerSessions.maxSessions {
            let superseded: [Session] = sessions.filter { $0.superseded }.sorted { $0.createdAt < $1.createdAt }
            guard let victim = superseded.first else { break }
            deleteSession(sid: victim.sid, reason: .pruned, now: now)
        }
        seenEk.removeAll { now > $0.seenAt && now - $0.seenAt > PeerSessions.seenEkTTL }
        knownSids.removeAll { now > $0.deletedAt && now - $0.deletedAt > PeerSessions.knownSidTTL }
    }

    /// Sending-session rule (deterministic, clock-free): among non-superseded sessions, if any has
    /// `lastActivity`, the one with the lexicographically smallest `sid` among those; otherwise the newest
    /// own-initiated one by `createdAt`; nil means "fetch a bundle and initiate".
    func sendingSession() -> Session? {
        let candidates: [Session] = sessions.filter { !$0.superseded }
        let active: [Session] = candidates.filter { $0.lastActivity != nil }
        if !active.isEmpty {
            return active.min { Bytes.lexLess($0.sid, $1.sid) }
        }
        let own: [Session] = candidates.filter { $0.role == .initiator }
        return own.max { a, b in
            if a.createdAt != b.createdAt { return a.createdAt < b.createdAt }
            return Bytes.lexLess(b.sid, a.sid)
        }
    }

    /// The 10-minute gate of the rejected-initiation path; records the time when it opens.
    mutating func gateRejectedInitiationRecovery(now: UInt64) -> Bool {
        if let last = lastRejectedInitiationRecoveryAt, now >= last, now - last < PeerSessions.recoveryInterval {
            return false
        }
        lastRejectedInitiationRecoveryAt = now
        return true
    }

    /// The 10-minute gate of the S3 trigger; records the time when it opens.
    mutating func gateS3Recovery(now: UInt64) -> Bool {
        if let last = lastS3RecoveryAt, now >= last, now - last < PeerSessions.recoveryInterval {
            return false
        }
        lastS3RecoveryAt = now
        return true
    }
}

// MARK: - Contact record and watermark secrets (§5.9)

struct WMSecret: Codable, Equatable {
    let sid: Data
    let ws: Data
}

struct ContactRecord: Codable, Equatable {
    let username: String
    var identity: IdentityPublicKeys
    var verified: Bool
    /// "Kabul et" tapped; before that the conversation is a pending message request.
    var accepted: Bool
    var blocked: Bool
    var wmSecrets: [WMSecret]

    enum CodingKeys: String, CodingKey {
        case username, identity, verified, accepted, blocked
        case wmSecrets = "wm_secrets"
    }

    init(username: String, identity: IdentityPublicKeys, verified: Bool = false, accepted: Bool = false,
         blocked: Bool = false, wmSecrets: [WMSecret] = []) {
        self.username = username
        self.identity = identity
        self.verified = verified
        self.accepted = accepted
        self.blocked = blocked
        self.wmSecrets = wmSecrets
    }

    mutating func appendWMSecret(sid: Data, ws: Data) {
        if !wmSecrets.contains(where: { $0.sid == sid }) {
            wmSecrets.append(WMSecret(sid: sid, ws: ws))
        }
    }

    /// The `ws` of the entry with the lexicographically smallest `sid` (same on both devices).
    var canonicalWMSecret: Data? {
        wmSecrets.min { Bytes.lexLess($0.sid, $1.sid) }?.ws
    }

    /// Accepted key change: replaces the identity and resets `wm_secrets`.
    mutating func acceptKeyChange(_ newIdentity: IdentityPublicKeys) {
        identity = newIdentity
        wmSecrets = []
    }
}

// MARK: - Outbound (sender side)

/// A message this device sent, kept for the `ctrl.resync` resend rule.
struct OwnSentMessage: Codable, Equatable {
    let id: String
    let sid: Data
    let sentAt: UInt64

    enum CodingKeys: String, CodingKey {
        case id, sid
        case sentAt = "sent_at"
    }
}

struct OutboundEnvelope: Equatable {
    let bytes: Data
    let kind: EnvelopeKind
    let sid: Data
    let header: MessageHeader
    let wire: Data
}

enum SessionOutbound {
    static let resendWindow: UInt64 = 7 * 86400
    static let resendMax: Int = 50

    /// Fetch-bundle-and-initiate: X3DH (draws `EK`) then `RatchetInitAlice` (draws `DHs`).
    static func initiate(bundle: PrekeyBundle, local: IdentityKeys, localUsername: String,
                         now: UInt64, keySource: KeySource) throws -> Session {
        let x: X3DHInitiation = try X3DH.initiate(bundle: bundle, local: local, localUsername: localUsername,
                                                  now: now, keySource: keySource)
        let state: RatchetState = try DoubleRatchet.initAlice(sk: x.result.sk, peerDhPub: x.peerSpkPub, keySource: keySource)
        return Session(sid: x.result.sid, role: .initiator, createdAt: now, ws: x.result.ws, ad: x.result.ad,
                       localIdentity: local.publicKeys, peerIdentity: bundle.identity, state: state, pendingX3DH: x.pending)
    }

    /// Pads, ratchet-encrypts and builds the envelope (`prekey` while `pendingX3DH` is present).
    /// The caller persists the advanced `session` before the bytes leave the device.
    static func encrypt(session: inout Session, inner: InnerMessage, local: IdentityKeys) throws -> OutboundEnvelope {
        let json: Data = try inner.encodedForPadding()
        let padded: Data = try Padding.pad(json)
        let enc: RatchetEncryption = try DoubleRatchet.encrypt(state: &session.state, plaintext: padded,
                                                               ad: session.ad, sid: session.sid)
        var x3dh: X3DHBlock? = nil
        var kind: EnvelopeKind = .msg
        if let p = session.pendingX3DH {
            let ids: IdentityPublicKeys = local.publicKeys
            let bind: Data = try local.ikBindSig()
            x3dh = X3DHBlock(ikSig: ids.ikSig, ikDh: ids.ikDh, ikBindSig: bind,
                             ek: p.ekPub, spkId: p.spkId, opkId: p.opkId)
            kind = .prekey
        }
        let outer: OuterEnvelope = OuterEnvelope(kind: kind, sid: session.sid, x3dh: x3dh, hdr: enc.header.bytes, ct: enc.wire)
        let bytes: Data = try outer.encoded()
        return OutboundEnvelope(bytes: bytes, kind: kind, sid: session.sid, header: enc.header, wire: enc.wire)
    }

    /// `ctrl.resync` resend set: own messages sent on `lostSid` within the last 7 days, oldest first, ≤ 50.
    static func resendCandidates(sent: [OwnSentMessage], lostSid: Data, now: UInt64) -> [OwnSentMessage] {
        let eligible: [OwnSentMessage] = sent.filter { m in
            m.sid == lostSid && !(now > m.sentAt && now - m.sentAt > resendWindow)
        }
        let ordered: [OwnSentMessage] = eligible.sorted { $0.sentAt < $1.sentAt }
        return Array(ordered.prefix(resendMax))
    }
}

// MARK: - Ack ledger (index.json)

/// `index.json`'s `cursor` + `pendingAcks[]` (§3.2b step 5): every ack of every reason is appended in the
/// same write that advances the cursor; an id leaves the list only on server confirmation.
struct AckLedger: Codable, Equatable {
    static let maxPending: Int = 5_000

    var cursor: Int64
    var pendingAcks: [String]

    enum CodingKeys: String, CodingKey {
        case cursor
        case pendingAcks
    }

    init(cursor: Int64 = 0, pendingAcks: [String] = []) {
        self.cursor = cursor
        self.pendingAcks = pendingAcks
    }

    mutating func record(serverId: Int64, acks: [String]) {
        if serverId > cursor { cursor = serverId }
        for id in acks where !pendingAcks.contains(id) {
            pendingAcks.append(id)
        }
        if pendingAcks.count > AckLedger.maxPending {
            pendingAcks.removeFirst(pendingAcks.count - AckLedger.maxPending)
        }
    }

    mutating func confirm(_ ids: [String]) {
        pendingAcks.removeAll { ids.contains($0) }
    }
}
