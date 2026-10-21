import Foundation

// MARK: - sessions/<peer>.json

/// An encrypted outbound message kept until `POST /v1/messages` succeeds (write-before-send, §5.4).
struct CachedEnvelope: Codable, Equatable {
    let msgId: String
    let to: String
    let envelope: Data
    let kind: EnvelopeKind
    let sid: Data
    let innerId: String
    let innerType: String
    let createdAt: UInt64
}

struct SessionDocument: Codable, Equatable {
    var peer: PeerSessions
    var pendingSends: [CachedEnvelope]

    init() {
        peer = PeerSessions()
        pendingSends = []
    }

    func cached(msgId: String) -> CachedEnvelope? {
        pendingSends.first { $0.msgId == msgId }
    }
}

enum SessionStoreError: Error, Equatable {
    /// No non-superseded session can send: fetch a bundle and initiate (§3.2 sending-session rule).
    case noSendingSession
    case unknownSession
}

// MARK: - SessionStore

/// Loads `sessions/<peer>.json` under the §3.7 rule (rollback → sessions deleted with `deletedReason =
/// rollback`, S3 queued), encrypts outbound messages on the sending session and keeps the pending-send cache.
/// Persistence goes through `LocalStore.commit` so the caller controls the normative write order.
final class SessionStore {
    private let store: LocalStore
    private let clock: KilitClock
    /// Lost sids awaiting S3 recovery per peer; `[]` means "re-initiate without a resync" (unparseable file).
    private(set) var pendingRecovery: [String: [Data]] = [:]

    init(store: LocalStore, clock: KilitClock) {
        self.store = store
        self.clock = clock
    }

    static func path(_ peer: String) -> String {
        LocalStore.sessionPath(peer)
    }

    /// Loads (or creates) the document, pruning by age/cap. A rollback or parse failure replaces the file at once
    /// (the replacement carries the new generation so the condition is not re-detected) and queues S3.
    func load(peer: String) throws -> SessionDocument {
        let now: UInt64 = clock.now
        let path: String = SessionStore.path(peer)
        switch try store.loadDetailed(SessionDocument.self, at: path) {
        case .missing:
            return SessionDocument()
        case .ok(var doc):
            doc.peer.prune(now: now)
            return doc
        case .rollback(let stale):
            var fresh: SessionDocument = SessionDocument()
            var lost: [Data] = []
            if let s = stale {
                fresh.peer.seenEk = s.peer.seenEk
                fresh.peer.knownSids = s.peer.knownSids
                fresh.peer.lastRecoveryAt = s.peer.lastRecoveryAt
                lost = s.peer.sessions.map { $0.sid }
            }
            for sid in lost {
                fresh.peer.rememberDeleted(sid: sid, reason: .rollback, now: now)
            }
            // Go `LoseSession` → `initiateResync` stamps the shared bound without consulting it.
            if !lost.isEmpty { fresh.peer.stampRecovery(now: now) }
            pendingRecovery[peer] = lost
            try store.commit([try DocumentWrite(path: path, value: fresh)])
            return fresh
        case .corrupt:
            let fresh: SessionDocument = SessionDocument()
            pendingRecovery[peer] = []
            try store.commit([try DocumentWrite(path: path, value: fresh)])
            return fresh
        }
    }

    func takePendingRecovery(peer: String) -> [Data]? {
        pendingRecovery.removeValue(forKey: peer)
    }

    func write(peer: String, _ doc: SessionDocument) throws -> DocumentWrite {
        try DocumentWrite(path: SessionStore.path(peer), value: doc)
    }

    /// Persists the document alone (e.g. after adding a freshly initiated session).
    func save(peer: String, _ doc: SessionDocument, mutateIndex: ((inout StoreIndex) -> Void)? = nil) throws {
        try store.commit([try write(peer: peer, doc)], mutateIndex: mutateIndex)
    }

    // MARK: outbound encryption

    /// Encrypts `inner` on the sending session (§3.2 rule) and appends the bytes to the pending-send cache.
    /// The caller commits `doc` before the envelope leaves the device.
    static func encrypt(doc: inout SessionDocument, peer: String, inner: InnerMessage, msgId: String,
                        local: IdentityKeys, now: UInt64) throws -> CachedEnvelope {
        guard let sending = doc.peer.sendingSession() else { throw SessionStoreError.noSendingSession }
        return try encrypt(doc: &doc, on: sending.sid, peer: peer, inner: inner, msgId: msgId, local: local, now: now)
    }

    /// Encrypts on a specific session (the `ctrl.resync` first message of a recovery session).
    static func encrypt(doc: inout SessionDocument, on sid: Data, peer: String, inner: InnerMessage, msgId: String,
                        local: IdentityKeys, now: UInt64) throws -> CachedEnvelope {
        guard let i = doc.peer.index(of: sid) else { throw SessionStoreError.unknownSession }
        var session: Session = doc.peer.sessions[i]
        let out: OutboundEnvelope = try SessionOutbound.encrypt(session: &session, inner: inner, local: local)
        doc.peer.sessions[i] = session
        let cached: CachedEnvelope = CachedEnvelope(msgId: msgId, to: peer, envelope: out.bytes, kind: out.kind,
                                                    sid: out.sid, innerId: inner.id, innerType: inner.t, createdAt: now)
        doc.pendingSends.removeAll { $0.msgId == msgId }
        doc.pendingSends.append(cached)
        return cached
    }

    /// Removes a cache entry after the server accepted the message (`202`) or the send was abandoned.
    func markSent(peer: String, msgId: String, mutateIndex: ((inout StoreIndex) -> Void)? = nil) throws {
        var doc: SessionDocument = try load(peer: peer)
        guard doc.pendingSends.contains(where: { $0.msgId == msgId }) else {
            if let m = mutateIndex { try store.commitIndex(m) }
            return
        }
        doc.pendingSends.removeAll { $0.msgId == msgId }
        try save(peer: peer, doc, mutateIndex: mutateIndex)
    }

    func cached(peer: String, msgId: String) throws -> CachedEnvelope? {
        try load(peer: peer).cached(msgId: msgId)
    }

    /// Adds an initiator session (bundle fetched by the caller) and persists.
    func addInitiated(peer: String, session: Session) throws -> SessionDocument {
        var doc: SessionDocument = try load(peer: peer)
        doc.peer.addSession(session)
        try save(peer: peer, doc)
        return doc
    }
}
