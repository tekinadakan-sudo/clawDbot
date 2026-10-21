import Foundation

// MARK: - Conversation policy state (§3.2b): parked envelopes, outer and inner dedupe

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

    /// Presence lookup without the age window (store bookkeeping and tests).
    func isProcessed(msgId: String) -> Bool {
        processedMsgIds.contains { $0.msgId == msgId }
    }

    /// Go `isProcessed`: only ids recorded at most 30 d before `now` count (step 0).
    func isProcessed(msgId: String, now: UInt64) -> Bool {
        processedMsgIds.contains { $0.msgId == msgId && !(now > $0.at && now - $0.at > ConversationState.processedTTL) }
    }

    func isParked(msgId: String) -> ParkedEnvelope? {
        parked.first { $0.msgId == msgId }
    }

    mutating func markProcessed(msgId: String, now: UInt64) {
        processedMsgIds.removeAll { $0.msgId == msgId || (now > $0.at && now - $0.at > ConversationState.processedTTL) }
        processedMsgIds.append(ProcessedId(msgId: msgId, at: now))
        if processedMsgIds.count > ConversationState.processedMax {
            processedMsgIds.removeFirst(processedMsgIds.count - ConversationState.processedMax)
        }
    }

    /// Go `isDuplicate`: only entries recorded at most 45 d before `now` count.
    func isKnownMessage(author: MessageAuthor, id: String, now: UInt64) -> Bool {
        seenMessageIds.contains { e in
            e.author == author && e.id == id && !(now > e.at && now - e.at > ConversationState.dedupeTTL)
        }
    }

    /// Records `(author, id)`; returns false when it was already known (duplicate).
    mutating func rememberMessage(author: MessageAuthor, id: String, now: UInt64) -> Bool {
        if isKnownMessage(author: author, id: id, now: now) { return false }
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

    /// Removes expired parked envelopes and returns them with the reason they are classified under; like Go's
    /// expiry (which runs `classify`), each expired id is recorded in `processed_msg_ids`.
    mutating func expireParked(now: UInt64) -> [(envelope: ParkedEnvelope, reason: InboundReason)] {
        var out: [(envelope: ParkedEnvelope, reason: InboundReason)] = []
        for p in parked where now > p.receivedAt && now - p.receivedAt > p.reason.lifetime {
            out.append((p, p.reason.expiryReason))
        }
        parked.removeAll { p in now > p.receivedAt && now - p.receivedAt > p.reason.lifetime }
        for e in out {
            markProcessed(msgId: e.envelope.msgId, now: now)
        }
        return out
    }
}
