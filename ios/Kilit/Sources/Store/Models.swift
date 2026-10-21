import Foundation

// MARK: - Clock

/// Unix seconds; injected everywhere a deadline or timestamp is computed.
protocol KilitClock: AnyObject {
    var now: UInt64 { get }
}

final class SystemClock: KilitClock {
    init() {}
    var now: UInt64 { UInt64(max(0, Date().timeIntervalSince1970)) }
}

final class ManualClock: KilitClock {
    var now: UInt64
    init(now: UInt64) { self.now = now }
    func advance(_ seconds: UInt64) { now += seconds }
}

// MARK: - Messages (§5.3)

enum MessageKind: String, Codable, Equatable {
    case text
    case image
    /// System rows.
    case timer
    case capture
    case undecryptable
    case resync
    case keyChange = "key_change"
}

enum MessageState: Codable, Equatable {
    case outbox
    case sent
    case received
    case revealed
    case undecryptable(String)
}

/// A local capture-log entry and the payload of a `ctrl.capture` system row. `kind` is the §3.4 wire spelling
/// (`CaptureEventKind.rawValue`); `Store/` never imports `Security/`. `seq` is nil for `blanking_unavailable`.
struct CaptureEvent: Codable, Equatable {
    let peer: String
    let seq: UInt32?
    let kind: String
    let ts: UInt64
    let ref: [String]
    /// Range as received in a `ctrl.capture` (nil for local events).
    var seqFrom: UInt32?
    var seqTo: UInt32?
    var count: UInt32?

    init(peer: String, seq: UInt32?, kind: String, ts: UInt64, ref: [String],
         seqFrom: UInt32? = nil, seqTo: UInt32? = nil, count: UInt32? = nil) {
        self.peer = peer
        self.seq = seq
        self.kind = kind
        self.ts = ts
        self.ref = ref
        self.seqFrom = seqFrom
        self.seqTo = seqTo
        self.count = count
    }
}

struct Message: Codable, Equatable, Identifiable {
    let id: String
    let conversationID: String
    let author: MessageAuthor
    let kind: MessageKind
    /// Sender clock (metadata only; ordering uses `sentAt`/`receivedAt`).
    let ts: UInt64
    var sentAt: UInt64?
    var receivedAt: UInt64?
    var firstRevealedAt: UInt64?
    var expiresAt: UInt64?
    let ttl: UInt32
    var text: String?
    var att: InnerAttachment?
    var sentOnSid: Data?
    var state: MessageState
    /// `ctrl.timer` rows: the new timer in seconds (0 = off).
    var timer: UInt32?
    /// `ctrl.capture` rows and the local capture rows.
    var capture: CaptureEvent?
    /// Set by a `ctrl.read` from the peer ("Görüldü").
    var readByPeer: Bool
    /// Attachment ciphertext present in `blobs/<id>.bin`.
    var blobDownloaded: Bool
    /// `GET /v1/attachments/{id}` answered 404 or the digest failed ("Ek süresi doldu").
    var blobExpired: Bool

    init(id: String, conversationID: String, author: MessageAuthor, kind: MessageKind, ts: UInt64, ttl: UInt32,
         state: MessageState, sentAt: UInt64? = nil, receivedAt: UInt64? = nil, text: String? = nil,
         att: InnerAttachment? = nil, sentOnSid: Data? = nil, timer: UInt32? = nil, capture: CaptureEvent? = nil) {
        self.id = id
        self.conversationID = conversationID
        self.author = author
        self.kind = kind
        self.ts = ts
        self.sentAt = sentAt
        self.receivedAt = receivedAt
        self.firstRevealedAt = nil
        self.expiresAt = nil
        self.ttl = ttl
        self.text = text
        self.att = att
        self.sentOnSid = sentOnSid
        self.state = state
        self.timer = timer
        self.capture = capture
        self.readByPeer = false
        self.blobDownloaded = false
        self.blobExpired = false
    }

    /// Local ordering key (§5.2): `receivedAt`/`sentAt`, falling back to the sender clock.
    var orderingTime: UInt64 { receivedAt ?? sentAt ?? ts }

    var isContent: Bool { kind == .text || kind == .image }
}

// MARK: - Conversation metadata (index.json) and the per-peer document

struct Conversation: Codable, Equatable, Identifiable {
    /// Canonical peer username (one conversation per contact, survives key change).
    let peer: String
    /// Current disappearing timer in seconds (0 = off).
    var timer: UInt32
    var lastActivityAt: UInt64
    var unreadCount: Int
    /// The identity carried by a parked `key_change` envelope, shown by the "Güvenlik numarası değişti" banner.
    var pendingKeyChange: IdentityPublicKeys?

    var id: String { peer }

    init(peer: String, timer: UInt32 = 0, lastActivityAt: UInt64 = 0) {
        self.peer = peer
        self.timer = timer
        self.lastActivityAt = lastActivityAt
        self.unreadCount = 0
        self.pendingKeyChange = nil
    }
}

/// `conv/<peer>.json`: the message log plus the §3.2b policy state (`processed_msg_ids`, `parked[]`,
/// `(author, id)` dedupe), `lastPeerCaptureSeq` and the own-sent records used by `ctrl.resync`.
struct ConversationDocument: Codable, Equatable {
    var messages: [Message]
    var state: ConversationState
    var lastPeerCaptureSeq: UInt32?
    var sent: [OwnSentMessage]

    init() {
        messages = []
        state = ConversationState()
        lastPeerCaptureSeq = nil
        sent = []
    }

    func index(id: String, author: MessageAuthor) -> Int? {
        messages.firstIndex { $0.id == id && $0.author == author }
    }

    mutating func append(_ message: Message) {
        messages.append(message)
    }

    /// Removes the messages and returns them (the caller deletes blobs).
    @discardableResult
    mutating func remove(ids: [String], author: MessageAuthor) -> [Message] {
        let removed: [Message] = messages.filter { ids.contains($0.id) && $0.author == author }
        messages.removeAll { ids.contains($0.id) && $0.author == author }
        return removed
    }

    /// `ctrl.read`: only ids authored by the local user (the recipient of the receipt) are honoured.
    mutating func applyRead(ids: [String]) {
        for i in messages.indices where messages[i].author == .me && ids.contains(messages[i].id) {
            messages[i].readByPeer = true
        }
    }

    mutating func recordSent(id: String, sid: Data, at: UInt64) {
        sent.removeAll { at > $0.sentAt && at - $0.sentAt > SessionOutbound.resendWindow }
        sent.append(OwnSentMessage(id: id, sid: sid, sentAt: at))
    }
}

// MARK: - Settings (§5.11 defaults)

struct Settings: Codable, Equatable {
    var defaultTimer: UInt32
    var appLock: Bool
    var secureLayer: Bool
    /// `SecureLayerMode.rawValue` (`canvas` | `layerSwap`); stored as a String so `Store/` never imports `Security/`.
    var secureLayerMode: String
    var captureReports: Bool
    var readReceipts: Bool
    var accessibilityHide: Bool
    var flicker: Bool

    init() {
        defaultTimer = 0
        appLock = true
        secureLayer = true
        secureLayerMode = "canvas"
        captureReports = true
        readReceipts = false
        accessibilityHide = false
        flicker = false
    }

    enum CodingKeys: String, CodingKey {
        case defaultTimer, appLock, secureLayer, secureLayerMode, captureReports, readReceipts, accessibilityHide, flicker
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let d: Settings = Settings()
        defaultTimer = try c.decodeIfPresent(UInt32.self, forKey: .defaultTimer) ?? d.defaultTimer
        appLock = try c.decodeIfPresent(Bool.self, forKey: .appLock) ?? d.appLock
        secureLayer = try c.decodeIfPresent(Bool.self, forKey: .secureLayer) ?? d.secureLayer
        secureLayerMode = try c.decodeIfPresent(String.self, forKey: .secureLayerMode) ?? d.secureLayerMode
        captureReports = try c.decodeIfPresent(Bool.self, forKey: .captureReports) ?? d.captureReports
        readReceipts = try c.decodeIfPresent(Bool.self, forKey: .readReceipts) ?? d.readReceipts
        accessibilityHide = try c.decodeIfPresent(Bool.self, forKey: .accessibilityHide) ?? d.accessibilityHide
        flicker = try c.decodeIfPresent(Bool.self, forKey: .flicker) ?? d.flicker
    }
}

// MARK: - Outbox (§5.4)

enum OutboxPayload: Codable, Equatable {
    /// An already encrypted message; the bytes are in `sessions/<to>.json`'s pending-send cache.
    case envelope(to: String, msgId: String, innerId: String)
    /// A control message encrypted when it is dequeued (after content messages).
    case control(to: String, inner: InnerMessage)
    /// `DELETE /v1/attachments/{id}` after a verified download.
    case deleteBlob(id: String)
}

struct OutboxItem: Codable, Equatable, Identifiable {
    let id: String
    let payload: OutboxPayload
    /// 0 = content, 1 = control / housekeeping (sent after content).
    let priority: Int
    var attempts: Int
    var nextAttemptAt: UInt64
    let createdAt: UInt64

    init(id: String, payload: OutboxPayload, priority: Int, createdAt: UInt64) {
        self.id = id
        self.payload = payload
        self.priority = priority
        self.attempts = 0
        self.nextAttemptAt = createdAt
        self.createdAt = createdAt
    }
}

enum Backoff {
    /// Outbox: 5 s doubling to 10 min.
    static func outbox(attempts: Int) -> UInt64 {
        let capped: Int = min(max(attempts, 1), 8)
        return min(600, 5 * (UInt64(1) << UInt64(capped - 1)))
    }

    /// WebSocket reconnect: 1 s doubling to 30 s.
    static func webSocket(attempt: Int) -> Double {
        let capped: Int = min(max(attempt, 1), 6)
        return min(30, Double(1 << (capped - 1)))
    }
}

/// Diagnostics entry for an undecryptable envelope.
struct UndecryptableEntry: Codable, Equatable {
    let peer: String
    let msgId: String
    let reason: String
    let at: UInt64
}

// MARK: - index.json

struct StoreIndex: Codable, Equatable {
    static let undecryptableLogMax: Int = 200
    static let captureLogMax: Int = 500

    var version: Int
    var username: String?
    var serverOrigin: String?
    var clockOffset: Int64
    var contacts: [ContactRecord]
    var conversations: [Conversation]
    var settings: Settings
    var prekeys: PrekeyRecords
    var captureLog: [CaptureEvent]
    var captureSeq: [String: UInt32]
    var ledger: AckLedger
    var outbox: [OutboxItem]
    /// Per-document generation counters of the child documents (§3.7).
    var generations: [String: UInt64]
    var undecryptableLog: [UndecryptableEntry]

    init() {
        version = 1
        username = nil
        serverOrigin = nil
        clockOffset = 0
        contacts = []
        conversations = []
        settings = Settings()
        prekeys = PrekeyRecords()
        captureLog = []
        captureSeq = [:]
        ledger = AckLedger()
        outbox = []
        generations = [:]
        undecryptableLog = []
    }

    func contact(_ username: String) -> ContactRecord? {
        contacts.first { $0.username == username }
    }

    mutating func upsertContact(_ record: ContactRecord) {
        if let i = contacts.firstIndex(where: { $0.username == record.username }) {
            contacts[i] = record
        } else {
            contacts.append(record)
        }
    }

    func conversation(_ peer: String) -> Conversation? {
        conversations.first { $0.peer == peer }
    }

    /// Returns the index of the conversation, creating it when absent.
    mutating func conversationIndex(_ peer: String, now: UInt64) -> Int {
        if let i = conversations.firstIndex(where: { $0.peer == peer }) { return i }
        conversations.append(Conversation(peer: peer, timer: settings.defaultTimer, lastActivityAt: now))
        return conversations.count - 1
    }

    mutating func logUndecryptable(peer: String, msgId: String, reason: String, at: UInt64) {
        undecryptableLog.append(UndecryptableEntry(peer: peer, msgId: msgId, reason: reason, at: at))
        if undecryptableLog.count > StoreIndex.undecryptableLogMax {
            undecryptableLog.removeFirst(undecryptableLog.count - StoreIndex.undecryptableLogMax)
        }
    }

    mutating func appendCapture(_ event: CaptureEvent) {
        captureLog.append(event)
        if captureLog.count > StoreIndex.captureLogMax {
            captureLog.removeFirst(captureLog.count - StoreIndex.captureLogMax)
        }
    }
}

// MARK: - Control coalescing (§3.4)

/// One open `ctrl.capture` window: 2 s per (peer, kind).
struct CaptureWindow: Equatable {
    let peer: String
    let kind: String
    let openedAt: UInt64
    var seqFrom: UInt32?
    var seqTo: UInt32?
    var count: UInt32
    var ref: [String]

    /// The inner message of §3.4; counters absent for `blanking_unavailable`.
    func inner(id: String, ts: UInt64) -> InnerMessage {
        let counters: Bool = kind != CaptureKindWire.blankingUnavailable
        return InnerMessage(t: InnerMessageType.ctrlCapture, id: id, ts: ts, ttl: 0,
                            seqFrom: counters ? seqFrom : nil, seqTo: counters ? seqTo : nil,
                            count: counters ? count : nil, kind: kind, ref: counters ? ref : [])
    }
}

struct ReadBatch: Equatable {
    let peer: String
    let openedAt: UInt64
    var ids: [String]
}

/// Coalesces capture events (2 s per peer and kind) and read receipts (5 s per conversation).
struct ControlCoalescer: Equatable {
    static let captureWindow: UInt64 = 2
    static let readWindow: UInt64 = 5

    var captures: [CaptureWindow] = []
    var reads: [ReadBatch] = []

    init() {}

    mutating func addCapture(peer: String, kind: String, seq: UInt32?, ref: [String], now: UInt64) {
        if let i = captures.firstIndex(where: { $0.peer == peer && $0.kind == kind && now < $0.openedAt + ControlCoalescer.captureWindow }) {
            if let s = seq {
                if captures[i].seqFrom == nil { captures[i].seqFrom = s }
                captures[i].seqTo = s
            }
            captures[i].count += 1
            for r in ref where !captures[i].ref.contains(r) {
                captures[i].ref.append(r)
            }
            return
        }
        captures.append(CaptureWindow(peer: peer, kind: kind, openedAt: now, seqFrom: seq, seqTo: seq, count: 1, ref: ref))
    }

    /// Windows that are closed at `now` (or all of them when `force`), removed from the coalescer.
    mutating func dueCaptures(now: UInt64, force: Bool) -> [CaptureWindow] {
        let due: [CaptureWindow] = captures.filter { force || now >= $0.openedAt + ControlCoalescer.captureWindow }
        captures.removeAll { w in due.contains(w) }
        return due
    }

    mutating func addRead(peer: String, ids: [String], now: UInt64) {
        if let i = reads.firstIndex(where: { $0.peer == peer }) {
            for id in ids where !reads[i].ids.contains(id) {
                reads[i].ids.append(id)
            }
            return
        }
        reads.append(ReadBatch(peer: peer, openedAt: now, ids: ids))
    }

    mutating func dueReads(now: UInt64, force: Bool) -> [ReadBatch] {
        let due: [ReadBatch] = reads.filter { force || now >= $0.openedAt + ControlCoalescer.readWindow }
        reads.removeAll { b in due.contains(b) }
        return due
    }

    var isEmpty: Bool { captures.isEmpty && reads.isEmpty }
}

// MARK: - Identifiers

enum Identifiers {
    /// `msg_id` / `blob_id`: 32 lowercase hex chars.
    static func hex32() -> String {
        Bytes.random(16).hex
    }

    /// Inner message id: lowercase UUID.
    static func messageId() -> String {
        UUID().uuidString.lowercased()
    }

    /// `device_id`: lowercase UUIDv4.
    static func deviceId() -> String {
        UUID().uuidString.lowercased()
    }
}
