import Foundation

// MARK: - §4.3 message, ack, attachment DTOs and §4.4 WebSocket frames (field names exactly as the server)

/// `POST /v1/messages` body; `envelope` = base64url(E2E bytes).
struct SendRequest: Codable, Equatable {
    let to: String
    let msgId: String
    let envelope: Data

    enum CodingKeys: String, CodingKey {
        case to
        case msgId = "msg_id"
        case envelope
    }

    init(to: String, msgId: String, envelope: Data) {
        self.to = to
        self.msgId = msgId
        self.envelope = envelope
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        to = try c.decode(String.self, forKey: .to)
        msgId = try c.decode(String.self, forKey: .msgId)
        envelope = try c.decodeB64(.envelope)
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(to, forKey: .to)
        try c.encode(msgId, forKey: .msgId)
        try c.encodeB64(envelope, forKey: .envelope)
    }
}

struct SendResponse: Codable, Equatable {
    let id: Int64
}

/// One row of `GET /v1/messages` and of the WS `msg` frame.
struct MessageRow: Codable, Equatable {
    let id: Int64
    let msgId: String
    let from: String
    let envelope: Data
    let ts: UInt64

    enum CodingKeys: String, CodingKey {
        case id
        case msgId = "msg_id"
        case from, envelope, ts
    }

    init(id: Int64, msgId: String, from: String, envelope: Data, ts: UInt64) {
        self.id = id
        self.msgId = msgId
        self.from = from
        self.envelope = envelope
        self.ts = ts
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(Int64.self, forKey: .id)
        msgId = try c.decode(String.self, forKey: .msgId)
        from = try c.decode(String.self, forKey: .from)
        envelope = try c.decodeB64(.envelope)
        ts = try c.decode(UInt64.self, forKey: .ts)
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(id, forKey: .id)
        try c.encode(msgId, forKey: .msgId)
        try c.encode(from, forKey: .from)
        try c.encodeB64(envelope, forKey: .envelope)
        try c.encode(ts, forKey: .ts)
    }
}

struct MessagesResponse: Codable, Equatable {
    let messages: [MessageRow]
    let hasMore: Bool

    enum CodingKeys: String, CodingKey {
        case messages
        case hasMore = "has_more"
    }
}

struct AckRequest: Codable, Equatable {
    let msgIds: [String]

    enum CodingKeys: String, CodingKey {
        case msgIds = "msg_ids"
    }
}

struct AckResponse: Codable, Equatable {
    let deleted: Int
}

/// `POST /v1/attachments/{id}` → `201 {id, expires_at}`.
struct AttachmentUploadResponse: Codable, Equatable {
    let id: String
    let expiresAt: UInt64

    enum CodingKeys: String, CodingKey {
        case id
        case expiresAt = "expires_at"
    }
}

struct PushTokenRequest: Codable, Equatable {
    let token: String
    let env: String
}

// MARK: - §4.4 WebSocket frames

/// Client → server: `hello` (with `after`), `ack` (with `msg_ids`), `ping`.
struct WSClientFrame: Codable, Equatable {
    let t: String
    let after: Int64?
    let msgIds: [String]?

    enum CodingKeys: String, CodingKey {
        case t, after
        case msgIds = "msg_ids"
    }

    static func hello(after: Int64) -> WSClientFrame { WSClientFrame(t: "hello", after: after, msgIds: nil) }
    static func ack(msgIds: [String]) -> WSClientFrame { WSClientFrame(t: "ack", after: nil, msgIds: msgIds) }
    static let ping: WSClientFrame = WSClientFrame(t: "ping", after: nil, msgIds: nil)

    func encoded() throws -> String {
        let data: Data = try KilitJSON.encoder().encode(self)
        return String(decoding: data, as: UTF8.self)
    }
}

/// Server → client: `msg` | `pong` | `prekeys_low` | `error`; every field beyond `t` is optional.
struct WSServerFrame: Codable, Equatable {
    let t: String
    let id: Int64?
    let msgId: String?
    let from: String?
    let envelope: Data?
    let ts: UInt64?
    let opkCount: Int?
    let consumedIds: [UInt32]?
    let code: String?

    enum CodingKeys: String, CodingKey {
        case t, id
        case msgId = "msg_id"
        case from, envelope, ts
        case opkCount = "opk_count"
        case consumedIds = "consumed_ids"
        case code
    }

    init(t: String, id: Int64? = nil, msgId: String? = nil, from: String? = nil, envelope: Data? = nil, ts: UInt64? = nil,
         opkCount: Int? = nil, consumedIds: [UInt32]? = nil, code: String? = nil) {
        self.t = t
        self.id = id
        self.msgId = msgId
        self.from = from
        self.envelope = envelope
        self.ts = ts
        self.opkCount = opkCount
        self.consumedIds = consumedIds
        self.code = code
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        t = try c.decode(String.self, forKey: .t)
        id = try c.decodeIfPresent(Int64.self, forKey: .id)
        msgId = try c.decodeIfPresent(String.self, forKey: .msgId)
        from = try c.decodeIfPresent(String.self, forKey: .from)
        envelope = try c.decodeB64IfPresent(.envelope)
        ts = try c.decodeIfPresent(UInt64.self, forKey: .ts)
        opkCount = try c.decodeIfPresent(Int.self, forKey: .opkCount)
        consumedIds = try c.decodeIfPresent([UInt32].self, forKey: .consumedIds)
        code = try c.decodeIfPresent(String.self, forKey: .code)
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(t, forKey: .t)
        try c.encodeIfPresent(id, forKey: .id)
        try c.encodeIfPresent(msgId, forKey: .msgId)
        try c.encodeIfPresent(from, forKey: .from)
        try c.encodeB64IfPresent(envelope, forKey: .envelope)
        try c.encodeIfPresent(ts, forKey: .ts)
        try c.encodeIfPresent(opkCount, forKey: .opkCount)
        try c.encodeIfPresent(consumedIds, forKey: .consumedIds)
        try c.encodeIfPresent(code, forKey: .code)
    }

    static func decode(_ text: String) -> WSServerFrame? {
        try? KilitJSON.decoder().decode(WSServerFrame.self, from: Data(text.utf8))
    }

    /// The `msg` frame as a `MessageRow` (nil for other frames or a malformed one).
    var messageRow: MessageRow? {
        guard t == "msg", let id = id, let m = msgId, let f = from, let e = envelope else { return nil }
        return MessageRow(id: id, msgId: m, from: f, envelope: e, ts: ts ?? 0)
    }
}
