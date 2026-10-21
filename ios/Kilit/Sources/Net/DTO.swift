import Foundation

// MARK: - §4.3 request/response structs (field names exactly as the server)
// Byte fields are base64url strings on the wire (strict decode); timestamps are unix seconds.

struct ErrorResponse: Codable, Equatable {
    let error: String
    let message: String?
    let serverTime: UInt64?

    enum CodingKeys: String, CodingKey {
        case error, message
        case serverTime = "server_time"
    }
}

struct ChallengeRequest: Codable, Equatable {
    let username: String
}

struct ChallengeResponse: Codable, Equatable {
    let nonce: Data
    let expiresAt: UInt64
    let serverTime: UInt64

    enum CodingKeys: String, CodingKey {
        case nonce
        case expiresAt = "expires_at"
        case serverTime = "server_time"
    }

    init(nonce: Data, expiresAt: UInt64, serverTime: UInt64) {
        self.nonce = nonce
        self.expiresAt = expiresAt
        self.serverTime = serverTime
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        nonce = try c.decodeB64(.nonce)
        expiresAt = try c.decode(UInt64.self, forKey: .expiresAt)
        serverTime = try c.decode(UInt64.self, forKey: .serverTime)
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encodeB64(nonce, forKey: .nonce)
        try c.encode(expiresAt, forKey: .expiresAt)
        try c.encode(serverTime, forKey: .serverTime)
    }
}

/// `spk:{id, pub, sig, created_at}`.
struct SPKDTO: Codable, Equatable {
    let id: UInt32
    let pub: Data
    let sig: Data
    let createdAt: UInt64

    enum CodingKeys: String, CodingKey {
        case id, pub, sig
        case createdAt = "created_at"
    }

    init(id: UInt32, pub: Data, sig: Data, createdAt: UInt64) {
        self.id = id
        self.pub = pub
        self.sig = sig
        self.createdAt = createdAt
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(UInt32.self, forKey: .id)
        pub = try c.decodeB64(.pub)
        sig = try c.decodeB64(.sig)
        createdAt = try c.decode(UInt64.self, forKey: .createdAt)
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(id, forKey: .id)
        try c.encodeB64(pub, forKey: .pub)
        try c.encodeB64(sig, forKey: .sig)
        try c.encode(createdAt, forKey: .createdAt)
    }

    var asPublic: SignedPrekeyPublic {
        SignedPrekeyPublic(id: id, pub: pub, sig: sig, createdAt: createdAt)
    }
}

/// `opk:{id, pub}` / `opks:[{id, pub}]`.
struct OPKDTO: Codable, Equatable {
    let id: UInt32
    let pub: Data

    enum CodingKeys: String, CodingKey {
        case id, pub
    }

    init(id: UInt32, pub: Data) {
        self.id = id
        self.pub = pub
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(UInt32.self, forKey: .id)
        pub = try c.decodeB64(.pub)
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(id, forKey: .id)
        try c.encodeB64(pub, forKey: .pub)
    }
}

struct RegisterRequest: Codable, Equatable {
    let username: String
    let ikSig: Data
    let ikDh: Data
    let ikBindSig: Data
    let registerProof: Data
    let nonce: Data
    let ts: UInt64
    let spk: SPKDTO
    let opks: [OPKDTO]
    let opksSig: Data?
    let deviceId: String

    enum CodingKeys: String, CodingKey {
        case username
        case ikSig = "ik_sig"
        case ikDh = "ik_dh"
        case ikBindSig = "ik_bind_sig"
        case registerProof = "register_proof"
        case nonce, ts, spk, opks
        case opksSig = "opks_sig"
        case deviceId = "device_id"
    }

    init(username: String, ikSig: Data, ikDh: Data, ikBindSig: Data, registerProof: Data, nonce: Data, ts: UInt64,
         spk: SPKDTO, opks: [OPKDTO], opksSig: Data?, deviceId: String) {
        self.username = username
        self.ikSig = ikSig
        self.ikDh = ikDh
        self.ikBindSig = ikBindSig
        self.registerProof = registerProof
        self.nonce = nonce
        self.ts = ts
        self.spk = spk
        self.opks = opks
        self.opksSig = opksSig
        self.deviceId = deviceId
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        username = try c.decode(String.self, forKey: .username)
        ikSig = try c.decodeB64(.ikSig)
        ikDh = try c.decodeB64(.ikDh)
        ikBindSig = try c.decodeB64(.ikBindSig)
        registerProof = try c.decodeB64(.registerProof)
        nonce = try c.decodeB64(.nonce)
        ts = try c.decode(UInt64.self, forKey: .ts)
        spk = try c.decode(SPKDTO.self, forKey: .spk)
        opks = try c.decode([OPKDTO].self, forKey: .opks)
        opksSig = try c.decodeB64IfPresent(.opksSig)
        deviceId = try c.decode(String.self, forKey: .deviceId)
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(username, forKey: .username)
        try c.encodeB64(ikSig, forKey: .ikSig)
        try c.encodeB64(ikDh, forKey: .ikDh)
        try c.encodeB64(ikBindSig, forKey: .ikBindSig)
        try c.encodeB64(registerProof, forKey: .registerProof)
        try c.encodeB64(nonce, forKey: .nonce)
        try c.encode(ts, forKey: .ts)
        try c.encode(spk, forKey: .spk)
        try c.encode(opks, forKey: .opks)
        try c.encodeB64IfPresent(opksSig, forKey: .opksSig)
        try c.encode(deviceId, forKey: .deviceId)
    }
}

struct RegisterResponse: Codable, Equatable {
    let userId: Int64
    let token: String
    let expiresAt: UInt64

    enum CodingKeys: String, CodingKey {
        case userId = "user_id"
        case token
        case expiresAt = "expires_at"
    }
}

struct LoginRequest: Codable, Equatable {
    let username: String
    let nonce: Data
    let ts: UInt64
    let deviceId: String
    let sig: Data

    enum CodingKeys: String, CodingKey {
        case username, nonce, ts
        case deviceId = "device_id"
        case sig
    }

    init(username: String, nonce: Data, ts: UInt64, deviceId: String, sig: Data) {
        self.username = username
        self.nonce = nonce
        self.ts = ts
        self.deviceId = deviceId
        self.sig = sig
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        username = try c.decode(String.self, forKey: .username)
        nonce = try c.decodeB64(.nonce)
        ts = try c.decode(UInt64.self, forKey: .ts)
        deviceId = try c.decode(String.self, forKey: .deviceId)
        sig = try c.decodeB64(.sig)
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(username, forKey: .username)
        try c.encodeB64(nonce, forKey: .nonce)
        try c.encode(ts, forKey: .ts)
        try c.encode(deviceId, forKey: .deviceId)
        try c.encodeB64(sig, forKey: .sig)
    }
}

struct LoginResponse: Codable, Equatable {
    let token: String
    let expiresAt: UInt64

    enum CodingKeys: String, CodingKey {
        case token
        case expiresAt = "expires_at"
    }
}

/// `DELETE /v1/users/me` body (`delete_sig`).
struct DeleteAccountRequest: Codable, Equatable {
    let nonce: Data
    let ts: UInt64
    let sig: Data

    enum CodingKeys: String, CodingKey {
        case nonce, ts, sig
    }

    init(nonce: Data, ts: UInt64, sig: Data) {
        self.nonce = nonce
        self.ts = ts
        self.sig = sig
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        nonce = try c.decodeB64(.nonce)
        ts = try c.decode(UInt64.self, forKey: .ts)
        sig = try c.decodeB64(.sig)
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encodeB64(nonce, forKey: .nonce)
        try c.encode(ts, forKey: .ts)
        try c.encodeB64(sig, forKey: .sig)
    }
}

/// `GET /v1/users/{username}`.
struct UserResponse: Codable, Equatable {
    let username: String
    let ikSig: Data
    let ikDh: Data
    let ikBindSig: Data

    enum CodingKeys: String, CodingKey {
        case username
        case ikSig = "ik_sig"
        case ikDh = "ik_dh"
        case ikBindSig = "ik_bind_sig"
    }

    init(username: String, ikSig: Data, ikDh: Data, ikBindSig: Data) {
        self.username = username
        self.ikSig = ikSig
        self.ikDh = ikDh
        self.ikBindSig = ikBindSig
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        username = try c.decode(String.self, forKey: .username)
        ikSig = try c.decodeB64(.ikSig)
        ikDh = try c.decodeB64(.ikDh)
        ikBindSig = try c.decodeB64(.ikBindSig)
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(username, forKey: .username)
        try c.encodeB64(ikSig, forKey: .ikSig)
        try c.encodeB64(ikDh, forKey: .ikDh)
        try c.encodeB64(ikBindSig, forKey: .ikBindSig)
    }

    var identity: IdentityPublicKeys {
        IdentityPublicKeys(ikSig: ikSig, ikDh: ikDh)
    }

    /// `ik_bind_sig` re-verified by the client (server untrusted).
    func verifyBinding() throws {
        guard identity.isWellFormed else { throw KilitCryptoError.badKeyLength }
        try Ed25519Strict.verify(signature: ikBindSig, message: SignedMessages.ikBind(ikDh: ikDh), publicKey: ikSig)
    }
}

/// `GET /v1/users/{username}/prekeys`.
struct BundleResponse: Codable, Equatable {
    let username: String
    let ikSig: Data
    let ikDh: Data
    let ikBindSig: Data
    let spk: SPKDTO
    let opk: OPKDTO?

    enum CodingKeys: String, CodingKey {
        case username
        case ikSig = "ik_sig"
        case ikDh = "ik_dh"
        case ikBindSig = "ik_bind_sig"
        case spk, opk
    }

    init(username: String, ikSig: Data, ikDh: Data, ikBindSig: Data, spk: SPKDTO, opk: OPKDTO?) {
        self.username = username
        self.ikSig = ikSig
        self.ikDh = ikDh
        self.ikBindSig = ikBindSig
        self.spk = spk
        self.opk = opk
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        username = try c.decode(String.self, forKey: .username)
        ikSig = try c.decodeB64(.ikSig)
        ikDh = try c.decodeB64(.ikDh)
        ikBindSig = try c.decodeB64(.ikBindSig)
        spk = try c.decode(SPKDTO.self, forKey: .spk)
        opk = try c.decodeIfPresent(OPKDTO.self, forKey: .opk)
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(username, forKey: .username)
        try c.encodeB64(ikSig, forKey: .ikSig)
        try c.encodeB64(ikDh, forKey: .ikDh)
        try c.encodeB64(ikBindSig, forKey: .ikBindSig)
        try c.encode(spk, forKey: .spk)
        try c.encodeIfPresent(opk, forKey: .opk)
    }

    /// The Crypto-layer bundle (verified by `X3DH.initiate` via `BundleVerifier`).
    var bundle: PrekeyBundle {
        PrekeyBundle(username: username, identity: IdentityPublicKeys(ikSig: ikSig, ikDh: ikDh), ikBindSig: ikBindSig,
                     spk: spk.asPublic, opkId: opk?.id, opkPub: opk?.pub)
    }
}

/// `PUT /v1/prekeys`.
struct PrekeysPutRequest: Codable, Equatable {
    let spk: SPKDTO?
    let opks: [OPKDTO]
    let opksSig: Data?

    enum CodingKeys: String, CodingKey {
        case spk, opks
        case opksSig = "opks_sig"
    }

    init(spk: SPKDTO?, opks: [OPKDTO], opksSig: Data?) {
        self.spk = spk
        self.opks = opks
        self.opksSig = opksSig
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        spk = try c.decodeIfPresent(SPKDTO.self, forKey: .spk)
        opks = try c.decodeIfPresent([OPKDTO].self, forKey: .opks) ?? []
        opksSig = try c.decodeB64IfPresent(.opksSig)
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encodeIfPresent(spk, forKey: .spk)
        try c.encode(opks, forKey: .opks)
        try c.encodeB64IfPresent(opksSig, forKey: .opksSig)
    }
}

struct PrekeysPutResponse: Codable, Equatable {
    let opkCount: Int
    let spkId: UInt32

    enum CodingKeys: String, CodingKey {
        case opkCount = "opk_count"
        case spkId = "spk_id"
    }
}

/// `GET /v1/prekeys/count`.
struct PrekeyCountResponse: Codable, Equatable {
    let opkCount: Int
    let spkId: UInt32
    let consumedIds: [UInt32]

    enum CodingKeys: String, CodingKey {
        case opkCount = "opk_count"
        case spkId = "spk_id"
        case consumedIds = "consumed_ids"
    }

    init(opkCount: Int, spkId: UInt32, consumedIds: [UInt32]) {
        self.opkCount = opkCount
        self.spkId = spkId
        self.consumedIds = consumedIds
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        opkCount = try c.decode(Int.self, forKey: .opkCount)
        spkId = try c.decode(UInt32.self, forKey: .spkId)
        consumedIds = try c.decodeIfPresent([UInt32].self, forKey: .consumedIds) ?? []
    }
}

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
