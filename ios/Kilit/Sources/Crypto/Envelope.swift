import Foundation

// MARK: - JSON conventions (§3)

enum KilitJSON {
    static func encoder() -> JSONEncoder {
        let e: JSONEncoder = JSONEncoder()
        e.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return e
    }

    static func decoder() -> JSONDecoder {
        JSONDecoder()
    }
}

/// Thrown by the outer parser for every §3.2b step-1 failure other than the header ones (`badHeader`).
enum EnvelopeError: Error, Equatable {
    case badEnvelope(String)
}

// Base64url coding helpers for the wire structs (strict decode; a failure is a `DecodingError`).
extension KeyedDecodingContainer {
    func decodeB64(_ key: Key) throws -> Data {
        let s: String = try decode(String.self, forKey: key)
        guard let d = Data(base64url: s) else {
            throw DecodingError.dataCorruptedError(forKey: key, in: self, debugDescription: "bad base64url")
        }
        return d
    }

    func decodeB64IfPresent(_ key: Key) throws -> Data? {
        guard let s = try decodeIfPresent(String.self, forKey: key) else { return nil }
        guard let d = Data(base64url: s) else {
            throw DecodingError.dataCorruptedError(forKey: key, in: self, debugDescription: "bad base64url")
        }
        return d
    }
}

extension KeyedEncodingContainer {
    mutating func encodeB64(_ data: Data, forKey key: Key) throws {
        try encode(data.base64url(), forKey: key)
    }

    mutating func encodeB64IfPresent(_ data: Data?, forKey key: Key) throws {
        if let d = data { try encode(d.base64url(), forKey: key) }
    }
}

// MARK: - Outer envelope

enum EnvelopeKind: String, Codable, Equatable {
    case prekey
    case msg
}

/// The `x3dh` block of a `prekey` envelope. `opk_id` absent and `null` are equivalent.
struct X3DHBlock: Codable, Equatable {
    let ikSig: Data
    let ikDh: Data
    let ikBindSig: Data
    let ek: Data
    let spkId: UInt32
    let opkId: UInt32?

    enum CodingKeys: String, CodingKey {
        case ikSig = "ik_sig"
        case ikDh = "ik_dh"
        case ikBindSig = "ik_bind_sig"
        case ek
        case spkId = "spk_id"
        case opkId = "opk_id"
    }

    init(ikSig: Data, ikDh: Data, ikBindSig: Data, ek: Data, spkId: UInt32, opkId: UInt32?) {
        self.ikSig = ikSig
        self.ikDh = ikDh
        self.ikBindSig = ikBindSig
        self.ek = ek
        self.spkId = spkId
        self.opkId = opkId
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        ikSig = try c.decodeB64(.ikSig)
        ikDh = try c.decodeB64(.ikDh)
        ikBindSig = try c.decodeB64(.ikBindSig)
        ek = try c.decodeB64(.ek)
        spkId = try c.decode(UInt32.self, forKey: .spkId)
        opkId = try c.decodeIfPresent(UInt32.self, forKey: .opkId)
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encodeB64(ikSig, forKey: .ikSig)
        try c.encodeB64(ikDh, forKey: .ikDh)
        try c.encodeB64(ikBindSig, forKey: .ikBindSig)
        try c.encodeB64(ek, forKey: .ek)
        try c.encode(spkId, forKey: .spkId)
        try c.encodeIfPresent(opkId, forKey: .opkId)
    }

    var identity: IdentityPublicKeys {
        IdentityPublicKeys(ikSig: ikSig, ikDh: ikDh)
    }
}

/// E2E envelope JSON (§3.4): `{"v":1,"kind","sid","x3dh"?,"hdr","ct"}` with base64url fields.
struct OuterEnvelope: Codable, Equatable {
    let v: Int
    let kind: EnvelopeKind
    let sid: Data
    let x3dh: X3DHBlock?
    let hdr: Data
    let ct: Data

    enum CodingKeys: String, CodingKey {
        case v, kind, sid, x3dh, hdr, ct
    }

    init(v: Int = 1, kind: EnvelopeKind, sid: Data, x3dh: X3DHBlock?, hdr: Data, ct: Data) {
        self.v = v
        self.kind = kind
        self.sid = sid
        self.x3dh = x3dh
        self.hdr = hdr
        self.ct = ct
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        v = try c.decode(Int.self, forKey: .v)
        kind = try c.decode(EnvelopeKind.self, forKey: .kind)
        sid = try c.decodeB64(.sid)
        x3dh = try c.decodeIfPresent(X3DHBlock.self, forKey: .x3dh)
        hdr = try c.decodeB64(.hdr)
        ct = try c.decodeB64(.ct)
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(v, forKey: .v)
        try c.encode(kind, forKey: .kind)
        try c.encodeB64(sid, forKey: .sid)
        try c.encodeIfPresent(x3dh, forKey: .x3dh)
        try c.encodeB64(hdr, forKey: .hdr)
        try c.encodeB64(ct, forKey: .ct)
    }

    /// Encodes with the §3 conventions; `sizeLimit` when the result exceeds `EnvelopeParser.maxEnvelope`.
    func encoded() throws -> Data {
        let bytes: Data = try KilitJSON.encoder().encode(self)
        guard bytes.count <= EnvelopeParser.maxEnvelope else { throw KilitCryptoError.sizeLimit }
        return bytes
    }
}

/// Result of the §3.2b step-1 checks: the outer object, the parsed 41-byte header and the effective `sid`
/// (recomputed from `ek` for `prekey` envelopes; the carried field is ignored there).
struct ParsedEnvelope: Equatable {
    let outer: OuterEnvelope
    let header: MessageHeader
    let sid: Data
}

enum EnvelopeParser {
    /// Largest accepted (and produced) envelope encoding in bytes (Go `MaxEnvelope`).
    static let maxEnvelope: Int = 65536

    /// Everything that is rejected before any KDF: an encoding over `maxEnvelope`, `v != 1`, unknown `kind`,
    /// bad `sid`, `hdr` not 41 bytes or version byte != 0x01 (`KilitCryptoError.badHeader`), `ct` shorter
    /// than 272 bytes, a `prekey` without `x3dh`, a `msg` with one.
    static func parse(_ bytes: Data) throws -> ParsedEnvelope {
        guard bytes.count <= maxEnvelope else { throw EnvelopeError.badEnvelope("size") }
        let outer: OuterEnvelope
        do {
            outer = try KilitJSON.decoder().decode(OuterEnvelope.self, from: bytes)
        } catch {
            throw EnvelopeError.badEnvelope("json")
        }
        return try validate(outer)
    }

    static func validate(_ outer: OuterEnvelope) throws -> ParsedEnvelope {
        guard outer.v == 1 else { throw EnvelopeError.badEnvelope("v") }
        guard outer.sid.count == 8 else { throw EnvelopeError.badEnvelope("sid") }
        let header: MessageHeader = try MessageHeader(bytes: outer.hdr)
        guard outer.ct.count >= Padding.minWire else { throw EnvelopeError.badEnvelope("ct") }
        var sid: Data = outer.sid
        switch outer.kind {
        case .prekey:
            guard let x = outer.x3dh else { throw EnvelopeError.badEnvelope("x3dh") }
            guard x.ek.count == 32 else { throw EnvelopeError.badEnvelope("ek") }
            sid = X3DH.sid(ek: x.ek)
        case .msg:
            guard outer.x3dh == nil else { throw EnvelopeError.badEnvelope("x3dh") }
        }
        return ParsedEnvelope(outer: outer, header: header, sid: sid)
    }
}

// MARK: - Inner message (§3.4)

enum InnerMessageType {
    static let text: String = "text"
    static let image: String = "image"
    static let ctrlTimer: String = "ctrl.timer"
    static let ctrlCapture: String = "ctrl.capture"
    static let ctrlRead: String = "ctrl.read"
    static let ctrlDelete: String = "ctrl.delete"
    static let ctrlResync: String = "ctrl.resync"
}

/// Wire spellings of `ctrl.capture.kind`; the inner message carries them as a plain `String`
/// (`Security/CaptureEventKind` has the same raw values; `App/CaptureGlue` converts).
enum CaptureKindWire {
    static let screenshot: String = "screenshot"
    static let recordingStarted: String = "recording_started"
    static let recordingStopped: String = "recording_stopped"
    static let blankingUnavailable: String = "blanking_unavailable"
    static let all: [String] = [screenshot, recordingStarted, recordingStopped, blankingUnavailable]
}

/// `att` of an image message.
struct InnerAttachment: Codable, Equatable {
    let blob: String
    let key: Data
    let sha256: Data
    let mime: String
    let len: UInt64
    let w: Int
    let h: Int

    enum CodingKeys: String, CodingKey {
        case blob, key, sha256, mime, len, w, h
    }

    init(blob: String, key: Data, sha256: Data, mime: String, len: UInt64, w: Int, h: Int) {
        self.blob = blob
        self.key = key
        self.sha256 = sha256
        self.mime = mime
        self.len = len
        self.w = w
        self.h = h
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        blob = try c.decode(String.self, forKey: .blob)
        key = try c.decodeB64(.key)
        sha256 = try c.decodeB64(.sha256)
        mime = try c.decode(String.self, forKey: .mime)
        len = try c.decode(UInt64.self, forKey: .len)
        w = try c.decode(Int.self, forKey: .w)
        h = try c.decode(Int.self, forKey: .h)
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(blob, forKey: .blob)
        try c.encodeB64(key, forKey: .key)
        try c.encodeB64(sha256, forKey: .sha256)
        try c.encode(mime, forKey: .mime)
        try c.encode(len, forKey: .len)
        try c.encode(w, forKey: .w)
        try c.encode(h, forKey: .h)
    }
}

/// Inner plaintext JSON. Optional fields: absent and `null` are equivalent on decode; encode omits nil.
/// Only `t` and `id` are required on decode (Go `DecodeInner`): an absent, `null` or negative `ts`/`ttl`
/// decodes as 0, and a malformed `lost_sid` is kept as text and simply yields no `lostSid`.
struct InnerMessage: Codable, Equatable {
    var t: String
    var id: String
    var ts: UInt64
    var ttl: UInt32
    var text: String?
    var att: InnerAttachment?
    var timer: UInt32?
    var seqFrom: UInt32?
    var seqTo: UInt32?
    var count: UInt32?
    /// `ctrl.capture` kind: one of `CaptureKindWire`; a plain String by design (§3.4).
    var kind: String?
    var ref: [String]?
    /// `lost_sid` exactly as carried on the wire (base64url text), decoded lazily by `lostSid`.
    var lostSidRaw: String?

    /// The 8-byte `lost_sid` of a `ctrl.resync`, nil when absent or malformed (the resync is then skipped).
    var lostSid: Data? {
        get {
            guard let raw = lostSidRaw, let d = Data(base64url: raw), d.count == 8 else { return nil }
            return d
        }
        set { lostSidRaw = newValue?.base64url() }
    }

    enum CodingKeys: String, CodingKey {
        case t, id, ts, ttl, text, att, timer
        case seqFrom = "seq_from"
        case seqTo = "seq_to"
        case count, kind, ref
        case lostSid = "lost_sid"
    }

    init(t: String, id: String, ts: UInt64, ttl: UInt32, text: String? = nil, att: InnerAttachment? = nil,
         timer: UInt32? = nil, seqFrom: UInt32? = nil, seqTo: UInt32? = nil, count: UInt32? = nil,
         kind: String? = nil, ref: [String]? = nil, lostSid: Data? = nil) {
        self.t = t
        self.id = id
        self.ts = ts
        self.ttl = ttl
        self.text = text
        self.att = att
        self.timer = timer
        self.seqFrom = seqFrom
        self.seqTo = seqTo
        self.count = count
        self.kind = kind
        self.ref = ref
        self.lostSidRaw = lostSid?.base64url()
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        t = try c.decode(String.self, forKey: .t)
        id = try c.decode(String.self, forKey: .id)
        guard !t.isEmpty, !id.isEmpty else {
            throw DecodingError.dataCorruptedError(forKey: .t, in: c, debugDescription: "empty t or id")
        }
        ts = try InnerMessage.decodeNonNegative(c, .ts, as: UInt64.self)
        ttl = try InnerMessage.decodeNonNegative(c, .ttl, as: UInt32.self)
        text = try c.decodeIfPresent(String.self, forKey: .text)
        att = try c.decodeIfPresent(InnerAttachment.self, forKey: .att)
        timer = try c.decodeIfPresent(UInt32.self, forKey: .timer)
        seqFrom = try c.decodeIfPresent(UInt32.self, forKey: .seqFrom)
        seqTo = try c.decodeIfPresent(UInt32.self, forKey: .seqTo)
        count = try c.decodeIfPresent(UInt32.self, forKey: .count)
        kind = try c.decodeIfPresent(String.self, forKey: .kind)
        ref = try c.decodeIfPresent([String].self, forKey: .ref)
        lostSidRaw = try c.decodeIfPresent(String.self, forKey: .lostSid)
    }

    /// Go tolerance for `ts` (int64) and `ttl` (int): absent/`null` → 0, a negative integer → 0,
    /// a non-integer → `DecodingError`.
    private static func decodeNonNegative<T: FixedWidthInteger & Decodable>(
        _ c: KeyedDecodingContainer<CodingKeys>, _ key: CodingKeys, as _: T.Type
    ) throws -> T {
        if let v = try? c.decodeIfPresent(T.self, forKey: key) { return v }
        let signed: Int64 = try c.decodeIfPresent(Int64.self, forKey: key) ?? 0
        guard signed > 0, let v = T(exactly: signed) else { return 0 }
        return v
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(t, forKey: .t)
        try c.encode(id, forKey: .id)
        try c.encode(ts, forKey: .ts)
        try c.encode(ttl, forKey: .ttl)
        try c.encodeIfPresent(text, forKey: .text)
        try c.encodeIfPresent(att, forKey: .att)
        try c.encodeIfPresent(timer, forKey: .timer)
        try c.encodeIfPresent(seqFrom, forKey: .seqFrom)
        try c.encodeIfPresent(seqTo, forKey: .seqTo)
        try c.encodeIfPresent(count, forKey: .count)
        try c.encodeIfPresent(kind, forKey: .kind)
        try c.encodeIfPresent(ref, forKey: .ref)
        try c.encodeIfPresent(lostSidRaw, forKey: .lostSid)
    }

    static func text(id: String, ts: UInt64, ttl: UInt32, text: String) -> InnerMessage {
        InnerMessage(t: InnerMessageType.text, id: id, ts: ts, ttl: ttl, text: text)
    }

    static func resync(id: String, ts: UInt64, lostSid: Data) -> InnerMessage {
        InnerMessage(t: InnerMessageType.ctrlResync, id: id, ts: ts, ttl: 0, lostSid: lostSid)
    }

    /// Encodes with the §3 conventions and checks the 40 960-byte limit (`sizeLimit`).
    func encodedForPadding() throws -> Data {
        let json: Data = try KilitJSON.encoder().encode(self)
        guard json.count <= Padding.maxInner else { throw KilitCryptoError.sizeLimit }
        return json
    }

    static func decode(_ json: Data) throws -> InnerMessage {
        try KilitJSON.decoder().decode(InnerMessage.self, from: json)
    }
}
