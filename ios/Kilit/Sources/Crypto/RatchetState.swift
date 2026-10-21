import Foundation
import CryptoKit

/// One `MKSKIPPED` entry: `(dh_pub, n) → (mk, insertedAt)`; the chain is identified by `dh`.
struct SkippedKey: Codable, Equatable {
    let dh: Data
    let n: UInt32
    let mk: Data
    let insertedAt: UInt64

    enum CodingKeys: String, CodingKey {
        case dh, n, mk
        case insertedAt = "inserted_at"
    }
}

/// Double Ratchet state (§3.3). `dhsPriv` is held in a `ZeroizingKey`; a `DHRatchet` replaces it, and
/// the previous `SymmetricKey` storage is zeroised by CryptoKit when its last copy is released.
struct RatchetState: Codable, Equatable {
    static let maxSkip: UInt32 = 1000
    static let maxSkippedEntries: Int = 2000
    static let maxSkippedChains: Int = 5
    static let skippedMaxAge: UInt64 = 7 * 86400

    var dhsPriv: ZeroizingKey
    var dhsPub: Data
    var dhr: Data?
    var rk: Data
    var cks: Data?
    var ckr: Data?
    var ns: UInt32
    var nr: UInt32
    var pn: UInt32
    var mkskipped: [SkippedKey]

    enum CodingKeys: String, CodingKey {
        case dhsPriv = "dhs_priv"
        case dhsPub = "dhs_pub"
        case dhr, rk, cks, ckr, ns, nr, pn, mkskipped
    }

    init(dhs: Curve25519.KeyAgreement.PrivateKey, dhr: Data?, rk: Data, cks: Data?, ckr: Data?) {
        self.dhsPriv = ZeroizingKey(data: dhs.rawRepresentation)
        self.dhsPub = dhs.publicKey.rawRepresentation
        self.dhr = dhr
        self.rk = rk
        self.cks = cks
        self.ckr = ckr
        self.ns = 0
        self.nr = 0
        self.pn = 0
        self.mkskipped = []
    }

    /// Replaces `DHs`; the old key material is released (and zeroised by its storage) here.
    mutating func replaceDHs(with key: Curve25519.KeyAgreement.PrivateKey) {
        dhsPriv = ZeroizingKey(data: key.rawRepresentation)
        dhsPub = key.publicKey.rawRepresentation
    }

    /// True when `bytes` equals the private ratchet key or any chain/root key (used by the
    /// `expect_state_excludes` vector op: a committed responder state never holds the SPK private key).
    func contains(secret bytes: Data) -> Bool {
        if dhsPriv.dataCopy == bytes { return true }
        if rk == bytes { return true }
        if let c = cks, c == bytes { return true }
        if let c = ckr, c == bytes { return true }
        for e in mkskipped where e.mk == bytes { return true }
        return false
    }

    // MARK: MKSKIPPED

    /// Total order `(insertedAt, dh bytes lexicographically, n)` ascending.
    static func ordered(_ a: SkippedKey, _ b: SkippedKey) -> Bool {
        if a.insertedAt != b.insertedAt { return a.insertedAt < b.insertedAt }
        if a.dh != b.dh { return Bytes.lexLess(a.dh, b.dh) }
        return a.n < b.n
    }

    func skippedIndex(dh: Data, n: UInt32) -> Int? {
        mkskipped.firstIndex { $0.dh == dh && $0.n == n }
    }

    /// Removes and returns the key for `(dh, n)` ("an entry is deleted the moment it is used").
    mutating func takeSkipped(dh: Data, n: UInt32) -> Data? {
        guard let i = skippedIndex(dh: dh, n: n) else { return nil }
        let mk: Data = mkskipped[i].mk
        mkskipped.remove(at: i)
        return mk
    }

    /// Inserts entries (all stamped with one `insertedAt`) and applies the exact eviction of §3.3:
    /// (1) drop entries older than 7 days; (2) while more than 5 distinct chains remain, drop every entry
    /// of the chain whose newest entry is smallest in the total order; (3) while more than 2000 entries
    /// remain, drop the first entry in that order.
    mutating func insertSkipped(_ entries: [SkippedKey], now: UInt64) {
        mkskipped.append(contentsOf: entries)
        evictSkipped(now: now)
    }

    mutating func evictSkipped(now: UInt64) {
        mkskipped.removeAll { now > $0.insertedAt && now - $0.insertedAt > RatchetState.skippedMaxAge }
        mkskipped.sort(by: RatchetState.ordered)
        while distinctChains().count > RatchetState.maxSkippedChains {
            // Newest entry per chain; the chain whose newest entry is smallest goes.
            var newest: [Data: SkippedKey] = [:]
            for e in mkskipped {
                if let cur = newest[e.dh] {
                    if RatchetState.ordered(cur, e) { newest[e.dh] = e }
                } else {
                    newest[e.dh] = e
                }
            }
            guard var victim: SkippedKey = newest.values.first else { break }
            for (_, e) in newest where RatchetState.ordered(e, victim) {
                victim = e
            }
            let victimChain: Data = victim.dh
            mkskipped.removeAll { $0.dh == victimChain }
        }
        if mkskipped.count > RatchetState.maxSkippedEntries {
            mkskipped.removeFirst(mkskipped.count - RatchetState.maxSkippedEntries)
        }
    }

    private func distinctChains() -> Set<Data> {
        var s: Set<Data> = []
        for e in mkskipped { s.insert(e.dh) }
        return s
    }

    /// SHA-256 over `dh(32) || u32BE(n) || mk(32)` for all entries sorted by `(dh bytes, n)` (§3.8 hash form).
    func mkskippedSHA256() -> Data {
        let sorted: [SkippedKey] = mkskipped.sorted { a, b in
            if a.dh != b.dh { return Bytes.lexLess(a.dh, b.dh) }
            return a.n < b.n
        }
        var buf: Data = Data()
        for e in sorted {
            buf.append(e.dh)
            buf.append(BE.u32(e.n))
            buf.append(e.mk)
        }
        return KDF.sha256(buf)
    }
}
