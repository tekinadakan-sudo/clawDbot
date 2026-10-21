import Foundation
import CryptoKit

// MARK: - Records (index.json)

struct StoredOPK: Codable, Equatable {
    let key: OneTimePrekey
    /// Informational; only used for the 500-cap ordering.
    let uploadedAt: UInt64
    /// First time the id appeared in `consumed_ids`; the private key is deleted 7 days later (rule (b)).
    var consumedReportedAt: UInt64?
    /// False until `PUT /v1/prekeys` succeeded; such keys are re-uploaded with the next batch.
    var uploaded: Bool
}

/// SPK/OPK private keys with the §3.1 lifetimes: no age rule for OPKs, SPK deleted 28 d after `created_at`.
struct PrekeyRecords: Codable, Equatable {
    static let rotateAfter: UInt64 = 7 * 86400
    static let spkLifetime: UInt64 = 28 * 86400
    static let opkGrace: UInt64 = 7 * 86400
    static let refillBelow: Int = 20
    static let refillTarget: Int = 100
    static let opkCap: Int = 500

    var spks: [SignedPrekey]
    var opks: [StoredOPK]
    var nextSpkId: UInt32
    var nextOpkId: UInt32
    var lastServerCount: Int?

    init() {
        spks = []
        opks = []
        nextSpkId = 1
        nextOpkId = 1
        lastServerCount = nil
    }

    // MARK: SPK

    var currentSPK: SignedPrekey? {
        spks.max { $0.id < $1.id }
    }

    /// Rotate when the current SPK is older than 7 d (or none is stored).
    func needsRotation(now: UInt64) -> Bool {
        guard let c = currentSPK else { return true }
        return now > c.createdAt && now - c.createdAt > PrekeyRecords.rotateAfter
    }

    @discardableResult
    mutating func rotateSPK(now: UInt64, keySource: KeySource) -> SignedPrekey {
        let spk: SignedPrekey = SignedPrekey(id: nextSpkId, createdAt: now, privateKey: keySource.x25519())
        nextSpkId += 1
        spks.append(spk)
        return spk
    }

    /// Deletes every SPK private key with `now − created_at > 28 d`, regardless of rotation.
    @discardableResult
    mutating func pruneSPKs(now: UInt64) -> [UInt32] {
        let gone: [UInt32] = spks.filter { now > $0.createdAt && now - $0.createdAt > PrekeyRecords.spkLifetime }.map { $0.id }
        spks.removeAll { gone.contains($0.id) }
        return gone
    }

    func spk(id: UInt32) -> SignedPrekey? {
        spks.first { $0.id == id }
    }

    // MARK: OPK

    func opk(id: UInt32) -> OneTimePrekey? {
        opks.first { $0.key.id == id }?.key
    }

    /// Rule (a): deleted on first successful use in X3DH.
    @discardableResult
    mutating func markUsed(opkId: UInt32) -> Bool {
        let before: Int = opks.count
        opks.removeAll { $0.key.id == opkId }
        return opks.count != before
    }

    /// `consumed_ids` is only a refill signal; it starts the 7-day grace window, nothing is deleted here.
    mutating func reportConsumed(ids: [UInt32], now: UInt64) {
        for i in opks.indices where ids.contains(opks[i].key.id) && opks[i].consumedReportedAt == nil {
            opks[i].consumedReportedAt = now
        }
    }

    /// Rule (b): deleted 7 days after the id first appeared in `consumed_ids`. Never on age.
    @discardableResult
    mutating func pruneOPKs(now: UInt64) -> [UInt32] {
        let gone: [UInt32] = opks.filter { o in
            guard let r = o.consumedReportedAt else { return false }
            return now > r && now - r > PrekeyRecords.opkGrace
        }.map { $0.key.id }
        opks.removeAll { gone.contains($0.key.id) }
        return gone
    }

    static func needsRefill(serverCount: Int) -> Bool {
        serverCount < refillBelow
    }

    /// Generates `count` keys (not yet uploaded) and enforces the 500 cap by deleting the oldest by
    /// `uploadedAt` first; evicted ids are never re-uploaded (ids are monotonic).
    @discardableResult
    mutating func generateOPKs(count: Int, now: UInt64, keySource: KeySource) -> [OneTimePrekey] {
        var fresh: [OneTimePrekey] = []
        var n: Int = 0
        while n < count {
            let k: OneTimePrekey = OneTimePrekey(id: nextOpkId, privateKey: keySource.x25519())
            nextOpkId += 1
            opks.append(StoredOPK(key: k, uploadedAt: now, consumedReportedAt: nil, uploaded: false))
            fresh.append(k)
            n += 1
        }
        enforceCap()
        return fresh
    }

    mutating func enforceCap() {
        while opks.count > PrekeyRecords.opkCap {
            guard let oldest = opks.indices.min(by: { a, b in
                if opks[a].uploadedAt != opks[b].uploadedAt { return opks[a].uploadedAt < opks[b].uploadedAt }
                return opks[a].key.id < opks[b].key.id
            }) else { break }
            opks.remove(at: oldest)
        }
    }

    /// Keys whose upload has not been confirmed.
    var pendingUpload: [OneTimePrekey] {
        opks.filter { !$0.uploaded }.map { $0.key }
    }

    mutating func markUploaded(ids: [UInt32]) {
        for i in opks.indices where ids.contains(opks[i].key.id) {
            opks[i].uploaded = true
        }
    }

    /// Resolver for `Inbound.process`.
    func lookup() -> PrekeyLookup {
        PrekeyLookup.from(spks: spks, opks: opks.map { $0.key })
    }

    /// Registration: a first SPK and 100 OPKs.
    mutating func initialBatch(now: UInt64, keySource: KeySource) -> (spk: SignedPrekey, opks: [OneTimePrekey]) {
        let spk: SignedPrekey = rotateSPK(now: now, keySource: keySource)
        let opks: [OneTimePrekey] = generateOPKs(count: PrekeyRecords.refillTarget, now: now, keySource: keySource)
        return (spk, opks)
    }
}

// MARK: - Signed upload payloads

enum PrekeyUpload {
    static func spkDTO(_ spk: SignedPrekey, local: IdentityKeys) throws -> SPKDTO {
        let signed: SignedPrekeyPublic = try spk.signed(by: local)
        return SPKDTO(id: signed.id, pub: signed.pub, sig: signed.sig, createdAt: signed.createdAt)
    }

    /// `opks_sig` over the batch in request order (required whenever `opks` is non-empty).
    static func opksSig(_ opks: [OneTimePrekey], local: IdentityKeys) throws -> Data? {
        guard !opks.isEmpty else { return nil }
        let batch: [(id: UInt32, pub: Data)] = opks.map { (id: $0.id, pub: $0.publicKey) }
        return try local.sign(SignedMessages.opkBatch(batch))
    }

    static func request(spk: SignedPrekey?, opks: [OneTimePrekey], local: IdentityKeys) throws -> PrekeysPutRequest {
        var spkDTO: SPKDTO? = nil
        if let s = spk { spkDTO = try PrekeyUpload.spkDTO(s, local: local) }
        return PrekeysPutRequest(spk: spkDTO, opks: opks.map { OPKDTO(id: $0.id, pub: $0.publicKey) },
                                 opksSig: try opksSig(opks, local: local))
    }
}

// MARK: - Maintenance (launch, foreground, hourly, `prekeys_low`)

enum PrekeyMaintenance {
    struct Outcome: Equatable {
        var rotated: Bool
        var uploadedOPKs: Int
        var opkCount: Int?
    }

    /// Housekeeping (consumed report → grace, OPK/SPK pruning), SPK rotation and OPK refill. Every key is
    /// persisted before it is uploaded. Network failures are swallowed (the next run retries).
    static func run(store: LocalStore, api: APIClient, local: IdentityKeys, keySource: KeySource, now: UInt64,
                    serverCount: Int?, consumedIds: [UInt32]) async -> Outcome {
        var outcome: Outcome = Outcome(rotated: false, uploadedOPKs: 0, opkCount: serverCount)
        do {
            try store.commitIndex { idx in
                idx.prekeys.reportConsumed(ids: consumedIds, now: now)
                idx.prekeys.pruneOPKs(now: now)
                idx.prekeys.pruneSPKs(now: now)
            }
            if store.index.prekeys.needsRotation(now: now) {
                var rotated: SignedPrekey? = nil
                try store.commitIndex { idx in
                    rotated = idx.prekeys.rotateSPK(now: now, keySource: keySource)
                }
                if let spk = rotated {
                    let req: PrekeysPutRequest = try PrekeyUpload.request(spk: spk, opks: [], local: local)
                    let resp: PrekeysPutResponse = try await api.uploadPrekeys(req)
                    outcome.rotated = true
                    outcome.opkCount = resp.opkCount
                }
            }
            let count: Int
            if let c = outcome.opkCount {
                count = c
            } else {
                let resp: PrekeyCountResponse = try await api.prekeyCount()
                count = resp.opkCount
                try store.commitIndex { idx in
                    idx.prekeys.reportConsumed(ids: resp.consumedIds, now: now)
                    idx.prekeys.pruneOPKs(now: now)
                    idx.prekeys.lastServerCount = count
                }
                outcome.opkCount = count
            }
            if PrekeyRecords.needsRefill(serverCount: count) {
                let pending: Int = store.index.prekeys.pendingUpload.count
                let missing: Int = max(0, PrekeyRecords.refillTarget - count - pending)
                if missing > 0 {
                    try store.commitIndex { idx in
                        idx.prekeys.generateOPKs(count: missing, now: now, keySource: keySource)
                    }
                }
                let batch: [OneTimePrekey] = store.index.prekeys.pendingUpload
                if !batch.isEmpty {
                    let req: PrekeysPutRequest = try PrekeyUpload.request(spk: nil, opks: batch, local: local)
                    let resp: PrekeysPutResponse = try await api.uploadPrekeys(req)
                    let ids: [UInt32] = batch.map { $0.id }
                    try store.commitIndex { idx in
                        idx.prekeys.markUploaded(ids: ids)
                        idx.prekeys.lastServerCount = resp.opkCount
                    }
                    outcome.uploadedOPKs = batch.count
                    outcome.opkCount = resp.opkCount
                }
            }
        } catch {
            return outcome
        }
        return outcome
    }
}
