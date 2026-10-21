import XCTest
import CryptoKit
@testable import Kilit

/// §3.1 lifetimes: OPK deleted on use or 7 d after the consumed report, never on report alone, never on age;
/// 500-cap by `uploadedAt`; SPK deleted 28 d after `created_at` regardless of rotation; rotation after 7 d; refill.
final class PrekeyLifecycleTests: XCTestCase {
    private let t0: UInt64 = 1_760_000_000
    private let day: UInt64 = 86_400

    private func records(opks: Int) -> PrekeyRecords {
        var r: PrekeyRecords = PrekeyRecords()
        r.rotateSPK(now: t0, keySource: RandomKeySource())
        r.generateOPKs(count: opks, now: t0, keySource: RandomKeySource())
        return r
    }

    func testOPKDeletedOnFirstUse() {
        var r: PrekeyRecords = records(opks: 3)
        XCTAssertNotNil(r.opk(id: 2))
        XCTAssertTrue(r.markUsed(opkId: 2))
        XCTAssertNil(r.opk(id: 2))
        XCTAssertFalse(r.markUsed(opkId: 2))
        XCTAssertEqual(r.opks.count, 2)
        XCTAssertNil(r.lookup().opk(2))
        XCTAssertNotNil(r.lookup().opk(1))
    }

    func testConsumedReportStartsGraceButDeletesNothing() {
        var r: PrekeyRecords = records(opks: 3)
        r.reportConsumed(ids: [1], now: t0)
        XCTAssertEqual(r.pruneOPKs(now: t0), [])
        XCTAssertNotNil(r.opk(id: 1))
        XCTAssertEqual(r.pruneOPKs(now: t0 + 7 * day), [])
        XCTAssertNotNil(r.opk(id: 1))
        // A later report does not restart the window.
        r.reportConsumed(ids: [1], now: t0 + 6 * day)
        XCTAssertEqual(r.pruneOPKs(now: t0 + 7 * day + 1), [1])
        XCTAssertNil(r.opk(id: 1))
        XCTAssertEqual(r.opks.count, 2)
        // Inside the grace window the key still answers an X3DH initiation (no `opk_gone`).
        var s: PrekeyRecords = records(opks: 1)
        s.reportConsumed(ids: [1], now: t0)
        XCTAssertNotNil(s.lookup().opk(1))
    }

    func testOPKNeverDeletedOnAge() {
        var r: PrekeyRecords = records(opks: 5)
        for age in [30 * day, 90 * day, 365 * day] {
            XCTAssertEqual(r.pruneOPKs(now: t0 + age), [])
            XCTAssertEqual(r.opks.count, 5)
            for id in 1...5 { XCTAssertNotNil(r.opk(id: UInt32(id))) }
        }
    }

    func testCapEvictsOldestByUploadedAtAndNeverReusesIds() {
        var r: PrekeyRecords = records(opks: PrekeyRecords.opkCap)
        XCTAssertEqual(r.opks.count, 500)
        r.generateOPKs(count: 10, now: t0 + 10, keySource: RandomKeySource())
        XCTAssertEqual(r.opks.count, 500)
        for id in 1...10 { XCTAssertNil(r.opk(id: UInt32(id))) }
        for id in 11...510 { XCTAssertNotNil(r.opk(id: UInt32(id))) }
        XCTAssertEqual(r.nextOpkId, 511)
        XCTAssertEqual(r.pendingUpload.count, 500)
        // Evicted ids are not in the upload set.
        XCTAssertFalse(r.pendingUpload.contains { $0.id <= 10 })
    }

    func testSPKDeleted28DaysAfterCreationRegardlessOfRotation() {
        var noRotation: PrekeyRecords = records(opks: 0)
        XCTAssertEqual(noRotation.pruneSPKs(now: t0 + 28 * day), [])
        XCTAssertNotNil(noRotation.spk(id: 1))
        XCTAssertEqual(noRotation.pruneSPKs(now: t0 + 28 * day + 1), [1])
        XCTAssertNil(noRotation.spk(id: 1))
        XCTAssertNil(noRotation.currentSPK)
        XCTAssertTrue(noRotation.needsRotation(now: t0 + 28 * day + 1))

        var rotated: PrekeyRecords = records(opks: 0)
        let rotateAt: UInt64 = t0 + 7 * day + 1
        XCTAssertTrue(rotated.needsRotation(now: rotateAt))
        let spk2: SignedPrekey = rotated.rotateSPK(now: rotateAt, keySource: RandomKeySource())
        XCTAssertEqual(spk2.id, 2)
        XCTAssertEqual(rotated.currentSPK?.id, 2)
        XCTAssertNotNil(rotated.spk(id: 1))
        XCTAssertEqual(rotated.pruneSPKs(now: t0 + 28 * day), [])
        XCTAssertEqual(rotated.pruneSPKs(now: t0 + 28 * day + 1), [1])
        XCTAssertNotNil(rotated.spk(id: 2))
        XCTAssertEqual(rotated.pruneSPKs(now: rotateAt + 28 * day + 1), [2])
        XCTAssertNil(rotated.lookup().spk(1))
    }

    func testRotationWhenOlderThanSevenDays() {
        let r: PrekeyRecords = records(opks: 0)
        XCTAssertFalse(r.needsRotation(now: t0))
        XCTAssertFalse(r.needsRotation(now: t0 + 7 * day))
        XCTAssertTrue(r.needsRotation(now: t0 + 7 * day + 1))
        XCTAssertTrue(PrekeyRecords().needsRotation(now: t0))
        XCTAssertEqual(PrekeyRecords.rotateAfter, 7 * day)
        XCTAssertEqual(PrekeyRecords.spkLifetime, 28 * day)
        XCTAssertEqual(PrekeyRecords.opkGrace, 7 * day)
    }

    func testRefillTrigger() {
        XCTAssertTrue(PrekeyRecords.needsRefill(serverCount: 19))
        XCTAssertFalse(PrekeyRecords.needsRefill(serverCount: 20))
        XCTAssertTrue(PrekeyRecords.needsRefill(serverCount: 0))
        var r: PrekeyRecords = PrekeyRecords()
        let batch: (spk: SignedPrekey, opks: [OneTimePrekey]) = r.initialBatch(now: t0, keySource: RandomKeySource())
        XCTAssertEqual(batch.opks.count, PrekeyRecords.refillTarget)
        XCTAssertEqual(batch.spk.id, 1)
        XCTAssertEqual(r.pendingUpload.count, 100)
        r.markUploaded(ids: batch.opks.map { $0.id })
        XCTAssertTrue(r.pendingUpload.isEmpty)
    }

    /// `GET /v1/prekeys/count` below 20 → generate, persist, then `PUT /v1/prekeys` with a valid `opks_sig`.
    func testMaintenanceRefillsThroughTheAPI() async throws {
        let h: SyncHarness = try SyncHarness()
        h.override = { request in
            let path: String = request.url?.path ?? ""
            if request.httpMethod == "GET", path == "/v1/prekeys/count" {
                return try StubTransport.json(200, request, ["opk_count": 10, "spk_id": 1, "consumed_ids": [1, 2]])
            }
            if request.httpMethod == "PUT", path == "/v1/prekeys" {
                return try StubTransport.json(200, request, ["opk_count": 100, "spk_id": 1])
            }
            return nil
        }
        XCTAssertEqual(h.store.index.prekeys.opks.count, 3)
        let outcome: PrekeyMaintenance.Outcome = await PrekeyMaintenance.run(
            store: h.store, api: h.api, local: h.me.identity, keySource: RandomKeySource(), now: h.clock.now,
            serverCount: nil, consumedIds: [])
        XCTAssertFalse(outcome.rotated)
        XCTAssertEqual(outcome.uploadedOPKs, 90)
        XCTAssertEqual(outcome.opkCount, 100)
        XCTAssertEqual(h.store.index.prekeys.opks.count, 90)
        XCTAssertTrue(h.store.index.prekeys.pendingUpload.isEmpty)
        XCTAssertEqual(h.store.index.prekeys.opks.first { $0.key.id == 1 }?.consumedReportedAt, h.clock.now)
        XCTAssertNil(h.store.index.prekeys.opks.first { $0.key.id == 3 }?.consumedReportedAt)
        let put: URLRequest = try XCTUnwrap(h.requests("PUT", pathSuffix: "/v1/prekeys").first)
        let body: PrekeysPutRequest = try KilitJSON.decoder().decode(PrekeysPutRequest.self, from: try XCTUnwrap(put.httpBody))
        XCTAssertNil(body.spk)
        XCTAssertEqual(body.opks.count, 90)
        let sig: Data = try XCTUnwrap(body.opksSig)
        let batch: [(id: UInt32, pub: Data)] = body.opks.map { (id: $0.id, pub: $0.pub) }
        XCTAssertNoThrow(try Ed25519Strict.verify(signature: sig, message: SignedMessages.opkBatch(batch),
                                                  publicKey: h.me.identity.publicKeys.ikSig))
        // Every uploaded key was persisted before the upload (ids are stored with their private keys).
        for dto in body.opks { XCTAssertNotNil(h.store.index.prekeys.opk(id: dto.id)) }
    }

    /// Above the threshold nothing is generated or uploaded; an SPK older than 7 d is rotated and uploaded.
    func testMaintenanceRotatesOldSPK() async throws {
        let h: SyncHarness = try SyncHarness()
        h.override = { request in
            let path: String = request.url?.path ?? ""
            if request.httpMethod == "PUT", path == "/v1/prekeys" {
                return try StubTransport.json(200, request, ["opk_count": 50, "spk_id": 2])
            }
            return nil
        }
        let later: UInt64 = h.clock.now + 7 * day + 1
        let outcome: PrekeyMaintenance.Outcome = await PrekeyMaintenance.run(
            store: h.store, api: h.api, local: h.me.identity, keySource: RandomKeySource(), now: later,
            serverCount: nil, consumedIds: [])
        XCTAssertTrue(outcome.rotated)
        XCTAssertEqual(outcome.opkCount, 50)
        XCTAssertEqual(outcome.uploadedOPKs, 0)
        XCTAssertEqual(h.store.index.prekeys.currentSPK?.id, 2)
        XCTAssertNotNil(h.store.index.prekeys.spk(id: 1))
        XCTAssertTrue(h.requests("GET", pathSuffix: "/v1/prekeys/count").isEmpty)
        let put: URLRequest = try XCTUnwrap(h.requests("PUT", pathSuffix: "/v1/prekeys").first)
        let body: PrekeysPutRequest = try KilitJSON.decoder().decode(PrekeysPutRequest.self, from: try XCTUnwrap(put.httpBody))
        XCTAssertEqual(body.spk?.id, 2)
        XCTAssertTrue(body.opks.isEmpty)
        XCTAssertNil(body.opksSig)
    }
}
