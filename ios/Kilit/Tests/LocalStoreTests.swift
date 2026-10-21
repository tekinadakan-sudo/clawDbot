import XCTest
import CryptoKit
@testable import Kilit

/// §3.7 local store wrapping: seal/open, docKey + generation nonce + AAD, `≥` acceptance, rollback, protection.
final class LocalStoreTests: XCTestCase {
    private func makeStore(writer: MemoryFileWriter = MemoryFileWriter(), keychain: InMemoryKeychain = InMemoryKeychain(),
                           directory: URL = URL(fileURLWithPath: "/kilit-tests/\(UUID().uuidString)", isDirectory: true)) -> LocalStore {
        let store: LocalStore = LocalStore(directory: directory, keychain: keychain, writer: writer, defaults: UserDefaults.standard)
        store.generationCoalesceInterval = 0
        return store
    }

    func testSealOpenRoundTripAndNonceLayout() throws {
        let storeKey: Data = Bytes.random(32)
        let json: Data = Data("{\"a\":1}".utf8)
        let prefix: Data = Data([1, 2, 3, 4])
        let sealed: Data = try LocalStore.seal(json: json, storeKey: storeKey, path: "conv/bob.json", generation: 7, randomPrefix: prefix)
        XCTAssertEqual(sealed.subdata(in: 0..<4), prefix)
        XCTAssertEqual(sealed.subdata(in: 4..<12), BE.u64(7))
        XCTAssertEqual(sealed.count, 12 + json.count + AEAD.tagLength)
        let opened: (json: Data, generation: UInt64) = try LocalStore.open(sealed: sealed, storeKey: storeKey, path: "conv/bob.json")
        XCTAssertEqual(opened.json, json)
        XCTAssertEqual(opened.generation, 7)
        XCTAssertThrowsError(try LocalStore.seal(json: json, storeKey: storeKey, path: "x", generation: 1, randomPrefix: Data([1])))
    }

    func testDocKeyAndAADBytes() {
        XCTAssertEqual(KilitInfo.localStore, "Kilit_LocalStore_v1")
        XCTAssertEqual(KilitInfo.localStoreDoc, "Kilit_LocalStoreDoc_v1")
        let master: Data = Bytes.random(32)
        let storeKey: Data = LocalStore.storeKey(masterKey: master)
        XCTAssertEqual(storeKey, KDF.hkdf(ikm: master, salt: KDF.zeros32, info: "Kilit_LocalStore_v1", length: 32))
        let path: String = "sessions/bob.json"
        let expectedDocKey: Data = KDF.hkdf(ikm: storeKey, salt: KDF.zeros32,
                                            info: Data("Kilit_LocalStoreDoc_v1".utf8) + Data(path.utf8), length: 32)
        XCTAssertEqual(LocalStore.docKey(storeKey: storeKey, path: path), expectedDocKey)
        XCTAssertNotEqual(LocalStore.docKey(storeKey: storeKey, path: path), LocalStore.docKey(storeKey: storeKey, path: "sessions/eve.json"))
        XCTAssertEqual(LocalStore.aad(path: path, generation: 3), Data("Kilit_LocalStore_v1".utf8) + Data(path.utf8) + BE.u64(3))
    }

    func testPathMismatchAndTamperFailClosed() throws {
        let storeKey: Data = Bytes.random(32)
        let json: Data = Data("{\"b\":2}".utf8)
        let sealed: Data = try LocalStore.seal(json: json, storeKey: storeKey, path: "conv/a.json", generation: 2)
        XCTAssertThrowsError(try LocalStore.open(sealed: sealed, storeKey: storeKey, path: "conv/b.json")) { error in
            XCTAssertEqual(error as? LocalStoreError, LocalStoreError.rollback(path: "conv/b.json"))
        }
        var generationTampered: Data = sealed
        generationTampered[11] ^= 0x01
        XCTAssertThrowsError(try LocalStore.open(sealed: generationTampered, storeKey: storeKey, path: "conv/a.json"))
        var bodyTampered: Data = sealed
        bodyTampered[13] ^= 0x80
        XCTAssertThrowsError(try LocalStore.open(sealed: bodyTampered, storeKey: storeKey, path: "conv/a.json"))
        XCTAssertThrowsError(try LocalStore.open(sealed: Data([0, 1, 2]), storeKey: storeKey, path: "conv/a.json"))
        XCTAssertNoThrow(try LocalStore.open(sealed: sealed, storeKey: storeKey, path: "conv/a.json"))
    }

    /// `generation ≥ recorded` is accepted (equality included); a higher value becomes the new record.
    func testGenerationAcceptanceAndAdoption() throws {
        let writer: MemoryFileWriter = MemoryFileWriter()
        let keychain: InMemoryKeychain = InMemoryKeychain()
        let directory: URL = URL(fileURLWithPath: "/kilit-tests/\(UUID().uuidString)", isDirectory: true)
        let store: LocalStore = makeStore(writer: writer, keychain: keychain, directory: directory)
        try store.open()
        try store.commitIndex { idx in idx.username = "alice" }
        try store.commitIndex { idx in idx.clockOffset = 5 }
        store.flushGeneration()
        XCTAssertEqual(store.indexGeneration, 2)
        XCTAssertEqual(try keychain.readStoreGeneration(), 2)

        // Equality: accepted.
        let store2: LocalStore = makeStore(writer: writer, keychain: keychain, directory: directory)
        XCTAssertNoThrow(try store2.open())
        XCTAssertEqual(store2.indexGeneration, 2)
        XCTAssertEqual(store2.index.username, "alice")

        // Higher on disk than recorded: accepted and adopted.
        let master: Data = try XCTUnwrap(try keychain.read(KeychainAccount.masterKey))
        let storeKey: Data = LocalStore.storeKey(masterKey: master)
        var idx: StoreIndex = store2.index
        idx.username = "zed"
        let sealed: Data = try LocalStore.seal(json: try KilitJSON.encoder().encode(idx), storeKey: storeKey,
                                               path: LocalStore.indexPath, generation: 9)
        try writer.write(sealed, to: store2.fileURL(LocalStore.indexPath))
        let store3: LocalStore = makeStore(writer: writer, keychain: keychain, directory: directory)
        try store3.open()
        XCTAssertEqual(store3.indexGeneration, 9)
        XCTAssertEqual(store3.index.username, "zed")
        store3.flushGeneration()
        XCTAssertEqual(try keychain.readStoreGeneration(), 9)
        // The next write continues from the adopted value.
        try store3.commitIndex { i in i.clockOffset = 1 }
        XCTAssertEqual(store3.indexGeneration, 10)
    }

    /// A generation below the recorded value fails closed, for `index.json` and for a child document.
    func testRollbackRefused() throws {
        let writer: MemoryFileWriter = MemoryFileWriter()
        let keychain: InMemoryKeychain = InMemoryKeychain()
        let directory: URL = URL(fileURLWithPath: "/kilit-tests/\(UUID().uuidString)", isDirectory: true)
        let store: LocalStore = makeStore(writer: writer, keychain: keychain, directory: directory)
        try store.open()
        let childPath: String = "conv/bob.json"
        var doc: ConversationDocument = ConversationDocument()
        try store.commit([try DocumentWrite(path: childPath, value: doc)])
        let childGen1: Data = try XCTUnwrap(try writer.read(store.fileURL(childPath)))
        let indexGen1: Data = try XCTUnwrap(try writer.read(store.fileURL(LocalStore.indexPath)))
        doc.lastPeerCaptureSeq = 4
        try store.commit([try DocumentWrite(path: childPath, value: doc)])
        store.flushGeneration()
        XCTAssertEqual(store.index.generations[childPath], 2)
        XCTAssertEqual(try keychain.readStoreGeneration(), 2)

        // Child rolled back to its generation-1 bytes: refused, stale content handed back.
        try writer.write(childGen1, to: store.fileURL(childPath))
        switch try store.loadDetailed(ConversationDocument.self, at: childPath) {
        case .rollback(let stale):
            XCTAssertNotNil(stale)
            XCTAssertNil(stale?.lastPeerCaptureSeq)
        default:
            XCTFail("expected rollback")
        }
        XCTAssertThrowsError(try store.load(ConversationDocument.self, at: childPath)) { error in
            XCTAssertEqual(error as? LocalStoreError, LocalStoreError.rollback(path: childPath))
        }

        // index.json rolled back below the Keychain record: the open fails closed (wipe prompt).
        try writer.write(indexGen1, to: store.fileURL(LocalStore.indexPath))
        let store2: LocalStore = makeStore(writer: writer, keychain: keychain, directory: directory)
        XCTAssertThrowsError(try store2.open()) { error in
            XCTAssertEqual(error as? LocalStoreError, LocalStoreError.rollback(path: LocalStore.indexPath))
        }
        XCTAssertFalse(store2.isOpen)
    }

    /// A session file that rolls back is replaced and queued for S3 with `deletedReason = rollback`.
    func testSessionRollbackQueuesRecovery() throws {
        let writer: MemoryFileWriter = MemoryFileWriter()
        let keychain: InMemoryKeychain = InMemoryKeychain()
        let store: LocalStore = makeStore(writer: writer, keychain: keychain)
        try store.open()
        let clock: ManualClock = ManualClock(now: 1_760_000_000)
        let sessions: SessionStore = SessionStore(store: store, clock: clock)
        let bob: TestPeer = TestPeer(username: "bob", now: clock.now)
        let alice: IdentityKeys = IdentityKeys()
        let session: Session = try SessionOutbound.initiate(bundle: try bob.bundle(), local: alice, localUsername: "alice",
                                                            now: clock.now, keySource: RandomKeySource())
        var doc: SessionDocument = try sessions.addInitiated(peer: "bob", session: session)
        let gen1: Data = try XCTUnwrap(try writer.read(store.fileURL(LocalStore.sessionPath("bob"))))
        doc.pendingSends = []
        try sessions.save(peer: "bob", doc)
        try writer.write(gen1, to: store.fileURL(LocalStore.sessionPath("bob")))
        let fresh: SessionDocument = try sessions.load(peer: "bob")
        XCTAssertTrue(fresh.peer.sessions.isEmpty)
        XCTAssertEqual(fresh.peer.knownSid(session.sid)?.deletedReason, .rollback)
        XCTAssertEqual(sessions.takePendingRecovery(peer: "bob"), [session.sid])
        XCTAssertNil(sessions.takePendingRecovery(peer: "bob"))
        // The replacement carries a newer generation, so the next load is clean.
        XCTAssertEqual(try sessions.load(peer: "bob"), fresh)
    }

    func testWipeRemovesFilesKeychainAndMarker() throws {
        let writer: MemoryFileWriter = MemoryFileWriter()
        let keychain: InMemoryKeychain = InMemoryKeychain()
        let store: LocalStore = makeStore(writer: writer, keychain: keychain)
        try store.open()
        try store.commit([try DocumentWrite(path: "conv/bob.json", value: ConversationDocument())])
        store.markInstalled()
        try keychain.writeString(KeychainAccount.token, "t")
        XCTAssertFalse(writer.files.isEmpty)
        try store.wipe()
        XCTAssertTrue(writer.files.isEmpty)
        XCTAssertNil(try keychain.read(KeychainAccount.token))
        XCTAssertNil(try keychain.read(KeychainAccount.masterKey))
        XCTAssertFalse(store.isOpen)
        XCTAssertFalse(store.reinstallDetected())
        // Re-open after a wipe starts from generation 0 with an empty index (cursor 0).
        try store.open()
        XCTAssertEqual(store.indexGeneration, 0)
        XCTAssertEqual(store.index.ledger.cursor, 0)
    }

    func testReinstallDetection() throws {
        let keychain: InMemoryKeychain = InMemoryKeychain()
        let store: LocalStore = makeStore(keychain: keychain)
        UserDefaults.standard.removeObject(forKey: LocalStore.installMarkerKey)
        XCTAssertFalse(store.reinstallDetected())
        try keychain.writeIdentity(IdentityKeys())
        XCTAssertTrue(store.reinstallDetected())
        store.markInstalled()
        XCTAssertFalse(store.reinstallDetected())
        UserDefaults.standard.removeObject(forKey: LocalStore.installMarkerKey)
    }

    func testCompleteProtectionAttribute() throws {
        #if targetEnvironment(simulator)
        throw XCTSkip("File protection classes are not enforced on the Simulator")
        #else
        let dir: URL = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let writer: DiskFileWriter = DiskFileWriter()
        let file: URL = dir.appendingPathComponent("a.bin")
        try writer.write(Data([1, 2, 3]), to: file)
        let attrs: [FileAttributeKey: Any] = try FileManager.default.attributesOfItem(atPath: file.path)
        let raw: String? = (attrs[.protectionKey] as? FileProtectionType)?.rawValue ?? (attrs[.protectionKey] as? String)
        XCTAssertEqual(raw, FileProtectionType.complete.rawValue)
        let dirAttrs: [FileAttributeKey: Any] = try FileManager.default.attributesOfItem(atPath: dir.path)
        let dirRaw: String? = (dirAttrs[.protectionKey] as? FileProtectionType)?.rawValue ?? (dirAttrs[.protectionKey] as? String)
        XCTAssertEqual(dirRaw, FileProtectionType.complete.rawValue)
        #endif
    }
}
