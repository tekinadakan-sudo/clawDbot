import XCTest
import CryptoKit
@testable import Kilit

// MARK: - Shared test doubles (used by WebSocketClientTests, AttachmentUploadTests, PrekeyLifecycleTests too)

enum HarnessError: Error {
    case badURL
    case missing(String)
}

/// Scripted HTTP transport: `handler` answers every request; nothing touches the network.
final class StubTransport: HTTPTransport {
    var handler: (URLRequest) async throws -> (Data, HTTPURLResponse)
    private var recorded: [URLRequest] = []
    private let lock: NSLock = NSLock()

    init(handler: @escaping (URLRequest) async throws -> (Data, HTTPURLResponse)) {
        self.handler = handler
    }

    var requests: [URLRequest] {
        lock.lock()
        defer { lock.unlock() }
        return recorded
    }

    func perform(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        lock.lock()
        recorded.append(request)
        lock.unlock()
        return try await handler(request)
    }

    static func data(_ status: Int, _ request: URLRequest, _ body: Data) throws -> (Data, HTTPURLResponse) {
        guard let url = request.url,
              let response = HTTPURLResponse(url: url, statusCode: status, httpVersion: "HTTP/1.1", headerFields: nil) else {
            throw HarnessError.badURL
        }
        return (body, response)
    }

    static func json(_ status: Int, _ request: URLRequest, _ object: [String: Any]) throws -> (Data, HTTPURLResponse) {
        try data(status, request, try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]))
    }

    static func encoded<T: Encodable>(_ status: Int, _ request: URLRequest, _ value: T) throws -> (Data, HTTPURLResponse) {
        try data(status, request, try KilitJSON.encoder().encode(value))
    }
}

/// Real `Task.sleep` scaled down so coalescing / backoff timers finish within a test.
final class ScaledSleeper: Sleeper {
    let scale: Double
    init(scale: Double = 0.001) { self.scale = scale }
    func sleep(seconds: Double) async throws {
        try await Task.sleep(for: .seconds(max(0.001, seconds * scale)))
    }
}

/// One party with an identity and a prekey set; `bundle()` is what the server would serve for it.
struct TestPeer {
    let username: String
    let identity: IdentityKeys
    var prekeys: PrekeyRecords

    init(username: String, now: UInt64, opkCount: Int = 3) {
        self.username = username
        self.identity = IdentityKeys()
        var records: PrekeyRecords = PrekeyRecords()
        records.rotateSPK(now: now, keySource: RandomKeySource())
        records.generateOPKs(count: opkCount, now: now, keySource: RandomKeySource())
        self.prekeys = records
    }

    func bundleResponse() throws -> BundleResponse {
        guard let spk = prekeys.currentSPK else { throw HarnessError.missing("spk") }
        let signed: SignedPrekeyPublic = try spk.signed(by: identity)
        let opk: OneTimePrekey? = prekeys.opks.first?.key
        let ids: IdentityPublicKeys = identity.publicKeys
        return BundleResponse(username: username, ikSig: ids.ikSig, ikDh: ids.ikDh, ikBindSig: try identity.ikBindSig(),
                              spk: SPKDTO(id: signed.id, pub: signed.pub, sig: signed.sig, createdAt: signed.createdAt),
                              opk: opk.map { OPKDTO(id: $0.id, pub: $0.publicKey) })
    }

    func bundle() throws -> PrekeyBundle {
        try bundleResponse().bundle
    }

    func userResponse() throws -> UserResponse {
        let ids: IdentityPublicKeys = identity.publicKeys
        return UserResponse(username: username, ikSig: ids.ikSig, ikDh: ids.ikDh, ikBindSig: try identity.ikBindSig())
    }

    /// A fresh initiator session towards `recipient` plus the first (`prekey`) envelope carrying `text`.
    static func initiation(from sender: TestPeer, to recipient: TestPeer, text: String, now: UInt64) throws
        -> (session: Session, envelope: Data, inner: InnerMessage) {
        var session: Session = try SessionOutbound.initiate(bundle: try recipient.bundle(), local: sender.identity,
                                                            localUsername: sender.username, now: now, keySource: RandomKeySource())
        let inner: InnerMessage = InnerMessage.text(id: Identifiers.messageId(), ts: now, ttl: 0, text: text)
        let out: OutboundEnvelope = try SessionOutbound.encrypt(session: &session, inner: inner, local: sender.identity)
        return (session, out.bytes, inner)
    }
}

/// A `MessageSync` on in-memory stores with a scripted server: `peers` answers lookups and bundle fetches,
/// messages are accepted with `202`, acks with `200 {deleted}`; `override` intercepts anything first.
final class SyncHarness {
    static let now0: UInt64 = 1_760_000_000

    let clock: ManualClock
    let keychain: InMemoryKeychain
    let writer: MemoryFileWriter
    let directory: URL
    let store: LocalStore
    let blobs: BlobStore
    let transport: StubTransport
    let api: APIClient
    let me: TestPeer
    let sync: MessageSync
    var peers: [String: TestPeer] = [:]
    var override: ((URLRequest) async throws -> (Data, HTTPURLResponse)?)?
    private(set) var serverRowId: Int64 = 100

    init(username: String = "alice") throws {
        let clock: ManualClock = ManualClock(now: SyncHarness.now0)
        let keychain: InMemoryKeychain = InMemoryKeychain()
        let writer: MemoryFileWriter = MemoryFileWriter()
        let directory: URL = URL(fileURLWithPath: "/kilit-tests/\(UUID().uuidString)", isDirectory: true)
        let store: LocalStore = LocalStore(directory: directory, keychain: keychain, writer: writer, defaults: UserDefaults.standard)
        let blobs: BlobStore = BlobStore(directory: directory.appendingPathComponent("blobs", isDirectory: true), writer: writer)
        let me: TestPeer = TestPeer(username: username, now: SyncHarness.now0)
        let holder: TransportHolder = TransportHolder()
        let transport: StubTransport = StubTransport { request in try await holder.route(request) }
        let api: APIClient = APIClient(origin: "https://kilit.test", transport: transport, token: "test-token")
        try keychain.writeIdentity(me.identity)
        try store.open()
        let records: PrekeyRecords = me.prekeys
        try store.commitIndex { idx in
            idx.username = username
            idx.serverOrigin = "https://kilit.test"
            idx.prekeys = records
        }
        self.clock = clock
        self.keychain = keychain
        self.writer = writer
        self.directory = directory
        self.store = store
        self.blobs = blobs
        self.me = me
        self.transport = transport
        self.api = api
        self.sync = MessageSync(store: store, blobs: blobs, api: api, keychain: keychain, clock: clock, keySource: RandomKeySource(),
                                local: me.identity, username: username, webSocket: nil, sleeper: ScaledSleeper())
        holder.harness = self
    }

    /// Breaks the init-order cycle between the transport closure and `self`.
    final class TransportHolder {
        weak var harness: SyncHarness?
        func route(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
            guard let h = harness else { throw HarnessError.missing("harness") }
            return try await h.route(request)
        }
    }

    func nextRowId() -> Int64 {
        serverRowId += 1
        return serverRowId
    }

    func route(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        if let o = override, let answer = try await o(request) { return answer }
        let path: String = request.url?.path ?? ""
        let method: String = request.httpMethod ?? "GET"
        let parts: [String] = path.split(separator: "/").map(String.init)
        if method == "GET", parts.count == 3, parts[0] == "v1", parts[1] == "users", let p = peers[parts[2]] {
            return try StubTransport.encoded(200, request, try p.userResponse())
        }
        if method == "GET", parts.count == 4, parts[0] == "v1", parts[1] == "users", parts[3] == "prekeys", let p = peers[parts[2]] {
            return try StubTransport.encoded(200, request, try p.bundleResponse())
        }
        if method == "POST", path == "/v1/messages" {
            return try StubTransport.json(202, request, ["id": nextRowId()])
        }
        if method == "POST", path == "/v1/messages/ack" {
            let body: AckRequest = try KilitJSON.decoder().decode(AckRequest.self, from: request.httpBody ?? Data())
            return try StubTransport.json(200, request, ["deleted": body.msgIds.count])
        }
        if method == "GET", path == "/v1/messages" {
            return try StubTransport.json(200, request, ["messages": [], "has_more": false])
        }
        if method == "DELETE", parts.count == 3, parts[1] == "attachments" {
            return try StubTransport.data(204, request, Data())
        }
        return try StubTransport.json(404, request, ["error": "not_found"])
    }

    func row(from peer: String, envelope: Data) -> MessageRow {
        MessageRow(id: nextRowId(), msgId: Identifiers.hex32(), from: peer, envelope: envelope, ts: clock.now)
    }

    func sessionDocument(_ peer: String) throws -> SessionDocument? {
        try store.load(SessionDocument.self, at: LocalStore.sessionPath(peer))
    }

    func conversation(_ peer: String) throws -> ConversationDocument? {
        try store.load(ConversationDocument.self, at: LocalStore.conversationPath(peer))
    }

    func requests(_ method: String, pathSuffix: String) -> [URLRequest] {
        transport.requests.filter { ($0.httpMethod ?? "") == method && ($0.url?.path ?? "").hasSuffix(pathSuffix) }
    }
}

// MARK: - SessionStoreAtomicityTests (§3.7 write order, §5.12)

final class SessionStoreAtomicityTests: XCTestCase {
    /// Write-before-send: when `POST /v1/messages` is performed, `sessions/<peer>.json` on disk already holds
    /// the advanced ratchet state and the cached envelope; the row is `.outbox` until the `202`.
    func testStateOnDiskAdvancedBeforeSendCallback() async throws {
        let h: SyncHarness = try SyncHarness()
        let bob: TestPeer = TestPeer(username: "bob", now: SyncHarness.now0)
        h.peers["bob"] = bob
        var observedPending: Int = -1
        var observedNs: UInt32 = 0
        var observedState: MessageState? = nil
        h.override = { request in
            guard request.httpMethod == "POST", request.url?.path == "/v1/messages" else { return nil }
            let body: SendRequest = try KilitJSON.decoder().decode(SendRequest.self, from: request.httpBody ?? Data())
            let doc: SessionDocument? = try h.sessionDocument("bob")
            let conv: ConversationDocument? = try h.conversation("bob")
            let cached: CachedEnvelope? = doc?.cached(msgId: body.msgId)
            XCTAssertEqual(cached?.envelope, body.envelope)
            observedPending = doc?.pendingSends.count ?? 0
            observedNs = doc?.peer.sessions.first?.state.ns ?? 0
            observedState = conv?.messages.first?.state
            return try StubTransport.json(202, request, ["id": 1])
        }
        let msgId: String = try await h.sync.sendText(to: "bob", text: "merhaba")
        XCTAssertEqual(observedPending, 1)
        XCTAssertEqual(observedNs, 1)
        XCTAssertEqual(observedState, .outbox)
        let after: SessionDocument = try XCTUnwrap(try h.sessionDocument("bob"))
        XCTAssertNil(after.cached(msgId: msgId))
        let conv: ConversationDocument = try XCTUnwrap(try h.conversation("bob"))
        XCTAssertEqual(conv.messages.count, 1)
        XCTAssertEqual(conv.messages[0].state, .sent)
        XCTAssertEqual(conv.messages[0].sentAt, SyncHarness.now0)
        XCTAssertTrue(h.store.index.outbox.isEmpty)
        XCTAssertEqual(h.requests("GET", pathSuffix: "/v1/users/bob/prekeys").count, 1)
    }

    /// Inbound order: `conv/<peer>.json` (plaintext + outer id) → `sessions/<peer>.json` → `index.json` with the
    /// cursor and the ack appended to `pendingAcks` in the same write.
    func testInboundWriteOrderPlaintextRatchetAck() async throws {
        let h: SyncHarness = try SyncHarness()
        let bob: TestPeer = TestPeer(username: "bob", now: SyncHarness.now0)
        h.peers["bob"] = bob
        let start: (session: Session, envelope: Data, inner: InnerMessage) = try TestPeer.initiation(from: bob, to: h.me, text: "selam", now: SyncHarness.now0)
        h.writer.resetCounters()
        let row: MessageRow = h.row(from: "bob", envelope: start.envelope)
        await h.sync.handleRow(row)
        let paths: [String] = h.writer.writtenPaths.map { $0.replacingOccurrences(of: h.directory.path + "/", with: "") }
        XCTAssertEqual(paths, ["conv/bob.json", "sessions/bob.json", "index.json"])
        XCTAssertEqual(h.store.index.ledger.cursor, row.id)
        XCTAssertEqual(h.store.index.ledger.pendingAcks, [row.msgId])
        let conv: ConversationDocument = try XCTUnwrap(try h.conversation("bob"))
        XCTAssertEqual(conv.messages.count, 1)
        XCTAssertEqual(conv.messages[0].text, "selam")
        XCTAssertEqual(conv.messages[0].state, .received)
        XCTAssertTrue(conv.state.isProcessed(msgId: row.msgId))
        let doc: SessionDocument = try XCTUnwrap(try h.sessionDocument("bob"))
        XCTAssertEqual(doc.peer.sessions.count, 1)
        XCTAssertEqual(doc.peer.sessions[0].sid, start.session.sid)
        XCTAssertNotNil(doc.peer.sessions[0].lastActivity)
        XCTAssertNotNil(h.store.index.contact("bob"))
        XCTAssertEqual(h.requests("GET", pathSuffix: "/v1/users/bob").count, 1)
        // The consumed OPK private key is gone (rule (a)).
        if let opkId = start.session.pendingX3DH?.opkId {
            XCTAssertNil(h.store.index.prekeys.opk(id: opkId))
        }
    }

    /// A failing writer after the plaintext write: nothing is acked, the cursor does not move, the ratchet is not
    /// committed; the redelivery hits step 0 (`already_processed`) and the next genuine message recovers.
    func testInboundFailingWriterKeepsAckAndRatchetUntouched() async throws {
        let h: SyncHarness = try SyncHarness()
        let bob: TestPeer = TestPeer(username: "bob", now: SyncHarness.now0)
        h.peers["bob"] = bob
        var session: Session = try SessionOutbound.initiate(bundle: try h.me.bundle(), local: bob.identity, localUsername: "bob",
                                                            now: SyncHarness.now0, keySource: RandomKeySource())
        let first: InnerMessage = InnerMessage.text(id: Identifiers.messageId(), ts: SyncHarness.now0, ttl: 0, text: "bir")
        let env1: Data = try SessionOutbound.encrypt(session: &session, inner: first, local: bob.identity).bytes
        let row: MessageRow = h.row(from: "bob", envelope: env1)
        h.writer.failAfterWrites = h.writer.successfulWrites + 1
        await h.sync.handleRow(row)
        XCTAssertEqual(h.store.index.ledger.cursor, 0)
        XCTAssertTrue(h.store.index.ledger.pendingAcks.isEmpty)
        XCTAssertNil(try h.sessionDocument("bob"))
        h.writer.failAfterWrites = nil
        // Redelivery of the same row (crash between 3(a) and 3(b)).
        await h.sync.handleRow(row)
        XCTAssertEqual(h.store.index.ledger.cursor, row.id)
        XCTAssertEqual(h.store.index.ledger.pendingAcks, [row.msgId])
        XCTAssertEqual(try h.conversation("bob")?.messages.count, 1)
        XCTAssertNil(try h.sessionDocument("bob"))
        // The next genuine message (n = 1) re-derives the state via MKSKIPPED.
        let second: InnerMessage = InnerMessage.text(id: Identifiers.messageId(), ts: SyncHarness.now0, ttl: 0, text: "iki")
        let env2: Data = try SessionOutbound.encrypt(session: &session, inner: second, local: bob.identity).bytes
        let row2: MessageRow = h.row(from: "bob", envelope: env2)
        await h.sync.handleRow(row2)
        XCTAssertEqual(h.store.index.ledger.cursor, row2.id)
        XCTAssertEqual(h.store.index.ledger.pendingAcks, [row.msgId, row2.msgId])
        let conv: ConversationDocument = try XCTUnwrap(try h.conversation("bob"))
        XCTAssertEqual(conv.messages.map { $0.text }, ["bir", "iki"])
        let doc: SessionDocument = try XCTUnwrap(try h.sessionDocument("bob"))
        XCTAssertEqual(doc.peer.sessions.count, 1)
        XCTAssertEqual(doc.peer.sessions[0].state.mkskipped.count, 1)
    }

    /// A crash after each of the three §3.7 writes: the relaunch accepts the files (`≥`), there is no wipe
    /// prompt and the session is still the sending session (no forced X3DH).
    func testCrashAfterEachWriteNeedsNoWipeAndNoX3DH() async throws {
        let h: SyncHarness = try SyncHarness()
        let bob: TestPeer = TestPeer(username: "bob", now: SyncHarness.now0)
        let session: Session = try SessionOutbound.initiate(bundle: try bob.bundle(), local: h.me.identity, localUsername: "alice",
                                                            now: SyncHarness.now0, keySource: RandomKeySource())
        let sessions: SessionStore = SessionStore(store: h.store, clock: h.clock)
        var doc: SessionDocument = try sessions.addInitiated(peer: "bob", session: session)
        h.store.flushGeneration()
        XCTAssertEqual(try h.keychain.readStoreGeneration(), h.store.indexGeneration)

        // Crash after write 1 (child document written, index.json not).
        doc.pendingSends.append(CachedEnvelope(msgId: "m1", to: "bob", envelope: Data([1]), kind: .msg, sid: session.sid,
                                               innerId: "i1", innerType: "text", createdAt: SyncHarness.now0))
        h.writer.failAfterWrites = h.writer.successfulWrites + 1
        XCTAssertThrowsError(try sessions.save(peer: "bob", doc))
        h.writer.failAfterWrites = nil
        try relaunchAndAssertHealthy(h, expectedSid: session.sid)

        // Crash after write 2 (index.json written, Keychain generation not).
        let store2: LocalStore = LocalStore(directory: h.directory, keychain: h.keychain, writer: h.writer, defaults: UserDefaults.standard)
        try store2.open()
        let sessions2: SessionStore = SessionStore(store: store2, clock: h.clock)
        var doc2: SessionDocument = try sessions2.load(peer: "bob")
        doc2.pendingSends = []
        h.keychain.failWrites = true
        try sessions2.save(peer: "bob", doc2)
        store2.flushGeneration()
        XCTAssertLessThan(try h.keychain.readStoreGeneration(), store2.indexGeneration)
        h.keychain.failWrites = false
        try relaunchAndAssertHealthy(h, expectedSid: session.sid)

        // Crash after write 3 (everything written): trivially healthy.
        try relaunchAndAssertHealthy(h, expectedSid: session.sid)
    }

    private func relaunchAndAssertHealthy(_ h: SyncHarness, expectedSid: Data) throws {
        let store: LocalStore = LocalStore(directory: h.directory, keychain: h.keychain, writer: h.writer, defaults: UserDefaults.standard)
        XCTAssertNoThrow(try store.open())
        store.flushGeneration()
        XCTAssertEqual(try h.keychain.readStoreGeneration(), store.indexGeneration)
        let sessions: SessionStore = SessionStore(store: store, clock: h.clock)
        let doc: SessionDocument = try sessions.load(peer: "bob")
        XCTAssertNil(sessions.takePendingRecovery(peer: "bob"))
        XCTAssertEqual(doc.peer.sendingSession()?.sid, expectedSid)
        XCTAssertTrue(doc.peer.knownSids.isEmpty)
    }
}
