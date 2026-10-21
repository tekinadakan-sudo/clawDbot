import XCTest
@testable import Kilit

// MARK: - Stubs (no network)

/// Scripted socket: yields `frames` one per `receive()`, then either fails (connection lost) or hangs until
/// cancelled (the watchdog / `stop()` path).
final class StubWebSocketTask: WebSocketTask {
    private var frames: [String]
    private let hangAfterFrames: Bool
    private var waiter: CheckedContinuation<URLSessionWebSocketTask.Message, Error>?
    private let lock: NSLock = NSLock()
    private(set) var sent: [String] = []
    private(set) var cancelled: Bool = false
    private(set) var resumed: Bool = false

    init(frames: [String], hangAfterFrames: Bool) {
        self.frames = frames
        self.hangAfterFrames = hangAfterFrames
    }

    func resume() {
        lock.lock()
        resumed = true
        lock.unlock()
    }

    func cancel(with closeCode: URLSessionWebSocketTask.CloseCode, reason: Data?) {
        lock.lock()
        cancelled = true
        let w: CheckedContinuation<URLSessionWebSocketTask.Message, Error>? = waiter
        waiter = nil
        lock.unlock()
        w?.resume(throwing: URLError(.cancelled))
    }

    func send(_ message: URLSessionWebSocketTask.Message) async throws {
        lock.lock()
        defer { lock.unlock() }
        if cancelled { throw URLError(.cancelled) }
        if case .string(let s) = message { sent.append(s) }
    }

    func receive() async throws -> URLSessionWebSocketTask.Message {
        lock.lock()
        if cancelled {
            lock.unlock()
            throw URLError(.cancelled)
        }
        if !frames.isEmpty {
            let f: String = frames.removeFirst()
            lock.unlock()
            return .string(f)
        }
        if !hangAfterFrames {
            lock.unlock()
            throw URLError(.networkConnectionLost)
        }
        lock.unlock()
        return try await withCheckedThrowingContinuation { continuation in
            lock.lock()
            if cancelled {
                lock.unlock()
                continuation.resume(throwing: URLError(.cancelled))
                return
            }
            waiter = continuation
            lock.unlock()
        }
    }
}

final class StubWebSocketFactory: WebSocketTaskFactory {
    private let make: () -> StubWebSocketTask
    private(set) var tasks: [StubWebSocketTask] = []
    private(set) var requests: [URLRequest] = []

    init(make: @escaping () -> StubWebSocketTask) {
        self.make = make
    }

    func makeTask(_ request: URLRequest) -> WebSocketTask {
        let t: StubWebSocketTask = make()
        tasks.append(t)
        requests.append(request)
        return t
    }
}

/// Decides per requested duration: return at once (a timer "fires"), hang until cancelled, or fail.
final class StubSleeper: Sleeper {
    enum Behaviour {
        case immediate
        case hang
        case fail
    }

    private let rule: (Double) -> Behaviour
    private(set) var requested: [Double] = []
    private let lock: NSLock = NSLock()

    init(rule: @escaping (Double) -> Behaviour) {
        self.rule = rule
    }

    func sleep(seconds: Double) async throws {
        lock.lock()
        requested.append(seconds)
        lock.unlock()
        switch rule(seconds) {
        case .immediate:
            return
        case .fail:
            throw CancellationError()
        case .hang:
            try await Task.sleep(for: .seconds(3600))
        }
    }
}

// MARK: - WebSocketClientTests (§5.4, §5.12)

final class WebSocketClientTests: XCTestCase {
    private func makeClient(factory: StubWebSocketFactory, sleeper: StubSleeper) throws -> WebSocketClient {
        let url: URL = try XCTUnwrap(URL(string: "wss://kilit.test/v1/ws"))
        var request: URLRequest = URLRequest(url: url)
        request.setValue("Bearer t", forHTTPHeaderField: "Authorization")
        return WebSocketClient(factory: factory, sleeper: sleeper, config: WebSocketConfig(),
                               request: { request }, cursor: { 42 })
    }

    /// A task that fails right after `hello`: the attempt fails, the 1 s backoff starts and the 20 s poll
    /// fallback runs (its first poll happens immediately).
    func testFailingTaskStartsBackoffAndPollFallback() async throws {
        let factory: StubWebSocketFactory = StubWebSocketFactory { StubWebSocketTask(frames: [], hangAfterFrames: false) }
        let sleeper: StubSleeper = StubSleeper { _ in .hang }
        let client: WebSocketClient = try makeClient(factory: factory, sleeper: sleeper)
        let polled: XCTestExpectation = expectation(description: "poll fallback")
        polled.assertForOverFulfill = false
        await client.setHandlers(onMessage: nil, onPrekeysLow: nil, onPoll: { polled.fulfill() }, onState: nil)
        await client.start()
        await fulfillment(of: [polled], timeout: 2)
        let failed: Int = await client.failedAttempts
        let history: [Double] = await client.backoffHistory
        let polling: Bool = await client.pollStarted
        let state: WSState = await client.state
        XCTAssertEqual(failed, 1)
        XCTAssertEqual(history, [1])
        XCTAssertTrue(polling)
        XCTAssertEqual(state, .down(attempt: 1))
        XCTAssertEqual(factory.tasks.count, 1)
        XCTAssertEqual(factory.tasks.first?.sent, ["{\"after\":42,\"t\":\"hello\"}"])
        XCTAssertEqual(factory.requests.first?.value(forHTTPHeaderField: "Authorization"), "Bearer t")
        XCTAssertTrue(sleeper.requested.contains(1))
        XCTAssertTrue(sleeper.requested.contains(20))
        await client.stop()
        let stopped: WSState = await client.state
        XCTAssertEqual(stopped, .stopped)
    }

    func testBackoffDoublesToThirtySeconds() {
        XCTAssertEqual(Backoff.webSocket(attempt: 1), 1)
        XCTAssertEqual(Backoff.webSocket(attempt: 2), 2)
        XCTAssertEqual(Backoff.webSocket(attempt: 5), 16)
        XCTAssertEqual(Backoff.webSocket(attempt: 6), 30)
        XCTAssertEqual(Backoff.webSocket(attempt: 40), 30)
        XCTAssertEqual(Backoff.outbox(attempts: 1), 5)
        XCTAssertEqual(Backoff.outbox(attempts: 2), 10)
        XCTAssertEqual(Backoff.outbox(attempts: 7), 320)
        XCTAssertEqual(Backoff.outbox(attempts: 8), 600)
        XCTAssertEqual(Backoff.outbox(attempts: 20), 600)
    }

    /// No frame after `hello`: the stubbed 15 s watchdog fires, cancels the task and counts as a failed attempt.
    func testConnectWatchdogFiresAndCountsAsFailure() async throws {
        let factory: StubWebSocketFactory = StubWebSocketFactory { StubWebSocketTask(frames: [], hangAfterFrames: true) }
        let sleeper: StubSleeper = StubSleeper { seconds in seconds == 15 ? .immediate : .hang }
        let client: WebSocketClient = try makeClient(factory: factory, sleeper: sleeper)
        let down: XCTestExpectation = expectation(description: "down after watchdog")
        down.assertForOverFulfill = false
        await client.setHandlers(onMessage: nil, onPrekeysLow: nil, onPoll: nil, onState: { state in
            if state == .down(attempt: 1) { down.fulfill() }
        })
        await client.start()
        await fulfillment(of: [down], timeout: 2)
        let firings: Int = await client.watchdogFirings
        let failed: Int = await client.failedAttempts
        XCTAssertEqual(firings, 1)
        XCTAssertEqual(failed, 1)
        XCTAssertEqual(factory.tasks.first?.cancelled, true)
        XCTAssertTrue(sleeper.requested.contains(15))
        await client.stop()
    }

    /// The first server frame after `hello` cancels the watchdog: the attempt goes live and later drops as a
    /// successful attempt (failed counter reset), with no watchdog firing.
    func testFirstFrameCancelsWatchdog() async throws {
        let factory: StubWebSocketFactory = StubWebSocketFactory { StubWebSocketTask(frames: ["{\"t\":\"pong\"}"], hangAfterFrames: false) }
        let sleeper: StubSleeper = StubSleeper { _ in .hang }
        let client: WebSocketClient = try makeClient(factory: factory, sleeper: sleeper)
        var states: [WSState] = []
        await client.setHandlers(onMessage: nil, onPrekeysLow: nil, onPoll: nil, onState: { states.append($0) })
        let live: Bool = await client.attempt()
        XCTAssertTrue(live)
        let firings: Int = await client.watchdogFirings
        XCTAssertEqual(firings, 0)
        XCTAssertTrue(states.contains(.live))
        XCTAssertEqual(factory.tasks.first?.sent.count, 1)
    }

    /// `msg` frames reach the handler as rows; `prekeys_low` reaches its handler; `ack` frames are ≤ 500 ids.
    func testFramesDispatchToHandlers() async throws {
        let msg: String = "{\"t\":\"msg\",\"id\":4411,\"msg_id\":\"9f1c\",\"from\":\"alice\",\"envelope\":\"AQID\",\"ts\":1760000000}"
        let low: String = "{\"t\":\"prekeys_low\",\"opk_count\":12,\"consumed_ids\":[3,4]}"
        let factory: StubWebSocketFactory = StubWebSocketFactory { StubWebSocketTask(frames: [msg, low], hangAfterFrames: false) }
        let sleeper: StubSleeper = StubSleeper { _ in .hang }
        let client: WebSocketClient = try makeClient(factory: factory, sleeper: sleeper)
        var rows: [MessageRow] = []
        var lowCounts: [Int] = []
        var consumed: [[UInt32]] = []
        await client.setHandlers(onMessage: { rows.append($0) },
                                 onPrekeysLow: { count, ids in
                                     lowCounts.append(count)
                                     consumed.append(ids)
                                 },
                                 onPoll: nil, onState: nil)
        _ = await client.attempt()
        XCTAssertEqual(rows.count, 1)
        XCTAssertEqual(rows.first?.id, 4411)
        XCTAssertEqual(rows.first?.msgId, "9f1c")
        XCTAssertEqual(rows.first?.from, "alice")
        XCTAssertEqual(rows.first?.envelope, Data([1, 2, 3]))
        XCTAssertEqual(lowCounts, [12])
        XCTAssertEqual(consumed, [[3, 4]])
        XCTAssertEqual(WSServerFrame.decode("{\"t\":\"error\",\"code\":\"bad_frame\"}")?.code, "bad_frame")
        XCTAssertNil(WSServerFrame.decode("not json"))
        let ack: String = try WSClientFrame.ack(msgIds: ["a", "b"]).encoded()
        XCTAssertEqual(ack, "{\"msg_ids\":[\"a\",\"b\"],\"t\":\"ack\"}")
        XCTAssertEqual(try WSClientFrame.ping.encoded(), "{\"t\":\"ping\"}")
    }

    /// `msg_id` dedupe across the WS and poll paths, at the deduper and through `MessageSync`.
    func testMsgIdDedupeAcrossPaths() async throws {
        var d: InboundDeduper = InboundDeduper()
        XCTAssertTrue(d.admit("a"))
        XCTAssertFalse(d.admit("a"))
        XCTAssertTrue(d.admit("b"))
        d.forget("a")
        XCTAssertTrue(d.admit("a"))
        XCTAssertEqual(d.count, 2)

        let h: SyncHarness = try SyncHarness()
        let bob: TestPeer = TestPeer(username: "bob", now: SyncHarness.now0)
        h.peers["bob"] = bob
        let start: (session: Session, envelope: Data, inner: InnerMessage) = try TestPeer.initiation(from: bob, to: h.me, text: "bir", now: SyncHarness.now0)
        let row: MessageRow = h.row(from: "bob", envelope: start.envelope)
        await h.sync.handleRow(row)                                   // live push
        await h.sync.handleRow(row)                                   // the same row from the poll drain
        let conv: ConversationDocument = try XCTUnwrap(try h.conversation("bob"))
        XCTAssertEqual(conv.messages.count, 1)
        XCTAssertEqual(h.store.index.ledger.pendingAcks, [row.msgId])
        XCTAssertEqual(h.store.index.ledger.cursor, row.id)
        XCTAssertEqual(h.requests("GET", pathSuffix: "/v1/users/bob").count, 1)
    }

    /// Every ack reason lands in `pendingAcks[]` in the cursor write and is flushed only through REST.
    func testPendingAcksPersistedWithCursorAndFlushedViaREST() async throws {
        let h: SyncHarness = try SyncHarness()
        let bad: MessageRow = h.row(from: "bob", envelope: Data("not an envelope".utf8))
        await h.sync.handleRow(bad)
        XCTAssertEqual(h.store.index.ledger.cursor, bad.id)
        XCTAssertEqual(h.store.index.ledger.pendingAcks, [bad.msgId])
        let conv: ConversationDocument = try XCTUnwrap(try h.conversation("bob"))
        XCTAssertEqual(conv.messages.first?.state, .undecryptable("bad_envelope"))
        XCTAssertEqual(h.store.index.undecryptableLog.first?.reason, "bad_envelope")
        // A persisted index after relaunch still carries the pending ack.
        let relaunched: LocalStore = LocalStore(directory: h.directory, keychain: h.keychain, writer: h.writer, defaults: UserDefaults.standard)
        try relaunched.open()
        XCTAssertEqual(relaunched.index.ledger.pendingAcks, [bad.msgId])
        XCTAssertEqual(relaunched.index.ledger.cursor, bad.id)
        // REST flush: the id leaves the list only after `200 {deleted}`.
        h.override = { request in
            guard request.httpMethod == "POST", request.url?.path == "/v1/messages/ack" else { return nil }
            return try StubTransport.json(500, request, ["error": "internal"])
        }
        await h.sync.flushAcks()
        XCTAssertEqual(h.store.index.ledger.pendingAcks, [bad.msgId])
        h.override = nil
        await h.sync.flushAcks()
        XCTAssertTrue(h.store.index.ledger.pendingAcks.isEmpty)
        XCTAssertEqual(h.store.index.ledger.cursor, bad.id)
        let acks: [URLRequest] = h.requests("POST", pathSuffix: "/v1/messages/ack")
        XCTAssertEqual(acks.count, 2)
        let body: AckRequest = try KilitJSON.decoder().decode(AckRequest.self, from: try XCTUnwrap(acks.last?.httpBody))
        XCTAssertEqual(body.msgIds, [bad.msgId])
    }

    /// The two URLSession configurations of §5.4.
    func testSessionConfigurations() {
        let rest: URLSessionConfiguration = APIClient.restSession().configuration
        XCTAssertNil(rest.urlCache)
        XCTAssertEqual(rest.requestCachePolicy, .reloadIgnoringLocalCacheData)
        XCTAssertTrue(rest.waitsForConnectivity)
        XCTAssertEqual(rest.timeoutIntervalForRequest, 60)
        XCTAssertEqual(rest.timeoutIntervalForResource, 600)
        let ws: URLSessionConfiguration = APIClient.webSocketSession().configuration
        XCTAssertNil(ws.urlCache)
        XCTAssertEqual(ws.requestCachePolicy, .reloadIgnoringLocalCacheData)
        XCTAssertFalse(ws.waitsForConnectivity)
        XCTAssertEqual(ws.timeoutIntervalForRequest, 60)
        XCTAssertEqual(ws.timeoutIntervalForResource, 7 * 24 * 3600)
        XCTAssertEqual(WebSocketConfig().connectTimeout, 15)
        XCTAssertEqual(WebSocketConfig().pollInterval, 20)
    }
}
