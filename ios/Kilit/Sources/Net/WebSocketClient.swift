import Foundation

// MARK: - Injection points (tests use stubs; no network)

protocol WebSocketTask: AnyObject {
    func resume()
    func cancel(with closeCode: URLSessionWebSocketTask.CloseCode, reason: Data?)
    func send(_ message: URLSessionWebSocketTask.Message) async throws
    func receive() async throws -> URLSessionWebSocketTask.Message
}

extension URLSessionWebSocketTask: WebSocketTask {}

protocol WebSocketTaskFactory: AnyObject {
    func makeTask(_ request: URLRequest) -> WebSocketTask
}

final class URLSessionWebSocketFactory: WebSocketTaskFactory {
    let session: URLSession

    init(session: URLSession) {
        self.session = session
    }

    func makeTask(_ request: URLRequest) -> WebSocketTask {
        session.webSocketTask(with: request)
    }
}

/// Every delay of the networking layer goes through this so tests can stub the clock.
protocol Sleeper: AnyObject {
    func sleep(seconds: Double) async throws
}

final class TaskSleeper: Sleeper {
    init() {}

    func sleep(seconds: Double) async throws {
        try await Task.sleep(for: .seconds(seconds))
    }
}

// MARK: - msg_id dedupe across the WS and poll paths (§5.4)

struct InboundDeduper: Equatable {
    static let capacity: Int = 10_000

    private var order: [String] = []
    private var seen: Set<String> = []

    init() {}

    /// True the first time an id is seen.
    mutating func admit(_ msgId: String) -> Bool {
        if seen.contains(msgId) { return false }
        seen.insert(msgId)
        order.append(msgId)
        if order.count > InboundDeduper.capacity {
            let victim: String = order.removeFirst()
            seen.remove(victim)
        }
        return true
    }

    var count: Int { order.count }
}

// MARK: - WebSocketClient (§4.4, §5.4)

enum WSState: Equatable {
    case stopped
    case connecting
    case live
    /// Reconnecting after `attempt` consecutive failures; the poll fallback runs meanwhile.
    case down(attempt: Int)
}

struct WebSocketConfig: Equatable {
    var connectTimeout: Double = 15
    var pollInterval: Double = 20

    init() {}
}

/// `hello` with the persisted cursor, live `msg` frames, fire-and-forget `ack`, 15 s connect watchdog,
/// exponential backoff 1–30 s and a 20 s poll fallback while down.
actor WebSocketClient {
    private let factory: WebSocketTaskFactory
    private let sleeper: Sleeper
    private let config: WebSocketConfig
    private let requestProvider: () async -> URLRequest?
    private let cursorProvider: () async -> Int64

    private(set) var state: WSState = .stopped
    private(set) var failedAttempts: Int = 0
    private(set) var watchdogFirings: Int = 0
    private(set) var backoffHistory: [Double] = []
    private(set) var pollStarted: Bool = false

    private var loop: Task<Void, Never>?
    private var pollLoop: Task<Void, Never>?
    private var current: WebSocketTask?

    private var onMessage: ((MessageRow) async -> Void)?
    private var onPrekeysLow: ((Int, [UInt32]) async -> Void)?
    private var onPoll: (() async -> Void)?
    private var onState: ((WSState) -> Void)?

    init(factory: WebSocketTaskFactory, sleeper: Sleeper = TaskSleeper(), config: WebSocketConfig = WebSocketConfig(),
         request: @escaping () async -> URLRequest?, cursor: @escaping () async -> Int64) {
        self.factory = factory
        self.sleeper = sleeper
        self.config = config
        self.requestProvider = request
        self.cursorProvider = cursor
    }

    func setHandlers(onMessage: ((MessageRow) async -> Void)?, onPrekeysLow: ((Int, [UInt32]) async -> Void)?,
                     onPoll: (() async -> Void)?, onState: ((WSState) -> Void)?) {
        self.onMessage = onMessage
        self.onPrekeysLow = onPrekeysLow
        self.onPoll = onPoll
        self.onState = onState
    }

    private func setState(_ s: WSState) {
        state = s
        onState?(s)
    }

    func start() {
        guard loop == nil else { return }
        loop = Task { [weak self] in
            await self?.runLoop()
        }
    }

    func stop() {
        loop?.cancel()
        loop = nil
        stopPolling()
        current?.cancel(with: .normalClosure, reason: nil)
        current = nil
        setState(.stopped)
    }

    /// Reconnect loop: attempt → on failure (or drop) back off 1–30 s with the poll fallback running.
    /// Exposed so tests can drive it directly with a stubbed sleeper that ends the loop by throwing.
    func runLoop() async {
        while !Task.isCancelled {
            setState(.connecting)
            let wentLive: Bool = await attempt()
            if Task.isCancelled { break }
            failedAttempts = wentLive ? 0 : failedAttempts + 1
            let delay: Double = Backoff.webSocket(attempt: max(1, failedAttempts))
            backoffHistory.append(delay)
            setState(.down(attempt: failedAttempts))
            startPollingIfNeeded()
            do {
                try await sleeper.sleep(seconds: delay)
            } catch {
                break
            }
        }
        stopPolling()
        setState(.stopped)
    }

    /// One connection attempt. Returns true when at least one server frame arrived after `hello`.
    func attempt() async -> Bool {
        guard let request = await requestProvider() else { return false }
        let task: WebSocketTask = factory.makeTask(request)
        current = task
        task.resume()
        let timeout: Double = config.connectTimeout
        let watchdog: Task<Void, Never> = Task { [weak self] in
            guard let self = self else { return }
            do {
                try await self.sleeperSleep(timeout)
            } catch {
                return
            }
            await self.watchdogFired(task)
        }
        var sawFrame: Bool = false
        do {
            let after: Int64 = await cursorProvider()
            try await task.send(.string(try WSClientFrame.hello(after: after).encoded()))
            while !Task.isCancelled {
                let message: URLSessionWebSocketTask.Message = try await task.receive()
                if !sawFrame {
                    sawFrame = true
                    watchdog.cancel()
                    stopPolling()
                    setState(.live)
                }
                await handle(message)
            }
        } catch {
            // Any receive/send failure ends the attempt; the caller backs off.
        }
        watchdog.cancel()
        if current === task { current = nil }
        return sawFrame
    }

    private func sleeperSleep(_ seconds: Double) async throws {
        try await sleeper.sleep(seconds: seconds)
    }

    private func watchdogFired(_ task: WebSocketTask) {
        guard current === task else { return }
        watchdogFirings += 1
        task.cancel(with: .abnormalClosure, reason: nil)
    }

    private func handle(_ message: URLSessionWebSocketTask.Message) async {
        let text: String
        switch message {
        case .string(let s):
            text = s
        case .data(let d):
            text = String(decoding: d, as: UTF8.self)
        @unknown default:
            return
        }
        guard let frame = WSServerFrame.decode(text) else { return }
        switch frame.t {
        case "msg":
            if let row = frame.messageRow, let h = onMessage {
                await h(row)
            }
        case "prekeys_low":
            if let h = onPrekeysLow {
                await h(frame.opkCount ?? 0, frame.consumedIds ?? [])
            }
        default:
            break
        }
    }

    /// Fire-and-forget `ack` frame (the REST flush of `pendingAcks` is the durable path).
    func sendAck(msgIds: [String]) async {
        guard state == .live, let task = current, !msgIds.isEmpty else { return }
        let batch: [String] = Array(msgIds.prefix(500))
        guard let text = try? WSClientFrame.ack(msgIds: batch).encoded() else { return }
        try? await task.send(.string(text))
    }

    func sendPing() async {
        guard state == .live, let task = current, let text = try? WSClientFrame.ping.encoded() else { return }
        try? await task.send(.string(text))
    }

    // MARK: poll fallback

    private func startPollingIfNeeded() {
        guard pollLoop == nil else { return }
        pollStarted = true
        let interval: Double = config.pollInterval
        pollLoop = Task { [weak self] in
            while !Task.isCancelled {
                guard let self = self else { return }
                await self.pollOnce()
                do {
                    try await self.sleeperSleep(interval)
                } catch {
                    return
                }
            }
        }
    }

    private func pollOnce() async {
        if let h = onPoll {
            await h()
        }
    }

    private func stopPolling() {
        pollLoop?.cancel()
        pollLoop = nil
    }
}
