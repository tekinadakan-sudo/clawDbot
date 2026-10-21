import Foundation
import OSLog

// MARK: - Events the UI observes (AsyncStream; the simplest facade)

enum SyncEvent: Equatable {
    /// `conv/<peer>.json` or the conversation's metadata changed; the UI reloads that conversation.
    case conversationChanged(peer: String)
    case contactsChanged
    /// A `key_change` envelope was parked or a fetch showed new keys: show "Güvenlik numarası değişti".
    case keyChangeDetected(peer: String)
    case connection(WSState)
    case prekeys(opkCount: Int)
    /// Re-login failed persistently: the UI shows the explanation of §4.5.
    case authInvalid
}

enum SyncError: Error, Equatable {
    case notOpen
    /// Sending is disabled until "Yeni anahtarı kabul et".
    case keyChangePending(peer: String)
    case blocked(peer: String)
    case usernameTaken
    case notRegistered
    case unknownContact(String)
}

// MARK: - MessageSync (§3.2b, §3.4, §3.5, §5.4)

/// The single owner of `LocalStore` at run time. Coordinates the inbound pipeline, outbound encrypt → persist →
/// POST, the outbox, control coalescing, prekey maintenance, attachments and durable acks. Methods are split over
/// `MessageSync+Inbound.swift`, `MessageSync+Outbound.swift` and `MessageSync+Account.swift`.
actor MessageSync {
    static let logger: Logger = Logger(subsystem: "com.kilit", category: "sync")
    static let ackFlushInterval: Double = 60
    static let maintenanceInterval: Double = 3600
    static let controlFlushDelay: Double = 2
    /// §3.2 step 1: 10 s, 1 m, 10 m, 1 h, then hourly.
    static let lookupRetryDelays: [Double] = [10, 60, 600, 3600]

    let store: LocalStore
    let sessions: SessionStore
    let blobs: BlobStore
    let api: APIClient
    let keychain: KeychainStore
    let clock: KilitClock
    let keySource: KeySource
    let sleeper: Sleeper
    let local: IdentityKeys
    let username: String
    let webSocket: WebSocketClient?

    nonisolated let events: AsyncStream<SyncEvent>
    let eventContinuation: AsyncStream<SyncEvent>.Continuation

    var deduper: InboundDeduper = InboundDeduper()
    var coalescer: ControlCoalescer = ControlCoalescer()
    var pumping: Bool = false
    var reauthenticatedThisPump: Bool = false
    var running: Bool = false
    var connection: WSState = .stopped
    var outboxWake: Task<Void, Never>?
    var controlFlush: Task<Void, Never>?
    var ackLoop: Task<Void, Never>?
    var maintenanceLoop: Task<Void, Never>?
    var lookupRetries: [String: Int] = [:]
    var lookupTasks: [String: Task<Void, Never>] = [:]
    var protectedDataObservers: [NSObjectProtocol] = []

    init(store: LocalStore, blobs: BlobStore, api: APIClient, keychain: KeychainStore, clock: KilitClock,
         keySource: KeySource, local: IdentityKeys, username: String, webSocket: WebSocketClient?,
         sleeper: Sleeper = TaskSleeper()) {
        self.store = store
        self.sessions = SessionStore(store: store, clock: clock)
        self.blobs = blobs
        self.api = api
        self.keychain = keychain
        self.clock = clock
        self.keySource = keySource
        self.sleeper = sleeper
        self.local = local
        self.username = username
        self.webSocket = webSocket
        let (stream, continuation) = AsyncStream<SyncEvent>.makeStream()
        self.events = stream
        self.eventContinuation = continuation
    }

    func emit(_ event: SyncEvent) {
        eventContinuation.yield(event)
    }

    // MARK: lifecycle

    /// Opens the store (`LocalStoreError.rollback(index.json)` → the UI shows the wipe prompt).
    func openStore() throws {
        try store.open()
    }

    /// Launch: acks, parked expiry, purge, WS, loops, outbox, prekeys. Returns the next disappearing deadline.
    @discardableResult
    func start() async -> UInt64? {
        guard store.isOpen else { return nil }
        guard !running else { return await purgeExpired() }
        running = true
        observeProtectedData()
        await wireWebSocket()
        await flushAcks()
        await expireAllParked()
        let next: UInt64? = await purgeExpired()
        await recoverLostSessions()
        startLoops()
        await webSocket?.start()
        await pumpOutbox()
        await retryDownloads()
        await maintainPrekeys()
        return next
    }

    /// `scenePhase == .active`: acks, parked expiry, purge, outbox, prekeys. Returns the next deadline.
    @discardableResult
    func foreground() async -> UInt64? {
        guard store.isOpen else { return nil }
        await flushAcks()
        await expireAllParked()
        let next: UInt64? = await purgeExpired()
        await pumpOutbox()
        await retryDownloads()
        await maintainPrekeys()
        return next
    }

    /// `sceneDidEnterBackground`: flush the coalesced controls and the Keychain generation (§3.7 step 3).
    func background() async {
        await flushControls(force: true)
        store.flushGeneration()
    }

    func stop() async {
        running = false
        ackLoop?.cancel()
        ackLoop = nil
        maintenanceLoop?.cancel()
        maintenanceLoop = nil
        outboxWake?.cancel()
        outboxWake = nil
        controlFlush?.cancel()
        controlFlush = nil
        for (_, t) in lookupTasks { t.cancel() }
        lookupTasks = [:]
        await webSocket?.stop()
        store.flushGeneration()
    }

    func startLoops() {
        if ackLoop == nil {
            ackLoop = Task { [weak self] in
                guard let self = self else { return }
                await self.runAckLoop()
            }
        }
        if maintenanceLoop == nil {
            maintenanceLoop = Task { [weak self] in
                guard let self = self else { return }
                await self.runMaintenanceLoop()
            }
        }
    }

    func runAckLoop() async {
        while !Task.isCancelled {
            do {
                try await sleeper.sleep(seconds: MessageSync.ackFlushInterval)
            } catch {
                return
            }
            await flushAcks()
        }
    }

    func runMaintenanceLoop() async {
        while !Task.isCancelled {
            do {
                try await sleeper.sleep(seconds: MessageSync.maintenanceInterval)
            } catch {
                return
            }
            await expireAllParked()
            await maintainPrekeys()
        }
    }

    // MARK: protected data (§5.3)

    func observeProtectedData() {
        guard protectedDataObservers.isEmpty else { return }
        protectedDataObservers = LocalStore.observeProtectedData { [weak self] available in
            guard let self = self else { return }
            Task { await self.protectedData(available: available) }
        }
    }

    func protectedData(available: Bool) async {
        if available {
            if !store.isOpen {
                do {
                    try store.open()
                } catch {
                    MessageSync.logger.error("store reopen failed: \(String(describing: error), privacy: .public)")
                    return
                }
            }
            if running {
                await webSocket?.start()
                await pumpOutbox()
            }
        } else {
            await webSocket?.stop()
            store.close()
        }
    }

    // MARK: WebSocket + poll (§5.4)

    func wireWebSocket() async {
        guard let ws = webSocket else { return }
        await ws.setHandlers(
            onMessage: { [weak self] row in
                await self?.handleRow(row)
            },
            onPrekeysLow: { [weak self] count, ids in
                await self?.maintainPrekeys(serverCount: count, consumedIds: ids)
            },
            onPoll: { [weak self] in
                await self?.pollOnce()
            },
            onState: { [weak self] state in
                guard let self = self else { return }
                Task { await self.setConnection(state) }
            })
    }

    func setConnection(_ state: WSState) {
        connection = state
        emit(.connection(state))
    }

    func connectionState() -> WSState { connection }

    /// One fetched row (WS live push or poll drain), deduplicated by `msg_id` across both paths.
    func handleRow(_ row: MessageRow) async {
        guard store.isOpen else { return }
        guard deduper.admit(row.msgId) else { return }
        let persisted: Bool = await processEnvelope(from: row.from, msgId: row.msgId, envelope: row.envelope,
                                                    serverId: row.id, reprocessing: false)
        if !persisted {
            deduper.forget(row.msgId)
            return
        }
        await webSocket?.sendAck(msgIds: store.index.ledger.pendingAcks)
    }

    /// `GET /v1/messages?after=<cursor>` until `has_more` is false.
    func pollOnce() async {
        guard store.isOpen else { return }
        var more: Bool = true
        while more {
            let after: Int64 = store.index.ledger.cursor
            let page: MessagesResponse
            do {
                page = try await api.poll(after: after)
            } catch let e as APIError {
                if e.status == 401 { await reauthenticateIfNeeded() }
                return
            } catch {
                return
            }
            for row in page.messages {
                await handleRow(row)
            }
            more = page.hasMore && !page.messages.isEmpty && store.index.ledger.cursor > after
        }
    }

    // MARK: durable acks (§3.2b step 5)

    /// `POST /v1/messages/ack` from `pendingAcks[]` in batches of ≤ 500; an id leaves the list only on `200`.
    func flushAcks() async {
        guard store.isOpen else { return }
        while true {
            let batch: [String] = Array(store.index.ledger.pendingAcks.prefix(500))
            guard !batch.isEmpty else { return }
            do {
                _ = try await api.ack(msgIds: batch)
            } catch let e as APIError {
                if e.status == 401 { await reauthenticateIfNeeded() }
                return
            } catch {
                return
            }
            do {
                try store.commitIndex { idx in idx.ledger.confirm(batch) }
            } catch {
                MessageSync.logger.error("ack confirm write failed: \(String(describing: error), privacy: .public)")
                return
            }
            if batch.count < 500 { return }
        }
    }

    // MARK: prekeys (§3.1)

    func maintainPrekeys(serverCount: Int? = nil, consumedIds: [UInt32] = []) async {
        guard store.isOpen else { return }
        let outcome: PrekeyMaintenance.Outcome = await PrekeyMaintenance.run(
            store: store, api: api, local: local, keySource: keySource, now: clock.now,
            serverCount: serverCount, consumedIds: consumedIds)
        if let c = outcome.opkCount { emit(.prekeys(opkCount: c)) }
    }

    // MARK: disappearing messages (§5.8)

    /// Deletes every expired message (with its blob and key); returns the earliest remaining deadline.
    func purgeExpired() async -> UInt64? {
        guard store.isOpen else { return nil }
        let now: UInt64 = clock.now
        var next: UInt64? = nil
        for conversation in store.index.conversations {
            let peer: String = conversation.peer
            var doc: ConversationDocument = loadConversation(peer)
            let expired: [Message] = DisappearingScheduler.expired(doc.messages, now: now)
            if !expired.isEmpty {
                for m in expired {
                    if let att = m.att { blobs.delete(id: att.blob) }
                }
                doc.messages.removeAll { m in expired.contains { $0.id == m.id && $0.author == m.author } }
                do {
                    try store.commit([try DocumentWrite(path: LocalStore.conversationPath(peer), value: doc)])
                    emit(.conversationChanged(peer: peer))
                } catch {
                    MessageSync.logger.error("purge write failed: \(String(describing: error), privacy: .public)")
                }
            }
            if let d = DisappearingScheduler.earliestDeadline(doc.messages) {
                next = min(next ?? d, d)
            }
        }
        return next
    }

    // MARK: reads for the UI

    func index() -> StoreIndex { store.index }
    func contacts() -> [ContactRecord] { store.index.contacts }
    func conversations() -> [Conversation] { store.index.conversations }
    func settings() -> Settings { store.index.settings }

    func updateSettings(_ settings: Settings) throws {
        try store.commitIndex { idx in idx.settings = settings }
    }

    /// `conv/<peer>.json`; a rollback or corrupt history document is replaced by an empty one (logged).
    func loadConversation(_ peer: String) -> ConversationDocument {
        do {
            if let doc = try store.load(ConversationDocument.self, at: LocalStore.conversationPath(peer)) { return doc }
            return ConversationDocument()
        } catch {
            MessageSync.logger.error("conversation document reset: \(String(describing: error), privacy: .public)")
            return ConversationDocument()
        }
    }

    func conversationDocument(peer: String) -> ConversationDocument {
        loadConversation(peer)
    }

    func messages(peer: String) -> [Message] {
        loadConversation(peer).messages.sorted { a, b in
            if a.orderingTime != b.orderingTime { return a.orderingTime < b.orderingTime }
            return a.id < b.id
        }
    }

    func markConversationRead(peer: String) throws {
        try store.commitIndex { idx in
            if let i = idx.conversations.firstIndex(where: { $0.peer == peer }) { idx.conversations[i].unreadCount = 0 }
        }
    }
}
