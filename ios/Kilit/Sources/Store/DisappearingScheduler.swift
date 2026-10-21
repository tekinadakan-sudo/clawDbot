import Foundation

// MARK: - Deadlines (§5.8)

enum Deadlines {
    /// Unrevealed messages expire at `receivedAt + max(ttl, 24 h) + 7 d`.
    static let unrevealedFloor: UInt64 = 24 * 3600
    static let unrevealedGrace: UInt64 = 7 * 86400

    /// Receiver, once revealed: `firstRevealedAt + ttl`; nil when `ttl = 0` (never expires).
    static func receiver(firstRevealedAt: UInt64, ttl: UInt32) -> UInt64? {
        guard ttl > 0 else { return nil }
        return firstRevealedAt + UInt64(ttl)
    }

    /// Receiver, unrevealed: `receivedAt + max(ttl, 24 h) + 7 d`; nil when `ttl = 0`.
    static func unrevealed(receivedAt: UInt64, ttl: UInt32) -> UInt64? {
        guard ttl > 0 else { return nil }
        return receivedAt + max(UInt64(ttl), unrevealedFloor) + unrevealedGrace
    }

    /// Sender: `sentAt + ttl` regardless of reveal; nil when `ttl = 0`.
    static func sender(sentAt: UInt64, ttl: UInt32) -> UInt64? {
        guard ttl > 0 else { return nil }
        return sentAt + UInt64(ttl)
    }

    /// The deadline that applies to a message in its current state (content messages only).
    static func expiresAt(for message: Message) -> UInt64? {
        guard message.isContent, message.ttl > 0 else { return nil }
        switch message.author {
        case .me:
            guard let sentAt = message.sentAt else { return nil }
            return sender(sentAt: sentAt, ttl: message.ttl)
        case .peer:
            if let revealed = message.firstRevealedAt {
                return receiver(firstRevealedAt: revealed, ttl: message.ttl)
            }
            guard let receivedAt = message.receivedAt else { return nil }
            return unrevealed(receivedAt: receivedAt, ttl: message.ttl)
        }
    }
}

extension Message {
    /// First reveal: records the time, moves to `.revealed` and fixes the receiver deadline.
    mutating func markRevealed(at now: UInt64) {
        guard author == .peer, firstRevealedAt == nil else { return }
        firstRevealedAt = now
        state = .revealed
        expiresAt = Deadlines.receiver(firstRevealedAt: now, ttl: ttl)
    }

    /// Sent: records the time, moves to `.sent` and fixes the sender deadline.
    mutating func markSent(at now: UInt64) {
        sentAt = now
        state = .sent
        expiresAt = Deadlines.sender(sentAt: now, ttl: ttl)
    }

    /// Received: records the time and the unrevealed deadline.
    mutating func markReceived(at now: UInt64) {
        receivedAt = now
        if state == .outbox { state = .received }
        expiresAt = Deadlines.unrevealed(receivedAt: now, ttl: ttl)
    }
}

// MARK: - Scheduler

/// One sleeping task for the earliest deadline while foregrounded; the owner purges on launch, on
/// `scenePhase == .active` and whenever the task fires (message + blob + key are deleted by the owner).
@MainActor
final class DisappearingScheduler {
    private let clock: KilitClock
    private let onFire: () -> Void
    private var task: Task<Void, Never>?
    private(set) var scheduledDeadline: UInt64?

    init(clock: KilitClock, onFire: @escaping () -> Void) {
        self.clock = clock
        self.onFire = onFire
        self.task = nil
        self.scheduledDeadline = nil
    }

    /// Messages whose deadline has passed, earliest deadline first (purge order), ties by id.
    nonisolated static func expired(_ messages: [Message], now: UInt64) -> [Message] {
        messages.filter { m in
            guard let e = m.expiresAt else { return false }
            return e <= now
        }.sorted { a, b in
            let ea: UInt64 = a.expiresAt ?? 0
            let eb: UInt64 = b.expiresAt ?? 0
            if ea != eb { return ea < eb }
            return a.id < b.id
        }
    }

    nonisolated static func earliestDeadline(_ messages: [Message]) -> UInt64? {
        messages.compactMap { $0.expiresAt }.min()
    }

    /// Re-arms the single timer for `deadline` (nil cancels).
    func schedule(deadline: UInt64?) {
        task?.cancel()
        task = nil
        scheduledDeadline = deadline
        guard let d = deadline else { return }
        let delay: UInt64 = d > clock.now ? d - clock.now : 0
        task = Task { [weak self] in
            if delay > 0 {
                try? await Task.sleep(for: .seconds(Double(delay)))
            }
            guard !Task.isCancelled, let self = self else { return }
            self.task = nil
            self.scheduledDeadline = nil
            self.onFire()
        }
    }

    func cancel() {
        task?.cancel()
        task = nil
        scheduledDeadline = nil
    }
}
