import XCTest
@testable import Kilit

/// §5.8: receiver / sender / unrevealed deadlines, `ttl = 0` never expires, purge order, the single timer.
final class DisappearingSchedulerTests: XCTestCase {
    private let t0: UInt64 = 1_760_000_000
    private let day: UInt64 = 86_400

    private func peerMessage(id: String, ttl: UInt32, receivedAt: UInt64) -> Message {
        var m: Message = Message(id: id, conversationID: "bob", author: .peer, kind: .text, ts: receivedAt, ttl: ttl,
                                 state: .received, text: "x")
        m.markReceived(at: receivedAt)
        return m
    }

    func testReceiverDeadlineOnceRevealed() {
        XCTAssertEqual(Deadlines.receiver(firstRevealedAt: t0, ttl: 30), t0 + 30)
        XCTAssertEqual(Deadlines.receiver(firstRevealedAt: t0, ttl: 7 * 86_400), t0 + 7 * day)
        XCTAssertNil(Deadlines.receiver(firstRevealedAt: t0, ttl: 0))
    }

    func testUnrevealedDeadlineUsesMaxTtl24hPlus7d() {
        XCTAssertEqual(Deadlines.unrevealed(receivedAt: t0, ttl: 30), t0 + day + 7 * day)
        XCTAssertEqual(Deadlines.unrevealed(receivedAt: t0, ttl: 3600), t0 + day + 7 * day)
        XCTAssertEqual(Deadlines.unrevealed(receivedAt: t0, ttl: UInt32(2 * day)), t0 + 2 * day + 7 * day)
        XCTAssertNil(Deadlines.unrevealed(receivedAt: t0, ttl: 0))
    }

    func testSenderDeadlineRegardlessOfReveal() {
        XCTAssertEqual(Deadlines.sender(sentAt: t0, ttl: 300), t0 + 300)
        XCTAssertNil(Deadlines.sender(sentAt: t0, ttl: 0))
    }

    func testMessageTransitionsFixTheDeadlines() {
        var peer: Message = peerMessage(id: "p", ttl: 30, receivedAt: t0)
        XCTAssertEqual(peer.expiresAt, t0 + day + 7 * day)
        XCTAssertEqual(Deadlines.expiresAt(for: peer), peer.expiresAt)
        peer.markRevealed(at: t0 + 10)
        XCTAssertEqual(peer.state, .revealed)
        XCTAssertEqual(peer.firstRevealedAt, t0 + 10)
        XCTAssertEqual(peer.expiresAt, t0 + 40)
        // A second reveal does not move the deadline.
        peer.markRevealed(at: t0 + 20)
        XCTAssertEqual(peer.expiresAt, t0 + 40)

        var mine: Message = Message(id: "m", conversationID: "bob", author: .me, kind: .text, ts: t0, ttl: 60, state: .outbox, text: "y")
        XCTAssertNil(mine.expiresAt)
        mine.markSent(at: t0 + 5)
        XCTAssertEqual(mine.state, .sent)
        XCTAssertEqual(mine.expiresAt, t0 + 65)
        XCTAssertEqual(Deadlines.expiresAt(for: mine), t0 + 65)
        // Own messages never get a receiver deadline.
        mine.markRevealed(at: t0 + 6)
        XCTAssertEqual(mine.expiresAt, t0 + 65)
    }

    func testTtlZeroNeverExpires() {
        var peer: Message = peerMessage(id: "p", ttl: 0, receivedAt: t0)
        XCTAssertNil(peer.expiresAt)
        peer.markRevealed(at: t0 + 1)
        XCTAssertNil(peer.expiresAt)
        var mine: Message = Message(id: "m", conversationID: "bob", author: .me, kind: .image, ts: t0, ttl: 0, state: .outbox)
        mine.markSent(at: t0)
        XCTAssertNil(mine.expiresAt)
        XCTAssertNil(Deadlines.expiresAt(for: mine))
        let system: Message = Message(id: "s", conversationID: "bob", author: .peer, kind: .timer, ts: t0, ttl: 0, state: .received, timer: 30)
        XCTAssertNil(Deadlines.expiresAt(for: system))
        XCTAssertTrue(DisappearingScheduler.expired([peer, mine, system], now: t0 + 400 * day).isEmpty)
    }

    func testPurgeOrderEarliestDeadlineFirstThenId() {
        var a: Message = peerMessage(id: "a", ttl: 30, receivedAt: t0)
        a.markRevealed(at: t0 + 100)                       // expires t0 + 130
        var b: Message = peerMessage(id: "b", ttl: 30, receivedAt: t0)
        b.markRevealed(at: t0 + 50)                        // expires t0 + 80
        var c: Message = peerMessage(id: "c", ttl: 60, receivedAt: t0)
        c.markRevealed(at: t0 + 20)                        // expires t0 + 80 (tie with b → id order)
        var d: Message = Message(id: "d", conversationID: "bob", author: .me, kind: .text, ts: t0, ttl: 5, state: .outbox, text: "z")
        d.markSent(at: t0)                                 // expires t0 + 5
        let later: Message = peerMessage(id: "e", ttl: 30, receivedAt: t0 + 1000)   // far in the future
        let all: [Message] = [a, b, c, d, later]
        XCTAssertEqual(DisappearingScheduler.expired(all, now: t0 + 130).map { $0.id }, ["d", "b", "c", "a"])
        XCTAssertEqual(DisappearingScheduler.expired(all, now: t0 + 100).map { $0.id }, ["d", "b", "c"])
        XCTAssertEqual(DisappearingScheduler.expired(all, now: t0 + 4).map { $0.id }, [])
        XCTAssertEqual(DisappearingScheduler.earliestDeadline(all), t0 + 5)
        XCTAssertNil(DisappearingScheduler.earliestDeadline([peerMessage(id: "z", ttl: 0, receivedAt: t0)]))
    }

    @MainActor
    func testSchedulerFiresForPastDeadline() async {
        let clock: ManualClock = ManualClock(now: t0)
        let fired: XCTestExpectation = expectation(description: "fire")
        let scheduler: DisappearingScheduler = DisappearingScheduler(clock: clock) { fired.fulfill() }
        scheduler.schedule(deadline: t0 - 1)
        await fulfillment(of: [fired], timeout: 2)
        XCTAssertNil(scheduler.scheduledDeadline)
    }

    @MainActor
    func testScheduleReplacesAndCancels() async {
        let clock: ManualClock = ManualClock(now: t0)
        var fires: Int = 0
        let scheduler: DisappearingScheduler = DisappearingScheduler(clock: clock) { fires += 1 }
        scheduler.schedule(deadline: t0 + 3600)
        XCTAssertEqual(scheduler.scheduledDeadline, t0 + 3600)
        scheduler.schedule(deadline: t0 + 7200)
        XCTAssertEqual(scheduler.scheduledDeadline, t0 + 7200)
        scheduler.schedule(deadline: nil)
        XCTAssertNil(scheduler.scheduledDeadline)
        scheduler.schedule(deadline: t0 + 60)
        scheduler.cancel()
        XCTAssertNil(scheduler.scheduledDeadline)
        try? await Task.sleep(for: .milliseconds(50))
        XCTAssertEqual(fires, 0)
    }
}
