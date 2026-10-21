//  HoldToRevealTests.swift
//  Kilit — WP6 tests (§5.12): single reveal, 20 s auto-end with an injected clock,
//  scroll guard with a stubbed isDragging provider, `.ended` / `.cancelled` release.

import UIKit
import XCTest
@testable import Kilit

final class HoldToRevealTests: XCTestCase {

    @MainActor
    func testSingleRevealInvariant() {
        var clock: Date = Date(timeIntervalSince1970: 10_000)
        var haptics: Int = 0
        let controller: RevealController = RevealController(now: { clock }, haptic: { haptics += 1 })
        var began: [String] = []
        var ended: [String] = []
        controller.onRevealBegan = { began.append($0) }
        controller.onRevealEnded = { ended.append($0) }

        controller.begin(id: "a")
        XCTAssertEqual(controller.revealedID, "a")
        XCTAssertTrue(controller.isRevealed("a"))
        controller.begin(id: "a")                      // idempotent
        XCTAssertEqual(began, ["a"])
        XCTAssertEqual(haptics, 1)

        clock = clock.addingTimeInterval(1)
        controller.begin(id: "b")                      // replaces a
        XCTAssertEqual(controller.revealedID, "b")
        XCTAssertFalse(controller.isRevealed("a"))
        XCTAssertEqual(ended, ["a"])
        XCTAssertEqual(began, ["a", "b"])

        controller.end(id: "a")                        // stale release: no-op
        XCTAssertEqual(controller.revealedID, "b")
        controller.end(id: "b")
        XCTAssertNil(controller.revealedID)
        XCTAssertEqual(ended, ["a", "b"])
    }

    @MainActor
    func testAutoEndAfterTwentySecondsOnInjectedClock() {
        var clock: Date = Date(timeIntervalSince1970: 20_000)
        let controller: RevealController = RevealController(now: { clock }, haptic: {})
        var ended: [String] = []
        controller.onRevealEnded = { ended.append($0) }

        controller.begin(id: "m")
        clock = clock.addingTimeInterval(19.9)
        controller.endIfExpired()
        XCTAssertEqual(controller.revealedID, "m", "still revealed before 20 s")

        clock = clock.addingTimeInterval(0.1)
        controller.endIfExpired()
        XCTAssertNil(controller.revealedID, "auto-ended at 20 s")
        XCTAssertEqual(ended, ["m"])
        XCTAssertEqual(controller.autoEndInterval, 20)

        controller.endIfExpired()                      // nothing revealed: no-op
        XCTAssertEqual(ended, ["m"])
    }

    @MainActor
    func testScrollGuardSuppressesRevealWhileDragging() {
        var changes: [Bool] = []
        var dragging: Bool = true
        let coordinator: PressHoldCoordinator = PressHoldCoordinator(
            onChange: { changes.append($0) },
            scrollGuard: { _ in dragging })
        let recognizer: UILongPressGestureRecognizer = UILongPressGestureRecognizer()

        coordinator.process(state: .began, recognizer: recognizer)
        XCTAssertEqual(changes, [], "no reveal may start from a scroll")
        XCTAssertEqual(coordinator.resetCount, 1)
        XCTAssertTrue(recognizer.isEnabled, "recognizer is re-armed after the reset")
        XCTAssertFalse(coordinator.isPressing)

        coordinator.process(state: .cancelled, recognizer: recognizer)
        XCTAssertEqual(changes, [], "no release without a reveal")

        dragging = false
        coordinator.process(state: .began, recognizer: recognizer)
        XCTAssertEqual(changes, [true])
        XCTAssertTrue(coordinator.isPressing)
        coordinator.process(state: .changed, recognizer: recognizer)
        XCTAssertEqual(changes, [true])
        coordinator.process(state: .ended, recognizer: recognizer)
        XCTAssertEqual(changes, [true, false])
        XCTAssertFalse(coordinator.isPressing)

        coordinator.process(state: .began, recognizer: recognizer)
        coordinator.process(state: .cancelled, recognizer: recognizer)
        XCTAssertEqual(changes, [true, false, true, false])
    }

    @MainActor
    func testDefaultScrollGuardWalksToTheEnclosingScrollView() {
        let scrollView: UIScrollView = UIScrollView(frame: CGRect(x: 0, y: 0, width: 100, height: 100))
        let inner: UIView = UIView(frame: scrollView.bounds)
        let leaf: PressHoldHostView = PressHoldHostView(frame: inner.bounds)
        scrollView.addSubview(inner)
        inner.addSubview(leaf)
        XCTAssertFalse(PressHoldCoordinator.defaultScrollGuard(leaf), "idle scroll view does not block")
        XCTAssertFalse(PressHoldCoordinator.defaultScrollGuard(nil))
        XCTAssertFalse(PressHoldCoordinator.defaultScrollGuard(UIView()))
    }

    @MainActor
    func testRecognizerConfiguration() {
        let view: PressHoldView = PressHoldView(onChange: { _ in })
        let coordinator: PressHoldCoordinator = view.makeCoordinator()
        let lp: UILongPressGestureRecognizer = UILongPressGestureRecognizer(
            target: coordinator, action: #selector(PressHoldCoordinator.handle(_:)))
        lp.minimumPressDuration = RevealMetrics.minimumPressDuration
        lp.allowableMovement = RevealMetrics.allowableMovement
        XCTAssertEqual(RevealMetrics.minimumPressDuration, 0.3)
        XCTAssertEqual(RevealMetrics.allowableMovement, 8)
        XCTAssertEqual(RevealMetrics.textPlaceholderHeight, 56)
        XCTAssertEqual(RevealMetrics.imagePlaceholderSize, CGSize(width: 200, height: 150))
        XCTAssertEqual(RevealMetrics.revealBandHeight(forViewerHeight: 400), 120)
        XCTAssertEqual(RevealMetrics.revealBandHeight(forViewerHeight: 800), 200)
        XCTAssertEqual(lp.minimumPressDuration, 0.3)
    }
}
