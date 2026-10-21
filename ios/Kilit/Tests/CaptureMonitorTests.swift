//  CaptureMonitorTests.swift
//  Kilit — WP6 tests (§5.12): the 0.5 s screenshot debounce only. Per-peer `seq`
//  and the 2 s coalescing window belong to CaptureGlueTests (WP8).

import UIKit
import XCTest
@testable import Kilit

final class CaptureMonitorTests: XCTestCase {

    @MainActor
    func testTwoScreenshotsWithinHalfASecondYieldOneEvent() {
        var clock: Date = Date(timeIntervalSince1970: 1_000)
        let monitor: CaptureMonitor = CaptureMonitor(now: { clock }, observesScreenshots: false)
        var events: [(CaptureEventKind, Date)] = []
        monitor.onEvent = { kind, ts in events.append((kind, ts)) }

        monitor.noteScreenshot()
        clock = clock.addingTimeInterval(0.2)
        monitor.noteScreenshot()
        XCTAssertEqual(events.count, 1)
        XCTAssertEqual(events.first?.0, .screenshot)
        XCTAssertEqual(events.first?.1, Date(timeIntervalSince1970: 1_000))

        clock = clock.addingTimeInterval(0.29)        // 0.49 s after the first
        monitor.noteScreenshot()
        XCTAssertEqual(events.count, 1)

        clock = clock.addingTimeInterval(0.02)        // 0.51 s after the first
        monitor.noteScreenshot()
        XCTAssertEqual(events.count, 2)
        XCTAssertEqual(events.last?.1.timeIntervalSince1970 ?? 0, 1_000.51, accuracy: 0.001)
    }

    @MainActor
    func testNotificationPathIsDebounced() {
        let center: NotificationCenter = NotificationCenter()
        let clock: Date = Date(timeIntervalSince1970: 2_000)
        let monitor: CaptureMonitor = CaptureMonitor(now: { clock }, notificationCenter: center)
        var kinds: [CaptureEventKind] = []
        monitor.onEvent = { kind, _ in kinds.append(kind) }

        center.post(name: UIApplication.userDidTakeScreenshotNotification, object: nil)
        center.post(name: UIApplication.userDidTakeScreenshotNotification, object: nil)
        XCTAssertEqual(kinds, [.screenshot])
    }

    @MainActor
    func testCaptureTransitionsEmitStartedAndStoppedOnce() {
        let clock: Date = Date(timeIntervalSince1970: 3_000)
        let monitor: CaptureMonitor = CaptureMonitor(now: { clock }, observesScreenshots: false)
        var kinds: [CaptureEventKind] = []
        monitor.onEvent = { kind, _ in kinds.append(kind) }

        monitor.update(captured: false)
        XCTAssertEqual(kinds, [])
        XCTAssertFalse(monitor.isCaptured)
        monitor.update(captured: true)
        monitor.update(captured: true)
        XCTAssertEqual(kinds, [.recordingStarted])
        XCTAssertTrue(monitor.isCaptured)
        monitor.update(captured: false)
        XCTAssertEqual(kinds, [.recordingStarted, .recordingStopped])
        monitor.reportBlankingUnavailable()
        XCTAssertEqual(kinds.last, .blankingUnavailable)
    }

    func testWireSpellings() {
        XCTAssertEqual(CaptureEventKind.screenshot.rawValue, "screenshot")
        XCTAssertEqual(CaptureEventKind.recordingStarted.rawValue, "recording_started")
        XCTAssertEqual(CaptureEventKind.recordingStopped.rawValue, "recording_stopped")
        XCTAssertEqual(CaptureEventKind.blankingUnavailable.rawValue, "blanking_unavailable")
        XCTAssertEqual(CaptureEventKind(rawValue: "recording_started"), .recordingStarted)
        XCTAssertNil(CaptureEventKind(rawValue: "recordingStarted"))
        XCTAssertFalse(CaptureEventKind.blankingUnavailable.consumesSequenceNumber)
        XCTAssertTrue(CaptureEventKind.screenshot.consumesSequenceNumber)
        XCTAssertEqual(SecureLayerMode(rawValue: "layerSwap"), .layerSwap)
        XCTAssertEqual(SecureLayerMode.canvas.rawValue, "canvas")
    }
}
