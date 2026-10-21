//  CaptureMonitor.swift
//  Kilit — Security/ (WP6), §5.6.
//
//  `CaptureMonitor` bridges `@Environment(\.isSceneCaptured)` (via
//  `CaptureEnvironmentReader`) and `UIApplication.userDidTakeScreenshotNotification`
//  (0.5 s leading-edge debounce; UIKit can post twice) into
//  `onEvent(kind, timestamp)`. It owns NO counter: `App/CaptureGlue.swift` keeps
//  the per-conversation `seq`, the local log and the encrypted report.

import Foundation
import Observation
import SwiftUI
import UIKit

@MainActor
@Observable
final class CaptureMonitor {

    /// Minimum spacing between two accepted screenshot notifications.
    static let screenshotDebounce: TimeInterval = 0.5

    /// Mirrors `isSceneCaptured` / `sceneCaptureState == .active`.
    private(set) var isCaptured: Bool = false

    /// Event sink. The timestamp comes from the injected clock.
    @ObservationIgnored var onEvent: ((CaptureEventKind, _ timestamp: Date) -> Void)?

    @ObservationIgnored private let now: () -> Date
    @ObservationIgnored private var screenshotObserver: NotificationObserverToken?
    @ObservationIgnored private var lastScreenshotAt: Date?

    init(now: @escaping () -> Date = { Date() },
         notificationCenter: NotificationCenter = .default,
         observesScreenshots: Bool = true) {
        self.now = now
        if observesScreenshots {
            // UIKit posts on the main thread; `queue: nil` runs the block synchronously
            // on the posting thread, so the main-actor assumption below holds.
            let token: NSObjectProtocol = notificationCenter.addObserver(
                forName: UIApplication.userDidTakeScreenshotNotification,
                object: nil,
                queue: nil
            ) { [weak self] _ in
                MainActor.assumeIsolated {
                    self?.noteScreenshot()
                }
            }
            screenshotObserver = NotificationObserverToken(center: notificationCenter, token: token)
        }
    }

    /// Called by `CaptureEnvironmentReader` (and by `SceneDelegate` for the trait path).
    func update(captured: Bool) {
        guard captured != isCaptured else { return }
        isCaptured = captured
        onEvent?(captured ? .recordingStarted : .recordingStopped, now())
    }

    /// Screenshot notification handler (debounced). Internal so tests can drive it.
    func noteScreenshot() {
        let timestamp: Date = now()
        if let last = lastScreenshotAt,
           timestamp.timeIntervalSince(last) < CaptureMonitor.screenshotDebounce {
            return
        }
        lastScreenshotAt = timestamp
        onEvent?(.screenshot, timestamp)
    }

    /// Emitted by WP8 the first time a conversation opens while `isProtected == false`
    /// (once per app launch per peer; the per-peer bookkeeping lives in CaptureGlue).
    func reportBlankingUnavailable() {
        onEvent?(.blankingUnavailable, now())
    }
}

/// Removes a block-based observer when released, so the main-actor monitor needs
/// no `deinit` that touches isolated state.
final class NotificationObserverToken {
    private let center: NotificationCenter
    private let token: NSObjectProtocol

    init(center: NotificationCenter, token: NSObjectProtocol) {
        self.center = center
        self.token = token
    }

    deinit {
        center.removeObserver(token)
    }
}

/// Invisible view that feeds `@Environment(\.isSceneCaptured)` into the monitor.
/// Place it anywhere inside the scene's SwiftUI hierarchy.
struct CaptureEnvironmentReader: View {
    @Environment(\.isSceneCaptured) private var isSceneCaptured: Bool
    let monitor: CaptureMonitor

    init(monitor: CaptureMonitor) {
        self.monitor = monitor
    }

    var body: some View {
        Color.clear
            .frame(width: 0, height: 0)
            .accessibilityHidden(true)
            .allowsHitTesting(false)
            .onChange(of: isSceneCaptured, initial: true) { _, captured in
                monitor.update(captured: captured)
            }
    }
}
