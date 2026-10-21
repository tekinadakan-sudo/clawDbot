//  HoldToReveal.swift
//  Kilit — Security/ (WP6), §5.7.
//
//  `PressHoldView` installs a UIKit `UILongPressGestureRecognizer` (SwiftUI's
//  long-press modifier is NOT used: its `LongPressGesture` succeeds and ends when
//  `minimumDuration` elapses, so the release would fire in the same frame as the
//  reveal). `.began → onChange(true)` unless the enclosing UIScrollView
//  `isDragging || isDecelerating` (scroll guard: the recognizer is reset and
//  nothing is revealed); `.ended / .cancelled → onChange(false)`.
//  `RevealController` allows one revealed bubble at a time, auto-ends after 20 s
//  (injected clock) and plays a `.soft` haptic. Placeholder sizes live here too.

import Observation
import SwiftUI
import UIKit

enum RevealMetrics {
    /// Constant text placeholder height (never sized by content: length would leak).
    static let textPlaceholderHeight: CGFloat = 56
    /// Constant image placeholder panel.
    static let imagePlaceholderSize: CGSize = CGSize(width: 200, height: 150)
    static let autoEndInterval: TimeInterval = 20
    static let minimumPressDuration: TimeInterval = 0.3
    /// Below UIScrollView's pan-start distance, so a drag that pauses never reveals.
    static let allowableMovement: CGFloat = 8
    /// Band height for the image partial reveal: `max(120, height / 4)`.
    static func revealBandHeight(forViewerHeight height: CGFloat) -> CGFloat {
        max(120, height / 4)
    }
}

// MARK: - RevealController

@MainActor
@Observable
final class RevealController {

    /// The single revealed message id, or nil.
    private(set) var revealedID: String?

    @ObservationIgnored let autoEndInterval: TimeInterval
    @ObservationIgnored private let now: () -> Date
    @ObservationIgnored private var startedAt: Date?
    @ObservationIgnored private var timer: Timer?
    @ObservationIgnored var haptic: @MainActor () -> Void
    /// WP8 hooks: first reveal starts the disappearing timer and queues `ctrl.read`.
    @ObservationIgnored var onRevealBegan: ((String) -> Void)?
    @ObservationIgnored var onRevealEnded: ((String) -> Void)?

    init(now: @escaping () -> Date = { Date() },
         autoEndInterval: TimeInterval = RevealMetrics.autoEndInterval,
         haptic: (@MainActor () -> Void)? = nil) {
        self.now = now
        self.autoEndInterval = autoEndInterval
        self.haptic = haptic ?? { UIImpactFeedbackGenerator(style: .soft).impactOccurred() }
    }

    func isRevealed(_ id: String) -> Bool {
        revealedID == id
    }

    /// Reveals `id`, ending any other revealed bubble first.
    func begin(id: String) {
        if let current = revealedID, current != id {
            finish(current)
        }
        guard revealedID != id else { return }
        revealedID = id
        startedAt = now()
        haptic()
        scheduleAutoEnd()
        onRevealBegan?(id)
    }

    /// Ends the reveal of `id` (no-op when another id, or nothing, is revealed).
    func end(id: String) {
        guard revealedID == id else { return }
        finish(id)
    }

    func endAll() {
        if let current = revealedID { finish(current) }
    }

    /// Ends the current reveal when `autoEndInterval` has elapsed on the injected clock.
    func endIfExpired() {
        guard let current = revealedID, let start = startedAt else { return }
        if now().timeIntervalSince(start) >= autoEndInterval {
            finish(current)
        }
    }

    private func finish(_ id: String) {
        timer?.invalidate()
        timer = nil
        revealedID = nil
        startedAt = nil
        onRevealEnded?(id)
    }

    private func scheduleAutoEnd() {
        timer?.invalidate()
        // Scheduled from the main run loop, so the callback runs on the main thread.
        timer = Timer.scheduledTimer(withTimeInterval: autoEndInterval + 0.05, repeats: false) { [weak self] _ in
            MainActor.assumeIsolated {
                self?.endIfExpired()
            }
        }
    }
}

// MARK: - PressHoldView

/// Transparent UIKit view carrying the long-press recognizer. Overlay it on the
/// placeholder; `cancelsTouchesInView = false` keeps List scrolling intact.
final class PressHoldHostView: UIView {
    override init(frame: CGRect) {
        super.init(frame: frame)
        backgroundColor = .clear
        isOpaque = false
        isAccessibilityElement = false
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        return nil
    }
}

@MainActor
final class PressHoldCoordinator: NSObject {

    var onChange: (Bool) -> Void
    /// Scroll guard: true while the enclosing scroll view is dragging/decelerating.
    var scrollGuard: (UIView?) -> Bool
    private(set) var isPressing: Bool = false
    private(set) var resetCount: Int = 0

    init(onChange: @escaping (Bool) -> Void, scrollGuard: ((UIView?) -> Bool)?) {
        self.onChange = onChange
        self.scrollGuard = scrollGuard ?? { view in PressHoldCoordinator.defaultScrollGuard(view) }
        super.init()
    }

    /// Walks `superview`s for the first UIScrollView.
    static func defaultScrollGuard(_ view: UIView?) -> Bool {
        var candidate: UIView? = view?.superview
        while let current = candidate {
            if let scrollView = current as? UIScrollView {
                return scrollView.isDragging || scrollView.isDecelerating
            }
            candidate = current.superview
        }
        return false
    }

    @objc func handle(_ sender: UILongPressGestureRecognizer) {
        process(state: sender.state, recognizer: sender)
    }

    /// State machine (internal so tests can drive it without touch events).
    func process(state: UIGestureRecognizer.State, recognizer: UIGestureRecognizer?) {
        switch state {
        case .began:
            if scrollGuard(recognizer?.view) {
                resetCount += 1
                recognizer?.isEnabled = false      // reset: nothing is revealed
                recognizer?.isEnabled = true
                return
            }
            guard !isPressing else { return }
            isPressing = true
            onChange(true)
        case .ended, .cancelled:
            guard isPressing else { return }
            isPressing = false
            onChange(false)
        default:
            // .possible, .changed, .failed: UIKit sends no action for .failed, and a
            // press that failed before minimumPressDuration never produced .began.
            break
        }
    }
}

struct PressHoldView: UIViewRepresentable {

    let onChange: (Bool) -> Void
    /// Test hook; nil uses the UIScrollView walk.
    var scrollGuard: ((UIView?) -> Bool)? = nil

    init(onChange: @escaping (Bool) -> Void, scrollGuard: ((UIView?) -> Bool)? = nil) {
        self.onChange = onChange
        self.scrollGuard = scrollGuard
    }

    func makeCoordinator() -> PressHoldCoordinator {
        PressHoldCoordinator(onChange: onChange, scrollGuard: scrollGuard)
    }

    func makeUIView(context: Context) -> PressHoldHostView {
        let view: PressHoldHostView = PressHoldHostView(frame: .zero)
        let lp: UILongPressGestureRecognizer = UILongPressGestureRecognizer(
            target: context.coordinator, action: #selector(PressHoldCoordinator.handle(_:)))
        lp.minimumPressDuration = RevealMetrics.minimumPressDuration
        lp.allowableMovement = RevealMetrics.allowableMovement
        lp.cancelsTouchesInView = false
        lp.delaysTouchesBegan = false
        view.addGestureRecognizer(lp)
        return view
    }

    func updateUIView(_ uiView: PressHoldHostView, context: Context) {
        context.coordinator.onChange = onChange
        if let scrollGuard {
            context.coordinator.scrollGuard = scrollGuard
        }
    }
}

extension View {
    /// Overlays a `PressHoldView`; `onChange(true)` while held, `false` on release.
    func pressHold(_ onChange: @escaping (Bool) -> Void) -> some View {
        overlay {
            PressHoldView(onChange: onChange)
        }
    }
}
