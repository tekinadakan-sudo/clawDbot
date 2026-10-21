//  FlickerMaskView.swift
//  Kilit — Security/ (WP6), §5.10. EXPERIMENTAL "temporal sub-frame" deterrent
//  (opt-in, default OFF, photosensitivity-gated). Imports MediaAccessibility for
//  `MADimFlashingLightsEnabled()` / `kMADimFlashingLightsChangedNotification`.
//
//  Alternates two complementary device-pixel checkerboard masks (cell 3 pt, mask
//  colour = bubble background) over the currently revealed text bubble at 120 Hz
//  with a CADisplayLink. Requires `CADisableMinimumFrameDurationOnPhone = true`
//  in both plists. Hard blocks: panel < 120 Hz, Reduce Motion, Dim Flashing
//  Lights, Low Power Mode, thermal .serious/.critical, app not active, captured.
//  Self-stops when the measured rate (EMA of 1/(targetTimestamp − timestamp))
//  stays below 100 Hz for 30 consecutive frames. There is no per-tick polling of
//  the environment: changes arrive through notifications.

import MediaAccessibility
import QuartzCore
import SwiftUI
import UIKit

/// Snapshot of every gating input. Tests inject one through `environmentOverride`.
struct FlickerEnvironment: Equatable {
    var maximumFramesPerSecond: Int
    var reduceMotion: Bool
    var dimFlashingLights: Bool
    var lowPowerMode: Bool
    var thermalState: ProcessInfo.ThermalState
    var isApplicationActive: Bool
    var isCaptured: Bool

    /// Everything permitted on a 120 Hz panel.
    static let permissive: FlickerEnvironment = FlickerEnvironment(
        maximumFramesPerSecond: 120, reduceMotion: false, dimFlashingLights: false,
        lowPowerMode: false, thermalState: .nominal, isApplicationActive: true, isCaptured: false)
}

final class FlickerMaskView: UIView {

    enum StopReason: Equatable {
        case rateTooLow(measuredHz: Double)
        case accessibilitySetting        // Reduce Motion or Dim Flashing Lights
        case lowPowerMode
        case thermal
        case notActive                   // app resigned active / view left the window
        case captured                    // isSceneCaptured
        case hostRequest                 // isEnabled set to false
    }

    // MARK: - Configuration

    /// Checkerboard cell side in points (≤ 3 pt keeps each cell below ~0.1° of
    /// visual field at normal viewing distance).
    var cellSize: CGFloat = 3 {
        didSet { if cellSize != oldValue { regenerateMasks() } }
    }

    /// Colour painted over hidden cells: the bubble background, never black.
    var maskColor: UIColor = UIColor(red: 0x4A / 255.0, green: 0x4A / 255.0, blue: 0x4F / 255.0, alpha: 1) {
        didSet { regenerateMasks() }
    }

    /// Minimum measured rate (Hz) at which the deterrent may run.
    var minimumEffectiveRate: Double = 100
    /// Consecutive slow frames tolerated before self-stop (~0.25 s at 120 Hz).
    var slowFrameTolerance: Int = 30

    /// Host switch: starts as soon as the view is in a window and nothing blocks.
    var isEnabled: Bool = false {
        didSet {
            guard isEnabled != oldValue else { return }
            if isEnabled { startIfPossible() } else { stop(.hostRequest) }
        }
    }

    /// Mirrors `isSceneCaptured`; set by `FlickerShield`.
    var isCaptured: Bool = false {
        didSet {
            guard isCaptured != oldValue else { return }
            if isCaptured { stop(.captured) } else if isEnabled { startIfPossible() }
        }
    }

    /// Test hook: replaces every live gating input when non-nil.
    var environmentOverride: FlickerEnvironment?

    /// Called on the main thread whenever the view stops or refuses to start.
    var onStopped: ((StopReason) -> Void)?

    private(set) var isRunning: Bool = false
    /// EMA of the delivered rate; 0 until the first callback.
    private(set) var measuredHz: Double = 0

    // MARK: - Private state

    private let maskLayer: CALayer = CALayer()
    private var masks: [CGImage] = []
    private var phase: Int = 0
    private var displayLink: CADisplayLink?
    private var proxy: FlickerDisplayLinkProxy?
    private var slowFrames: Int = 0
    private var renderedPixelSize: CGSize = .zero
    private var observing: Bool = false

    // MARK: - Init / teardown

    override init(frame: CGRect) {
        super.init(frame: frame)
        isOpaque = false
        backgroundColor = .clear
        isUserInteractionEnabled = false
        isAccessibilityElement = false
        accessibilityElementsHidden = true
        maskLayer.contentsGravity = .resize
        maskLayer.magnificationFilter = .nearest
        maskLayer.minificationFilter = .nearest
        maskLayer.actions = ["contents": NSNull(), "hidden": NSNull(),
                             "bounds": NSNull(), "position": NSNull()]
        maskLayer.isHidden = true
        layer.addSublayer(maskLayer)
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        return nil
    }

    deinit {
        displayLink?.invalidate()           // the run loop retains the link; break it explicitly
    }

    // MARK: - UIView

    override func layoutSubviews() {
        super.layoutSubviews()
        maskLayer.frame = bounds
        let scale: CGFloat = currentScale
        maskLayer.contentsScale = scale
        let px: CGSize = CGSize(width: (bounds.width * scale).rounded(.up),
                                height: (bounds.height * scale).rounded(.up))
        if px != renderedPixelSize { regenerateMasks() }
        if isEnabled, !isRunning, window != nil { startIfPossible() }
    }

    override func didMoveToWindow() {
        super.didMoveToWindow()
        if window == nil {
            stop(.notActive)
        } else if isEnabled {
            startIfPossible()
        }
    }

    private var currentScale: CGFloat {
        window?.windowScene?.screen.scale ?? traitCollection.displayScale
    }

    // MARK: - Gating

    func currentEnvironment() -> FlickerEnvironment {
        if let environmentOverride { return environmentOverride }
        return FlickerEnvironment(
            maximumFramesPerSecond: window?.windowScene?.screen.maximumFramesPerSecond ?? 60,
            reduceMotion: UIAccessibility.isReduceMotionEnabled,
            dimFlashingLights: MADimFlashingLightsEnabled(),
            lowPowerMode: ProcessInfo.processInfo.isLowPowerModeEnabled,
            thermalState: ProcessInfo.processInfo.thermalState,
            isApplicationActive: UIApplication.shared.applicationState == .active,
            isCaptured: isCaptured)
    }

    /// The first hard block that applies, or nil when flicker may run.
    func blockingCondition() -> StopReason? {
        let env: FlickerEnvironment = currentEnvironment()
        if env.isCaptured { return .captured }
        if env.reduceMotion || env.dimFlashingLights { return .accessibilitySetting }
        if env.lowPowerMode { return .lowPowerMode }
        switch env.thermalState {
        case .serious, .critical: return .thermal
        case .nominal, .fair: break
        @unknown default: break
        }
        if !env.isApplicationActive { return .notActive }
        if env.maximumFramesPerSecond < 120 {
            return .rateTooLow(measuredHz: Double(env.maximumFramesPerSecond))
        }
        return nil
    }

    // MARK: - Start / stop

    private func startIfPossible() {
        guard isEnabled, !isRunning, window != nil else { return }
        if let reason = blockingCondition() {
            onStopped?(reason)
            return
        }
        regenerateMasks()
        guard masks.count == 2 else { return }    // zero-size bounds; layoutSubviews retries

        let linkProxy: FlickerDisplayLinkProxy = FlickerDisplayLinkProxy(owner: self)
        proxy = linkProxy
        // CADisplayLink retains its target; the proxy holds `self` weakly.
        let link: CADisplayLink = CADisplayLink(target: linkProxy,
                                                selector: #selector(FlickerDisplayLinkProxy.tick(_:)))
        link.preferredFrameRateRange = CAFrameRateRange(minimum: 120, maximum: 120, preferred: 120)
        link.add(to: .main, forMode: .common)
        displayLink = link

        slowFrames = 0
        measuredHz = 0
        phase = 0
        isRunning = true
        maskLayer.contents = masks[phase]
        maskLayer.isHidden = false
        installObservers()
    }

    func stop(_ reason: StopReason) {
        displayLink?.invalidate()
        displayLink = nil
        proxy = nil
        removeObservers()
        guard isRunning else { return }
        isRunning = false
        CATransaction.begin()
        CATransaction.setDisableActions(true)
        maskLayer.contents = nil
        maskLayer.isHidden = true
        CATransaction.commit()
        onStopped?(reason)
    }

    /// Re-runs the hard blocks (notification-driven, never per tick).
    func reevaluateBlocking() {
        guard isRunning else { return }
        if let reason = blockingCondition() { stop(reason) }
    }

    // MARK: - Per-frame callback

    fileprivate func handleTick(_ link: CADisplayLink) {
        let interval: CFTimeInterval = link.targetTimestamp - link.timestamp
        if interval > 0 {
            let hz: Double = 1.0 / interval
            measuredHz = measuredHz == 0 ? hz : (measuredHz * 0.9 + hz * 0.1)
        }
        if measuredHz > 0 && measuredHz < minimumEffectiveRate {
            slowFrames += 1
            if slowFrames >= slowFrameTolerance {
                stop(.rateTooLow(measuredHz: measuredHz))
                return
            }
        } else {
            slowFrames = 0
        }
        guard masks.count == 2 else { return }
        phase ^= 1
        CATransaction.begin()
        CATransaction.setDisableActions(true)
        maskLayer.contents = masks[phase]
        CATransaction.commit()
    }

    // MARK: - Masks (two complementary checkerboards, device-pixel exact)

    private func regenerateMasks() {
        let scale: CGFloat = currentScale
        let w: Int = Int((bounds.width * scale).rounded(.up))
        let h: Int = Int((bounds.height * scale).rounded(.up))
        guard w > 0, h > 0 else {
            masks = []
            renderedPixelSize = .zero
            return
        }
        renderedPixelSize = CGSize(width: w, height: h)
        let cell: Int = max(1, Int((cellSize * scale).rounded()))
        let format: UIGraphicsImageRendererFormat = UIGraphicsImageRendererFormat()
        format.scale = 1
        format.opaque = false
        let renderer: UIGraphicsImageRenderer =
            UIGraphicsImageRenderer(size: CGSize(width: w, height: h), format: format)
        let fill: CGColor = maskColor.cgColor

        var generated: [CGImage] = []
        for parity in 0...1 {
            let uiImage: UIImage = renderer.image { ctx in
                let cg: CGContext = ctx.cgContext
                cg.setFillColor(fill)
                var row: Int = 0
                var y: Int = 0
                while y < h {
                    var col: Int = 0
                    var x: Int = 0
                    while x < w {
                        if (row + col) & 1 == parity {
                            cg.fill(CGRect(x: x, y: y, width: cell, height: cell))
                        }
                        x += cell
                        col += 1
                    }
                    y += cell
                    row += 1
                }
            }
            if let cgImage = uiImage.cgImage {
                generated.append(cgImage)
            }
        }
        masks = generated.count == 2 ? generated : []

        if isRunning, masks.count == 2 {
            CATransaction.begin()
            CATransaction.setDisableActions(true)
            maskLayer.contents = masks[phase]
            CATransaction.commit()
        }
    }

    // MARK: - Environment observers

    private func installObservers() {
        guard !observing else { return }
        observing = true
        let nc: NotificationCenter = NotificationCenter.default
        nc.addObserver(self, selector: #selector(appWillResignActive(_:)),
                       name: UIApplication.willResignActiveNotification, object: nil)
        nc.addObserver(self, selector: #selector(environmentChanged(_:)),
                       name: UIApplication.didBecomeActiveNotification, object: nil)
        nc.addObserver(self, selector: #selector(environmentChanged(_:)),
                       name: UIAccessibility.reduceMotionStatusDidChangeNotification, object: nil)
        // kMADimFlashingLightsChangedNotification is a CFString: bridge it by raw value.
        nc.addObserver(self, selector: #selector(environmentChanged(_:)),
                       name: Notification.Name(rawValue: kMADimFlashingLightsChangedNotification as String),
                       object: nil)
        // May be posted on any thread (documented for both):
        nc.addObserver(self, selector: #selector(environmentChanged(_:)),
                       name: .NSProcessInfoPowerStateDidChange, object: nil)
        nc.addObserver(self, selector: #selector(environmentChanged(_:)),
                       name: ProcessInfo.thermalStateDidChangeNotification, object: nil)
    }

    private func removeObservers() {
        guard observing else { return }
        observing = false
        NotificationCenter.default.removeObserver(self)
    }

    @objc nonisolated private func appWillResignActive(_ note: Notification) {
        onMain { view in view.stop(.notActive) }
    }

    @objc nonisolated private func environmentChanged(_ note: Notification) {
        onMain { view in view.reevaluateBlocking() }
    }

    /// Runs `body` on the main actor: synchronously when already on the main
    /// thread (UIKit / accessibility notifications), otherwise after a hop
    /// (power and thermal notifications arrive on arbitrary threads).
    nonisolated private func onMain(_ body: @escaping @MainActor (FlickerMaskView) -> Void) {
        if Thread.isMainThread {
            MainActor.assumeIsolated { body(self) }
        } else {
            DispatchQueue.main.async { [weak self] in
                guard let self else { return }
                MainActor.assumeIsolated { body(self) }
            }
        }
    }
}

// MARK: - Weak target for CADisplayLink (the link retains its target)

@MainActor
private final class FlickerDisplayLinkProxy: NSObject {
    weak var owner: FlickerMaskView?

    init(owner: FlickerMaskView) {
        self.owner = owner
        super.init()
    }

    @objc func tick(_ link: CADisplayLink) {
        owner?.handleTick(link)
    }
}

// MARK: - SwiftUI bridge

/// Overlays only the currently revealed text bubble during the hold — never
/// photos, never the full screen: `.overlay { FlickerShield(enabled: on, maskColor: bg) }`.
struct FlickerShield: UIViewRepresentable {
    var enabled: Bool
    var maskColor: UIColor
    var onStopped: ((FlickerMaskView.StopReason) -> Void)? = nil

    @Environment(\.isSceneCaptured) private var isSceneCaptured: Bool

    func makeUIView(context: Context) -> FlickerMaskView {
        let view: FlickerMaskView = FlickerMaskView(frame: .zero)
        view.maskColor = maskColor
        view.onStopped = onStopped
        view.isCaptured = isSceneCaptured
        return view
    }

    func updateUIView(_ uiView: FlickerMaskView, context: Context) {
        uiView.maskColor = maskColor
        uiView.onStopped = onStopped
        uiView.isCaptured = isSceneCaptured
        uiView.isEnabled = enabled
    }
}
