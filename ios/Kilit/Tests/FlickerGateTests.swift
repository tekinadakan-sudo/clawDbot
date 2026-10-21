//  FlickerGateTests.swift
//  Kilit — WP6 tests (§5.12): `blockingCondition()` with injected flags and the
//  `Notification.Name(rawValue: kMADimFlashingLightsChangedNotification)` observer.

import MediaAccessibility
import UIKit
import XCTest
@testable import Kilit

final class FlickerGateTests: XCTestCase {

    private var window: UIWindow?

    override func tearDown() {
        let w: UIWindow? = window
        window = nil
        MainActor.assumeIsolated {
            w?.isHidden = true
        }
        super.tearDown()
    }

    @MainActor
    private func makeWindow() -> UIWindow {
        let scene: UIWindowScene? = UIApplication.shared.connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .first
        let w: UIWindow
        if let scene {
            w = UIWindow(windowScene: scene)
        } else {
            w = UIWindow(frame: CGRect(x: 0, y: 0, width: 320, height: 480))
        }
        w.frame = CGRect(x: 0, y: 0, width: 320, height: 480)
        w.isHidden = false
        window = w
        return w
    }

    @MainActor
    private func makeView(_ env: FlickerEnvironment) -> FlickerMaskView {
        let view: FlickerMaskView = FlickerMaskView(frame: CGRect(x: 0, y: 0, width: 200, height: 56))
        view.environmentOverride = env
        return view
    }

    @MainActor
    func testPermissiveEnvironmentDoesNotBlock() {
        XCTAssertNil(makeView(.permissive).blockingCondition())
    }

    @MainActor
    func testEachHardBlock() {
        var env: FlickerEnvironment = .permissive
        env.maximumFramesPerSecond = 60
        XCTAssertEqual(makeView(env).blockingCondition(), .rateTooLow(measuredHz: 60))

        env = .permissive
        env.reduceMotion = true
        XCTAssertEqual(makeView(env).blockingCondition(), .accessibilitySetting)

        env = .permissive
        env.dimFlashingLights = true
        XCTAssertEqual(makeView(env).blockingCondition(), .accessibilitySetting)

        env = .permissive
        env.lowPowerMode = true
        XCTAssertEqual(makeView(env).blockingCondition(), .lowPowerMode)

        env = .permissive
        env.thermalState = .serious
        XCTAssertEqual(makeView(env).blockingCondition(), .thermal)
        env.thermalState = .critical
        XCTAssertEqual(makeView(env).blockingCondition(), .thermal)
        env.thermalState = .fair
        XCTAssertNil(makeView(env).blockingCondition())

        env = .permissive
        env.isApplicationActive = false
        XCTAssertEqual(makeView(env).blockingCondition(), .notActive)

        env = .permissive
        env.isCaptured = true
        XCTAssertEqual(makeView(env).blockingCondition(), .captured)
    }

    @MainActor
    func testCapturedWinsOverEverything() {
        var env: FlickerEnvironment = .permissive
        env.isCaptured = true
        env.reduceMotion = true
        env.lowPowerMode = true
        env.maximumFramesPerSecond = 60
        XCTAssertEqual(makeView(env).blockingCondition(), .captured)
    }

    @MainActor
    func testEnablingWhileBlockedReportsReasonAndDoesNotRun() {
        let w: UIWindow = makeWindow()
        var env: FlickerEnvironment = .permissive
        env.maximumFramesPerSecond = 60
        let view: FlickerMaskView = makeView(env)
        w.addSubview(view)
        var reasons: [FlickerMaskView.StopReason] = []
        view.onStopped = { reasons.append($0) }
        view.isEnabled = true
        XCTAssertFalse(view.isRunning)
        XCTAssertEqual(reasons.first, .rateTooLow(measuredHz: 60))
    }

    @MainActor
    func testDimFlashingLightsNotificationStopsARunningView() {
        let w: UIWindow = makeWindow()
        let view: FlickerMaskView = makeView(.permissive)
        w.addSubview(view)
        view.layoutIfNeeded()
        var reasons: [FlickerMaskView.StopReason] = []
        view.onStopped = { reasons.append($0) }

        view.isEnabled = true
        XCTAssertTrue(view.isRunning, "permissive injected environment must allow the link to start")

        var changed: FlickerEnvironment = .permissive
        changed.dimFlashingLights = true
        view.environmentOverride = changed
        NotificationCenter.default.post(
            name: Notification.Name(rawValue: kMADimFlashingLightsChangedNotification as String),
            object: nil)

        XCTAssertFalse(view.isRunning)
        XCTAssertEqual(reasons.last, .accessibilitySetting)
        view.isEnabled = false
    }

    @MainActor
    func testCapturedFlagStopsARunningView() {
        let w: UIWindow = makeWindow()
        let view: FlickerMaskView = makeView(.permissive)
        w.addSubview(view)
        view.layoutIfNeeded()
        var reasons: [FlickerMaskView.StopReason] = []
        view.onStopped = { reasons.append($0) }
        view.isEnabled = true
        XCTAssertTrue(view.isRunning)
        view.isCaptured = true
        XCTAssertFalse(view.isRunning)
        XCTAssertEqual(reasons.last, .captured)
        view.isEnabled = false
    }

    @MainActor
    func testHostRequestStops() {
        let w: UIWindow = makeWindow()
        let view: FlickerMaskView = makeView(.permissive)
        w.addSubview(view)
        view.layoutIfNeeded()
        var reasons: [FlickerMaskView.StopReason] = []
        view.onStopped = { reasons.append($0) }
        view.isEnabled = true
        XCTAssertTrue(view.isRunning)
        view.isEnabled = false
        XCTAssertFalse(view.isRunning)
        XCTAssertEqual(reasons.last, .hostRequest)
    }

    @MainActor
    func testLiveEnvironmentIsReadableOffWindow() {
        let view: FlickerMaskView = FlickerMaskView(frame: .zero)
        let env: FlickerEnvironment = view.currentEnvironment()
        XCTAssertEqual(env.maximumFramesPerSecond, 60, "no window → the 60 Hz fallback")
        XCTAssertEqual(env.dimFlashingLights, MADimFlashingLightsEnabled())
    }
}
