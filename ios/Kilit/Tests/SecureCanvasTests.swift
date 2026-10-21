//  SecureCanvasTests.swift
//  Kilit — WP6 tests (§5.12). Run on the Simulator: the private canvas subview
//  exists there even though render-server blanking does not (device only).

import AVFoundation
import Observation
import SwiftUI
import UIKit
import XCTest
@testable import Kilit

// MARK: - Probe types for environment propagation

private struct ProbeTagKey: EnvironmentKey {
    static let defaultValue: String = ""
}

private extension EnvironmentValues {
    var probeTag: String {
        get { self[ProbeTagKey.self] }
        set { self[ProbeTagKey.self] = newValue }
    }
}

@MainActor
@Observable
private final class ProbeModel {
    var title: String = "probe-title"
    var renderedTitle: String?
    var seenTag: String?
    @ObservationIgnored var onRender: (() -> Void)?

    func record(title: String, tag: String) {
        renderedTitle = title
        seenTag = tag
        onRender?()
    }
}

private struct ProbeInner: View {
    @Environment(ProbeModel.self) private var model: ProbeModel?
    @Environment(\.probeTag) private var tag: String

    var body: some View {
        let title: String = model?.title ?? "missing"
        Text(title)
            .accessibilityLabel(title)
            .onAppear {
                model?.record(title: title, tag: tag)
            }
    }
}

private struct ProbeRoot: View {
    let model: ProbeModel

    var body: some View {
        SecureContainer(mode: .canvas, enabled: true) {
            ProbeInner()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .environment(model)
        .environment(\.probeTag, "tag-42")
    }
}

// MARK: - Tests

final class SecureCanvasTests: XCTestCase {

    private var window: UIWindow?

    override func tearDown() {
        let w: UIWindow? = window
        window = nil
        MainActor.assumeIsolated {
            w?.rootViewController = nil
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
    private func makeSecureView(in w: UIWindow) -> SecureCanvasView {
        let view: SecureCanvasView = SecureCanvasView(frame: w.bounds)
        w.addSubview(view)
        view.setNeedsLayout()
        view.layoutIfNeeded()
        return view
    }

    @MainActor
    func testSecureCanvasIsDiscoverable() {
        let w: UIWindow = makeWindow()
        let view: SecureCanvasView = makeSecureView(in: w)
        XCTAssertTrue(view.isProtected,
                      "Secure canvas subview not found: UIKit changed the UITextField hierarchy on this iOS; blanking is OFF")
        XCTAssertNotNil(view.hostField.secureCanvas)
        XCTAssertTrue(view.contentView.superview === view.hostField.secureCanvas)
        XCTAssertTrue(view.hostField.secureCanvas?.superview === view.hostField)
        XCTAssertEqual(view.hostField.secureCanvas?.frame, view.hostField.bounds)
    }

    @MainActor
    func testHitTestReachesContent() {
        let w: UIWindow = makeWindow()
        let view: SecureCanvasView = makeSecureView(in: w)
        let button: UIButton = UIButton(type: .system)
        button.translatesAutoresizingMaskIntoConstraints = false
        view.contentView.addSubview(button)
        NSLayoutConstraint.activate([
            button.leadingAnchor.constraint(equalTo: view.contentView.leadingAnchor),
            button.trailingAnchor.constraint(equalTo: view.contentView.trailingAnchor),
            button.topAnchor.constraint(equalTo: view.contentView.topAnchor),
            button.bottomAnchor.constraint(equalTo: view.contentView.bottomAnchor),
        ])
        view.setNeedsLayout()
        view.layoutIfNeeded()
        XCTAssertTrue(view.hitTest(CGPoint(x: 10, y: 10), with: nil) === button)
        XCTAssertFalse(view.hostField.canBecomeFirstResponder)
    }

    @MainActor
    func testTextChangeKeepsContentInCurrentCanvasAndDisablesRecognizers() {
        let w: UIWindow = makeWindow()
        let view: SecureCanvasView = makeSecureView(in: w)
        XCTAssertTrue(view.isProtected)

        view.hostField.text = "canary"
        view.setNeedsLayout()
        view.layoutIfNeeded()
        view.hostField.setNeedsLayout()
        view.hostField.layoutIfNeeded()
        view.evaluateCanary()

        let currentCanvas: UIView? = view.hostField.secureCanvas
        XCTAssertNotNil(currentCanvas)
        XCTAssertTrue(view.isProtected)
        XCTAssertTrue(view.contentView.superview === currentCanvas,
                      "content must live inside the CURRENT canvas after a text change")
        for recognizer in view.installedRecognizers {
            XCTAssertFalse(recognizer.isEnabled, "recognizer \(type(of: recognizer)) must be disabled")
        }
    }

    @MainActor
    func testProtectionChangeFiresOnTransition() {
        let w: UIWindow = makeWindow()
        let view: SecureCanvasView = SecureCanvasView(frame: w.bounds)
        var reported: [Bool] = []
        view.onProtectionChange = { ok in reported.append(ok) }
        XCTAssertFalse(view.isProtected)
        w.addSubview(view)
        view.setNeedsLayout()
        view.layoutIfNeeded()
        XCTAssertTrue(view.isProtected)
        XCTAssertEqual(reported.last, true)
        XCTAssertTrue(reported.contains(true))
    }

    @MainActor
    func testCaptureShieldCanary() {
        let w: UIWindow = makeWindow()
        let target: UIView = UIView(frame: w.bounds)
        w.addSubview(target)
        XCTAssertTrue(CaptureShield.isAvailable(), "TextLayoutCanvasView not found on this iOS")
        XCTAssertTrue(CaptureShield.setHidden(true, layerOf: target))
        XCTAssertTrue(CaptureShield.setHidden(false, layerOf: target))
    }

    @MainActor
    func testHostingControllerModesAndSizing() {
        let w: UIWindow = makeWindow()
        let root: AnyView = AnyView(Text("x"))
        let controller: SecureHostingController =
            SecureHostingController(rootView: root, mode: .canvas, enabled: true)
        var reports: [Bool] = []
        controller.onProtectionChange = { ok in reports.append(ok) }
        w.rootViewController = controller
        w.makeKeyAndVisible()
        w.layoutIfNeeded()
        controller.view.layoutIfNeeded()
        controller.secureView.layoutIfNeeded()

        XCTAssertEqual(controller.hosting.sizingOptions, [])
        XCTAssertEqual(controller.hosting.safeAreaRegions, .container)
        XCTAssertTrue(controller.isProtected)
        XCTAssertTrue(controller.hosting.view.isDescendant(of: controller.secureView.contentView))

        controller.apply(mode: .layerSwap, enabled: true)
        XCTAssertTrue(controller.isProtected)
        XCTAssertFalse(controller.hosting.view.isDescendant(of: controller.secureView))
        XCTAssertNil(controller.secureView.superview)

        controller.apply(mode: .canvas, enabled: false)
        XCTAssertFalse(controller.isProtected)
        XCTAssertEqual(reports.last, false)
    }

    @MainActor
    func testEnvironmentPropagates() {
        let w: UIWindow = makeWindow()
        let model: ProbeModel = ProbeModel()
        let rendered: XCTestExpectation = expectation(description: "hosted view rendered")
        rendered.assertForOverFulfill = false
        model.onRender = { rendered.fulfill() }

        let host: UIHostingController<ProbeRoot> = UIHostingController(rootView: ProbeRoot(model: model))
        w.rootViewController = host
        w.makeKeyAndVisible()
        host.view.setNeedsLayout()
        host.view.layoutIfNeeded()

        wait(for: [rendered], timeout: 5)
        XCTAssertEqual(model.renderedTitle, "probe-title",
                       "the @Observable model did not cross the UIViewControllerRepresentable boundary")
        XCTAssertEqual(model.seenTag, "tag-42",
                       "the custom environment key did not cross the boundary")
    }

    // MARK: - Watermark (WP6 side: tile construction and layer geometry)

    @MainActor
    func testWatermarkTileFromSyntheticDeltaMap() {
        let width: Int = 4
        let height: Int = 2
        let delta: [Int8] = [5, -5, 0, 3,
                             -3, 1, -1, 5]
        let tiles: (lighter: CGImage, darker: CGImage) =
            WatermarkTile.make(delta: delta, width: width, height: height, scale: 1)
        XCTAssertEqual(tiles.lighter.width, width)
        XCTAssertEqual(tiles.lighter.height, height)
        XCTAssertEqual(tiles.lighter.bitsPerPixel, 32)
        XCTAssertEqual(tiles.lighter.bytesPerRow, 4 * width)
        XCTAssertEqual(tiles.darker.bitsPerComponent, 8)

        func check(_ x: Int, _ y: Int, _ d: Int, line: UInt = #line) {
            let l: UInt8 = UInt8(max(0, d))
            let k: UInt8 = UInt8(255 - max(0, -d))
            let lp: (r: UInt8, g: UInt8, b: UInt8)? = WatermarkTile.samplePixel(tiles.lighter, x: x, y: y)
            let dp: (r: UInt8, g: UInt8, b: UInt8)? = WatermarkTile.samplePixel(tiles.darker, x: x, y: y)
            XCTAssertEqual(lp?.r, l, line: line)
            XCTAssertEqual(lp?.g, l, line: line)
            XCTAssertEqual(lp?.b, l, line: line)
            XCTAssertEqual(dp?.r, k, line: line)
            XCTAssertEqual(dp?.g, k, line: line)
            XCTAssertEqual(dp?.b, k, line: line)
        }
        check(0, 0, 5)
        check(1, 0, -5)
        check(2, 0, 0)
        check(3, 0, 3)
        check(0, 1, -3)
        check(1, 1, 1)
        check(2, 1, -1)
        check(3, 1, 5)
    }

    @MainActor
    func testWatermarkLayersFrameContainsContentBoundsForRandomPhases() {
        let delta: [Int8] = [Int8](repeating: 2, count: 168 * 168)
        let tiles: (lighter: CGImage, darker: CGImage) =
            WatermarkTile.make(delta: delta, width: 168, height: 168, scale: 1)
        let parent: CALayer = CALayer()
        let contentBounds: CGRect = CGRect(x: 0, y: 0, width: 393, height: 700)
        parent.frame = contentBounds
        for _ in 0..<12 {
            let phase: CGPoint = WatermarkOverlay.randomPhase()
            XCTAssertTrue(phase.x >= 0 && phase.x < 168 && phase.y >= 0 && phase.y < 168)
            let layers: WatermarkLayers = WatermarkLayers(lighter: tiles.lighter, darker: tiles.darker, phase: phase)
            layers.install(in: parent, displayScale: 3)
            layers.layout(contentBounds: contentBounds)
            for layer in [layers.lighterLayer, layers.darkerLayer] {
                XCTAssertTrue(layer.frame.contains(contentBounds),
                              "overlay frame \(layer.frame) must contain \(contentBounds) for phase \(phase)")
                XCTAssertEqual(layer.bounds.origin, phase)
                XCTAssertEqual(layer.frame, contentBounds.insetBy(dx: -168, dy: -168))
                XCTAssertNotNil(layer.backgroundColor)
            }
            XCTAssertEqual(layers.lighterLayer.compositingFilter as? String, "plusL")
            XCTAssertEqual(layers.darkerLayer.compositingFilter as? String, "plusD")
            XCTAssertTrue(parent.masksToBounds)
            layers.removeFromSuperlayer()
        }
        XCTAssertEqual(parent.sublayers?.count ?? 0, 0)
    }

    @MainActor
    func testCaptureProtectedImageViewDisplaysAndClears() throws {
        let w: UIWindow = makeWindow()
        let delta: [Int8] = [Int8](repeating: 0, count: 16 * 16)
        let tiles: (lighter: CGImage, darker: CGImage) =
            WatermarkTile.make(delta: delta, width: 16, height: 16, scale: 1)
        let view: CaptureProtectedImageView = CaptureProtectedImageView(frame: w.bounds)
        w.addSubview(view)
        let owned: UnsafeMutableRawBufferPointer = UnsafeMutableRawBufferPointer.allocate(byteCount: 64, alignment: 8)
        owned.copyBytes(from: [UInt8](repeating: 0xAB, count: 64))
        try view.display(tiles.lighter, source: nil, decryptBuffer: owned)
        XCTAssertTrue((view.layer as? AVSampleBufferDisplayLayer)?.preventsCapture ?? false)
        view.setWatermark(WatermarkLayers(lighter: tiles.lighter, darker: tiles.darker, phase: CGPoint(x: 10, y: 20)))
        view.setNeedsLayout()
        view.layoutIfNeeded()
        XCTAssertEqual(view.layer.sublayers?.count ?? 0, 2)
        view.clear()                // scrubs + deallocates `owned`
        view.setWatermark(nil)
        XCTAssertEqual(view.layer.sublayers?.count ?? 0, 0)
    }
}
