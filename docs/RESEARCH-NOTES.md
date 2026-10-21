# Research digest (generated)

### secure-layer: hiding message/media content from screenshots and screen recordings on iOS 17–26 via the UITextField isSecureTextEntry "secure canvas" technique, plus capture detection and the public-API alternative (AVSampleBufferDisplayLayer.preventsCapture)
- [high] Apple's own documentation for isSecureTextEntry states the effect we rely on: "Setting this property to true in any view that conforms to UITextInputTraits disables the user's ability to copy the text in the view and, in some cases, also disables the user's ability to record and broadcast the text in the view." The render server blanks the text field's secure canvas layer in screenshots, screen recordings, AirPlay mirroring and the App Switcher snapshot. There is NO public API to block screenshots of arbitrary views; Apple DTS says so repeatedly (threads 767320, 788571, 838583) and recommends detection via sceneCaptureState instead. Our design therefore uses: (1) the secure-canvas trick (best effort, undocumented hierarchy), (2) sceneCaptureState / isSceneCaptured to replace content while recording/mirroring is active, (3) userDidTakeScreenshotNotification to log + notify the peer, in that order of priority. (https://developer.apple.com/documentation/uikit/uitextinputtraits/issecuretextentry ; https://developer.apple.com/forums/thread/767320 ; https://developer.apple.com/forums/thread/788571 ; https://developer.apple.com/forums/thread/838583)
- [high] Which subview to use: on iOS 15 through iOS 26 the secure canvas is the UITextField's DIRECT SUBVIEW of private class `_UITextLayoutCanvasView` (iOS 13–14: `_UITextFieldCanvasView`; iOS 12: `_UITextFieldContentView`). Locate it by class-name string (`String(describing: type(of: subview)).hasSuffix("CanvasView")`), never by layer index. Evidence: an Apple-forum post from July 2025 (iOS 18 era) ships exactly this lookup in production; the Flutter package secure_text_widget uses the same `contains("CanvasView")` lookup and its 0.1.1 changelog states "Confirmed compatibility with iOS 26; documented supported range as iOS 13 → 26". The canvas is created LAZILY by UIKit (after the field is in a window and laid out), so call `textField.layoutIfNeeded()` and retry in didMoveToWindow/layoutSubviews. UITextField lays the canvas out one text-line tall regardless of the field's frame, so the canvas frame must be forced to the field's bounds after `super.layoutSubviews()`. (https://developer.apple.com/forums/thread/792624 ; https://github.com/cup-of-Aygiz/secure_text_widget (ios/Classes/SecureTextView.swift, CHANGELOG.md, README.md) ; https://pub.dev/packages/secure_text_widget)
```
// Verified lookup (public API only; private class located by name)
func secureCanvas(in field: UITextField) -> UIView? {
    field.layoutIfNeeded() // forces lazy creation of the private subtree
    return field.subviews.first { String(describing: type(of: $0)).hasSuffix("CanvasView") }
}
// iOS 15–26: "_UITextLayoutCanvasView"; iOS 13–14: "_UITextFieldCanvasView"
```
- [high] Layer-index variants (`textField.layer.sublayers?.first` vs `.last`) are what broke across versions and are the source of the 'iOS 17 broke it' / 'iOS 18 broke it' reports. The accepted answer on the iOS 17 thread had to switch from `.first` to `.last` for its window-reparenting variant; Expo's current (2026) expo-screen-capture uses `textField.layer.sublayers?.first` and ships in Expo SDK 54+ (iOS 26). These are mutually contradictory anecdotes about the same hierarchy, which is exactly why we select by subview class name instead of layer position. The Oct-2024 'no longer works in iOS 18' thread contains no code and no Apple confirmation; the per-view canvas approach has multiple reports of working on iOS 18 and 26. (https://developer.apple.com/forums/thread/736112 ; https://raw.githubusercontent.com/expo/expo/main/packages/expo-screen-capture/ios/SecureWindowCanvas.swift ; https://developer.apple.com/forums/thread/767320)
```
// Expo main (2026), SecureWindowCanvas.swift — whole-window variant, shown for reference, NOT recommended for Kilit:
let textField = UITextField()
textField.isSecureTextEntry = true
textField.isUserInteractionEnabled = false
textField.backgroundColor = .clear
textField.frame = window.bounds
originalParent.addSublayer(textField.layer)
guard let canvasLayer = textField.layer.sublayers?.first else { /* fail */ }
window.layer.removeFromSuperlayer()
canvasLayer.addSublayer(window.layer)
```
- [high] Do NOT use the whole-window layer-reparenting variant (`window.layer.superlayer?.addSublayer(field.layer); field.layer.sublayers?.first/last?.addSublayer(window.layer)`). Documented failure modes: Expo changelog PR #49372 'repeated preventScreenCaptureAsync call ... corrupting the layer hierarchy and permanently black-screening the app'; ScreenProtectorKit deprecated its `configurePreventionScreenshot()` with message 'This API will be removed in a future release due to crashes on some devices'; Apple forum 838583 reports 'App is hang after go back from a screen that's protected' and black screen during transitions; forum 736112 reports it disables screenshots for the entire app. Use the per-view container (content inside the canvas) instead. (https://raw.githubusercontent.com/expo/expo/main/packages/expo-screen-capture/CHANGELOG.md ; https://raw.githubusercontent.com/prongbang/ScreenProtectorKit/main/Sources/ScreenProtectorKit/ScreenProtectorKit.swift ; https://developer.apple.com/forums/thread/838583)
- [high] Exact UIKit implementation for Kilit (iOS 17+). SecureHostField is a UITextField subclass that never becomes first responder, forwards hit-testing to the hosted content (so hold-to-reveal long-press gestures inside work) and forces the canvas to fill its bounds. SecureCanvasView exposes `contentView` (Auto Layout works normally inside it) and an `isProtected` canary that is false if UIKit's private hierarchy changed (content is then shown unprotected and the app must fall back to detection-only mode and tell the user). (knowledge (assembled from the verified sources above: forum 792624 code, secure_text_widget SecureTextView.swift, Apple UIKit docs))
```
import UIKit

/// UITextField that never takes focus and keeps its private secure canvas
/// sized to its own bounds. Public API only; the private subview is
/// located by class-name suffix ("_UITextLayoutCanvasView" on iOS 15–26).
final class SecureHostField: UITextField {

    var secureCanvas: UIView? {
        subviews.first { String(describing: type(of: $0)).hasSuffix("CanvasView") }
    }

    /// Hit-testing is forwarded to this view (the hosted content).
    weak var hostedContent: UIView?

    override init(frame: CGRect) {
        super.init(frame: frame)
        isSecureTextEntry = true
        borderStyle = .none
        backgroundColor = .clear
        textColor = .clear      // never use alpha: it propagates to the canvas
        tintColor = .clear
        clipsToBounds = true
        autocorrectionType = .no
        spellCheckingType = .no
        isAccessibilityElement = false
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) is not supported") }

    override var canBecomeFirstResponder: Bool { false }

    override func textRect(forBounds bounds: CGRect) -> CGRect { bounds }
    override func editingRect(forBounds bounds: CGRect) -> CGRect { bounds }
    override func placeholderRect(forBounds bounds: CGRect) -> CGRect { bounds }

    override func layoutSubviews() {
        super.layoutSubviews()
        // UITextField lays its canvas out one text line tall; force it to fill.
        if let canvas = secureCanvas {
            canvas.frame = bounds
            canvas.clipsToBounds = true
        }
    }

    override func hitTest(_ point: CGPoint, with event: UIEvent?) -> UIView? {
        guard let content = hostedContent, !content.isHidden, content.alpha > 0.01 else { return nil }
        return content.hitTest(content.convert(point, from: self), with: event)
    }

    override func gestureRecognizerShouldBegin(_ gestureRecognizer: UIGestureRecognizer) -> Bool { false }
}

/// Container whose `contentView` is rendered inside the secure canvas.
/// Subviews of `contentView` are blanked by the render server in screenshots,
/// screen recordings and AirPlay mirroring (physical devices only).
public final class SecureCanvasView: UIView {

    public let contentView = UIView()

    /// true when `contentView` really sits inside the secure canvas.
    public private(set) var isProtected = false

    /// Called once the view is in a window, with the final protection state.
    public var onProtectionChange: ((Bool) -> Void)?

    private let field = SecureHostField(frame: .zero)
    private var contentConstraints: [NSLayoutConstraint] = []

    public override init(frame: CGRect) {
        super.init(frame: frame)
        backgroundColor = .clear
        field.translatesAutoresizingMaskIntoConstraints = false
        addSubview(field)
        NSLayoutConstraint.activate([
            field.leadingAnchor.constraint(equalTo: leadingAnchor),
            field.trailingAnchor.constraint(equalTo: trailingAnchor),
            field.topAnchor.constraint(equalTo: topAnchor),
            field.bottomAnchor.constraint(equalTo: bottomAnchor),
        ])
        contentView.backgroundColor = .clear
        contentView.translatesAutoresizingMaskIntoConstraints = false
        field.hostedContent = contentView
        attachContent()
    }

    public required init?(coder: NSCoder) { fatalError("init(coder:) is not supported") }

    public override func didMoveToWindow() {
        super.didMoveToWindow()
        field.layoutIfNeeded()   // forces lazy creation of the private canvas
        attachContent()
        if window != nil { onProtectionChange?(isProtected) }
    }

    public override func layoutSubviews() {
        super.layoutSubviews()
        if !isProtected { attachContent() }
    }

    private func attachContent() {
        let canvas = field.secureCanvas
        let host: UIView = canvas ?? self
        guard contentView.superview !== host else { return }
        NSLayoutConstraint.deactivate(contentConstraints)
        contentView.removeFromSuperview()
        host.addSubview(contentView)
        contentConstraints = [
            contentView.leadingAnchor.constraint(equalTo: host.leadingAnchor),
            contentView.trailingAnchor.constraint(equalTo: host.trailingAnchor),
            contentView.topAnchor.constraint(equalTo: host.topAnchor),
            contentView.bottomAnchor.constraint(equalTo: host.bottomAnchor),
        ]
        NSLayoutConstraint.activate(contentConstraints)
        isProtected = (canvas != nil)
    }

    public override var intrinsicContentSize: CGSize { contentView.intrinsicContentSize }
}
```
- [high] SwiftUI integration: wrap with UIViewControllerRepresentable (not UIViewRepresentable) so the UIHostingController gets proper child containment (environment, safe areas, sheets propagate). Sizing uses `sizeThatFits(_:uiViewController:context:)` (iOS 16+, verified signature) delegating to `UIHostingController.sizeThatFits(in:)` (iOS 13+) and `hosting.sizingOptions = [.intrinsicContentSize]` (iOS 16+, verified) so content size changes invalidate layout. In a List/ScrollView this works per-row (proposal width finite, height nil → intrinsic height) and for a full-size region (both finite → fills). Recommended usage in Kilit: ONE SecureContainer around the whole conversation content area (the message List) and ONE around the protected media viewer; do not wrap every message bubble (one hidden UITextField + hosting controller per container). (https://developer.apple.com/documentation/swiftui/uiviewcontrollerrepresentable/sizethatfits(_:uiviewcontroller:context:) ; https://developer.apple.com/documentation/swiftui/uihostingcontroller/sizethatfits(in:) ; https://developer.apple.com/documentation/swiftui/uihostingcontroller/sizingoptions ; https://developer.apple.com/documentation/swiftui/uihostingcontrollersizingoptions)
```
import SwiftUI
import UIKit

public final class SecureHostingController<Content: View>: UIViewController {
    public let hosting: UIHostingController<Content>
    public let secureView = SecureCanvasView(frame: .zero)

    public init(rootView: Content) {
        hosting = UIHostingController(rootView: rootView)
        super.init(nibName: nil, bundle: nil)
    }
    public required init?(coder: NSCoder) { fatalError("init(coder:) is not supported") }

    public override func loadView() { view = secureView }

    public override func viewDidLoad() {
        super.viewDidLoad()
        hosting.view.backgroundColor = .clear
        hosting.sizingOptions = [.intrinsicContentSize]   // iOS 16+
        addChild(hosting)
        hosting.view.translatesAutoresizingMaskIntoConstraints = false
        secureView.contentView.addSubview(hosting.view)
        NSLayoutConstraint.activate([
            hosting.view.leadingAnchor.constraint(equalTo: secureView.contentView.leadingAnchor),
            hosting.view.trailingAnchor.constraint(equalTo: secureView.contentView.trailingAnchor),
            hosting.view.topAnchor.constraint(equalTo: secureView.contentView.topAnchor),
            hosting.view.bottomAnchor.constraint(equalTo: secureView.contentView.bottomAnchor),
        ])
        hosting.didMove(toParent: self)
    }
}

/// Everything inside `content` is blanked in screenshots/recordings/AirPlay.
public struct SecureContainer<Content: View>: UIViewControllerRepresentable {
    private let content: Content
    private let onProtectionChange: ((Bool) -> Void)?

    public init(onProtectionChange: ((Bool) -> Void)? = nil, @ViewBuilder content: () -> Content) {
        self.content = content()
        self.onProtectionChange = onProtectionChange
    }

    public func makeUIViewController(context: Context) -> SecureHostingController<Content> {
        let vc = SecureHostingController(rootView: content)
        vc.secureView.onProtectionChange = onProtectionChange
        return vc
    }

    public func updateUIViewController(_ uiViewController: SecureHostingController<Content>, context: Context) {
        uiViewController.hosting.rootView = content
    }

    public func sizeThatFits(_ proposal: ProposedViewSize, uiViewController: SecureHostingController<Content>, context: Context) -> CGSize? {
        let target = CGSize(
            width: proposal.width ?? UIView.layoutFittingExpandedSize.width,
            height: proposal.height ?? UIView.layoutFittingExpandedSize.height)
        return uiViewController.hosting.sizeThatFits(in: target)
    }
}

// Usage:
// SecureContainer(onProtectionChange: { ok in diagnostics.secureCanvasAvailable = ok }) {
//     MessageListView(conversation: conversation)
// }
```
- [medium] Screen recording / mirroring behaviour of the secure canvas: it is blanked (black) in Control Center screen recording, ReplayKit in-app recording, AirPlay mirroring and the App Switcher snapshot, on physical devices. Apple's doc wording ('disables the user's ability to record and broadcast the text') plus three independent library authors (secure_text_widget: 'screenshots, screen recordings, AirPlay mirroring and the App Switcher preview'; privacy_mask: 'black out recordings and screenshots', test with 'Screen Recording or Screen Mirroring'). QuickTime USB capture from a Mac uses the same system capture path (UIScreen.isCaptured becomes true) and is expected to blank too — medium confidence, must be tested by the owner. KNOWN EXCEPTION: macOS iPhone Mirroring. screen_security's docs report that on 'an iPhone 13 Pro Max running iOS 26.5.2' the mirrored screen 'did not honor the secure text-field layer or report an active public scene capture state'. Nothing at app level mitigates that; document it in the threat model (and note that managed devices can disable iPhone Mirroring via MDM). The iOS SIMULATOR does not apply the blanking ('the Simulator bypasses the iOS Render Server'), so Simulator screenshots are not a valid test. (https://developer.apple.com/documentation/uikit/uitextinputtraits/issecuretextentry ; https://pub.dev/packages/secure_text_widget ; https://pub.dev/documentation/privacy_mask/1.0.6/ ; https://pub.dev/documentation/screen_security/1.1.1/)
- [high] Capture-state detection APIs (all verified on developer.apple.com): `UITraitCollection.sceneCaptureState: UISceneCaptureState` (iOS 17.0+; cases `.active`, `.inactive`, `.unspecified`), SwiftUI `@Environment(\.isSceneCaptured)` (`var isSceneCaptured: Bool`, iOS 17.0+: 'whether the scene is actively being cloned to another destination (like during AirPlay) or is being mirrored or recorded'), `UIScreen.isCaptured` (iOS 11, DEPRECATED in iOS 27.0 with message 'Use the sceneCaptureState in UITraitCollection instead'), `UIScreen.capturedDidChangeNotification` (iOS 11+, not deprecated, posted on the main actor, object = UIScreen, no userInfo), `UIApplication.userDidTakeScreenshotNotification` (iOS 7+, 'This notification posts AFTER the screenshot is taken' — it cannot be used to hide content pre-emptively). Apple's article 'Protecting sensitive content when screen sharing and remote control are active' shows the UIKit registration form `registerForTraitChanges([UITraitSceneCaptureState.self]) { (self: Self, previousTraitCollection: UITraitCollection) in ... }`. Note: that article compares against `.notCaptured`, which does NOT exist in the UISceneCaptureState documentation (cases are active/inactive/unspecified) — use `== .active`. Since Kilit's minimum is iOS 17, use the trait/environment, not UIScreen.isCaptured. (https://developer.apple.com/documentation/uikit/uitraitcollection/scenecapturestate ; https://developer.apple.com/documentation/uikit/uiscenecapturestate ; https://developer.apple.com/documentation/swiftui/environmentvalues/isscenecaptured ; https://developer.apple.com/documentation/uikit/uiscreen/iscaptured ; https://developer.apple.com/documentation/uikit/uiscreen/captureddidchangenotification ; https://developer.apple.com/documentation/uikit/uiapplication/userdidtakescreenshotnotification ; https://developer.apple.com/documentation/swiftui/protecting-sensitive-content-when-screen-sharing)
```
import SwiftUI
import UIKit

/// Second line of defence (public API, iOS 17+): replaces content while the
/// scene is recorded / mirrored / AirPlayed, and reports screenshots.
struct CaptureProtection: ViewModifier {
    @Environment(\.isSceneCaptured) private var isSceneCaptured
    let onScreenshot: () -> Void

    func body(content: Content) -> some View {
        content
            .overlay {
                if isSceneCaptured {
                    ZStack {
                        Rectangle().fill(.background)
                        Label("Ekran kaydı sırasında içerik gizli", systemImage: "eye.slash")
                    }
                }
            }
            .onReceive(NotificationCenter.default.publisher(for: UIApplication.userDidTakeScreenshotNotification)) { _ in
                onScreenshot()   // log locally + send encrypted "screenshot" system event to the peer
            }
    }
}

extension View {
    func captureProtected(onScreenshot: @escaping () -> Void) -> some View {
        modifier(CaptureProtection(onScreenshot: onScreenshot))
    }
}

// UIKit equivalent (iOS 17+), e.g. in a UIViewController:
// registerForTraitChanges([UITraitSceneCaptureState.self]) { (self: Self, _: UITraitCollection) in
//     self.setCaptureOverlay(visible: self.traitCollection.sceneCaptureState == .active)
// }
// Legacy notification still valid on iOS 17–26:
// NotificationCenter.default.addObserver(forName: UIScreen.capturedDidChangeNotification, object: nil, queue: .main) { note in
//     let captured = (note.object as? UIScreen)?.isCaptured ?? false   // isCaptured deprecated iOS 27
// }
```
- [medium] FairPlay/DRM is NOT needed and the public-API alternative exists: `AVSampleBufferDisplayLayer.preventsCapture: Bool` (iOS 13.0+, 'A Boolean value that indicates whether the layer protects against screen capture'). FairPlay Streaming only blacks out FPS-encrypted HLS video (UIScreen.isCaptured doc: 'The system doesn't include video content encrypted using FairPlay Streaming when recording, mirroring, or using AirPlay'), requires a key server and FPS licensing, and cannot carry still images or text. preventsCapture gives the same render-server protection for ANY pixel buffer we enqueue, with zero private API — it is the recommended mechanism for the protected photo viewer (decode in memory → CVPixelBuffer → CMSampleBuffer → enqueue), and a possible fallback for text (render text to an image) if the secure-canvas canary ever fails. Caveats from the field: a forum poster confirms preventsCapture=true 'blocks screenshots from physical hardware buttons'; another reports that with preventsCapture=true a ReplayKit broadcast extension never starts (recording may fail outright rather than show a black rectangle) — acceptable for Kilit but must be tested. `AVSampleBufferDisplayLayer.enqueue(_:)` is DEPRECATED in iOS 18.0 ('Use sampleBufferRenderer's enqueueSampleBuffer: instead'); use `layer.sampleBufferRenderer` (AVSampleBufferVideoRenderer, iOS 17.0+) `.enqueue(_:)`. `CMSampleBufferCreateReadyWithImageBuffer(allocator:imageBuffer:formatDescription:sampleTiming:sampleBufferOut:)` signature verified. (https://developer.apple.com/documentation/avfoundation/avsamplebufferdisplaylayer/preventscapture ; https://developer.apple.com/documentation/avfoundation/avsamplebufferdisplaylayer/enqueue(_:) ; https://developer.apple.com/documentation/avfoundation/avsamplebufferdisplaylayer/samplebufferrenderer ; https://developer.apple.com/documentation/coremedia/cmsamplebuffercreatereadywithimagebuffer(allocator:imagebuffer:formatdescription:sampletiming:samplebufferout:) ; https://developer.apple.com/forums/thread/693299 ; https://developer.apple.com/forums/thread/722846 ; https://developer.apple.com/documentation/uikit/uiscreen/iscaptured)
```
import AVFoundation
import CoreMedia
import CoreVideo
import UIKit

/// Shows a decrypted CGImage through an AVSampleBufferDisplayLayer with
/// preventsCapture = true (public API, iOS 13+; renderer path iOS 17+).
final class CaptureProtectedImageView: UIView {

    enum DisplayError: Error { case pixelBuffer, context, formatDescription, sampleBuffer }

    override class var layerClass: AnyClass { AVSampleBufferDisplayLayer.self }
    private var displayLayer: AVSampleBufferDisplayLayer { layer as! AVSampleBufferDisplayLayer }

    override init(frame: CGRect) {
        super.init(frame: frame)
        displayLayer.preventsCapture = true
        displayLayer.videoGravity = .resizeAspect
        backgroundColor = .black
    }
    required init?(coder: NSCoder) { fatalError("init(coder:) is not supported") }

    func display(_ image: CGImage) throws {
        let pixelBuffer = try Self.makePixelBuffer(from: image)

        var formatDescription: CMVideoFormatDescription?
        guard CMVideoFormatDescriptionCreateForImageBuffer(
            allocator: kCFAllocatorDefault,
            imageBuffer: pixelBuffer,
            formatDescriptionOut: &formatDescription) == noErr,
              let formatDescription else { throw DisplayError.formatDescription }

        var timing = CMSampleTimingInfo(duration: .invalid, presentationTimeStamp: .zero, decodeTimeStamp: .invalid)
        var sampleBuffer: CMSampleBuffer?
        guard CMSampleBufferCreateReadyWithImageBuffer(
            allocator: kCFAllocatorDefault,
            imageBuffer: pixelBuffer,
            formatDescription: formatDescription,
            sampleTiming: &timing,
            sampleBufferOut: &sampleBuffer) == noErr,
              let sampleBuffer else { throw DisplayError.sampleBuffer }

        if let attachments = CMSampleBufferGetSampleAttachmentsArray(sampleBuffer, createIfNecessary: true) as? [NSMutableDictionary],
           let first = attachments.first {
            first[kCMSampleAttachmentKey_DisplayImmediately] = true
        }

        let renderer = displayLayer.sampleBufferRenderer   // iOS 17+
        renderer.flush()
        renderer.enqueue(sampleBuffer)
    }

    func clear() { displayLayer.sampleBufferRenderer.flush() }

    private static func makePixelBuffer(from image: CGImage) throws -> CVPixelBuffer {
        let attrs: [CFString: Any] = [
            kCVPixelBufferCGImageCompatibilityKey: true,
            kCVPixelBufferCGBitmapContextCompatibilityKey: true,
            kCVPixelBufferIOSurfacePropertiesKey: [:] as CFDictionary
        ]
        var buffer: CVPixelBuffer?
        guard CVPixelBufferCreate(kCFAllocatorDefault, image.width, image.height,
                                  kCVPixelFormatType_32BGRA, attrs as CFDictionary, &buffer) == kCVReturnSuccess,
              let buffer else { throw DisplayError.pixelBuffer }
        CVPixelBufferLockBaseAddress(buffer, [])
        defer { CVPixelBufferUnlockBaseAddress(buffer, []) }
        guard let context = CGContext(
            data: CVPixelBufferGetBaseAddress(buffer),
            width: image.width, height: image.height,
            bitsPerComponent: 8,
            bytesPerRow: CVPixelBufferGetBytesPerRow(buffer),
            space: CGColorSpaceCreateDeviceRGB(),
            bitmapInfo: CGBitmapInfo.byteOrder32Little.rawValue | CGImageAlphaInfo.premultipliedFirst.rawValue
        ) else { throw DisplayError.context }
        context.draw(image, in: CGRect(x: 0, y: 0, width: image.width, height: image.height))
        return buffer
    }
}
```
- [high] Verification plan the owner can run on the Mac (no Linux-side test possible). (1) XCTest canary that fails loudly when UIKit's private hierarchy changes (runs in Simulator too, because the subview exists there even though blanking is not applied). (2) Manual device checklist: hardware screenshot, Control Center recording, AirPlay to Apple TV, QuickTime capture over USB, App Switcher, iPhone Mirroring (expected to FAIL — document). Test target needs a host app (TEST_HOST) because it creates a UIWindow.
```
import XCTest
@testable import Kilit

final class SecureCanvasTests: XCTestCase {
    @MainActor
    func testSecureCanvasIsDiscoverable() {
        let window = UIWindow(frame: CGRect(x: 0, y: 0, width: 320, height: 480))
        let view = SecureCanvasView(frame: window.bounds)
        window.addSubview(view)
        window.isHidden = false
        view.layoutIfNeeded()
        XCTAssertTrue(view.isProtected,
            "Secure canvas subview not found: UIKit changed the UITextField hierarchy on this iOS; screenshot blanking is OFF")
    }

    @MainActor
    func testHitTestReachesContent() {
        let window = UIWindow(frame: CGRect(x: 0, y: 0, width: 320, height: 480))
        let view = SecureCanvasView(frame: window.bounds)
        window.addSubview(view)
        window.isHidden = false
        let button = UIButton(type: .system)
        button.translatesAutoresizingMaskIntoConstraints = false
        view.contentView.addSubview(button)
        NSLayoutConstraint.activate([
            button.leadingAnchor.constraint(equalTo: view.contentView.leadingAnchor),
            button.trailingAnchor.constraint(equalTo: view.contentView.trailingAnchor),
            button.topAnchor.constraint(equalTo: view.contentView.topAnchor),
            button.bottomAnchor.constraint(equalTo: view.contentView.bottomAnchor),
        ])
        view.layoutIfNeeded()
        XCTAssertTrue(view.hitTest(CGPoint(x: 10, y: 10), with: nil) === button)
    }
}
```
- [medium] App Review posture: the technique calls only public API (UITextField, subviews, Auto Layout) and compares class names as strings; no private selectors (never call `setValue(_:forKey:"disableUpdateMask")` or similar — that IS private API). Apple DTS states 'There's no supported way for you to prevent screen captures with the public APIs currently available' and that apps 'depending on APIs that are subject to change without notice' risk rejection or breakage, but Apple has not said this specific pattern is rejected; it ships today in Expo (expo-screen-capture, SDK 53–55), several Flutter plugins and many banking apps. Design accordingly: treat blanking as best-effort, keep the `isProtected` canary + detection fallback, and never promise 'screenshots are impossible' in UI copy (also because a second phone camera defeats it — the watermark and the experimental flicker exist for that). (https://developer.apple.com/forums/thread/788571 ; https://developer.apple.com/forums/thread/767320 ; https://developer.apple.com/forums/thread/792624 ; https://raw.githubusercontent.com/expo/expo/main/packages/expo-screen-capture/ios/ScreenCaptureModule.swift)
Pitfalls: Never select the secure layer by index (`layer.sublayers?.first` / `.last`): that index is what flipped between iOS 16/17 and is contradicted between sources; select the SUBVIEW whose class name ends in "CanvasView" (`_UITextLayoutCanvasView` on iOS 15–26). | Never re-parent the whole window layer into the text field (the 'protect the whole app' variant): documented permanent black screens on repeated calls (Expo #49372), hangs/black transitions (Apple forum 838583) and crashes (ScreenProtectorKit deprecation note). Protect specific regions with SecureCanvasView instead. | The canvas is created lazily: look it up only after the field is in a window and `layoutIfNeeded()` ran; retry in `didMoveToWindow` / `layoutSubviews`. If it is never found, content silently renders UNPROTECTED — surface `isProtected == false` in diagnostics and switch the conversation to detection-only mode (notify the peer that this device cannot blank). | UITextField sizes the canvas to one text line; override `layoutSubviews` in the UITextField subclass and set `canvas.frame = bounds` after `super.layoutSubviews()`, plus override `textRect(forBounds:)`/`editingRect(forBounds:)` to return `bounds`. | Do not set `alpha` on the text field (it multiplies into the canvas and the hosted content); hide its own chrome with `.clear` colours and `borderStyle = .none`. | If content inside needs touches (hold-to-reveal long press, scrolling the List), do NOT set `isUserInteractionEnabled = false` on the field (Expo does, but it hosts nothing interactive). Instead override `canBecomeFirstResponder` → false, `gestureRecognizerShouldBegin(_:)` → false and forward `hitTest` to the hosted content; set `isAccessibilityElement = false` or VoiceOver announces a 'secure text field'. | Simulator does not apply render-server blanking; Simulator 'Device > Trigger Screenshot' proves nothing. All capture tests must run on a physical device. | macOS iPhone Mirroring (reported on iOS 26) bypasses BOTH the secure canvas and sceneCaptureState/isSceneCaptured — there is no app-level mitigation; put it in the threat model/README. | `UIApplication.userDidTakeScreenshotNotification` posts AFTER the capture; it can only log/notify. Only the secure canvas (or preventsCapture) removes content from the image itself. | `UIScreen.isCaptured` is deprecated in iOS 27 and `UIScreen.main` since iOS 16: with min iOS 17 use `@Environment(\.isSceneCaptured)` / `UITraitCollection.sceneCaptureState == .active`; `UIScreen.capturedDidChangeNotification` is still non-deprecated if a notification is wanted. | Apple's own 'Protecting sensitive content' article compares `sceneCaptureState != .notCaptured`, but the documented enum cases are `.active`, `.inactive`, `.unspecified` — write `== .active` or the build fails. | `AVSampleBufferDisplayLayer.enqueue(_:)` is deprecated in iOS 18; use `layer.sampleBufferRenderer.enqueue(_:)` (iOS 17+). `preventsCapture = true` may make system/ReplayKit recording fail to start entirely instead of showing a black rectangle — acceptable for Kilit, but test and word the UI accordingly. | The secure canvas also blanks the App Switcher snapshot, but only its own region; add a full-screen privacy overlay on `UIApplication.willResignActiveNotification` for the rest of the UI (Expo does the same). | Do not instantiate one SecureContainer per message bubble in a long List (one hidden UITextField + UIHostingController each). Wrap the conversation content region once; wrap the media viewer once. Use per-bubble containers only where partial reveal genuinely needs an independent region. | Leave `textContentType` nil and never let the field become first responder: a focused secure field triggers Password AutoFill / strong-password UI. | Do not call private API to get the same effect (e.g. KVC `disableUpdateMask` on CALayer): that is a real App Review rejection risk, unlike walking subviews and comparing class names. | This blanks captures only; it does nothing against a second camera (Apple's own objection). That is the job of the forensic watermark (and, optionally, the experimental flicker), not of this layer. | Because no Swift compiler is available on Linux, every signature above was checked against developer.apple.com JSON docs; the only unverifiable parts are private-hierarchy behaviours, which are covered by the XCTest canary the owner runs first on the Mac.

### iOS capture detection (screenshot / screen recording) for the Kilit anti-recording messenger: exact APIs, deprecations, what can be observed vs prevented, what Signal/Telegram ship, App Review position, and SwiftUI/UIWindowScene code
- [high] UIScreen.isCaptured exists since iOS 11.0 and is DEPRECATED in iOS 27.0 (deprecation text: 'Use sceneCaptureState instead'). Semantics: true while the system is actively recording, mirroring, or AirPlay-streaming the screen. With an iOS 17 deployment target and the iOS 26/27 SDK you get a deprecation warning, not an error. Prefer the iOS 17 trait (below); keep isCaptured only as a one-liner fallback via UIWindowScene.screen, never UIScreen.main. (https://developer.apple.com/documentation/uikit/uiscreen/iscaptured (Apple doc JSON: platforms iOS 11.0 deprecatedAt 27.0; deprecationSummary 'Use sceneCaptureState instead'))
```
// UIKit, UIScreen
var isCaptured: Bool { get }   // iOS 11.0+, deprecated iOS 27.0
```
- [high] UIScreen.capturedDidChangeNotification (ObjC: UIScreenCapturedDidChangeNotification) exists since iOS 11.0 and is NOT deprecated. The notification's object is the UIScreen whose isCaptured changed; there is no userInfo; it is posted on the main actor. It fires for recording, mirroring, AirPlay 'or otherwise cloned to another destination'. (https://developer.apple.com/documentation/uikit/uiscreen/captureddidchangenotification)
```
// UIKit, UIScreen
nonisolated class let capturedDidChangeNotification: NSNotification.Name   // iOS 11.0+
```
- [high] UIApplication.userDidTakeScreenshotNotification (ObjC: UIApplicationUserDidTakeScreenshotNotification) exists since iOS 7.0, no userInfo, and Apple's doc states explicitly: 'This notification posts after the screenshot is taken.' It is observe-only: the image is already saved when your handler runs. It is app-wide (no scene-scoped variant exists) and only the foreground app receives it. (https://developer.apple.com/documentation/uikit/uiapplication/userdidtakescreenshotnotification)
```
// UIKit, UIApplication
nonisolated class let userDidTakeScreenshotNotification: NSNotification.Name   // iOS 7.0+
```
- [high] UIScreen.main is formally DEPRECATED in iOS 26.0 ('Use screen instead', i.e. UIWindowScene.screen); it had been 'discouraged' since iOS 16. UIWindowScene.screen is `var screen: UIScreen { get }` (iOS 13+). Get the screen through context: view.window?.windowScene?.screen, or UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }. (https://developer.apple.com/documentation/uikit/uiscreen/main ; https://developer.apple.com/documentation/uikit/uiwindowscene/screen ; https://developer.apple.com/documentation/uikit/uiapplication/connectedscenes)
```
class var main: UIScreen { get }            // UIScreen, iOS 2.0, deprecated iOS 26.0
var screen: UIScreen { get }                 // UIWindowScene, iOS 13.0+
var connectedScenes: Set<UIScene> { get }    // UIApplication, iOS 13.0+
weak var windowScene: UIWindowScene? { get set }  // UIWindow, iOS 13.0+
```
- [high] The scene-based replacement for isCaptured is the iOS 17 trait UITraitCollection.sceneCaptureState: UISceneCaptureState (enum cases .active, .inactive, .unspecified). It is readable on any UITraitEnvironment (UIWindowScene.traitCollection, UIWindow, UIView, UIViewController). Apple's own article says it 'doesn't differentiate between capture types. Screen recording, AirPlay mirroring, and remote control all produce the same signal.' This is the API Apple names as isCaptured's successor and is available on our iOS 17 minimum. (https://developer.apple.com/documentation/uikit/uitraitcollection/scenecapturestate ; https://developer.apple.com/documentation/uikit/uiscenecapturestate)
```
// UIKit, UITraitCollection (iOS 17.0+)
var sceneCaptureState: UISceneCaptureState { get }
enum UISceneCaptureState { case unspecified, inactive, active }
// UIWindowScene
var traitCollection: UITraitCollection { get }   // iOS 13.0+
```
- [high] Trait-change observation (iOS 17): registerForTraitChanges(_:handler:) on UITraitChangeObservable (adopted by UIWindowScene, UIWindow, UIView, UIViewController). The trait type to pass is UITraitSceneCaptureState.self (Apple lists it under 'Registering traits for observation'; three independent open-source iOS apps use exactly `registerForTraitChanges([UITraitSceneCaptureState.self])` on a UIWindowScene). The returned token can be ignored; UIKit cleans up at end of object lifecycle. Closure's first parameter is the observed object (declare as `self: Self` or `(scene: UIWindowScene, _: UITraitCollection)`), so no weak capture is needed. (https://developer.apple.com/documentation/uikit/uitraitchangeobservable-67e94/registerfortraitchanges(_:handler:) ; https://github.com/onejs/one/blob/main/packages/one/ios/Nitro/HybridOneScreenCapture.swift)
```
@discardableResult @MainActor
func registerForTraitChanges<TraitEnvironment>(_ traits: [UITrait], handler: @escaping Self.TraitChangeHandler<TraitEnvironment>) -> any UITraitChangeRegistration where TraitEnvironment : UITraitEnvironment
@MainActor func unregisterForTraitChanges(_ registration: any UITraitChangeRegistration)

// Usage verified in the wild (onejs/one, codenameakshay/secure_content, yexca/kikoto):
let reg = scene.registerForTraitChanges([UITraitSceneCaptureState.self]) { (scene: UIWindowScene, _: UITraitCollection) in
    let captured = scene.traitCollection.sceneCaptureState == .active
}
```
- [high] SwiftUI has a first-class environment value for this on iOS 17: EnvironmentValues.isSceneCaptured (`var isSceneCaptured: Bool { get set }`, iOS 17.0+, Mac Catalyst 17, visionOS 1). Apple: 'Use this value to determine whether the scene is actively being cloned to another destination (like during AirPlay) or is being mirrored or recorded... take appropriate action, like obscuring content.' Read it with @Environment(\.isSceneCaptured). This removes the need for UIScreen or NotificationCenter for the recording case in SwiftUI views. (https://developer.apple.com/documentation/swiftui/environmentvalues/isscenecaptured)
```
// SwiftUI, EnvironmentValues (iOS 17.0+)
var isSceneCaptured: Bool { get set }

struct MessageBubble: View {
    @Environment(\.isSceneCaptured) private var isSceneCaptured
    var body: some View {
        content.redacted(reason: isSceneCaptured ? .placeholder : [])
    }
}
```
- [high] Exact SwiftUI observation code for both notifications via Combine publisher + .onReceive. NotificationCenter.publisher(for:object:) is `func publisher(for name: Notification.Name, object: AnyObject? = nil) -> NotificationCenter.Publisher` (Foundation, iOS 13+); View.onReceive is `nonisolated func onReceive<P>(_ publisher: P, perform action: @escaping (P.Output) -> Void) -> some View where P : Publisher, P.Failure == Never` (iOS 13+). Both notifications are posted on the main thread so no .receive(on:) is required. (https://developer.apple.com/documentation/swiftui/view/onreceive(_:perform:) ; https://developer.apple.com/documentation/foundation/notificationcenter/publisher(for:object:))
```
import SwiftUI
import UIKit

struct CaptureAwareScreen<Content: View>: View {
    @Environment(\.isSceneCaptured) private var isSceneCaptured      // iOS 17+
    @State private var screenshotEvents = 0
    let onScreenshot: () -> Void      // notify peer + append to local log
    let content: Content

    var body: some View {
        content
            .redacted(reason: isSceneCaptured ? .placeholder : [])
            .overlay { if isSceneCaptured { Text("Screen recording active") } }
            .onReceive(NotificationCenter.default.publisher(for: UIApplication.userDidTakeScreenshotNotification)) { _ in
                // Posted AFTER the screenshot was saved. Observe + react only.
                screenshotEvents += 1
                onScreenshot()
            }
            .onReceive(NotificationCenter.default.publisher(for: UIScreen.capturedDidChangeNotification)) { note in
                // Legacy path (iOS 11+). object is the UIScreen; prefer isSceneCaptured on iOS 17.
                let captured = (note.object as? UIScreen)?.isCaptured ?? false
                _ = captured
            }
    }
}
```
- [high] Exact UIWindowScene-based 'is anything capturing' check that avoids UIScreen.main and works on iOS 17 (trait) with an isCaptured fallback kept for completeness. Also a UIKit monitor object that registers for the trait on each connected window scene; use it from the App's UIApplicationDelegateAdaptor or a SceneDelegate, or from a UIViewRepresentable's view. (knowledge, composed from the Apple declarations verified above and the three GitHub usages of registerForTraitChanges([UITraitSceneCaptureState.self]))
```
import UIKit

@MainActor
enum CaptureState {
    static func isAnySceneCaptured() -> Bool {
        UIApplication.shared.connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .contains { scene in
                if #available(iOS 17, *) {
                    return scene.traitCollection.sceneCaptureState == .active
                } else {
                    return scene.screen.isCaptured   // UIScreen via scene, not UIScreen.main
                }
            }
    }
}

@MainActor
final class SceneCaptureMonitor {
    private var registrations: [ObjectIdentifier: any UITraitChangeRegistration] = [:]
    var onChange: ((Bool) -> Void)?

    func attach(_ scene: UIWindowScene) {
        guard registrations[ObjectIdentifier(scene)] == nil else { return }
        onChange?(scene.traitCollection.sceneCaptureState == .active)
        registrations[ObjectIdentifier(scene)] = scene.registerForTraitChanges([UITraitSceneCaptureState.self]) { [weak self] (scene: UIWindowScene, _: UITraitCollection) in
            self?.onChange?(scene.traitCollection.sceneCaptureState == .active)
        }
    }
}
```
- [high] Screenshots cannot be prevented with public API; they can only be observed after the fact. Apple DTS, Oct 2024 (thread 767320): 'There's no supported way for you to prevent screen captures with the public APIs currently available.' Apple DTS, Apr 2026 (thread 824922): 'There are no public APIs available for preventing screenshots at this time.' DTS also notes for isCaptured/UITraitSceneCaptureState an inherent race: content on screen when capture begins 'may be visible in the window before your handler runs' and these are 'not a prevention mechanism'. (https://developer.apple.com/forums/thread/767320 ; https://developer.apple.com/forums/thread/824922)
- [high] App Review position on the secure-UITextField blanking trick (DTS, May 2026, thread 824922, the most explicit statement Apple has made): Guideline 2.5.1 says 'apps should use APIs and frameworks for their intended purposes'; 'The isSecureTextEntry property is intended for secure text input. Using it as a wrapping container for arbitrary views to prevent screen capture is not its intended purpose. The screenshot-prevention behavior you're relying on is a side effect of how secure text fields work, not a documented feature of that API. There is no guarantee that this behavior will continue to work across system software updates.' DTS explicitly declined to predict App Review's verdict and asked for a Feedback Assistant enhancement request. By contrast, DTS confirmed that observing userDidTakeScreenshotNotification (overlay/audit log) and reacting to UIScreen.isCaptured / UITraitSceneCaptureState IS their intended use. No published rejection case for the trick was found; Telegram ships it in production and Signal ships it in internal builds (see below). (https://developer.apple.com/forums/thread/824922)
- [high] App Store Review Guideline 2.5.1 verbatim: 'Apps may only use public APIs and must run on the currently shipping OS... Apps should use APIs and frameworks for their intended purposes and indicate that integration in their app description.' No guideline mentions blanking screenshots or recordings. Guideline 2.5.14 ('Apps must request explicit user consent and provide a clear visual and/or audible indication when recording, logging, or otherwise making a record of user activity') is the one to keep in mind for the 'log screenshot events and notify the other party' feature: disclose it in-app (Telegram/Snapchat style 'X took a screenshot' service message is the accepted pattern). (https://developer.apple.com/app-store/review/guidelines/)
- [high] Apple's own documentation acknowledges the capture side effect of isSecureTextEntry (UITextInputTraits): 'Setting this property to true in any view that conforms to UITextInputTraits disables the user's ability to copy the text in the view and, in some cases, also disables the user's ability to record and broadcast the text in the view.' This is the only public-API hook; its documented scope is 'the text in the view', not arbitrary subviews. (https://developer.apple.com/documentation/uikit/uitextinputtraits/issecuretextentry)
```
optional var isSecureTextEntry: Bool { get set }   // UITextInputTraits
```
- [high] Apple's new (2026) article 'Protecting sensitive content when screen sharing and remote control are active' is the official pattern and introduces NO prevention API: detect via isSceneCaptured (SwiftUI) / sceneCaptureState (UIKit), then (1) inform the person with a neutral banner, (2) hide or redact sensitive fields with placeholder text or a blur overlay, (3) disable high-risk actions. It notes 'The Passwords app uses a similar pattern to protect sensitive content from screenshots' (Apple's own app uses the private layer flag). Recommends applying protection selectively, not an app-wide lockdown. iOS 27 added no public screenshot-blocking API (searched Apple docs, WWDC 2026 coverage; nothing found). (https://developer.apple.com/documentation/swiftui/protecting-sensitive-content-when-screen-sharing)
- [high] How the secure-text-field blanking actually works and why older implementations broke on iOS 17/18: the capture-exclusion flag is set by UITextField on the layer of its private subview `_UITextLayoutCanvasView` (iOS 15+; `_UITextFieldCanvasView` on iOS 14), not on the text field's own layer. Implementations that did `textField.layer.sublayers?.first/last.addSublayer(content)` or `window.layer.superlayer?.addSublayer(field.layer)` stopped working on iOS 17/18 (forum reports 'the UITextField trick no longer works in iOS 18'). The two implementations that still work on iOS 18/26 (Telegram production, Signal 2026) do NOT reparent views at all: they KVC-swap the canvas view's `layer` with the target layer, toggle isSecureTextEntry off->on so UITextField stamps the flag onto that layer, then swap the original layer back. (https://github.com/signalapp/Signal-iOS/blob/main/Signal/Screenshots/ScreenshotBlocking.swift ; https://github.com/TelegramMessenger/Telegram-iOS/blob/master/submodules/UIKitRuntimeUtils/Source/UIKitRuntimeUtils/UIKitUtils.m ; https://developer.apple.com/forums/thread/767320)
```
// Signal-iOS, Signal/Screenshots/ScreenshotBlocking.swift (2026, AGPL-3.0) — verbatim core
static func setBlocksScreenshots(_ blocksScreenshots: Bool, of view: UIView) {
    let textField = UITextField()
    guard
        let screenshotBlockingView = textField.subviews.first,
        String(describing: type(of: screenshotBlockingView)).contains("TextLayoutCanvasView")
    else { return }
    let canvasLayer = screenshotBlockingView.layer
    screenshotBlockingView.setValue(view.layer, forKey: "layer")
    textField.isSecureTextEntry = !blocksScreenshots
    textField.isSecureTextEntry = blocksScreenshots
    screenshotBlockingView.setValue(canvasLayer, forKey: "layer")
}

// Telegram-iOS, submodules/UIKitRuntimeUtils/Source/UIKitRuntimeUtils/UIKitUtils.m — same idea in ObjC
void setLayerDisableScreenshots(CALayer *layer, bool disableScreenshots) {
    static UITextField *textField; static UIView *secureView; static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        textField = [[UITextField alloc] init];
        for (UIView *subview in textField.subviews)
            if ([NSStringFromClass([subview class]) containsString:@"TextLayoutCanvasView"]) { secureView = subview; break; }
    });
    if (secureView == nil) return;
    CALayer *previousLayer = secureView.layer;
    [secureView setValue:layer forKey:@"layer"];
    if (disableScreenshots) { textField.secureTextEntry = false; textField.secureTextEntry = true; }
    else                    { textField.secureTextEntry = true;  textField.secureTextEntry = false; }
    [secureView setValue:previousLayer forKey:@"layer"];
}
```
- [high] The underlying private mechanism is the undocumented CALayer KVC key `disableUpdateMask`; secure text entry sets it to 0x12 = (1<<1)|(1<<4). ScreenShieldKit (Kyle-Ye), daangn/ScreenShieldKit, NSAntoine's demo and OpenSwiftUI all set it directly (`layer.setValue(0x12, forKey: "disableUpdateMask")`, with the string base64-obfuscated to dodge static private-API scanning). SwiftUI's counterpart is the private redaction reason `RedactionReasons.screencaptureProhibited` (rawValue 1<<3, iOS 18+, `@_spi(Private)`). Calling these directly is unambiguous private-API use (2.5.1 'public APIs only'); the UITextField route calls only public API but DTS calls it 'not its intended purpose'. Recommendation for Kilit: use the Signal/Telegram layer-swap (public calls only), never the raw key or the SPI reason; ship it as a feature-flagged layer with a graceful no-op when `TextLayoutCanvasView` is not found. (https://github.com/Kyle-Ye/ScreenShieldKit/blob/main/Sources/ScreenShieldKit/CALayer+ScreenShieldKit.swift ; https://github.com/OpenSwiftUIProject/OpenSwiftUI/blob/main/Sources/OpenSwiftUICore/Render/DisplayList/DisplayListViewPlatform.swift)
```
// ScreenShieldKit CALayer+ScreenShieldKit.swift (MIT) — DO NOT copy into Kilit; shown for understanding only
let hideFlag = (1 << 1) | (1 << 4)           // 0x12
setValue(NSNumber(value: hideFlag), forKey: "disableUpdateMask")   // private CALayer key
```
- [high] What Signal iOS actually does (verified from main branch, Oct 2026): (a) Long-standing 'ScreenLockUI' covers the app with a blocking window on willResignActive so the App Switcher snapshot is blank (the iOS setting is 'Hide Screen in App Switcher'); Signal iOS does NOT notify the other party about screenshots. (b) NEW in Sept–Oct 2026 (commits 'Add internal-only setting for app-wide Screenshot Blocking' 2026-09-16 and 'Expand Screenshot Blocking options; add "disable for 10m"' 2026-10-05): app-wide screenshot blocking applied to every UIWindow via the layer-swap trick, gated by `BuildFlags.screenshotBlocking = build <= .internal` AND `#available(iOS 27, *)`; on userDidTakeScreenshotNotification it shows a 'Screenshot blocked' toast with 'Turn Off for 10 Minutes'. Its user-facing text: 'This blocks screenshots and screen recordings of Signal, including in the App Switcher.' The iOS 27-only gate's reason is not stated in code (likely reliability of the flag on whole windows on older OSes). Takeaway: the leading privacy messenger considers the trick shippable but is rolling it out cautiously, defaults ON, and pairs it with detection-driven UX. (https://github.com/signalapp/Signal-iOS/blob/main/Signal/Screenshots/ScreenshotBlockingManager.swift ; https://github.com/signalapp/Signal-iOS/commit/da7f7b40d425727307a7d426b168ecde77a9d929 ; https://github.com/signalapp/Signal-iOS/commit/c94730b0f7ffc05d2c69bfa7635a6cd664a54645)
```
// Signal ScreenshotBlockingManager.swift
nonisolated static var isAvailable: Bool {
    guard BuildFlags.screenshotBlocking else { return false }
    if #available(iOS 27, *) { return true }
    return false
}
```
- [high] What Telegram iOS actually does (verified from master): secret chats apply setLayerDisableScreenshots(layer, isSecret) to the whole ChatControllerNode layer and to copy-protected media (TransformImageNode.captureProtected, galleries, video thumbnails, pinned panel), i.e. the blanking trick is in production in a top-tier App Store app. Screenshot detection: submodules/ScreenCaptureDetection observes UIApplication.userDidTakeScreenshotNotification (emitting .still) and KVOs UIScreen.main 'captured' (emitting .video on false->true); GalleryController subscribes only when `peerId.namespace == Namespaces.Peer.SecretChat` and sends the 'screenshot taken' service message to the peer. Telegram's source comment documents a real-world quirk: 'UIKit can deliver userDidTakeScreenshotNotification more than once for a single screenshot (observed: two back-to-back deliveries to the same observer)', so they debounce per observer with a 0.5 s window. (https://github.com/TelegramMessenger/Telegram-iOS/blob/master/submodules/ScreenCaptureDetection/Sources/ScreenCaptureDetection.swift ; https://github.com/TelegramMessenger/Telegram-iOS/blob/master/submodules/TelegramUI/Sources/ChatControllerNode.swift)
```
// Telegram ScreenCaptureDetection.swift
private let screenshotRepeatInterval: CFAbsoluteTime = 0.5
// ... in observer: if let last = lastTimestamp, now - last < screenshotRepeatInterval { return }
```
- [high] ReplayKit is NOT a detector of other apps'/system recording. RPScreenRecorder.shared().isRecording only reflects a ReplayKit session this app itself started; system Control Center recording, system broadcasts to broadcast-upload extensions, AirPlay mirroring, Sidecar/Continuity and (per community reports) QuickTime USB capture all surface through UIScreen.isCaptured / sceneCaptureState instead. RPScreenRecorder.shared() and isRecording are DEPRECATED in iOS 27.0 in favour of ScreenCaptureKit (SCStream.isCapturing, iOS 27.0+). Do not add ReplayKit to Kilit. (https://developer.apple.com/documentation/replaykit/rpscreenrecorder/isrecording ; https://developer.apple.com/documentation/screencapturekit/scstream/iscapturing ; https://developer.apple.com/forums/thread/824922 (DTS list of what isCaptured covers))
```
class func shared() -> RPScreenRecorder     // iOS 9.0, deprecated iOS 27.0 'Use ScreenCaptureKit instead'
var isRecording: Bool { get }               // deprecated iOS 27.0 'Use SCStream isCapturing instead'
var isCapturing: Bool { get }               // SCStream, iOS 27.0+
```
- [high] App Switcher snapshot: UIScene.didEnterBackgroundNotification doc says 'Shortly after your notification handler returns, UIKit takes a snapshot of your scene's interface for display in the app switcher. Make sure your interface doesn't contain sensitive user information.' UIScene.willDeactivateNotification is posted for temporary interruptions and before backgrounding. Apple QA1838 pattern: present a cover (no animation; 'The snapshot of your application's window is captured immediately upon returning from this method'). Signal shows its cover already on willResignActive because 'we need to show the screen protection before we become inactive in order for it to be reflected in the app switcher'. In SwiftUI use `@Environment(\.scenePhase)`: `.inactive` -> show cover, `.active` -> remove. (https://developer.apple.com/documentation/uikit/uiscene/didenterbackgroundnotification ; https://developer.apple.com/library/archive/qa/qa1838/_index.html ; https://github.com/signalapp/Signal-iOS/blob/main/Signal/util/ScreenLockUI.swift)
```
nonisolated class let willDeactivateNotification: NSNotification.Name     // UIScene, iOS 13+
nonisolated class let didEnterBackgroundNotification: NSNotification.Name  // UIScene, iOS 13+
nonisolated class let willResignActiveNotification: NSNotification.Name    // UIApplication
```
- [high] SwiftUI .privacySensitive(_:) (iOS 15+) does NOT hide content from screenshots or recordings; it only marks views to be redacted when the `.privacy` redaction reason is applied (widgets / Always-On). It becomes useful only when you drive it yourself: `.redacted(reason: isSceneCaptured ? .privacy : [])` together with `.privacySensitive()` on the message text. Public RedactionReasons are only .invalidated, .placeholder, .privacy. (https://developer.apple.com/documentation/swiftui/view/privacysensitive(_:) ; https://developer.apple.com/documentation/swiftui/redactionreasons)
```
nonisolated func privacySensitive(_ sensitive: Bool = true) -> some View   // iOS 15+
```
- [high] UIScreenshotService / UIWindowScene.screenshotService (iOS 13+) is the API by which an app VOLUNTEERS a full-page PDF of its content when the user screenshots. It is not a prevention hook. Kilit must never set a screenshotService delegate (it would hand the system a high-fidelity PDF of the conversation). (https://developer.apple.com/documentation/uikit/uiscreenshotservice)
```
var screenshotService: UIScreenshotService? { get }   // UIWindowScene, iOS 13+
```
- [medium] Recommended SwiftUI integration of the blanking layer (public calls only): wrap protected SwiftUI content in a UIViewControllerRepresentable that hosts a UIHostingController and applies the Signal-style flag to the hosting view's layer; re-apply in updateUIViewController because the flag lives on the layer object and survives as long as that layer does. Keep an `isSupported` probe (canvas view found) and expose it to Settings so the UI can say 'capture blanking unavailable on this OS' instead of silently failing. Combine with hold-to-reveal so the race window on capture start only ever exposes blurred content. (knowledge, derived from the verified Signal/Telegram implementations; not compiled here (no Swift toolchain) — owner must build on Mac)
```
import SwiftUI
import UIKit

enum CaptureShield {
    /// Returns false when the private subview is missing (future iOS) -> caller falls back to detection-only.
    @MainActor @discardableResult
    static func setHidden(_ hidden: Bool, layerOf view: UIView) -> Bool {
        let field = UITextField()
        guard let canvas = field.subviews.first,
              String(describing: type(of: canvas)).contains("TextLayoutCanvasView") else { return false }
        let original = canvas.layer
        let delegate = view.layer.delegate
        canvas.setValue(view.layer, forKey: "layer")
        field.isSecureTextEntry = !hidden
        field.isSecureTextEntry = hidden
        canvas.setValue(original, forKey: "layer")
        view.layer.delegate = delegate   // defensive: keep the view drawing/laying out
        return true
    }
}

struct ShieldedContent<Content: View>: UIViewControllerRepresentable {
    let enabled: Bool
    @ViewBuilder let content: () -> Content

    func makeUIViewController(context: Context) -> UIHostingController<Content> {
        let host = UIHostingController(rootView: content())
        host.view.backgroundColor = .clear
        CaptureShield.setHidden(enabled, layerOf: host.view)
        return host
    }
    func updateUIViewController(_ host: UIHostingController<Content>, context: Context) {
        host.rootView = content()
        CaptureShield.setHidden(enabled, layerOf: host.view)
    }
}
```
- [medium] iOS 26's new full-screen screenshot preview (Settings > General > Screen Capture > Full-Screen Previews) does not change the API: the screenshot is saved first and userDidTakeScreenshotNotification still posts afterwards (third-party apps report their screenshot-triggered behaviour still fires on iOS 26). No Apple statement found either way; verify on a device with the preview on and off. (https://tutorials.one-sec.app/en/articles/5719810 ; https://9to5mac.com/2025/09/18/ios-26-iphone-screenshot-changed-setting-full-screen/)
- [medium] Coverage of the layer flag in captures (what the user sees): in screenshots the flagged region renders black/blank (Signal: 'it'll be hidden by the blank screenshot'); same for screen recordings, AirPlay mirroring, QuickTime capture from a Mac and, per Signal's text, the App Switcher snapshot. It never affects a phone camera pointed at the screen; that is exactly why the per-viewer watermark and (opt-in) flicker exist. Content under the flag still renders normally on-device. (https://github.com/signalapp/Signal-iOS/blob/main/Signal/Screenshots/ScreenshotBlockingManager.swift ; https://github.com/NSAntoine/HideViewFromScreenCaptureDemo (comment: hides from Control Center recording and Mac QuickTime capture))
- [high] Design decision for Kilit phase 1 (consistent with everything above): (1) Detection is 100% public and Apple-endorsed: @Environment(\.isSceneCaptured) + UITraitSceneCaptureState on UIKit side, plus UIApplication.userDidTakeScreenshotNotification; on either event log locally, send an E2E 'capture' control message to the peer, show a neutral in-app banner, and (for recording) keep message bodies redacted while active. (2) Blanking is the Signal/Telegram layer-swap, applied to the message-list container and the protected media viewer only (selective, as Apple's article advises), feature-flagged and probe-guarded, documented in the App Review notes as 'uses UITextField secure entry rendering for message content'. (3) App-switcher cover on scenePhase == .inactive. (4) Never use UIScreen.main, ReplayKit, UIScreenshotService, or the raw disableUpdateMask key. (knowledge (synthesis of the verified sources above))
Pitfalls: userDidTakeScreenshotNotification fires AFTER the PNG is saved; nothing you do in the handler redacts that screenshot. Only the layer flag (secure-field trick) affects the captured image. Design the UX as 'detected + peer notified', not 'blocked', unless the shield layer is active. | Telegram's source documents that UIKit can post userDidTakeScreenshotNotification twice for one screenshot; debounce per observer (~0.5 s) or you will double-notify the peer and double-log. | Do not use UIScreen.main: deprecated in iOS 26.0 and the iOS 26/27 SDK warns; capturedDidChangeNotification's object is a UIScreen, so compare against windowScene.screen, or just use the iOS 17 trait / isSceneCaptured and skip UIScreen entirely. | UIScreen.isCaptured is deprecated in iOS 27.0 (successor: UITraitCollection.sceneCaptureState / SwiftUI isSceneCaptured, both iOS 17). Since min target is iOS 17, make the trait the primary path; using isCaptured only yields warnings but signals outdated code to reviewers. | sceneCaptureState / isCaptured cannot distinguish screen recording from AirPlay mirroring, Sidecar or remote control (Apple says so explicitly). Use neutral wording ('Screen sharing is active') and do not accuse the user. | There is a race window when capture starts: content already on screen can appear in the first frames before the trait change handler runs (DTS statement). Mitigation: hold-to-reveal default-blurred content, so unrevealed messages are never in the clear. | The secure-field layer flag lives on the private subview `_UITextLayoutCanvasView`'s layer. Implementations that reparent your view into `textField.layer.sublayers.first/last` or that reparent the window's layer broke on iOS 17/18. Use the KVC layer-swap (Signal/Telegram) and probe for the canvas view; if absent, degrade to detection-only and surface that in Settings. | Never call the private CALayer key `disableUpdateMask` or SwiftUI's `@_spi(Private) RedactionReasons.screencaptureProhibited` directly: that is unambiguous private-API use under 2.5.1. The UITextField route uses only public calls but DTS has stated (May 2026) it is 'not its intended purpose' and may stop working at any time; treat it as best-effort, feature-flagged, and document it in App Review notes. | Apply blanking selectively (message list + media viewer), not to every window: Apple's 2026 article warns against blanket lockdowns, and Signal (which does go app-wide) gates it to internal builds and iOS 27+ only, with a 10-minute disable escape hatch for users with legitimate needs. | Swift 6 strict concurrency: the notification constants are `nonisolated class let`, registerForTraitChanges is @MainActor, and NotificationCenter.publisher delivers on the posting thread (main for these); keep observers on the main actor and avoid capturing non-Sendable UIKit objects in detached tasks. | Do not set UIWindowScene.screenshotService.delegate: it exists to hand the system a full-page PDF of your content when a screenshot is taken. | RPScreenRecorder.isRecording is NOT a system-recording detector (only this app's own ReplayKit session) and is deprecated in iOS 27; do not add ReplayKit for detection. | privacySensitive() alone does nothing for screenshots/recordings; it only takes effect with a redaction reason you apply yourself (e.g. driven by isSceneCaptured). | App-switcher snapshot is taken right after the didEnterBackground handler returns; show the cover without animation and, like Signal, already on willResignActive / scenePhase == .inactive so Control Center pull-downs and incoming calls also get the cover. | iOS 26's full-screen screenshot preview does not change notification semantics (still posts after save), but test on an iOS 26/27 device with the preview both on and off; this project cannot compile or run Swift on Linux, so every snippet above must be built once on the owner's Mac before being relied upon. | Guideline 2.5.14 requires consent/indication when 'making a record of user activity'; disclose screenshot/recording logging and peer notification in-app (first-run notice + settings copy) the way Telegram secret chats and Snapchat do.

### display-link: CADisplayLink-driven 120 Hz alternating-mask ("temporal sub-frame") overlay on iOS 17/18 — exact APIs, ProMotion gating, device list, rendering approach, honest physics (eye / camera exposure / rolling shutter), photosensitivity safety (WCAG 2.3.1, Apple HIG, Dim Flashing Lights), and a complete FlickerMaskView UIView subclass
- [high] CADisplayLink.preferredFrameRateRange exists since iOS 15.0 (also visionOS 1, macOS 14). Apple: the link 'makes a best attempt' to call back within the range; the system can lower the range at any time for Low Power Mode, critical thermal state and accessibility settings; default is CAFrameRateRange.default = the display's maximumFramesPerSecond. (https://developer.apple.com/documentation/quartzcore/cadisplaylink/preferredframeraterange)
```
// QuartzCore, iOS 15+
var preferredFrameRateRange: CAFrameRateRange { get set }
// Older API, deprecated iOS 27.2: var preferredFramesPerSecond: Int { get set }
```
- [high] CAFrameRateRange is a struct (iOS 15+). The Swift initializer takes Float values and `preferred` is Optional with a nil default. The three fields may legitimately be set to the same value: Apple's own testing guidance says to 'set maximum, minimum, and preferred to the same value' to pin a rate during tests. (https://developer.apple.com/documentation/quartzcore/caframeraterange/init(minimum:maximum:preferred:))
```
struct CAFrameRateRange
init(minimum: Float, maximum: Float, preferred: Float? = nil)
var minimum: Float
var maximum: Float
var preferred: Float? { get set }
static let `default`: CAFrameRateRange
// usage:
link.preferredFrameRateRange = CAFrameRateRange(minimum: 120, maximum: 120, preferred: 120)
```
- [high] The Info.plist key CADisableMinimumFrameDurationOnPhone (Boolean, iOS 15+) is REQUIRED on iPhone to get anything above 60 Hz: 'If you don't enable this support, Core Animation won't access higher frame rates (above 60Hz)'. With it, preferredFrameRateRange hints for CADisplayLink and CAAnimation are honoured. iPad Pro does not need the key. Without the key the link silently runs at 60 Hz even though UIScreen.maximumFramesPerSecond reports 120. (https://developer.apple.com/documentation/quartzcore/optimizing-iphone-and-ipad-apps-to-support-promotion-displays)
```
<!-- Info.plist (main app target) -->
<key>CADisableMinimumFrameDurationOnPhone</key>
<true/>
```
- [high] Build-system consequence for the synchronized-folder Xcode 16 project: Apple states that Xcode does NOT read user-defined INFOPLIST_KEY_* build settings when generating Info.plist ('a user-defined build setting called INFOPLIST_KEY_ExampleKey doesn't result in Xcode generating an ExampleKey'). CADisableMinimumFrameDurationOnPhone is not one of Xcode's built-in Info.plist-Values settings, so it must be supplied in a real Info.plist referenced by INFOPLIST_FILE. With GENERATE_INFOPLIST_FILE = YES Xcode merges that file with the generated keys. The file must NOT be a member of the target (otherwise it is copied into Resources). Safest layout: keep ios/Kilit/Info.plist OUTSIDE the synchronized Sources folder so the PBXFileSystemSynchronizedRootGroup never picks it up as a resource. (https://developer.apple.com/documentation/bundleresources/managing-your-app-s-information-property-list)
```
// pbxproj build settings (both Debug/Release) for the app target:
GENERATE_INFOPLIST_FILE = YES;
INFOPLIST_FILE = Kilit/Info.plist;   // path relative to project dir, outside the synced Sources/ group
SWIFT_VERSION = 5.0;                 // language mode 5; see concurrency note
IPHONEOS_DEPLOYMENT_TARGET = 17.0;

# XcodeGen project.yml fallback:
targets:
  Kilit:
    type: application
    platform: iOS
    deploymentTarget: "17.0"
    sources: [Kilit/Sources]
    info:
      path: Kilit/Info.plist
      properties:
        CADisableMinimumFrameDurationOnPhone: true
        UIApplicationSceneManifest:
          UIApplicationSupportsMultipleScenes: false
```
- [high] ProMotion devices per Apple's current article: iPhone Air; iPhone 17 and later; iPhone 13 Pro and later; iPhone 13 Pro Max and later; iPad Pro 11-inch, 13-inch, 12.9-inch (2nd gen+), 10.5-inch. Not in the list (60 Hz panels): iPhone 13/14/15/16 non-Pro, iPhone 16e, iPhone SE. Press coverage confirms the base iPhone 17 (2025) was the first non-Pro iPhone with ProMotion and that iPhone 16/16 Plus are 60 Hz. iPhone ProMotion rates: 120, 80, 60, 48, 40, 30, 24, 20, 16, 15, 12, 10 Hz (iPad Pro: 120, 60, 40, 30, 24). Apple: 'you can't force a ProMotion display to show your content at any specific rate'. (https://developer.apple.com/documentation/quartzcore/optimizing-iphone-and-ipad-apps-to-support-promotion-displays)
- [high] UIScreen.maximumFramesPerSecond: Int (iOS 10.3+) is 'up to 120 for devices with ProMotion displays'. It is the hardware ceiling, not the delivered rate. UIScreen.main is deprecated in iOS 26.0 (soft-deprecated earlier), so obtain the screen via the view's window scene: view.window?.windowScene?.screen (UIWindowScene.screen is iOS 13+). Use it only to decide whether to attempt 120 Hz; the real rate must be measured per callback. (https://developer.apple.com/documentation/uikit/uiscreen/maximumframespersecond)
```
var maximumFramesPerSecond: Int { get }   // UIScreen
var screen: UIScreen { get }             // UIWindowScene, iOS 13+
let maxFPS = view.window?.windowScene?.screen.maximumFramesPerSecond ?? 60
```
- [high] CADisplayLink creation/lifecycle signatures (iOS 3.1+, undeprecated): init(target:selector:) RETAINS the target (use a weak proxy to avoid a retain cycle), add(to:forMode:) makes the run loop retain the link (use RunLoop.main + .common so it keeps firing during scroll tracking), invalidate() removes it from all run loops and releases the target, isPaused pauses. timestamp = start of the current refresh interval, targetTimestamp = deadline for the next frame; `duration` is UNDEFINED until the first callback and is the interval at maximumFramesPerSecond, so compute the actual interval as targetTimestamp - timestamp (Apple's documented formula) and the available work time as targetTimestamp - CACurrentMediaTime(). If a callback overruns targetTimestamp, the next refresh gets no callback. (https://developer.apple.com/documentation/quartzcore/cadisplaylink)
```
init(target: Any, selector sel: Selector)   // selector shape: @objc func tick(_ sender: CADisplayLink)
func add(to runloop: RunLoop, forMode mode: RunLoop.Mode)
func remove(from runloop: RunLoop, forMode mode: RunLoop.Mode)
func invalidate()
var isPaused: Bool { get set }
var timestamp: CFTimeInterval { get }
var targetTimestamp: CFTimeInterval { get }
var duration: CFTimeInterval { get }
// actual rate this frame:
let hz = 1.0 / (link.targetTimestamp - link.timestamp)
```
- [high] Factory-method churn to avoid: UIScreen.displayLink(withTarget:selector:) is deprecated in iOS 27.0 ('Use the equivalent display link API on UIWindowScene'); the replacements UIWindowScene.displayLink(target:selector:) and displayLink(action:) are iOS 27+ only. There is NO UIView.displayLink(withTarget:selector:) on iOS (that exists only on AppKit's NSView). For an iOS 17 target use plain CADisplayLink(target:selector:), which is not deprecated. CADisplayLink.preferredFramesPerSecond is deprecated in iOS 27.2 — use preferredFrameRateRange. (https://developer.apple.com/documentation/uikit/uiscreen/displaylink(withtarget:selector:))
```
// iOS 27+ only (do not use with iOS 17 target):
func displayLink(target: Any, selector sel: Selector) -> CADisplayLink?   // UIWindowScene
@MainActor @preconcurrency func displayLink(action: @escaping @Sendable (CADisplayLink) -> Void) -> CADisplayLink?
```
- [high] iOS 18-only alternative (not needed for phase 1): UIUpdateLink (UIKit, iOS 18.0) — init(view:actionHandler:), preferredFrameRateRange: CAFrameRateRange, requiresContinuousUpdates, isEnabled; auto-activates when the view enters a window and retargets across displays. iOS 17 alternative for Metal: CAMetalDisplayLink (iOS 17.0) with preferredFrameRateRange/preferredFrameLatency and a CAMetalLayer. For a two-image mask swap neither is necessary; CADisplayLink + CALayer.contents is sufficient and cheapest. (https://developer.apple.com/documentation/uikit/uiupdatelink)
```
@MainActor class UIUpdateLink                       // iOS 18+
init(view: UIView, actionHandler handler: @escaping (UIUpdateLink, UIUpdateInfo) -> Void)
var preferredFrameRateRange: CAFrameRateRange { get set }
class CAMetalDisplayLink                            // iOS 17+
```
- [high] Rendering approach: pre-render two complementary checkerboard masks as CGImage at exact device-pixel size and swap a dedicated sublayer's `contents` once per callback inside CATransaction with implicit actions disabled (also set layer.actions = ["contents": NSNull()]). CALayer.contents is `Any?` and accepts a CGImage; Apple warns NOT to set `contents` on a view's own backing layer ('the view replacing the contents of this property during a subsequent update'), hence the separate sublayer. Set contentsGravity = .resize (default, 1:1 because the image is pixel-exact) and magnificationFilter/minificationFilter = .nearest so cells stay crisp. Cost per frame is one pointer swap and one Core Animation commit; the render server composites. Metal is unnecessary. (https://developer.apple.com/documentation/quartzcore/calayer/contents)
```
var contents: Any? { get set }   // CALayer; assign a CGImage
CATransaction.begin(); CATransaction.setDisableActions(true)
maskLayer.contents = masks[phase]
CATransaction.commit()
```
- [high] Complete UIView subclass (plus SwiftUI bridge) that toggles two complementary masks at the display's maximum rate, measures the delivered rate, and stops itself when the rate drops below 100 Hz, when Reduce Motion or Dim Flashing Lights is on, in Low Power Mode, under serious/critical thermal state, or when the app resigns active. Every API used is available on iOS 17 (nothing newer than iOS 16.4). File path in the repo: ios/Kilit/Sources/Security/FlickerMaskView.swift. Draft reviewed copy at /tmp/claude-0/-home-user-clawDbot/bdce7bc4-a479-5125-8ada-9eaadb92752b/scratchpad/FlickerMaskView.swift. (knowledge (assembled from the Apple signatures cited in the other findings; not compiled — no Swift toolchain on Linux))
```
//  FlickerMaskView.swift
//  Kilit — EXPERIMENTAL "temporal sub-frame" anti-camera deterrent (opt-in, default OFF).
//
//  Requirements
//  - iOS 17+ (all APIs used here exist since iOS 15/16.4 at the latest).
//  - Info.plist: <key>CADisableMinimumFrameDurationOnPhone</key><true/>  (iPhone only; without it
//    Core Animation never delivers more than 60 Hz to a third-party app on ProMotion iPhones).
//  - Swift language mode 5 (SWIFT_VERSION = 5.0). Nothing here is unsafe in mode 6, but the
//    notification handlers and deinit would need extra isolation annotations.
//
//  What it does: alternates two complementary checkerboard masks (A = even cells, B = odd cells)
//  over the content at the display's maximum refresh rate. At 120 Hz each cell flickers at 60 Hz
//  (50 % duty). The eye spatially pools neighbouring counter-phase cells and sees a steady 50 %
//  blend; a short-exposure camera frame captures only one half-pattern. It is a DETERRENT ONLY:
//  a long exposure (>= 1/60 s), a 2-frame burst, or a video averages the two halves back together.
//
//  Safety: it refuses to run (and stops itself) when the measured callback rate falls below
//  `minimumEffectiveRate` (a 60 Hz panel would produce a 30 Hz full-modulation square wave,
//  squarely inside the 3–50 Hz photosensitive band), when Reduce Motion or Dim Flashing Lights is
//  on, in Low Power Mode, under serious/critical thermal state, or when the app resigns active.

import UIKit
import QuartzCore
import MediaAccessibility   // MADimFlashingLightsEnabled(), kMADimFlashingLightsChangedNotification (iOS 16.4+)
import SwiftUI

final class FlickerMaskView: UIView {

    // MARK: - Public configuration

    enum StopReason {
        case rateTooLow(measuredHz: Double)
        case accessibilitySetting     // Reduce Motion or Dim Flashing Lights is on
        case lowPowerMode
        case thermal
        case notActive                // app resigned active / view left the window
        case hostRequest              // isEnabled set to false
    }

    /// Checkerboard cell side in points. Keep <= 3 pt: at ~30 cm on a 460 ppi panel 3.2 pt ≈ 0.1°
    /// of visual field, the size below which WCAG treats a balanced alternating checkerboard as
    /// not violating the flash thresholds.
    var cellSize: CGFloat = 3 { didSet { if cellSize != oldValue { regenerateMasks() } } }

    /// Colour painted over hidden cells. Use the content's BACKGROUND colour (bubble colour), not
    /// black, so luminance only changes where there is ink/image, which keeps the per-flash
    /// luminance change small. Pass a resolved (non-dynamic) colour and update it on appearance change.
    var maskColor: UIColor = .white { didSet { regenerateMasks() } }

    /// Minimum *measured* CADisplayLink rate (Hz) at which the deterrent is allowed to run.
    /// 120 Hz nominal; anything that settles below this (60 Hz panel, Low Power Mode, thermal
    /// throttling, Settings > Accessibility > Motion > Limit Frame Rate) stops the view.
    var minimumEffectiveRate: Double = 100

    /// Number of consecutive slow callbacks tolerated before stopping (~0.25 s at 120 Hz).
    var slowFrameTolerance: Int = 30

    /// Host switch. Setting it to true starts as soon as the view is in a window and conditions allow.
    var isEnabled: Bool = false {
        didSet {
            guard isEnabled != oldValue else { return }
            if isEnabled { startIfPossible() } else { stop(.hostRequest) }
        }
    }

    /// Called on the main thread whenever the view stops (including self-stops). The host should
    /// fall back to its static protection (blur / hold-to-reveal) and may surface the reason.
    var onStopped: ((StopReason) -> Void)?

    private(set) var isRunning = false
    /// Exponential moving average of 1 / (targetTimestamp - timestamp). 0 until the first callback.
    private(set) var measuredHz: Double = 0

    /// Hardware maximum for the screen this view is on (120 on ProMotion, else 60). Note: this is
    /// the hardware ceiling, NOT a promise; always trust `measuredHz` instead.
    var displayMaximumFramesPerSecond: Int {
        window?.windowScene?.screen.maximumFramesPerSecond ?? 60
    }

    // MARK: - Private state

    private let maskLayer = CALayer()
    private var masks: [CGImage] = []          // [0] = even cells covered, [1] = odd cells covered
    private var phase = 0
    private var displayLink: CADisplayLink?
    private var proxy: DisplayLinkProxy?
    private var slowFrames = 0
    private var renderedPixelSize = CGSize.zero
    private var observing = false

    // MARK: - Init / teardown

    override init(frame: CGRect) {
        super.init(frame: frame)
        commonInit()
    }

    required init?(coder: NSCoder) {
        super.init(coder: coder)
        commonInit()
    }

    private func commonInit() {
        isOpaque = false
        backgroundColor = .clear
        isUserInteractionEnabled = false           // never intercept touches meant for the content
        maskLayer.contentsGravity = .resize        // masks are rendered at exact pixel size => 1:1
        maskLayer.magnificationFilter = .nearest
        maskLayer.minificationFilter = .nearest
        maskLayer.actions = ["contents": NSNull(), "hidden": NSNull(),
                             "bounds": NSNull(), "position": NSNull()]   // no implicit 0.25 s animations
        maskLayer.isHidden = true
        layer.addSublayer(maskLayer)
    }

    deinit {
        displayLink?.invalidate()                  // run loop retains the link; break it explicitly
        NotificationCenter.default.removeObserver(self)
    }

    // MARK: - UIView

    override func layoutSubviews() {
        super.layoutSubviews()
        maskLayer.frame = bounds
        let scale = currentScale
        maskLayer.contentsScale = scale
        let px = CGSize(width: (bounds.width * scale).rounded(.up),
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

    // MARK: - Start / stop

    private func startIfPossible() {
        guard isEnabled, !isRunning, window != nil else { return }
        if let reason = blockingCondition() {
            onStopped?(reason)
            return
        }
        guard displayMaximumFramesPerSecond >= 120 else {
            onStopped?(.rateTooLow(measuredHz: Double(displayMaximumFramesPerSecond)))
            return
        }
        regenerateMasks()
        guard masks.count == 2 else { return }     // zero-size bounds; layoutSubviews will retry

        let proxy = DisplayLinkProxy(owner: self)
        self.proxy = proxy
        // CADisplayLink retains its target, so the target is a proxy that holds `self` weakly.
        let link = CADisplayLink(target: proxy, selector: #selector(DisplayLinkProxy.tick(_:)))
        // min == max == preferred is explicitly allowed; we want 120 or nothing (we measure anyway).
        link.preferredFrameRateRange = CAFrameRateRange(minimum: 120, maximum: 120, preferred: 120)
        link.add(to: .main, forMode: .common)      // .common keeps it firing during scroll tracking
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

    private func blockingCondition() -> StopReason? {
        if UIAccessibility.isReduceMotionEnabled || MADimFlashingLightsEnabled() {
            return .accessibilitySetting
        }
        if ProcessInfo.processInfo.isLowPowerModeEnabled {
            return .lowPowerMode
        }
        switch ProcessInfo.processInfo.thermalState {
        case .serious, .critical: return .thermal
        default: break
        }
        return nil
    }

    // MARK: - Per-frame callback (main thread, once per display refresh)

    fileprivate func handleTick(_ link: CADisplayLink) {
        // `duration` is the interval at maximumFramesPerSecond, not the current one; the actual
        // interval of this refresh is targetTimestamp - timestamp (Apple's documented formula).
        let interval = link.targetTimestamp - link.timestamp
        if interval > 0 {
            let hz = 1.0 / interval
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
        maskLayer.contents = masks[phase]          // one pointer swap; the render server does the rest
        CATransaction.commit()
    }

    // MARK: - Mask generation (two complementary checkerboards, device-pixel exact)

    private func regenerateMasks() {
        let scale = currentScale
        let w = Int((bounds.width * scale).rounded(.up))
        let h = Int((bounds.height * scale).rounded(.up))
        guard w > 0, h > 0 else {
            masks = []
            renderedPixelSize = .zero
            return
        }
        renderedPixelSize = CGSize(width: w, height: h)
        let cell = max(1, Int((cellSize * scale).rounded()))

        let format = UIGraphicsImageRendererFormat()
        format.scale = 1                           // work in device pixels
        format.opaque = false
        let renderer = UIGraphicsImageRenderer(size: CGSize(width: w, height: h), format: format)
        let fill = maskColor.cgColor

        masks = (0...1).compactMap { parity -> CGImage? in
            renderer.image { ctx in
                let cg = ctx.cgContext
                cg.setFillColor(fill)
                var row = 0
                var y = 0
                while y < h {
                    var col = 0
                    var x = 0
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
            }.cgImage
        }

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
        let nc = NotificationCenter.default
        // Posted on the main thread:
        nc.addObserver(self, selector: #selector(appWillResignActive(_:)),
                       name: UIApplication.willResignActiveNotification, object: nil)
        nc.addObserver(self, selector: #selector(environmentChanged(_:)),
                       name: UIAccessibility.reduceMotionStatusDidChangeNotification, object: nil)
        nc.addObserver(self, selector: #selector(environmentChanged(_:)),
                       name: Notification.Name(rawValue: kMADimFlashingLightsChangedNotification as String),
                       object: nil)
        // May be posted on ANY thread (documented for both):
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

    @objc private func appWillResignActive(_ note: Notification) {
        stop(.notActive)
    }

    @objc private func environmentChanged(_ note: Notification) {
        // Hop to the main actor: power/thermal notifications arrive on arbitrary threads.
        Task { @MainActor [weak self] in
            guard let self, self.isRunning else { return }
            if let reason = self.blockingCondition() { self.stop(reason) }
        }
    }
}

// MARK: - Weak target for CADisplayLink (the link retains its target; this breaks the cycle)

private final class DisplayLinkProxy: NSObject {
    weak var owner: FlickerMaskView?
    init(owner: FlickerMaskView) { self.owner = owner }
    @objc func tick(_ link: CADisplayLink) { owner?.handleTick(link) }
}

// MARK: - SwiftUI bridge

/// Overlay this on the protected content: `.overlay { FlickerShield(enabled: on, maskColor: bg) }`
struct FlickerShield: UIViewRepresentable {
    var enabled: Bool
    var maskColor: UIColor
    var onStopped: ((FlickerMaskView.StopReason) -> Void)? = nil

    func makeUIView(context: Context) -> FlickerMaskView {
        let v = FlickerMaskView()
        v.maskColor = maskColor
        v.onStopped = onStopped
        return v
    }

    func updateUIView(_ v: FlickerMaskView, context: Context) {
        v.maskColor = maskColor
        v.onStopped = onStopped
        v.isEnabled = enabled
    }
}
```
- [high] Frame-rate physics (honest): at a 120 Hz panel each frame lasts 8.33 ms; alternating A/B every frame makes every cell a 60 Hz square wave with 50 % duty and (for black masks over light content) ~100 % modulation. On a 60 Hz panel the same code yields a 30 Hz square wave — inside the 3–50 Hz band that WCAG 1.0 banned outright and far above any 3-flashes-per-second limit — so the feature must refuse to run unless the MEASURED rate is >= ~100 Hz; UIScreen.maximumFramesPerSecond == 120 is not sufficient because the system silently drops to 60 Hz under Low Power Mode, thermal pressure, Core Animation arbitration, or the user's Settings > Accessibility > Motion > Limit Frame Rate switch (present since iPhone 13 Pro/iOS 15; no public API to read it). (https://developer.apple.com/documentation/quartzcore/optimizing-iphone-and-ipad-apps-to-support-promotion-displays)
- [medium] Perceived flicker: critical flicker fusion (CFF) rises with log retinal illuminance (Ferry–Porter law) and with stimulus size/eccentricity; a 2023 study found peripheral CFF saturates at ~90 Hz for a 5.7° target and ~100 Hz for a 10° target at high luminance. Therefore a 60 Hz full-modulation modulation of a bright OLED area is at/near foveal fusion for many viewers but can be seen as shimmer in peripheral vision, at high brightness, and during saccades (phantom-array effect). The counter-phase checkerboard with small cells mitigates this: neighbouring cells are in opposite phase, so the spatially pooled luminance of any area >= 2 cells is constant every frame and the eye sees a steady ~50 % blend rather than a flash. This is exactly why WCAG exempts 'a fine, balanced pattern such as ... an alternating checkerboard pattern with squares smaller than 0.1 degree'. (https://www.ncbi.nlm.nih.gov/pmc/articles/PMC10057432/)
- [high] Camera exposure integration (why it is a deterrent at best): a sensor pixel integrates light over the exposure time T. With a 2-frame cycle of 16.7 ms: if T >= 16.7 ms (1/60 s — ordinary indoor auto-exposure, Night mode, or any manual pro-camera app) both halves integrate and the photo contains the FULL content at ~50 % contrast, trivially restored in post. If T <= 8.3 ms and phase-aligned to one frame (bright screen, dark room, 1/250–1/1000 s) the photo contains exactly one half-pattern: 50 % of the cells are hidden but, because 3-pt cells are far smaller than glyphs, text remains largely readable. Any 2-frame burst or a 60/120/240 fps video reconstructs the original exactly by per-pixel max() of consecutive frames (masks are complementary). Net: a casual single snapshot is degraded, nothing more. Screen recording is unaffected by this feature (it bypasses the panel) and is handled by the secure-text-field blanking instead. (knowledge (elementary photometric integration; no reachable primary source — proxy blocked wikipedia/energy.gov))
- [medium] Rolling shutter: phone sensors read out rows sequentially; a full-frame readout typically takes on the order of 10–30 ms (sensor/mode dependent), i.e. 1–4 display frames at 120 Hz. Rows exposed during frame A capture mask A, rows exposed during frame B capture mask B, so a single photo shows horizontal bands alternating between the two half-patterns (plus beat bands from the OLED's own top-to-bottom scan-out and its PWM dimming at low brightness). Both halves therefore end up in one photo in different bands — rolling shutter helps the attacker, it does not add protection. Severity of banding falls as exposure time grows (bands wash out when T spans several frames). (https://image-ppubs.uspto.gov/dirsearch-public/print/downloadPdf/12671906)
- [medium] Prior art: 'Kaleido: You Can Watch It But Cannot Record It' (Zhang et al., MobiCom 2015) re-encodes each video frame into multiple displayed frames to exploit the gap between the screen–eye and screen–camera channels; the authors reported reduced camera-capture quality on 2015-era smartphone cameras while preserving viewer quality. It is the academic ancestor of this feature; its effectiveness was camera/exposure specific, which is consistent with the integration analysis above. Cite it in the design doc as the basis, not as proof of security. (https://old.sigmobile.org/mobicom/2015/papers/p372-zhangA.pdf)
- [high] WCAG 2.1/2.2 SC 2.3.1 (Level A) verbatim essentials: content must not flash more than three times in any one-second period, or the flash must be below the general flash and red flash thresholds. Threshold definition: passes if 'there are no more than three general flashes and/or no more than three red flashes within any one-second period; or the combined area of flashes occurring concurrently occupies no more than a total of .006 steradians within any 10 degree visual field on the screen (25% of any 10 degree visual field on the screen) at typical viewing distance'. A general flash is 'a pair of opposing changes in relative luminance of 10% or more of the maximum relative luminance (1.0) where the relative luminance of the darker image is below 0.80'. A 341 x 256 pixel block at 1024 x 768 (87,296 CSS px) approximates the 10° field. Exception: 'Flashing that is a fine, balanced, pattern such as white noise or an alternating checkerboard pattern with "squares" smaller than 0.1 degree (of visual field at typical viewing distance) on a side does not violate the thresholds.' The understanding doc notes WCAG 1.0 forbade any flashing in the 3–50 Hz range and that mobile screens occupy a smaller part of the visual field; recommended analysis tool: Trace Center PEAT. (https://raw.githubusercontent.com/w3c/wcag/main/guidelines/terms/20/general-flash-and-red-flash-thresholds.html)
- [high] Applying WCAG's 0.1° exception to iPhone geometry: 0.1° subtends 0.44 mm at 25 cm, 0.52 mm at 30 cm, 0.70 mm at 40 cm. On the 460 ppi panels of every ProMotion iPhone (13 Pro through 17/Air) that is 7.9 / 9.5 / 12.6 physical px = 2.6 / 3.2 / 4.2 pt (@3x). Hence the default cellSize of 3 pt (9 px) keeps the pattern inside the 'fine balanced checkerboard' exception at normal phone viewing distance; 4 pt and up falls outside it. Also use the content background colour as the mask colour so that luminance only changes where there is ink (typically 10–20 % of a text bubble), which keeps most cells under the 10 % relative-luminance flash definition. For photos (dense, high-contrast content) the balance argument weakens — restrict phase-1 flicker to text bubbles, or accept that for photos the 3-pt rule is the only mitigation. (knowledge (geometry computed from the WCAG definition and 460 ppi panel density))
- [medium] IEEE 1789-2015 (LED flicker recommended practice; listed by IEEE as inactive-reserved as of 2026-03) gives tighter numbers than WCAG for continuous flicker: for f < 90 Hz the low-risk region is modulation % < 0.08 x f and the no-observable-effect level is < 0.025 x f; for 90–1250 Hz low-risk is < 0.08 x f and NOEL < 0.0333 x f; above 1250 Hz no limit. At 60 Hz this means low-risk requires < 4.8 % modulation — a 100 %-modulated 60 Hz cell is far outside it, which is the honest reason this feature stays opt-in with a warning even at 120 Hz panel rate. Use these numbers for the design-doc rationale only; they could not be verified online from this environment. (knowledge (IEEE listing https://standards.ieee.org/ieee/1789/4479/ reachable; limit values from memory))
- [high] Apple's own guidance and APIs for flashing content: HIG Accessibility says 'Be cautious with fast-moving and blinking animations ... in some cases even result in epileptic episodes' and 'Allow people to opt out of flashing lights'. iOS 16.4+ exposes the Dim Flashing Lights setting: MADimFlashingLightsEnabled() -> Bool and kMADimFlashingLightsChangedNotification: CFString (MediaAccessibility framework); iOS 17 adds MAFlashingLightsProcessor (video IOSurface mitigation — not applicable to our overlay, but shows the system expectation). Also honour UIAccessibility.isReduceMotionEnabled (@MainActor static var Bool, iOS 8+) and UIAccessibility.reduceMotionStatusDidChangeNotification. The view above treats either setting as a hard block. (https://developer.apple.com/documentation/mediaaccessibility/flashing-lights)
```
import MediaAccessibility
func MADimFlashingLightsEnabled() -> Bool                 // iOS 16.4+
let kMADimFlashingLightsChangedNotification: CFString   // iOS 16.4+
// Swift observer name:
Notification.Name(rawValue: kMADimFlashingLightsChangedNotification as String)
@MainActor static var isReduceMotionEnabled: Bool { get }   // UIAccessibility
UIAccessibility.reduceMotionStatusDidChangeNotification
```
- [medium] How to present the photosensitivity warning (design recommendation): default OFF; the toggle lives under Settings > Experimental; flipping it on presents a modal sheet that must be acknowledged EVERY time it is turned on (not once); the non-destructive 'Keep off' button is the default/cancel action and 'Turn on' is styled destructive; the sheet does not preview the effect; the toggle is disabled with an explanation when Reduce Motion or Dim Flashing Lights is on, in Low Power Mode, or on a 60 Hz device (show 'requires a 120 Hz display'); while active, show a persistent status indicator and stop on any tap; limit flicker to the revealed message bubble (never full screen) and to the hold-to-reveal window (seconds, not indefinitely); log activation; state plainly in the sheet that it does not prevent recording. Suggested wording (EN; Turkish below): 'Flicker Shield rapidly alternates a fine pattern over message content (60 times per second). Rapidly flashing or flickering images can trigger seizures in people with photosensitive epilepsy and can cause eye strain, headaches, dizziness or nausea in others. Do not turn this on if you, or anyone who may see your screen, has a history of seizures. Stop and turn it off immediately if you feel unwell. This is an experimental deterrent only; it does not prevent someone from photographing or recording your screen.' TR: 'Titreşim Kalkanı mesaj içeriğinin üzerinde ince bir deseni saniyede 60 kez değiştirir. Hızla yanıp sönen görüntüler fotosensitif epilepsisi olan kişilerde nöbeti tetikleyebilir; diğer kişilerde göz yorgunluğu, baş ağrısı, baş dönmesi veya bulantıya yol açabilir. Sizde ya da ekranınızı görebilecek birinde nöbet geçmişi varsa bu özelliği açmayın. Kendinizi kötü hissederseniz hemen kapatın. Bu deneysel bir caydırıcıdır; ekranınızın fotoğraflanmasını veya kaydedilmesini engellemez.' (https://developer.apple.com/design/human-interface-guidelines/accessibility)
```
import SwiftUI

struct PhotosensitivityWarningSheet: View {
    @Environment(\.dismiss) private var dismiss
    var onAccept: () -> Void

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    Label("Photosensitivity warning", systemImage: "exclamationmark.triangle.fill")
                        .font(.title2.bold())
                    Text("Flicker Shield rapidly alternates a fine pattern over message content (60 times per second). Rapidly flashing or flickering images can trigger seizures in people with photosensitive epilepsy, and can cause eye strain, headaches, dizziness or nausea in others.")
                    Text("Do not turn this on if you, or anyone who may see your screen, has a history of seizures. Stop and turn it off immediately if you feel unwell.")
                    Text("This is an experimental deterrent only. It does not prevent someone from photographing or recording your screen.")
                        .foregroundStyle(.secondary)
                }
                .padding()
            }
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Keep off") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Turn on", role: .destructive) { onAccept(); dismiss() }
                }
            }
        }
        .interactiveDismissDisabled()
    }
}
```
- [medium] Build/concurrency notes for the Mac build cycle: compile the UIKit file in Swift language mode 5 (SWIFT_VERSION = 5.0, the Xcode 16 default for new targets) — in Swift 6 mode the @objc notification selectors that fire on background threads and `deinit` touching MainActor state would need `nonisolated` annotations. UIView is implicitly @MainActor, so no explicit annotation is needed. The 120 Hz behaviour cannot be validated in the Simulator; test on a ProMotion iPhone with Low Power Mode off and Settings > Accessibility > Motion > Limit Frame Rate off, then toggle those to confirm the self-stop path. Apple: 'Lengthy callback execution times can prevent refresh intervals from receiving CADisplayLink callbacks' — keep decryption/decoding off the main thread while the link runs. (https://developer.apple.com/documentation/quartzcore/optimizing-iphone-and-ipad-apps-to-support-promotion-displays)
Pitfalls: Forgetting CADisableMinimumFrameDurationOnPhone (or putting it in a user-defined INFOPLIST_KEY_ build setting, which Xcode ignores): the link silently runs at 60 Hz on iPhone while UIScreen.maximumFramesPerSecond still says 120. Put the key in a real Info.plist referenced by INFOPLIST_FILE, outside the synchronized Sources folder, and never add that plist to the target. | Trusting UIScreen.maximumFramesPerSecond or preferredFrameRateRange as a guarantee. Apple: 'Your app must not assume that Core Animation calls your CADisplayLink callback at any specific refresh rate or even at the rate requested.' Low Power Mode, thermal state, the 'Limit Frame Rate' accessibility switch (no API) and CA arbitration all drop you to 60 Hz; measure targetTimestamp - timestamp every frame and stop below ~100 Hz. | Running the toggle on a 60 Hz panel (iPhone 13/14/15/16 non-Pro, 16e, SE): per-cell flicker becomes a 30 Hz full-modulation square wave, inside the 3–50 Hz photosensitive band. Hard-block it. | Using CADisplayLink.duration to derive timing: it is undefined before the first callback and reflects the display's maximum rate, not the current one. | Retain cycle / leak: CADisplayLink(target:selector:) retains the target and the run loop retains the link. Use a weak proxy as target and invalidate() in stop() and deinit; stop in didMoveToWindow when window becomes nil. | Setting `contents` on the view's own backing layer (UIKit may overwrite it) or leaving implicit animations on: the 0.25 s cross-fade would smear the two masks. Use a dedicated sublayer with actions = ["contents": NSNull()] and CATransaction.setDisableActions(true). | Using UIScreen.main (deprecated iOS 26), UIScreen.displayLink(withTarget:selector:) (deprecated iOS 27), UIWindowScene.displayLink (iOS 27+ only), UIUpdateLink (iOS 18+ only), or a non-existent UIView.displayLink on iOS. For an iOS 17 target use CADisplayLink(target:selector:) and window?.windowScene?.screen. | Large mask cells or black masks: a cell larger than ~3 pt at 460 ppi exceeds WCAG's 0.1° 'fine balanced pattern' exception, and black-over-light content makes every cell a ~100 % luminance flash. Keep cellSize <= 3 pt and use the content background colour as maskColor; prefer text bubbles over photos. | Overselling the feature: a >= 1/60 s exposure, a two-frame burst, or any video reconstructs the content exactly (complementary masks sum to the original); rolling shutter puts both halves in one photo as bands. Describe it everywhere as a casual-snapshot deterrent, never as recording protection; screen recording is handled by the secure-text-field blanking, not by this. | Ignoring the system accessibility settings: check UIAccessibility.isReduceMotionEnabled and MADimFlashingLightsEnabled() before starting and on their change notifications; NSProcessInfoPowerStateDidChange and thermalStateDidChangeNotification arrive on arbitrary threads, so hop to the main actor before touching the view. | Swift 6 language mode would reject the @objc background-thread selectors and deinit access in this file without nonisolated annotations; build the target in Swift 5 mode (SWIFT_VERSION = 5.0). | Heavy main-thread work (decryption, image decoding) while the link runs causes missed callbacks (Apple: the next refresh interval gets no callback), which both halves the effective rate and visibly stutters the pattern; keep that work off the main thread and start the link only after the content is rendered. | The iOS Simulator does not reproduce ProMotion timing; the only valid test is a ProMotion iPhone, including toggling Low Power Mode and Limit Frame Rate to exercise the self-stop path. | No reachable primary sources in this environment for IEEE 1789 limit values, typical rolling-shutter readout times, or the Kaleido paper body (w3.org, apple.com, wikipedia, energy.gov, digikey and sigmobile were blocked by the proxy); those claims are marked medium confidence and should be re-checked before being quoted in user-facing text.

### cryptokit
- [high] Curve25519.KeyAgreement.PrivateKey (iOS 13+): exact members. rawRepresentation is exactly 32 bytes; init(rawRepresentation:) throws CryptoKitError.incorrectKeySize on wrong length. sharedSecretFromKeyAgreement's label is `with`. (https://developer.apple.com/documentation/cryptokit/curve25519/keyagreement/privatekey (verified via developer.apple.com/tutorials/data JSON) + https://github.com/apple/swift-crypto/blob/main/Sources/Crypto/Keys/EC/X25519Keys.swift)
```
struct Curve25519.KeyAgreement.PrivateKey {
  init()                                                        // random key
  init<D: ContiguousBytes>(rawRepresentation: D) throws          // 32 bytes
  var rawRepresentation: Data { get }                            // 32 bytes
  var publicKey: Curve25519.KeyAgreement.PublicKey { get }
  func sharedSecretFromKeyAgreement(with publicKeyShare: Curve25519.KeyAgreement.PublicKey) throws -> SharedSecret
}
struct Curve25519.KeyAgreement.PublicKey {
  init<D: ContiguousBytes>(rawRepresentation: D) throws          // 32 bytes (u-coordinate)
  var rawRepresentation: Data { get }
}
```
- [high] Curve25519.Signing (Ed25519, iOS 13+): private rawRepresentation is the 32-byte SEED (not 64 bytes), signature is 64 bytes, verification is non-throwing Bool. CryptoKit's signature(for:) is RANDOMIZED (doc comment in swift-crypto: 'employs randomization to generate a different signature on every call') so Ed25519 signatures are NOT byte-reproducible across Swift/Go. (https://developer.apple.com/documentation/cryptokit/curve25519/signing/privatekey + https://developer.apple.com/documentation/cryptokit/curve25519/signing/publickey/isvalidsignature(_:for:) + https://github.com/apple/swift-crypto/blob/main/Sources/Crypto/Signatures/Ed25519.swift)
```
struct Curve25519.Signing.PrivateKey {
  init()
  init<D: ContiguousBytes>(rawRepresentation data: D) throws     // 32-byte seed
  var rawRepresentation: Data { get }                            // 32-byte seed
  var publicKey: Curve25519.Signing.PublicKey { get }
  func signature<D: DataProtocol>(for data: D) throws -> Data   // 64 bytes, randomized
}
struct Curve25519.Signing.PublicKey {
  init<D: ContiguousBytes>(rawRepresentation: D) throws          // 32 bytes
  var rawRepresentation: Data { get }
  func isValidSignature<S: DataProtocol, D: DataProtocol>(_ signature: S, for data: D) -> Bool
}
```
- [high] SharedSecret (iOS 13+) conforms to ContiguousBytes, Hashable, Equatable (constant-time ==). Raw DH bytes (needed for X3DH concatenation DH1||DH2||DH3||DH4) are obtained with withUnsafeBytes. hkdfDerivedSymmetricKey is NON-throwing and is literally HKDF<H>.deriveKey(inputKeyMaterial: SymmetricKey(data: ss), salt: salt, info: sharedInfo, outputByteCount:). (https://developer.apple.com/documentation/cryptokit/sharedsecret + https://github.com/apple/swift-crypto/blob/main/Sources/Crypto/Key%20Agreement/DH.swift)
```
struct SharedSecret: ContiguousBytes, Hashable, Equatable, Sendable {
  func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R
  func hkdfDerivedSymmetricKey<H: HashFunction, Salt: DataProtocol, SI: DataProtocol>(using hashFunction: H.Type, salt: Salt, sharedInfo: SI, outputByteCount: Int) -> SymmetricKey
  func x963DerivedSymmetricKey<H: HashFunction, SI: DataProtocol>(using hashFunction: H.Type, sharedInfo: SI, outputByteCount: Int) -> SymmetricKey
  static func == <D: DataProtocol>(lhs: SharedSecret, rhs: D) -> Bool
}
// raw bytes:
let dh: Data = try priv.sharedSecretFromKeyAgreement(with: pub).withUnsafeBytes { Data($0) }
```
- [high] CryptoKit on Apple platforms does NOT reject low-order X25519 public keys / all-zero shared secrets (swift-crypto source comment: 'CryptoKit on Apple platforms currently does not'). Go's crypto/ecdh DOES return error 'bad X25519 remote ECDH input: low order point' when the output is all zero. For Swift/Go parity, the Swift code must add an explicit constant-time all-zero check on every DH output and treat it as a fatal protocol error. (https://github.com/apple/swift-crypto/blob/main/Sources/Crypto/Keys/EC/BoringSSL/X25519Keys_boring.swift + https://github.com/golang/go/blob/go1.24.0/src/crypto/ecdh/x25519.go)
```
// Swift parity check (constant-time OR-accumulate):
let dh = try priv.sharedSecretFromKeyAgreement(with: pub).withUnsafeBytes { Data($0) }
var acc: UInt8 = 0; for b in dh { acc |= b }
guard acc != 0 else { throw KilitCryptoError.lowOrderPoint }
// Go: priv.ECDH(pub) already returns an error in this case (crypto/ecdh/x25519.go isZero)
```
- [high] HKDF<H: HashFunction> is iOS 14+ (fine for iOS 17 minimum). deriveKey variants are non-throwing. extract/expand exist for two-step use (expand's prk is ContiguousBytes so HashedAuthenticationCode from extract feeds it directly). The overloads taking RawSpan/OutputRawSpan/MutableRawSpan (deriveKey(inputKeyMaterial:salt:info:output:), expand(pseudoRandomKey:info:into:), extract(inputKeyMaterial:salt: RawSpan?)) are iOS 26-era additions: do NOT use them with an iOS 17 target. (https://developer.apple.com/documentation/cryptokit/hkdf + https://developer.apple.com/documentation/cryptokit/hkdf/derivekey(inputkeymaterial:salt:info:outputbytecount:) + https://github.com/apple/swift-crypto/blob/main/Sources/Crypto/Key%20Derivation/HKDF.swift)
```
struct HKDF<H> where H: HashFunction {
  static func deriveKey<Salt: DataProtocol, Info: DataProtocol>(inputKeyMaterial: SymmetricKey, salt: Salt, info: Info, outputByteCount: Int) -> SymmetricKey
  static func deriveKey<Info: DataProtocol>(inputKeyMaterial: SymmetricKey, info: Info, outputByteCount: Int) -> SymmetricKey   // salt = empty
  static func deriveKey<Salt: DataProtocol>(inputKeyMaterial: SymmetricKey, salt: Salt, outputByteCount: Int) -> SymmetricKey
  static func deriveKey(inputKeyMaterial: SymmetricKey, outputByteCount: Int) -> SymmetricKey
  static func extract<Salt: DataProtocol>(inputKeyMaterial: SymmetricKey, salt: Salt?) -> HashedAuthenticationCode<H>
  static func expand<PRK: ContiguousBytes, Info: DataProtocol>(pseudoRandomKey prk: PRK, info: Info?, outputByteCount: Int) -> SymmetricKey
}
// usage
let okm = HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: ikm), salt: salt, info: Data("Kilit_DR_v1_RootChain".utf8), outputByteCount: 64)
let okmBytes = okm.withUnsafeBytes { Data($0) }
```
- [high] HMAC<H> (iOS 13+): MAC typealias is HashedAuthenticationCode<H>, which conforms to ContiguousBytes, Sequence (Element == UInt8), Equatable, MessageAuthenticationCode, and has byteCount. Convert to Data with Data(mac) or mac.withUnsafeBytes { Data($0) }. isValidAuthenticationCode is constant-time; use it instead of == on Data. (https://developer.apple.com/documentation/cryptokit/hmac + https://developer.apple.com/documentation/cryptokit/hashedauthenticationcode + https://github.com/apple/swift-crypto/blob/main/Sources/Crypto/Message%20Authentication%20Codes/HMAC/HMAC.swift)
```
struct HMAC<H: HashFunction> {
  typealias Key = SymmetricKey
  typealias MAC = HashedAuthenticationCode<H>
  init(key: SymmetricKey)
  mutating func update<D: DataProtocol>(data: D)
  func finalize() -> HMAC<H>.MAC
  static func authenticationCode<D: DataProtocol>(for data: D, using key: SymmetricKey) -> HMAC<H>.MAC
  static func isValidAuthenticationCode<D: DataProtocol>(_ authenticationCode: HMAC<H>.MAC, authenticating authenticatedData: D, using key: SymmetricKey) -> Bool
  static func isValidAuthenticationCode<C: ContiguousBytes, D: DataProtocol>(_ authenticationCode: C, authenticating authenticatedData: D, using key: SymmetricKey) -> Bool
}
// KDF_CK:
let mk  = Data(HMAC<SHA256>.authenticationCode(for: Data([0x01]), using: SymmetricKey(data: ck)))
let ck2 = Data(HMAC<SHA256>.authenticationCode(for: Data([0x02]), using: SymmetricKey(data: ck)))
```
- [high] ChaChaPoly (ChaCha20-Poly1305, iOS 13+): exact signatures. Key MUST be 256-bit (otherwise throws CryptoKitError.incorrectKeySize). Nonce is exactly 12 bytes. SealedBox.combined is NON-optional `let combined: Data` with layout nonce(12) || ciphertext || tag(16); init(combined:) throws incorrectParameterSize if count < 28; init(nonce:ciphertext:tag:) throws if tag.count != 16. open throws CryptoKitError.authenticationFailure on bad tag/AAD. The inPlace RawSpan overloads are iOS 26: avoid. (https://developer.apple.com/documentation/cryptokit/chachapoly + https://developer.apple.com/documentation/cryptokit/chachapoly/seal(_:using:nonce:authenticating:) + https://developer.apple.com/documentation/cryptokit/chachapoly/sealedbox + https://github.com/apple/swift-crypto/blob/main/Sources/Crypto/AEADs/ChachaPoly/ChaChaPoly.swift)
```
enum ChaChaPoly {
  static func seal<Plaintext: DataProtocol, AuthenticatedData: DataProtocol>(_ message: Plaintext, using key: SymmetricKey, nonce: ChaChaPoly.Nonce? = nil, authenticating authenticatedData: AuthenticatedData) throws -> ChaChaPoly.SealedBox
  static func seal<Plaintext: DataProtocol>(_ message: Plaintext, using key: SymmetricKey, nonce: ChaChaPoly.Nonce? = nil) throws -> ChaChaPoly.SealedBox
  static func open<AuthenticatedData: DataProtocol>(_ sealedBox: ChaChaPoly.SealedBox, using key: SymmetricKey, authenticating authenticatedData: AuthenticatedData) throws -> Data
  static func open(_ sealedBox: ChaChaPoly.SealedBox, using key: SymmetricKey) throws -> Data
  struct Nonce: ContiguousBytes, Sequence { init(); init<D: DataProtocol>(data: D) throws /* 12 bytes */ }
  struct SealedBox {
    let combined: Data                     // nonce || ciphertext || tag
    var nonce: ChaChaPoly.Nonce { get }; var ciphertext: Data { get }; var tag: Data { get }  // tag 16 bytes
    init<D: DataProtocol>(combined: D) throws
    init<C: DataProtocol, T: DataProtocol>(nonce: ChaChaPoly.Nonce, ciphertext: C, tag: T) throws
  }
}
// deterministic nonce from derived material:
let box = try ChaChaPoly.seal(plaintext, using: SymmetricKey(data: key32), nonce: try ChaChaPoly.Nonce(data: nonce12), authenticating: aad)
let wire = box.combined   // or box.ciphertext + box.tag if nonce is implicit
```
- [high] AES.GCM (iOS 13+) has the same shape as ChaChaPoly with one important difference: `var combined: Data?` is OPTIONAL and is nil unless the nonce is the default 12 bytes (AES.GCM.Nonce accepts other sizes). Keys may be 128/192/256-bit. Prefer ChaChaPoly for the ratchet (owner decision) and use AES.GCM only if needed; if used, guard-unwrap combined. (https://developer.apple.com/documentation/cryptokit/aes/gcm + https://developer.apple.com/documentation/cryptokit/aes/gcm/sealedbox/combined)
```
enum AES.GCM {
  static func seal<Plaintext: DataProtocol, AuthenticatedData: DataProtocol>(_ message: Plaintext, using key: SymmetricKey, nonce: AES.GCM.Nonce? = nil, authenticating authenticatedData: AuthenticatedData) throws -> AES.GCM.SealedBox
  static func seal<Plaintext: DataProtocol>(_ message: Plaintext, using key: SymmetricKey, nonce: AES.GCM.Nonce? = nil) throws -> AES.GCM.SealedBox
  static func open<AuthenticatedData: DataProtocol>(_ sealedBox: AES.GCM.SealedBox, using key: SymmetricKey, authenticating authenticatedData: AuthenticatedData) throws -> Data
  static func open(_ sealedBox: AES.GCM.SealedBox, using key: SymmetricKey) throws -> Data
  struct Nonce { init(); init<D: DataProtocol>(data: D) throws }
  struct SealedBox {
    var combined: Data? { get }   // nil unless nonce is 12 bytes; layout nonce||ciphertext||tag
    var nonce: AES.GCM.Nonce { get }; var ciphertext: Data { get }; var tag: Data { get }
    init<D: DataProtocol>(combined: D) throws
    init<C: DataProtocol, T: DataProtocol>(nonce: AES.GCM.Nonce, ciphertext: C, tag: T) throws
  }
}
```
- [high] SymmetricKey (iOS 13+): init(size:), init<D: ContiguousBytes>(data:), bitCount, and withUnsafeBytes via ContiguousBytes; Equatable (constant-time). SymmetricKeySize is a struct with static bits128/bits192/bits256 and init(bitCount:). Key material is zeroized on deallocation (SecureBytes), so prefer keeping secrets as SymmetricKey rather than Data. The init(copying:)/init(copyingWithZeroing:)/bytes: RawSpan members are iOS 26: avoid. (https://developer.apple.com/documentation/cryptokit/symmetrickey + https://developer.apple.com/documentation/cryptokit/symmetrickeysize + https://github.com/apple/swift-crypto/blob/main/Sources/Crypto/Keys/Symmetric/SymmetricKeys.swift)
```
struct SymmetricKey: ContiguousBytes, Equatable {
  init(size: SymmetricKeySize)                     // random
  init<D: ContiguousBytes>(data: D)                // from bytes (any length)
  var bitCount: Int { get }
  func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R
}
struct SymmetricKeySize { static var bits128/bits192/bits256: SymmetricKeySize; init(bitCount: Int); let bitCount: Int }
// extract bytes (copies into Data; Data is NOT zeroized):
let bytes = key.withUnsafeBytes { Data($0) }
// Data -> key with ContiguousBytes: Data conforms, so SymmetricKey(data: someData) works directly.
```
- [high] CryptoKitError is the error enum thrown by CryptoKit; match on it in tests and wrap in app errors. (https://developer.apple.com/documentation/cryptokit/cryptokiterror)
```
enum CryptoKitError: Error {
  case incorrectKeySize
  case incorrectParameterSize
  case authenticationFailure
  case underlyingCoreCryptoError(error: Int32)
  case wrapFailure
  case unwrapFailure
  case invalidParameter
}
```
- [high] Keychain C API exact Swift signatures. All four block the calling thread (Apple: call from a background queue / async). Return codes: errSecSuccess = 0, errSecDuplicateItem = -25299, errSecItemNotFound = -25300, errSecAuthFailed = -25293, errSecUserCanceled = -128, errSecInteractionNotAllowed = -25308 (returned when item is WhenUnlocked and device is locked), errSecParam = -50. (https://developer.apple.com/documentation/security/secitemadd(_:_:) + https://developer.apple.com/documentation/security/secitemcopymatching(_:_:) + https://developer.apple.com/documentation/security/secitemupdate(_:_:) + https://developer.apple.com/documentation/security/secaccesscontrolcreatewithflags(_:_:_:_:) (numeric values from SecBase.h, knowledge))
```
func SecItemAdd(_ attributes: CFDictionary, _ result: UnsafeMutablePointer<CFTypeRef?>?) -> OSStatus
func SecItemCopyMatching(_ query: CFDictionary, _ result: UnsafeMutablePointer<CFTypeRef?>?) -> OSStatus
func SecItemUpdate(_ query: CFDictionary, _ attributesToUpdate: CFDictionary) -> OSStatus
func SecItemDelete(_ query: CFDictionary) -> OSStatus
func SecAccessControlCreateWithFlags(_ allocator: CFAllocator?, _ protection: CFTypeRef, _ flags: SecAccessControlCreateFlags, _ error: UnsafeMutablePointer<Unmanaged<CFError>?>?) -> SecAccessControl?
```
- [high] Generic-password primary key = (kSecAttrAccessGroup, kSecAttrAccount, kSecAttrService, kSecAttrSynchronizable). Adding a second item with the same (service, account) returns errSecDuplicateItem; handle by SecItemUpdate or delete-then-add. kSecAttrAccessible and kSecAttrAccessControl both apply to generic passwords but are not part of the primary key. Apple's official pattern ('Storing CryptoKit Keys in the Keychain') stores Curve25519 private keys' rawRepresentation as kSecClassGenericPassword with kSecUseDataProtectionKeychain: true, and restores with init(rawRepresentation:). (https://developer.apple.com/documentation/cryptokit/storing-cryptokit-keys-in-the-keychain + https://developer.apple.com/documentation/security/ksecclassgenericpassword + https://developer.apple.com/documentation/security/ksecattraccessiblewhenunlockedthisdeviceonly)
```
// Apple sample (CryptoKit article) adapted, no biometrics:
import Security
func keychainStore(_ raw: Data, service: String, account: String) throws {
  let add: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: service,              // e.g. "com.kilit.keys"
    kSecAttrAccount as String: account,              // e.g. "identity.x25519.v1"
    kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    kSecUseDataProtectionKeychain as String: true,
    kSecValueData as String: raw ]
  var status = SecItemAdd(add as CFDictionary, nil)
  if status == errSecDuplicateItem {
    let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: account, kSecUseDataProtectionKeychain as String: true]
    status = SecItemUpdate(q as CFDictionary, [kSecValueData as String: raw] as CFDictionary)
  }
  guard status == errSecSuccess else { throw KeychainError(status) }
}
func keychainRead(service: String, account: String) throws -> Data? {
  let q: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: service,
    kSecAttrAccount as String: account,
    kSecUseDataProtectionKeychain as String: true,
    kSecMatchLimit as String: kSecMatchLimitOne,
    kSecReturnData as String: true ]
  var item: CFTypeRef?
  switch SecItemCopyMatching(q as CFDictionary, &item) {
  case errSecSuccess: return item as? Data
  case errSecItemNotFound: return nil
  case let s: throw KeychainError(s)
  }
}
// restore: try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: data)
```
- [high] Biometric-gated variant (optional setting): build a SecAccessControl with the protection class as first arg and flags; put it under kSecAttrAccessControl INSTEAD of kSecAttrAccessible (Apple: 'You don't need to set the accessible attribute directly if you set it as part of the access control attribute'; passing both is reported as errSecParam in practice). Flags: .userPresence (biometry OR passcode, recommended), .biometryCurrentSet (invalidated when biometrics re-enrolled), .biometryAny, .devicePasscode, combinable with .and/.or; .applicationPassword; .privateKeyUsage (SecKey only). On read, pass an LAContext via kSecUseAuthenticationContext with context.localizedReason set (kSecUseOperationPrompt is deprecated since iOS 14). Info.plist must contain NSFaceIDUsageDescription. Reads may return errSecUserCanceled / errSecAuthFailed / errSecInteractionNotAllowed. kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly is stricter: item cannot be created without a passcode and is deleted when the passcode is removed. (https://developer.apple.com/documentation/security/restricting-keychain-item-accessibility + https://developer.apple.com/documentation/localauthentication/accessing-keychain-items-with-face-id-or-touch-id + https://developer.apple.com/documentation/security/secaccesscontrolcreateflags + https://developer.apple.com/documentation/security/ksecuseauthenticationcontext)
```
import Security
import LocalAuthentication
var cfError: Unmanaged<CFError>?
guard let access = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        [.userPresence],                       // or [.biometryCurrentSet]
        &cfError) else { throw cfError!.takeRetainedValue() }
let add: [String: Any] = [
  kSecClass as String: kSecClassGenericPassword,
  kSecAttrService as String: service,
  kSecAttrAccount as String: account,
  kSecAttrAccessControl as String: access,        // NOT together with kSecAttrAccessible
  kSecUseDataProtectionKeychain as String: true,
  kSecValueData as String: raw ]
// read:
let ctx = LAContext(); ctx.localizedReason = "Unlock your Kilit identity key"
let q: [String: Any] = [
  kSecClass as String: kSecClassGenericPassword,
  kSecAttrService as String: service,
  kSecAttrAccount as String: account,
  kSecUseDataProtectionKeychain as String: true,
  kSecUseAuthenticationContext as String: ctx,
  kSecMatchLimit as String: kSecMatchLimitOne,
  kSecReturnData as String: true ]
// optional: kSecUseAuthenticationUI as String: kSecUseAuthenticationUISkip  (skip protected items silently)
```
- [high] kSecAttrAccessibleWhenUnlockedThisDeviceOnly semantics (Apple): accessible only while device unlocked; recommended for foreground-only use; items do not migrate to a new device (absent after restoring another device's backup). Consequence for Kilit: (a) ratchet/identity keys cannot be read in background (push extension / silent push) when locked, so notifications must be generic; (b) restoring to a new phone requires re-registration (new identity, new safety number). Keychain items DO survive app deletion/reinstall on iOS, so on first launch after reinstall the app must detect stale items (e.g. a UserDefaults marker is gone) and wipe them. (https://developer.apple.com/documentation/security/ksecattraccessiblewhenunlockedthisdeviceonly + https://developer.apple.com/documentation/security/restricting-keychain-item-accessibility (reinstall persistence: knowledge))
- [high] File data protection APIs (Foundation, all iOS ≤ 17): Data.write(to:options:) with .completeFileProtection; FileManager.setAttributes([.protectionKey: FileProtectionType.complete], ofItemAtPath:); FileManager.createFile(atPath:contents:attributes:) with the same attribute; URLResourceKey.fileProtectionKey with URLFileProtection.complete. Data.WritingOptions is a typealias of NSData.WritingOptions, so .atomic and .completeFileProtection can be combined. Semantics: .complete = encrypted and unreadable while locked or booting (reads/writes fail while locked); .completeUnlessOpen = can be created while locked, and a handle opened while unlocked keeps working after lock (use for in-flight downloads, then upgrade to .complete); .completeUntilFirstUserAuthentication = app default when no entitlement; the com.apple.developer.default-data-protection entitlement ('Data Protection' capability in Xcode) raises the app-wide default. Setting .protectionKey on a directory makes new files inside inherit it. (https://developer.apple.com/documentation/foundation/fileprotectiontype + https://developer.apple.com/documentation/foundation/nsdata/writingoptions/completefileprotection + https://developer.apple.com/documentation/foundation/fileattributekey/protectionkey + https://developer.apple.com/documentation/foundation/urlfileprotection + https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.default-data-protection (URLResourceValues.fileProtection property: knowledge, medium))
```
// write
try ciphertext.write(to: url, options: [.atomic, .completeFileProtection])
// or after the fact / for directories
try FileManager.default.setAttributes([.protectionKey: FileProtectionType.complete], ofItemAtPath: url.path)
// create with attributes
FileManager.default.createFile(atPath: url.path, contents: ciphertext, attributes: [.protectionKey: FileProtectionType.complete])
// URL resource variant (iOS 9+)
var rv = URLResourceValues(); rv.fileProtection = .complete; try url.setResourceValues(rv)   // URLFileProtection.complete
// verify
let attrs = try FileManager.default.attributesOfItem(atPath: url.path)
let level = attrs[.protectionKey] as? FileProtectionType   // == .complete
// signatures
func write(to url: URL, options: Data.WritingOptions = []) throws
static var completeFileProtection: NSData.WritingOptions { get }
func setAttributes(_ attributes: [FileAttributeKey : Any], ofItemAtPath path: String) throws
func createFile(atPath path: String, contents data: Data?, attributes attr: [FileAttributeKey : Any]? = nil) -> Bool
static let protectionKey: FileAttributeKey
struct FileProtectionType { static let complete, completeUnlessOpen, completeUntilFirstUserAuthentication, none }
struct URLFileProtection { static let complete, completeUnlessOpen, completeUntilFirstUserAuthentication, completeWhenUserInactive, none }
```
- [high] X3DH (Signal spec rev.1, 2016) — notation and KDF, precisely: X||Y = concatenation; DH(PK1,PK2) = X25519 shared secret; Sig(PK, M) = signature verifiable with PK; Encode(PK) = byte encoding of the public key (Signal uses 0x05||32 bytes; Kilit may use the raw 32 bytes, must be fixed in the protocol); KDF(KM) = 32 bytes of HKDF-SHA256 with ikm = F || KM where F = 32 bytes of 0xFF for X25519 (57 for X448; 'cryptographic domain separation with XEdDSA'), salt = zero-filled byte sequence of hash-output length (32 zero bytes; equivalent to empty salt in HMAC), info = an ASCII string identifying the application. libsignal corroborates byte-for-byte: `secrets.extend_from_slice(&[0xFFu8; 32]); // discontinuity bytes` followed by `Hkdf::<Sha256>::new(None, secret_input).expand(label, ...)` with label "WhisperText_X25519_SHA-256_CRYSTALS-KYBER-1024" (classic X3DH used "WhisperText"). (knowledge (signal.org/docs/specifications/x3dh/ unreachable from this network); corroborated by https://github.com/signalapp/libsignal/blob/main/rust/protocol/src/pqxdh.rs)
```
SK = HKDF-SHA256(ikm = 0xFF*32 || DH1 || DH2 || DH3 [|| DH4],
                 salt = 0x00*32,
                 info = "Kilit_X3DH_v1_X25519_SHA256_ChaChaPoly",  // app-specific ASCII
                 L = 32)
// Swift
let ikm = Data(repeating: 0xFF, count: 32) + dh1 + dh2 + dh3 + (dh4 ?? Data())
let sk = HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: ikm), salt: Data(repeating: 0, count: 32), info: Data("Kilit_X3DH_v1_X25519_SHA256_ChaChaPoly".utf8), outputByteCount: 32)
// Go 1.24
sk, err := hkdf.Key(sha256.New, ikm, make([]byte, 32), "Kilit_X3DH_v1_X25519_SHA256_ChaChaPoly", 32)
```
- [high] X3DH keys and prekey bundle. Bob publishes: identity key IK_B, signed prekey SPK_B (rotated periodically, e.g. weekly; old SPK private keys kept for a grace period so late initial messages still decrypt, then deleted), signature Sig(IK_B, Encode(SPK_B)), and a batch of one-time prekeys OPK_B^1..n (server hands out each exactly once and deletes it; refills when low). Alice fetches bundle = {IK_B, SPK_B, Sig, optional OPK_B}, verifies the signature (abort if invalid), generates ephemeral EK_A, computes DH1 = DH(IK_A, SPK_B), DH2 = DH(EK_A, IK_B), DH3 = DH(EK_A, SPK_B), DH4 = DH(EK_A, OPK_B) (only if OPK present), SK = KDF(DH1||DH2||DH3[||DH4]), then deletes EK_A private key and the DH outputs. AD = Encode(IK_A) || Encode(IK_B) (may append additional identifying info such as usernames). Initial message contains IK_A, EK_A, identifiers of which SPK_B/OPK_B were used, and the initial ciphertext (AEAD with AD; in practice the first Double Ratchet message). Bob: loads the corresponding private keys, computes DH1 = DH(SPK_B, IK_A), DH2 = DH(IK_B, EK_A), DH3 = DH(SPK_B, EK_A), DH4 = DH(OPK_B, EK_A), derives SK, deletes DH values, builds AD, decrypts; on failure abort and delete SK; on success delete OPK_B private key. The Double Ratchet is then initialised with SK and Bob's SPK_B as the initial ratchet key pair: RatchetInitAlice(state, SK, SPK_B.public) / RatchetInitBob(state, SK, SPK_B keypair), and the X3DH AD is used as the Double Ratchet AD. (knowledge (signal.org X3DH spec sections 3.2–3.5); DH ordering corroborated by https://github.com/signalapp/libsignal/blob/main/rust/protocol/src/pqxdh.rs (initiator: IK×SPK, EK×IK, EK×SPK, EK×OPK))
```
// Alice
DH1 = X25519(IK_A.priv, SPK_B)
DH2 = X25519(EK_A.priv, IK_B)
DH3 = X25519(EK_A.priv, SPK_B)
DH4 = X25519(EK_A.priv, OPK_B)      // if OPK_B present
SK  = KDF(DH1 || DH2 || DH3 [|| DH4])
AD  = Encode(IK_A) || Encode(IK_B)
// Bob mirrors with (SPK_B.priv, IK_A), (IK_B.priv, EK_A), (SPK_B.priv, EK_A), (OPK_B.priv, EK_A)
```
- [medium] X3DH security considerations (spec section 4), each with the implementation consequence: 4.1 Authentication: parties must compare identity public keys out of band (safety number), else the server can MITM. 4.2 Protocol replay: if the initial message has no OPK, it can be replayed to Bob and he will accept it with the same SK; mitigations: Bob rotates SPK and keeps old ones briefly; randomize the post-X3DH protocol (Double Ratchet init does this because Bob's first reply uses a fresh ratchet key). 4.3 Replay and key reuse: never reuse SK across sessions. 4.4 Deniability: X3DH signatures are only on SPK, so no non-repudiable proof of messages. 4.5 Signatures: the SPK MUST be signed; otherwise a weak-forward-secrecy attack exists (server substitutes SPK). 4.6 Key compromise: compromise of IK private keys lets an attacker impersonate; compromise of SPK/OPK private keys breaks forward secrecy for sessions set up with them, so delete OPK after use and old SPKs after the grace period. 4.7 Server trust: a malicious server can refuse OPKs (forcing the weaker no-OPK path) or drop messages, but cannot read content if identity keys are verified; clients should warn if OPKs are exhausted. 4.8 Identity binding: AD binds both identity keys; add usernames/service identifiers into AD if identities are identified by username (Kilit should append the two usernames to AD). (knowledge (signal.org/docs/specifications/x3dh/ section 4; not fetchable here))
- [high] XEdDSA gap: Signal uses ONE Curve25519 key for both DH (X25519) and signatures (XEdDSA), which CryptoKit does not provide and which cannot be built without custom field arithmetic (forbidden by the no-third-party-crypto rule). Design consequence: the identity is a PAIR of keys: IK_sig (Curve25519.Signing, Ed25519) and IK_dh (Curve25519.KeyAgreement, X25519). Bind them: the published identity record is {IK_sig, IK_dh, Sig(IK_sig, "Kilit_IKBind_v1" || Encode(IK_dh))}; the SPK signature is Sig(IK_sig, "Kilit_SPK_v1" || Encode(SPK)); server auth challenges are Sig(IK_sig, "Kilit_Auth_v1" || nonce || timestamp). AD = Encode(IK_sig_A) || Encode(IK_dh_A) || Encode(IK_sig_B) || Encode(IK_dh_B) || usernames. The safety number covers both keys of each party. Go side: crypto/ed25519 + crypto/ecdh X25519 match exactly (Go has no XEdDSA either). (knowledge (X3DH spec §2.1/§4 XEdDSA reference) + verified CryptoKit API surface above)
```
let ikSig = Curve25519.Signing.PrivateKey()
let ikDH  = Curve25519.KeyAgreement.PrivateKey()
let bind  = try ikSig.signature(for: Data("Kilit_IKBind_v1".utf8) + ikDH.publicKey.rawRepresentation)
let spk   = Curve25519.KeyAgreement.PrivateKey()
let spkSig = try ikSig.signature(for: Data("Kilit_SPK_v1".utf8) + spk.publicKey.rawRepresentation)
// verify: ikSigPub.isValidSignature(spkSig, for: Data("Kilit_SPK_v1".utf8) + spkPub.rawRepresentation)
```
- [high] Double Ratchet external functions (spec §3.1), exact definitions: GENERATE_DH() returns a new DH key pair; DH(dh_pair, dh_pub) returns the DH output; KDF_RK(rk, dh_out) returns a pair (32-byte root key, 32-byte chain key); KDF_CK(ck) returns a pair (32-byte chain key, 32-byte message key); ENCRYPT(mk, plaintext, associated_data) returns an AEAD ciphertext; DECRYPT(mk, ciphertext, associated_data) returns plaintext or raises on authentication failure; HEADER(dh_pair, pn, n) creates a header containing the ratchet public key from dh_pair, the previous chain length pn, and the message number n; CONCAT(ad, header) encodes the header into a parseable byte sequence, prepends ad, and returns the result — 'If ad is not guaranteed to be a parseable byte sequence, a length value should be prepended to the output to ensure that the output is parseable as a unique pair (ad, header)'. MAX_SKIP is a constant bounding skipped message keys in a single chain. State (§3.2): DHs (own ratchet key pair), DHr (remote ratchet public key), RK, CKs, CKr, Ns, Nr, PN, MKSKIPPED (dict keyed by (ratchet public key, message number) -> message key). (knowledge (signal.org/docs/specifications/doubleratchet/ §3.1–3.2); corroborated by https://gist.github.com/mimoo/356fd8c32216307d4f4f8b79659637c0 which quotes the spec pseudocode)
```
// Kilit concrete encodings (must be identical in Swift and Go):
header  = version(0x01) || dh_pub(32) || pn(uint32 BE) || n(uint32 BE)   // 41 bytes
CONCAT(ad, header) = len(ad) as uint16 BE || ad || header
```
- [high] Double Ratchet pseudocode (spec §3.3–3.5), verbatim semantics. Note the spec's RatchetDecrypt increments state.Nr AFTER deriving mk ('state.Nr += 1' precedes the return in the spec; the gist omitted that line but libsignal and the spec both advance the counter). SkipMessageKeys raises if state.Nr + MAX_SKIP < until. DHRatchet resets Ns and Nr to 0 and performs two KDF_RK steps (receive then send). (knowledge (signal.org/docs/specifications/doubleratchet/ §3.3–3.5); corroborated by https://gist.github.com/mimoo/356fd8c32216307d4f4f8b79659637c0 (quotes RatchetDecrypt/TrySkippedMessageKeys/SkipMessageKeys/DHRatchet verbatim) and libsignal state handling)
```
def RatchetInitAlice(state, SK, bob_dh_public_key):
    state.DHs = GENERATE_DH()
    state.DHr = bob_dh_public_key
    state.RK, state.CKs = KDF_RK(SK, DH(state.DHs, state.DHr))
    state.CKr = None
    state.Ns = 0; state.Nr = 0; state.PN = 0
    state.MKSKIPPED = {}

def RatchetInitBob(state, SK, bob_dh_key_pair):
    state.DHs = bob_dh_key_pair
    state.DHr = None
    state.RK = SK
    state.CKs = None; state.CKr = None
    state.Ns = 0; state.Nr = 0; state.PN = 0
    state.MKSKIPPED = {}

def RatchetEncrypt(state, plaintext, AD):
    state.CKs, mk = KDF_CK(state.CKs)
    header = HEADER(state.DHs, state.PN, state.Ns)
    state.Ns += 1
    return header, ENCRYPT(mk, plaintext, CONCAT(AD, header))

def RatchetDecrypt(state, header, ciphertext, AD):
    plaintext = TrySkippedMessageKeys(state, header, ciphertext, AD)
    if plaintext != None:
        return plaintext
    if header.dh != state.DHr:
        SkipMessageKeys(state, header.pn)
        DHRatchet(state, header)
    SkipMessageKeys(state, header.n)
    state.CKr, mk = KDF_CK(state.CKr)
    state.Nr += 1
    return DECRYPT(mk, ciphertext, CONCAT(AD, header))

def TrySkippedMessageKeys(state, header, ciphertext, AD):
    if (header.dh, header.n) in state.MKSKIPPED:
        mk = state.MKSKIPPED[header.dh, header.n]
        del state.MKSKIPPED[header.dh, header.n]
        return DECRYPT(mk, ciphertext, CONCAT(AD, header))
    else:
        return None

def SkipMessageKeys(state, until):
    if state.Nr + MAX_SKIP < until:
        raise Error()
    if state.CKr != None:
        while state.Nr < until:
            state.CKr, mk = KDF_CK(state.CKr)
            state.MKSKIPPED[state.DHr, state.Nr] = mk
            state.Nr += 1

def DHRatchet(state, header):
    state.PN = state.Ns
    state.Ns = 0
    state.Nr = 0
    state.DHr = header.dh
    state.RK, state.CKr = KDF_RK(state.RK, DH(state.DHs, state.DHr))
    state.DHs = GENERATE_DH()
    state.RK, state.CKs = KDF_RK(state.RK, DH(state.DHs, state.DHr))

# Implementation note: on DECRYPT failure the state changes made above must be
# rolled back (work on a copy of state and commit only after successful DECRYPT).
```
- [high] Double Ratchet recommended algorithms (spec §5.2) and how libsignal instantiates them: DH = X25519 (or X448); KDF_RK(rk, dh_out) = HKDF-SHA256 (or SHA-512) with rk as HKDF SALT, dh_out as IKM, and an application-specific info 'distinct from other uses of HKDF in the application', output 64 bytes split into (new rk, ck) — libsignal: `Hkdf::<Sha256>::new(Some(&self.key /*rk*/), &shared_secret).expand(b"WhisperRatchet", 64 bytes)`; KDF_CK(ck) = HMAC-SHA256 with ck as key and distinct single-byte constants as input: 0x01 -> message key, 0x02 -> next chain key — libsignal: MESSAGE_KEY_SEED=[0x01], CHAIN_KEY_SEED=[0x02], `hmac_sha256(&self.key, &seed)`; ENCRYPT(mk, pt, ad): spec recommends an AEAD based on SIV or CBC+HMAC for misuse resistance, concretely HKDF-SHA256(ikm = mk, salt = 32 zero bytes, info = app string) -> 80 bytes = 32-byte AES-256 key || 32-byte HMAC key || 16-byte IV; AES-256-CBC with PKCS#7; HMAC-SHA256 over (associated_data || ciphertext), tag appended — libsignal: `Hkdf::<Sha256>::new(None, mk).expand(b"WhisperMessageKeys", 80 bytes)` -> cipher_key[32], mac_key[32], iv[16]. (knowledge of spec §5.2 (signal.org unreachable) + verified https://github.com/signalapp/libsignal/blob/main/rust/protocol/src/ratchet/keys.rs)
```
// Signal reference instantiation (libsignal):
rk', ck  = HKDF-SHA256(salt = rk, ikm = dh_out, info = "WhisperRatchet", L = 64)
mk       = HMAC-SHA256(key = ck, msg = 0x01)
ck'      = HMAC-SHA256(key = ck, msg = 0x02)
enc||mac||iv = HKDF-SHA256(salt = zeros, ikm = mk, info = "WhisperMessageKeys", L = 80)
```
- [high] Kilit ChaChaPoly substitution for ENCRYPT and its implications. Replace AES-256-CBC+HMAC by: HKDF-SHA256(ikm = mk, salt = 32 zero bytes, info = "Kilit_DR_v1_MessageKeys", L = 44) -> key[32] || nonce[12]; ciphertext = ChaChaPoly.seal(plaintext, key, nonce, aad = CONCAT(AD, header)); wire = ciphertext || tag (16 bytes) — the nonce is implicit, so do not transmit SealedBox.combined; rebuild with SealedBox(nonce:ciphertext:tag:). Implications vs the spec's recommendation: (1) the spec prefers SIV/CBC+HMAC because they tolerate accidental key/nonce reuse; ChaCha20-Poly1305 is catastrophically broken on (key, nonce) reuse, so correctness of the ratchet (each mk used exactly once, state persisted atomically BEFORE the ciphertext leaves the device, no re-encryption with the same mk on retry) becomes a hard requirement; deriving the nonce from mk (rather than random) keeps the mk-uniqueness invariant the only thing to protect and makes vectors deterministic; (2) authentication tag is 128-bit instead of 256-bit HMAC (spec §6.6 warns against truncating tags; 128-bit Poly1305 is standard and acceptable); (3) AEAD natively authenticates the AAD, so CONCAT(AD, header) goes into `authenticating:` and no separate MAC is needed; (4) ChaChaPoly needs a 256-bit key — the 32-byte HKDF slice satisfies CryptoKit's incorrectKeySize check; (5) Go side uses golang.org/x/crypto/chacha20poly1305 which is bit-compatible (RFC 8439). (knowledge (spec §5.2/§6.6) + verified CryptoKit/ChaChaPoly API + https://github.com/golang/crypto/blob/master/chacha20poly1305/chacha20poly1305.go)
```
// Swift
let okm = HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: mk), salt: Data(repeating: 0, count: 32), info: Data("Kilit_DR_v1_MessageKeys".utf8), outputByteCount: 44).withUnsafeBytes { Data($0) }
let key = SymmetricKey(data: okm.prefix(32)); let nonce = try ChaChaPoly.Nonce(data: okm.suffix(12))
let box = try ChaChaPoly.seal(plaintext, using: key, nonce: nonce, authenticating: concatADHeader)
let wire = box.ciphertext + box.tag
// decrypt
let box2 = try ChaChaPoly.SealedBox(nonce: nonce, ciphertext: wire.dropLast(16), tag: wire.suffix(16))
let pt = try ChaChaPoly.open(box2, using: key, authenticating: concatADHeader)
// Go
aead, _ := chacha20poly1305.New(okm[:32]) // KeySize 32, NonceSize 12, Overhead 16
wire := aead.Seal(nil, okm[32:44], plaintext, concatADHeader) // = ciphertext||tag
```
- [high] Skipped-message-key handling and limits. Spec: MAX_SKIP 'should be set high enough to tolerate routine lost or delayed messages, but low enough that a malicious sender can't trigger excessive recipient computation'; §6.4 'Deletion of skipped message keys': storing them lets a malicious sender induce storage of large numbers of keys (DoS) and lost messages may have been seen by an attacker, so implementations should delete skipped keys after a time or number of events. libsignal values: MAX_FORWARD_JUMPS = 25_000 (max counter jump per chain), MAX_MESSAGE_KEYS = 2000 (stored skipped keys per receiver chain, FIFO eviction), MAX_RECEIVER_CHAINS = 5 (old receiving chains kept for out-of-order delivery across DH ratchets), ARCHIVED_STATES_MAX_LENGTH = 40, MAX_UNACKNOWLEDGED_SESSION_AGE = 30 days. OMEMO uses MAX_SKIP ~1000. Recommendation for Kilit: MAX_SKIP = 1000 per chain, MKSKIPPED capped at 2000 entries total with oldest-first eviction, entries expire after 7 days, keep at most 5 previous receiving chains' skipped keys; MKSKIPPED must be persisted with the session (keychain-wrapped/encrypted file), and a skipped key is deleted the moment it is used. (https://github.com/signalapp/libsignal/blob/main/rust/protocol/src/consts.rs + https://github.com/signalapp/libsignal/blob/main/rust/protocol/src/state/session.rs (MAX_MESSAGE_KEYS eviction) + knowledge of spec §3.5/§6.4; OMEMO figure from web search (code.moparisthebest.com xeps mirror))
- [medium] Double Ratchet security considerations (spec §6) in implementation terms: §6.1 secure deletion — delete every mk, old ck, old rk and old DHs private key as soon as it is no longer needed; keep secrets in SymmetricKey/SecureBytes where possible (Swift Data cannot be reliably zeroed); §6.2 recovery from compromise — forward secrecy comes from KDF chains, post-compromise security from DH ratchet steps, so clients must ratchet (send a message) regularly; §6.3 ratchet keys — attacker who learns a ratchet private key can compute until the next DH step; §6.4 skipped keys (above); §6.5 deferring new ratchet key generation — generating DHs lazily at send time is allowed; §6.6 truncating tags weakens security (keep 16-byte Poly1305 tag); §6.7 implementation fingerprinting — identical wire formats across clients. Also: on DECRYPT failure do not persist any state changes (rollback), and persist state before releasing ciphertext to the network to never reuse mk. (knowledge (signal.org/docs/specifications/doubleratchet/ §6))
- [high] Concrete KDF/domain-separation string catalogue for Kilit (ASCII, distinct per use as both specs require). All HKDF uses are HKDF-SHA256; 'zeros' = 32 zero bytes. (knowledge (spec requirement: distinct HKDF info per use; Signal fingerprint algorithm from libsignal, medium))
```
X3DH session key   : HKDF(ikm = 0xFF*32||DH1||DH2||DH3[||DH4], salt = zeros, info = "Kilit_X3DH_v1_X25519_SHA256_ChaChaPoly", L=32) -> SK
DR root KDF_RK     : HKDF(ikm = dh_out, salt = rk, info = "Kilit_DR_v1_RootChain", L=64) -> rk'(32)||ck(32)
DR chain KDF_CK    : HMAC-SHA256(ck, 0x01) -> mk ; HMAC-SHA256(ck, 0x02) -> ck'
DR message AEAD    : HKDF(ikm = mk, salt = zeros, info = "Kilit_DR_v1_MessageKeys", L=44) -> key(32)||nonce(12)
Attachment AEAD    : fileKey = 32 random bytes; HKDF(ikm = fileKey, salt = zeros, info = "Kilit_Attach_v1", L=44) -> key||nonce; AAD = blobID||mime||byteLength; wire = ciphertext||tag; fileKey+blobID+digest(SHA-256 of ciphertext) sent inside a ratchet message
SPK signature      : Ed25519(IK_sig, "Kilit_SPK_v1" || Encode(SPK_pub))
Identity binding   : Ed25519(IK_sig, "Kilit_IKBind_v1" || Encode(IK_dh_pub))
Server auth        : Ed25519(IK_sig, "Kilit_Auth_v1" || serverNonce(32) || unixSeconds(uint64 BE) || username)
Safety number      : per party fp = SHA-256 iterated 5200 times over ("Kilit_SafetyNumber_v1" || IK_sig || IK_dh || username) (Signal uses 5200 iterations of SHA-512 over version||key||id); take 30 decimal digits from each (5-digit groups from 5-byte chunks mod 100000), concatenate lexicographically smaller first -> 60 digits
Local state wrap   : masterKey = SymmetricKey(size: .bits256) in Keychain; HKDF(ikm = masterKey, salt = zeros, info = "Kilit_LocalStore_v1", L=32) -> ChaChaPoly key for the session-state file (random nonce, store combined)
Encode(PK)         : raw 32 bytes (no 0x05 prefix); all integers big-endian; all strings UTF-8 without length unless inside CONCAT where ad is uint16-length-prefixed
```
- [high] Go 1.24 standard library coverage for the reference implementation (no third-party except x/crypto for ChaCha20-Poly1305): crypto/hkdf is NEW in Go 1.24 (release notes: 'The new crypto/hkdf package implements ... HKDF, as defined in RFC 5869'); crypto/ecdh X25519 (Go 1.20+); crypto/ed25519; golang.org/x/crypto/chacha20poly1305 (or crypto/cipher with x/crypto). ed25519.PrivateKey is 64 bytes = seed(32)||public(32); CryptoKit rawRepresentation is the 32-byte seed, so vectors must carry the seed: Go loads with ed25519.NewKeyFromSeed(seed) and exports priv.Seed(). Go Ed25519 Sign is deterministic (RFC 8032), CryptoKit's is randomized: compare by verification, not bytes. (https://github.com/golang/go/blob/go1.24.0/src/crypto/hkdf/hkdf.go + https://github.com/golang/go/blob/go1.24.0/src/crypto/ed25519/ed25519.go + https://github.com/golang/go/blob/go1.24.0/src/crypto/ecdh/x25519.go + https://pkg.go.dev/crypto/ecdh + https://github.com/golang/crypto/blob/master/chacha20poly1305/chacha20poly1305.go + https://github.com/golang/website/blob/master/_content/doc/go1.24.md)
```
// crypto/hkdf (Go 1.24)
func Key[Hash hash.Hash](h func() Hash, secret, salt []byte, info string, keyLength int) ([]byte, error)
func Extract[H hash.Hash](h func() H, secret, salt []byte) ([]byte, error)
func Expand[H hash.Hash](h func() H, pseudorandomKey []byte, info string, keyLength int) ([]byte, error)
// crypto/ecdh
func X25519() Curve
type Curve interface { GenerateKey(rand io.Reader) (*PrivateKey, error); NewPrivateKey(key []byte) (*PrivateKey, error); NewPublicKey(key []byte) (*PublicKey, error) }
func (k *PrivateKey) ECDH(remote *PublicKey) ([]byte, error)  // error on all-zero output
func (k *PrivateKey) Bytes() []byte; func (k *PrivateKey) PublicKey() *PublicKey; func (k *PublicKey) Bytes() []byte
// crypto/ed25519
const PublicKeySize = 32; PrivateKeySize = 64; SignatureSize = 64; SeedSize = 32
func GenerateKey(rand io.Reader) (PublicKey, PrivateKey, error)
func NewKeyFromSeed(seed []byte) PrivateKey
func (priv PrivateKey) Seed() []byte
func Sign(privateKey PrivateKey, message []byte) []byte
func Verify(publicKey PublicKey, message, sig []byte) bool
// golang.org/x/crypto/chacha20poly1305
const KeySize = 32; NonceSize = 12; NonceSizeX = 24; Overhead = 16
func New(key []byte) (cipher.AEAD, error)
// cipher.AEAD: Seal(dst, nonce, plaintext, additionalData []byte) []byte ; Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
// HMAC: hmac.New(sha256.New, key).Write(msg).Sum(nil); hmac.Equal(a,b)
```
- [high] Cross-platform test-vector strategy that is actually checkable on the Mac: generate in Go a JSON file of vectors {x25519: [priv, pub, peerPub, sharedSecret]}, {hkdf: [ikm, salt, info, L, okm]}, {hmac_kdf_ck: [ck, mk, ck']}, {chachapoly: [key, nonce, aad, pt, ciphertext||tag]}, {ed25519: [seed, pub, msg, goSignature]}, {x3dh: full bundle + SK + AD}, {ratchet: scripted conversation with every header and wire ciphertext}. Swift XCTest: (a) recompute and compare bytes for X25519/HKDF/HMAC/ChaChaPoly/X3DH/ratchet (all deterministic given explicit nonces derived from mk); (b) for Ed25519 verify Go's signature with isValidSignature and verify Swift's fresh signature against the same public key (bytes differ by design); (c) include negative vectors (tampered tag -> CryptoKitError.authenticationFailure, low-order X25519 point -> Kilit error, wrong-length keys -> incorrectKeySize). Embed the JSON as a resource in the test target (PBXFileSystemSynchronizedRootGroup picks up Tests/ folder resources when the target's exception set includes them, or simply put a Vectors.swift with string literals to avoid resource handling). (knowledge, built on verified API facts above)
```
// Swift test skeleton
func testX25519Vectors() throws {
  for v in vectors.x25519 {
    let priv = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: Data(hex: v.priv))
    XCTAssertEqual(priv.publicKey.rawRepresentation, Data(hex: v.pub))
    let ss = try priv.sharedSecretFromKeyAgreement(with: try .init(rawRepresentation: Data(hex: v.peerPub)))
    XCTAssertEqual(ss.withUnsafeBytes { Data($0) }, Data(hex: v.shared))
  }
}
func testEd25519Vectors() throws {
  for v in vectors.ed25519 {
    let priv = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(hex: v.seed))
    XCTAssertEqual(priv.publicKey.rawRepresentation, Data(hex: v.pub))
    XCTAssertTrue(priv.publicKey.isValidSignature(Data(hex: v.goSig), for: Data(hex: v.msg)))
    XCTAssertTrue(priv.publicKey.isValidSignature(try priv.signature(for: Data(hex: v.msg)), for: Data(hex: v.msg)))
  }
}
```
- [high] HKDF salt equivalence: RFC 5869 says an absent salt is treated as HashLen zero bytes; because HMAC zero-pads short keys, HKDF with salt = Data() (CryptoKit's info-only overload uses [UInt8]()), salt = 32 zero bytes (X3DH spec wording), and Go hkdf.Key(..., salt = nil, ...) all produce identical output. Pick one spelling per KDF (Kilit: explicit 32 zero bytes) and add a vector proving equality. (knowledge (RFC 5869 §2.2) + https://github.com/apple/swift-crypto/blob/main/Sources/Crypto/Key%20Derivation/HKDF.swift (info-only overload passes [UInt8]() as salt))
Pitfalls: signal.org (and every mirror tried: web.archive.org, cs.rit.edu, cs.wm.edu, miliao.org, r.jina.ai) is unreachable from this build network, so the X3DH/Double Ratchet text is from knowledge, corroborated by libsignal source and a gist quoting the spec; have the owner re-read §2.1 (X3DH) and §5.2/§6 (Double Ratchet) once on the Mac before freezing the wire format. | CryptoKit Ed25519 signatures are randomized: never write a test that compares signature bytes between Swift and Go; compare by verification only. Go's are deterministic, so Go-side golden signatures are fine to embed. | Ed25519 private key size mismatch: CryptoKit rawRepresentation = 32-byte seed; Go ed25519.PrivateKey = 64 bytes (seed||pub). Serialize/transport the SEED only; Go must use NewKeyFromSeed / Seed(). | CryptoKit does not reject low-order X25519 points (all-zero shared secret); Go crypto/ecdh does. Add an explicit all-zero check on the Swift side so both implementations fail identically, and include a low-order-point negative vector. | Do not use any CryptoKit API that takes RawSpan / OutputRawSpan / MutableRawSpan (HKDF.deriveKey(...output:), HKDF.expand(...into:), extract(inputKeyMaterial:salt: RawSpan?), SymmetricKey(copying:), Nonce(copying:), ChaChaPoly.seal(inPlace:...), SymmetricKey.bytes) — those are iOS 26-era and will not compile for an iOS 17 deployment target. HKDF itself is iOS 14+, so it is fine. | ChaChaPoly requires exactly a 256-bit SymmetricKey and a 12-byte nonce; AES.GCM.SealedBox.combined is Optional (nil for non-12-byte nonces) whereas ChaChaPoly.SealedBox.combined is non-optional. SealedBox(combined:) needs >= 28 bytes. | ChaCha20-Poly1305 has zero nonce-misuse resistance (the reason the Double Ratchet spec recommends SIV or CBC+HMAC). With the ratchet, the message key is the only thing guaranteeing uniqueness: persist ratchet state atomically BEFORE handing ciphertext to the network, never re-encrypt a retry with the same mk, and roll back state on decryption failure. | CONCAT(AD, header) must be length-prefixed and byte-identical in Swift and Go (uint16 BE length of AD, then AD, then 41-byte header). Any divergence (e.g. little-endian counters, 0x05 key prefix on one side only) silently breaks interop and only shows up as authenticationFailure. | Passing both kSecAttrAccessible and kSecAttrAccessControl in one SecItemAdd dictionary fails (errSecParam, -50): the protection class goes inside SecAccessControlCreateWithFlags when access control is used. | kSecAttrAccessibleWhenUnlockedThisDeviceOnly items return errSecInteractionNotAllowed while the device is locked; the app cannot decrypt in a Notification Service Extension or on a silent push while locked. Design pushes as generic ('New message') and do all decryption in the foreground. | Keychain items survive app uninstall on iOS and ThisDeviceOnly items are NOT restored to a new device: handle both 'stale identity after reinstall' (wipe on first launch marker) and 'new device' (re-register, new safety number) explicitly. | SecItemAdd/SecItemCopyMatching block the calling thread and biometric-protected reads show UI; never call them on the main thread, always pass an LAContext with localizedReason (kSecUseOperationPrompt is deprecated since iOS 14), and add NSFaceIDUsageDescription to Info.plist or Face ID is refused. | Data.write(options: .completeFileProtection) protects the file you write, but URLSession download temp files, UIImage/ImageIO caches, UIPasteboard, Spotlight and backups are separate leak paths: move downloads into a .complete-protected directory immediately, mark the directory with .protectionKey so children inherit it, and set isExcludedFromBackup. With .complete, open file handles stop working shortly after the device locks; use .completeUnlessOpen for in-flight writes and upgrade afterward. | Swift Data/[UInt8] buffers are not zeroized; keep long-lived secrets as SymmetricKey (zeroized on dealloc) and minimize copies via withUnsafeBytes. SharedSecret == is constant-time, Data == is not; use HMAC.isValidAuthenticationCode / SharedSecret == for security comparisons. | HKDF 'empty salt' vs '32 zero bytes' vs Go nil salt are equivalent (HMAC zero-pads), but 'no salt argument' in some libraries means something else; standardize on explicit 32 zero bytes and prove it with a vector. | MAX_SKIP without a storage cap is a DoS vector: bound both the jump (1000) and the stored skipped-key count (2000, FIFO) and expire entries; persist MKSKIPPED with the session or out-of-order messages become undecryptable after relaunch. | X3DH without a one-time prekey is replayable: the server must hand each OPK out once and delete it; clients should warn/refill when OPKs are exhausted; Bob must rotate SPK and keep old SPK private keys for a bounded grace period. | CryptoKit has no XEdDSA, so identity must be an Ed25519+X25519 key pair; forgetting to bind the two (signature of IK_dh by IK_sig) lets the server swap the DH identity key without breaking the signature chain. | Pure-Go SQLite driver (modernc.org/sqlite) is fine for the server, but the Go crypto reference library must stay cgo-free too: stdlib crypto/ecdh, crypto/ed25519, crypto/hkdf (Go 1.24+) and golang.org/x/crypto/chacha20poly1305 are all pure Go.

### xcode-project: minimal Xcode 16 project.pbxproj (objectVersion 77, PBXFileSystemSynchronizedRootGroup) for a SwiftUI iOS 17 app + XCTest unit-test target, Info.plist strategy (INFOPLIST_KEY_* vs custom file), shared scheme, and XcodeGen project.yml fallback. Validated template files written under /tmp/claude-0/-home-user-clawDbot/bdce7bc4-a479-5125-8ada-9eaadb92752b/scratchpad/template/ios/ (copy that whole tree to repo ios/).
- [high] Project format: Xcode 16+ writes `objectVersion = 77` at the top and `preferredProjectObjectVersion = 77` inside PBXProject. Verified on three real Xcode-generated files (Xcode 16.4, 26.2 and 26.3 all still default to 77) and XcodeGen 2.44.1 changelog ('Set the correct object version of 77 for Xcode 16 projects'). Newer opt-in formats exist (XcodeGen master: xcode26_3 -> objectVersion 100, xcode27_0 -> 110) but 77 is what Xcode 16.x creates and what every Xcode >= 16.0 opens. Xcode 15 cannot open it (Xcode 16 release notes: 'xcodebuild now validates the format version number of Xcode projects for compatibility'). Note: the tuist/XcodeProj fixture uses objectVersion 73 (Xcode 16 beta era) - do not copy that. (https://github.com/rkny6/echo/blob/master/echo.xcodeproj/project.pbxproj (CreatedOnToolsVersion 16.4), https://github.com/tfausak/Pylo/blob/main/Pylo.xcodeproj/project.pbxproj (26.2), https://github.com/DaviRain-Su/empty/blob/main/Empty.xcodeproj/project.pbxproj (26.3), https://github.com/yonaskolb/XcodeGen/blob/master/CHANGELOG.md, https://developer.apple.com/documentation/xcode-release-notes/xcode-16-release-notes)
```
// !$*UTF8*$!
{
	archiveVersion = 1;
	classes = {
	};
	objectVersion = 77;
	objects = {
		...
	};
	rootObject = <PROJECT_ID> /* Project object */;
}
```
- [high] Synchronized folder object: `PBXFileSystemSynchronizedRootGroup` with `path` (folder relative to the directory containing the .xcodeproj, since projectDirPath = "") and `sourceTree = "<group>"`. Xcode itself writes it multi-line and OMITS `explicitFileTypes`/`explicitFolders` when they are empty; XcodeGen writes `explicitFileTypes = {}; explicitFolders = ();` explicitly - both forms are accepted. An optional `exceptions = (...)` list points to `PBXFileSystemSynchronizedBuildFileExceptionSet` objects; each has `membershipExceptions` (folder-relative paths) and `target`. For the folder's owning target the listed paths are EXCLUDED from membership (Xcode writes this for Info.plist when INFOPLIST_FILE points inside the folder). The group is attached to a target via the target's `fileSystemSynchronizedGroups = (...)` array; Xcode shows it in the navigator because it is also a child of the mainGroup PBXGroup. (https://github.com/rkny6/echo/blob/master/echo.xcodeproj/project.pbxproj, https://github.com/tfausak/Pylo/blob/main/Pylo.xcodeproj/project.pbxproj, https://github.com/tuist/XcodeProj/blob/main/Fixtures/SynchronizedRootGroups/SynchronizedRootGroups.xcodeproj/project.pbxproj, https://github.com/yonaskolb/XcodeGen/blob/master/Tests/Fixtures/TestProject/Project.xcodeproj/project.pbxproj)
```
/* Begin PBXFileSystemSynchronizedBuildFileExceptionSet section */
		4B494C495400000000000008 /* Exceptions for "Sources" folder in "Kilit" target */ = {
			isa = PBXFileSystemSynchronizedBuildFileExceptionSet;
			membershipExceptions = (
				Info.plist,
			);
			target = 4B494C495400000000000010 /* Kilit */;
		};
/* End PBXFileSystemSynchronizedBuildFileExceptionSet section */

/* Begin PBXFileSystemSynchronizedRootGroup section */
		4B494C495400000000000006 /* Sources */ = {
			isa = PBXFileSystemSynchronizedRootGroup;
			exceptions = (
				4B494C495400000000000008 /* Exceptions for "Sources" folder in "Kilit" target */,
			);
			path = Sources;
			sourceTree = "<group>";
		};
		4B494C495400000000000007 /* Tests */ = {
			isa = PBXFileSystemSynchronizedRootGroup;
			path = Tests;
			sourceTree = "<group>";
		};
/* End PBXFileSystemSynchronizedRootGroup section */
```
- [high] Target + project wiring exactly as Xcode 16 writes it: PBXNativeTarget keeps the classic three build phases (Sources/Frameworks/Resources, all with empty `files = ()` because membership comes from the synced folder), `buildRules = ()`, `dependencies`, `fileSystemSynchronizedGroups`, `packageProductDependencies = ()`, `productName`, `productReference`, `productType`. The unit-test target depends on the app through a PBXTargetDependency + PBXContainerItemProxy (proxyType = 1, remoteGlobalIDString = app target id, remoteInfo = app name). PBXProject carries `attributes.TargetAttributes` with `CreatedOnToolsVersion` and, for the test target, `TestTargetID = <app id>`; plus `minimizedProjectReferenceProxies = 1;` and `preferredProjectObjectVersion = 77;` (both new in Xcode 16, present in every Xcode 16+ generated file I fetched). (https://github.com/rkny6/echo/blob/master/echo.xcodeproj/project.pbxproj)
```
		4B494C495400000000000020 /* KilitTests */ = {
			isa = PBXNativeTarget;
			buildConfigurationList = 4B494C495400000000000024 /* Build configuration list for PBXNativeTarget "KilitTests" */;
			buildPhases = (
				4B494C495400000000000021 /* Sources */,
				4B494C495400000000000022 /* Frameworks */,
				4B494C495400000000000023 /* Resources */,
			);
			buildRules = (
			);
			dependencies = (
				4B494C495400000000000028 /* PBXTargetDependency */,
			);
			fileSystemSynchronizedGroups = (
				4B494C495400000000000007 /* Tests */,
			);
			name = KilitTests;
			packageProductDependencies = (
			);
			productName = KilitTests;
			productReference = 4B494C495400000000000005 /* KilitTests.xctest */;
			productType = "com.apple.product-type.bundle.unit-test";
		};

		4B494C495400000000000001 /* Project object */ = {
			isa = PBXProject;
			attributes = {
				BuildIndependentTargetsInParallel = 1;
				LastSwiftUpdateCheck = 1600;
				LastUpgradeCheck = 1600;
				TargetAttributes = {
					4B494C495400000000000010 = {
						CreatedOnToolsVersion = 16.0;
					};
					4B494C495400000000000020 = {
						CreatedOnToolsVersion = 16.0;
						TestTargetID = 4B494C495400000000000010;
					};
				};
			};
			buildConfigurationList = 4B494C495400000000000030 /* Build configuration list for PBXProject "Kilit" */;
			developmentRegion = en;
			hasScannedForEncodings = 0;
			knownRegions = (
				en,
				Base,
			);
			mainGroup = 4B494C495400000000000002;
			minimizedProjectReferenceProxies = 1;
			preferredProjectObjectVersion = 77;
			productRefGroup = 4B494C495400000000000003 /* Products */;
			projectDirPath = "";
			projectRoot = "";
			targets = (
				4B494C495400000000000010 /* Kilit */,
				4B494C495400000000000020 /* KilitTests */,
			);
		};
```
- [high] COMPLETE project.pbxproj template (app `Kilit`, test target `KilitTests`, bundle ids `com.example.Kilit` / `com.example.KilitTests`, DEVELOPMENT_TEAM empty, iOS 17.0, Swift 5.0, iPhone only). Layout it expects: ios/Kilit.xcodeproj/project.pbxproj, ios/Sources/ (synced -> Kilit), ios/Tests/ (synced -> KilitTests), ios/Sources/Info.plist (custom keys, excluded from membership). Project-level Debug/Release settings are byte-for-byte the Xcode 16.4 template set with IPHONEOS_DEPLOYMENT_TARGET changed to 17.0. Validated: parses with the cordova `xcode` pbxproj parser (same parser parses the real Xcode 16.4 file), 27 defined ids == 27 referenced ids, no dangling/duplicate ids, per-isa attribute sets identical to the real Xcode 16.4 project. Canonical tab-indented copy: /tmp/claude-0/-home-user-clawDbot/bdce7bc4-a479-5125-8ada-9eaadb92752b/scratchpad/template/ios/Kilit.xcodeproj/project.pbxproj . To rename: replace `Kilit`, `KilitTests`, `com.example.Kilit`, `com.example.KilitTests`, and the usage-description strings. (Derived line-by-line from https://github.com/rkny6/echo/blob/master/echo.xcodeproj/project.pbxproj (Xcode 16.4) with deployment target/ids/names changed; structure validated locally with the cordova `xcode` npm parser (xcode@3.0.1) and an id cross-reference script.)
```
// !$*UTF8*$!
{
	archiveVersion = 1;
	classes = {
	};
	objectVersion = 77;
	objects = {

/* Begin PBXContainerItemProxy section */
		4B494C495400000000000027 /* PBXContainerItemProxy */ = {
			isa = PBXContainerItemProxy;
			containerPortal = 4B494C495400000000000001 /* Project object */;
			proxyType = 1;
			remoteGlobalIDString = 4B494C495400000000000010;
			remoteInfo = Kilit;
		};
/* End PBXContainerItemProxy section */

/* Begin PBXFileReference section */
		4B494C495400000000000004 /* Kilit.app */ = {isa = PBXFileReference; explicitFileType = wrapper.application; includeInIndex = 0; path = Kilit.app; sourceTree = BUILT_PRODUCTS_DIR; };
		4B494C495400000000000005 /* KilitTests.xctest */ = {isa = PBXFileReference; explicitFileType = wrapper.cfbundle; includeInIndex = 0; path = KilitTests.xctest; sourceTree = BUILT_PRODUCTS_DIR; };
/* End PBXFileReference section */

/* Begin PBXFileSystemSynchronizedBuildFileExceptionSet section */
		4B494C495400000000000008 /* Exceptions for "Sources" folder in "Kilit" target */ = {
			isa = PBXFileSystemSynchronizedBuildFileExceptionSet;
			membershipExceptions = (
				Info.plist,
			);
			target = 4B494C495400000000000010 /* Kilit */;
		};
/* End PBXFileSystemSynchronizedBuildFileExceptionSet section */

/* Begin PBXFileSystemSynchronizedRootGroup section */
		4B494C495400000000000006 /* Sources */ = {
			isa = PBXFileSystemSynchronizedRootGroup;
			exceptions = (
				4B494C495400000000000008 /* Exceptions for "Sources" folder in "Kilit" target */,
			);
			path = Sources;
			sourceTree = "<group>";
		};
		4B494C495400000000000007 /* Tests */ = {
			isa = PBXFileSystemSynchronizedRootGroup;
			path = Tests;
			sourceTree = "<group>";
		};
/* End PBXFileSystemSynchronizedRootGroup section */

/* Begin PBXFrameworksBuildPhase section */
		4B494C495400000000000012 /* Frameworks */ = {
			isa = PBXFrameworksBuildPhase;
			buildActionMask = 2147483647;
			files = (
			);
			runOnlyForDeploymentPostprocessing = 0;
		};
		4B494C495400000000000022 /* Frameworks */ = {
			isa = PBXFrameworksBuildPhase;
			buildActionMask = 2147483647;
			files = (
			);
			runOnlyForDeploymentPostprocessing = 0;
		};
/* End PBXFrameworksBuildPhase section */

/* Begin PBXGroup section */
		4B494C495400000000000002 = {
			isa = PBXGroup;
			children = (
				4B494C495400000000000006 /* Sources */,
				4B494C495400000000000007 /* Tests */,
				4B494C495400000000000003 /* Products */,
			);
			sourceTree = "<group>";
		};
		4B494C495400000000000003 /* Products */ = {
			isa = PBXGroup;
			children = (
				4B494C495400000000000004 /* Kilit.app */,
				4B494C495400000000000005 /* KilitTests.xctest */,
			);
			name = Products;
			sourceTree = "<group>";
		};
/* End PBXGroup section */

/* Begin PBXNativeTarget section */
		4B494C495400000000000010 /* Kilit */ = {
			isa = PBXNativeTarget;
			buildConfigurationList = 4B494C495400000000000014 /* Build configuration list for PBXNativeTarget "Kilit" */;
			buildPhases = (
				4B494C495400000000000011 /* Sources */,
				4B494C495400000000000012 /* Frameworks */,
				4B494C495400000000000013 /* Resources */,
			);
			buildRules = (
			);
			dependencies = (
			);
			fileSystemSynchronizedGroups = (
				4B494C495400000000000006 /* Sources */,
			);
			name = Kilit;
			packageProductDependencies = (
			);
			productName = Kilit;
			productReference = 4B494C495400000000000004 /* Kilit.app */;
			productType = "com.apple.product-type.application";
		};
		4B494C495400000000000020 /* KilitTests */ = {
			isa = PBXNativeTarget;
			buildConfigurationList = 4B494C495400000000000024 /* Build configuration list for PBXNativeTarget "KilitTests" */;
			buildPhases = (
				4B494C495400000000000021 /* Sources */,
				4B494C495400000000000022 /* Frameworks */,
				4B494C495400000000000023 /* Resources */,
			);
			buildRules = (
			);
			dependencies = (
				4B494C495400000000000028 /* PBXTargetDependency */,
			);
			fileSystemSynchronizedGroups = (
				4B494C495400000000000007 /* Tests */,
			);
			name = KilitTests;
			packageProductDependencies = (
			);
			productName = KilitTests;
			productReference = 4B494C495400000000000005 /* KilitTests.xctest */;
			productType = "com.apple.product-type.bundle.unit-test";
		};
/* End PBXNativeTarget section */

/* Begin PBXProject section */
		4B494C495400000000000001 /* Project object */ = {
			isa = PBXProject;
			attributes = {
				BuildIndependentTargetsInParallel = 1;
				LastSwiftUpdateCheck = 1600;
				LastUpgradeCheck = 1600;
				TargetAttributes = {
					4B494C495400000000000010 = {
						CreatedOnToolsVersion = 16.0;
					};
					4B494C495400000000000020 = {
						CreatedOnToolsVersion = 16.0;
						TestTargetID = 4B494C495400000000000010;
					};
				};
			};
			buildConfigurationList = 4B494C495400000000000030 /* Build configuration list for PBXProject "Kilit" */;
			developmentRegion = en;
			hasScannedForEncodings = 0;
			knownRegions = (
				en,
				Base,
			);
			mainGroup = 4B494C495400000000000002;
			minimizedProjectReferenceProxies = 1;
			preferredProjectObjectVersion = 77;
			productRefGroup = 4B494C495400000000000003 /* Products */;
			projectDirPath = "";
			projectRoot = "";
			targets = (
				4B494C495400000000000010 /* Kilit */,
				4B494C495400000000000020 /* KilitTests */,
			);
		};
/* End PBXProject section */

/* Begin PBXResourcesBuildPhase section */
		4B494C495400000000000013 /* Resources */ = {
			isa = PBXResourcesBuildPhase;
			buildActionMask = 2147483647;
			files = (
			);
			runOnlyForDeploymentPostprocessing = 0;
		};
		4B494C495400000000000023 /* Resources */ = {
			isa = PBXResourcesBuildPhase;
			buildActionMask = 2147483647;
			files = (
			);
			runOnlyForDeploymentPostprocessing = 0;
		};
/* End PBXResourcesBuildPhase section */

/* Begin PBXSourcesBuildPhase section */
		4B494C495400000000000011 /* Sources */ = {
			isa = PBXSourcesBuildPhase;
			buildActionMask = 2147483647;
			files = (
			);
			runOnlyForDeploymentPostprocessing = 0;
		};
		4B494C495400000000000021 /* Sources */ = {
			isa = PBXSourcesBuildPhase;
			buildActionMask = 2147483647;
			files = (
			);
			runOnlyForDeploymentPostprocessing = 0;
		};
/* End PBXSourcesBuildPhase section */

/* Begin PBXTargetDependency section */
		4B494C495400000000000028 /* PBXTargetDependency */ = {
			isa = PBXTargetDependency;
			target = 4B494C495400000000000010 /* Kilit */;
			targetProxy = 4B494C495400000000000027 /* PBXContainerItemProxy */;
		};
/* End PBXTargetDependency section */

/* Begin XCBuildConfiguration section */
		4B494C495400000000000031 /* Debug */ = {
			isa = XCBuildConfiguration;
			buildSettings = {
				ALWAYS_SEARCH_USER_PATHS = NO;
				ASSETCATALOG_COMPILER_GENERATE_SWIFT_ASSET_SYMBOL_EXTENSIONS = YES;
				CLANG_ANALYZER_NONNULL = YES;
				CLANG_ANALYZER_NUMBER_OBJECT_CONVERSION = YES_AGGRESSIVE;
				CLANG_CXX_LANGUAGE_STANDARD = "gnu++20";
				CLANG_ENABLE_MODULES = YES;
				CLANG_ENABLE_OBJC_ARC = YES;
				CLANG_ENABLE_OBJC_WEAK = YES;
				CLANG_WARN_BLOCK_CAPTURE_AUTORELEASING = YES;
				CLANG_WARN_BOOL_CONVERSION = YES;
				CLANG_WARN_COMMA = YES;
				CLANG_WARN_CONSTANT_CONVERSION = YES;
				CLANG_WARN_DEPRECATED_OBJC_IMPLEMENTATIONS = YES;
				CLANG_WARN_DIRECT_OBJC_ISA_USAGE = YES_ERROR;
				CLANG_WARN_DOCUMENTATION_COMMENTS = YES;
				CLANG_WARN_EMPTY_BODY = YES;
				CLANG_WARN_ENUM_CONVERSION = YES;
				CLANG_WARN_INFINITE_RECURSION = YES;
				CLANG_WARN_INT_CONVERSION = YES;
				CLANG_WARN_NON_LITERAL_NULL_CONVERSION = YES;
				CLANG_WARN_OBJC_IMPLICIT_RETAIN_SELF = YES;
				CLANG_WARN_OBJC_LITERAL_CONVERSION = YES;
				CLANG_WARN_OBJC_ROOT_CLASS = YES_ERROR;
				CLANG_WARN_QUOTED_INCLUDE_IN_FRAMEWORK_HEADER = YES;
				CLANG_WARN_RANGE_LOOP_ANALYSIS = YES;
				CLANG_WARN_STRICT_PROTOTYPES = YES;
				CLANG_WARN_SUSPICIOUS_MOVE = YES;
				CLANG_WARN_UNGUARDED_AVAILABILITY = YES_AGGRESSIVE;
				CLANG_WARN_UNREACHABLE_CODE = YES;
				CLANG_WARN__DUPLICATE_METHOD_MATCH = YES;
				COPY_PHASE_STRIP = NO;
				DEBUG_INFORMATION_FORMAT = dwarf;
				ENABLE_STRICT_OBJC_MSGSEND = YES;
				ENABLE_TESTABILITY = YES;
				ENABLE_USER_SCRIPT_SANDBOXING = YES;
				GCC_C_LANGUAGE_STANDARD = gnu17;
				GCC_DYNAMIC_NO_PIC = NO;
				GCC_NO_COMMON_BLOCKS = YES;
				GCC_OPTIMIZATION_LEVEL = 0;
				GCC_PREPROCESSOR_DEFINITIONS = (
					"DEBUG=1",
					"$(inherited)",
				);
				GCC_WARN_64_TO_32_BIT_CONVERSION = YES;
				GCC_WARN_ABOUT_RETURN_TYPE = YES_ERROR;
				GCC_WARN_UNDECLARED_SELECTOR = YES;
				GCC_WARN_UNINITIALIZED_AUTOS = YES_AGGRESSIVE;
				GCC_WARN_UNUSED_FUNCTION = YES;
				GCC_WARN_UNUSED_VARIABLE = YES;
				IPHONEOS_DEPLOYMENT_TARGET = 17.0;
				LOCALIZATION_PREFERS_STRING_CATALOGS = YES;
				MTL_ENABLE_DEBUG_INFO = INCLUDE_SOURCE;
				MTL_FAST_MATH = YES;
				ONLY_ACTIVE_ARCH = YES;
				SDKROOT = iphoneos;
				SWIFT_ACTIVE_COMPILATION_CONDITIONS = "DEBUG $(inherited)";
				SWIFT_OPTIMIZATION_LEVEL = "-Onone";
			};
			name = Debug;
		};
		4B494C495400000000000032 /* Release */ = {
			isa = XCBuildConfiguration;
			buildSettings = {
				ALWAYS_SEARCH_USER_PATHS = NO;
				ASSETCATALOG_COMPILER_GENERATE_SWIFT_ASSET_SYMBOL_EXTENSIONS = YES;
				CLANG_ANALYZER_NONNULL = YES;
				CLANG_ANALYZER_NUMBER_OBJECT_CONVERSION = YES_AGGRESSIVE;
				CLANG_CXX_LANGUAGE_STANDARD = "gnu++20";
				CLANG_ENABLE_MODULES = YES;
				CLANG_ENABLE_OBJC_ARC = YES;
				CLANG_ENABLE_OBJC_WEAK = YES;
				CLANG_WARN_BLOCK_CAPTURE_AUTORELEASING = YES;
				CLANG_WARN_BOOL_CONVERSION = YES;
				CLANG_WARN_COMMA = YES;
				CLANG_WARN_CONSTANT_CONVERSION = YES;
				CLANG_WARN_DEPRECATED_OBJC_IMPLEMENTATIONS = YES;
				CLANG_WARN_DIRECT_OBJC_ISA_USAGE = YES_ERROR;
				CLANG_WARN_DOCUMENTATION_COMMENTS = YES;
				CLANG_WARN_EMPTY_BODY = YES;
				CLANG_WARN_ENUM_CONVERSION = YES;
				CLANG_WARN_INFINITE_RECURSION = YES;
				CLANG_WARN_INT_CONVERSION = YES;
				CLANG_WARN_NON_LITERAL_NULL_CONVERSION = YES;
				CLANG_WARN_OBJC_IMPLICIT_RETAIN_SELF = YES;
				CLANG_WARN_OBJC_LITERAL_CONVERSION = YES;
				CLANG_WARN_OBJC_ROOT_CLASS = YES_ERROR;
				CLANG_WARN_QUOTED_INCLUDE_IN_FRAMEWORK_HEADER = YES;
				CLANG_WARN_RANGE_LOOP_ANALYSIS = YES;
				CLANG_WARN_STRICT_PROTOTYPES = YES;
				CLANG_WARN_SUSPICIOUS_MOVE = YES;
				CLANG_WARN_UNGUARDED_AVAILABILITY = YES_AGGRESSIVE;
				CLANG_WARN_UNREACHABLE_CODE = YES;
				CLANG_WARN__DUPLICATE_METHOD_MATCH = YES;
				COPY_PHASE_STRIP = NO;
				DEBUG_INFORMATION_FORMAT = "dwarf-with-dsym";
				ENABLE_NS_ASSERTIONS = NO;
				ENABLE_STRICT_OBJC_MSGSEND = YES;
				ENABLE_USER_SCRIPT_SANDBOXING = YES;
				GCC_C_LANGUAGE_STANDARD = gnu17;
				GCC_NO_COMMON_BLOCKS = YES;
				GCC_WARN_64_TO_32_BIT_CONVERSION = YES;
				GCC_WARN_ABOUT_RETURN_TYPE = YES_ERROR;
				GCC_WARN_UNDECLARED_SELECTOR = YES;
				GCC_WARN_UNINITIALIZED_AUTOS = YES_AGGRESSIVE;
				GCC_WARN_UNUSED_FUNCTION = YES;
				GCC_WARN_UNUSED_VARIABLE = YES;
				IPHONEOS_DEPLOYMENT_TARGET = 17.0;
				LOCALIZATION_PREFERS_STRING_CATALOGS = YES;
				MTL_ENABLE_DEBUG_INFO = NO;
				MTL_FAST_MATH = YES;
				SDKROOT = iphoneos;
				SWIFT_COMPILATION_MODE = wholemodule;
				VALIDATE_PRODUCT = YES;
			};
			name = Release;
		};
		4B494C495400000000000015 /* Debug */ = {
			isa = XCBuildConfiguration;
			buildSettings = {
				ASSETCATALOG_COMPILER_APPICON_NAME = AppIcon;
				ASSETCATALOG_COMPILER_GLOBAL_ACCENT_COLOR_NAME = AccentColor;
				CODE_SIGN_STYLE = Automatic;
				CURRENT_PROJECT_VERSION = 1;
				DEVELOPMENT_TEAM = "";
				ENABLE_PREVIEWS = YES;
				GENERATE_INFOPLIST_FILE = YES;
				INFOPLIST_FILE = Sources/Info.plist;
				INFOPLIST_KEY_NSCameraUsageDescription = "Kilit uses the camera to capture photos you send in protected conversations.";
				INFOPLIST_KEY_NSFaceIDUsageDescription = "Kilit uses Face ID to unlock protected conversations.";
				INFOPLIST_KEY_NSPhotoLibraryUsageDescription = "Kilit reads photos you choose to send; they are encrypted before leaving the device.";
				INFOPLIST_KEY_UIApplicationSceneManifest_Generation = YES;
				INFOPLIST_KEY_UIApplicationSupportsIndirectInputEvents = YES;
				INFOPLIST_KEY_UILaunchScreen_Generation = YES;
				INFOPLIST_KEY_UISupportedInterfaceOrientations_iPhone = UIInterfaceOrientationPortrait;
				IPHONEOS_DEPLOYMENT_TARGET = 17.0;
				LD_RUNPATH_SEARCH_PATHS = (
					"$(inherited)",
					"@executable_path/Frameworks",
				);
				MARKETING_VERSION = 1.0;
				PRODUCT_BUNDLE_IDENTIFIER = com.example.Kilit;
				PRODUCT_NAME = "$(TARGET_NAME)";
				SWIFT_EMIT_LOC_STRINGS = YES;
				SWIFT_VERSION = 5.0;
				TARGETED_DEVICE_FAMILY = 1;
			};
			name = Debug;
		};
		4B494C495400000000000016 /* Release */ = {
			isa = XCBuildConfiguration;
			buildSettings = {
				ASSETCATALOG_COMPILER_APPICON_NAME = AppIcon;
				ASSETCATALOG_COMPILER_GLOBAL_ACCENT_COLOR_NAME = AccentColor;
				CODE_SIGN_STYLE = Automatic;
				CURRENT_PROJECT_VERSION = 1;
				DEVELOPMENT_TEAM = "";
				ENABLE_PREVIEWS = YES;
				GENERATE_INFOPLIST_FILE = YES;
				INFOPLIST_FILE = Sources/Info.plist;
				INFOPLIST_KEY_NSCameraUsageDescription = "Kilit uses the camera to capture photos you send in protected conversations.";
				INFOPLIST_KEY_NSFaceIDUsageDescription = "Kilit uses Face ID to unlock protected conversations.";
				INFOPLIST_KEY_NSPhotoLibraryUsageDescription = "Kilit reads photos you choose to send; they are encrypted before leaving the device.";
				INFOPLIST_KEY_UIApplicationSceneManifest_Generation = YES;
				INFOPLIST_KEY_UIApplicationSupportsIndirectInputEvents = YES;
				INFOPLIST_KEY_UILaunchScreen_Generation = YES;
				INFOPLIST_KEY_UISupportedInterfaceOrientations_iPhone = UIInterfaceOrientationPortrait;
				IPHONEOS_DEPLOYMENT_TARGET = 17.0;
				LD_RUNPATH_SEARCH_PATHS = (
					"$(inherited)",
					"@executable_path/Frameworks",
				);
				MARKETING_VERSION = 1.0;
				PRODUCT_BUNDLE_IDENTIFIER = com.example.Kilit;
				PRODUCT_NAME = "$(TARGET_NAME)";
				SWIFT_EMIT_LOC_STRINGS = YES;
				SWIFT_VERSION = 5.0;
				TARGETED_DEVICE_FAMILY = 1;
			};
			name = Release;
		};
		4B494C495400000000000025 /* Debug */ = {
			isa = XCBuildConfiguration;
			buildSettings = {
				BUNDLE_LOADER = "$(TEST_HOST)";
				CODE_SIGN_STYLE = Automatic;
				CURRENT_PROJECT_VERSION = 1;
				DEVELOPMENT_TEAM = "";
				GENERATE_INFOPLIST_FILE = YES;
				IPHONEOS_DEPLOYMENT_TARGET = 17.0;
				MARKETING_VERSION = 1.0;
				PRODUCT_BUNDLE_IDENTIFIER = com.example.KilitTests;
				PRODUCT_NAME = "$(TARGET_NAME)";
				SWIFT_EMIT_LOC_STRINGS = NO;
				SWIFT_VERSION = 5.0;
				TARGETED_DEVICE_FAMILY = 1;
				TEST_HOST = "$(BUILT_PRODUCTS_DIR)/Kilit.app/$(BUNDLE_EXECUTABLE_FOLDER_PATH)/Kilit";
			};
			name = Debug;
		};
		4B494C495400000000000026 /* Release */ = {
			isa = XCBuildConfiguration;
			buildSettings = {
				BUNDLE_LOADER = "$(TEST_HOST)";
				CODE_SIGN_STYLE = Automatic;
				CURRENT_PROJECT_VERSION = 1;
				DEVELOPMENT_TEAM = "";
				GENERATE_INFOPLIST_FILE = YES;
				IPHONEOS_DEPLOYMENT_TARGET = 17.0;
				MARKETING_VERSION = 1.0;
				PRODUCT_BUNDLE_IDENTIFIER = com.example.KilitTests;
				PRODUCT_NAME = "$(TARGET_NAME)";
				SWIFT_EMIT_LOC_STRINGS = NO;
				SWIFT_VERSION = 5.0;
				TARGETED_DEVICE_FAMILY = 1;
				TEST_HOST = "$(BUILT_PRODUCTS_DIR)/Kilit.app/$(BUNDLE_EXECUTABLE_FOLDER_PATH)/Kilit";
			};
			name = Release;
		};
/* End XCBuildConfiguration section */

/* Begin XCConfigurationList section */
		4B494C495400000000000030 /* Build configuration list for PBXProject "Kilit" */ = {
			isa = XCConfigurationList;
			buildConfigurations = (
				4B494C495400000000000031 /* Debug */,
				4B494C495400000000000032 /* Release */,
			);
			defaultConfigurationIsVisible = 0;
			defaultConfigurationName = Release;
		};
		4B494C495400000000000014 /* Build configuration list for PBXNativeTarget "Kilit" */ = {
			isa = XCConfigurationList;
			buildConfigurations = (
				4B494C495400000000000015 /* Debug */,
				4B494C495400000000000016 /* Release */,
			);
			defaultConfigurationIsVisible = 0;
			defaultConfigurationName = Release;
		};
		4B494C495400000000000024 /* Build configuration list for PBXNativeTarget "KilitTests" */ = {
			isa = XCConfigurationList;
			buildConfigurations = (
				4B494C495400000000000025 /* Debug */,
				4B494C495400000000000026 /* Release */,
			);
			defaultConfigurationIsVisible = 0;
			defaultConfigurationName = Release;
		};
/* End XCConfigurationList section */
	};
	rootObject = 4B494C495400000000000001 /* Project object */;
}
```
- [high] Object ID convention: every object key is a 24-character uppercase hex string (Xcode generates 96-bit random-ish ids; XcodeGen generates MD5-derived ones). Any unique 24-hex string is accepted - Xcode never recomputes them - so the template uses a readable scheme: prefix 4B494C4954 ('KILIT' in ASCII hex) + 14 hex digits. Rules: unique within the file; every referenced id must be defined; the `/* comment */` after an id is cosmetic (Xcode regenerates comments on save); section ordering is cosmetic too. The mainGroup id has no comment (Xcode writes it bare). Quoting rules for values: alphanumerics/`.`/`_` can be unquoted (`SWIFT_VERSION = 5.0;`, `TARGETED_DEVICE_FAMILY = 1;`), anything with spaces or `$ @ , + / -` etc. must be double-quoted (`"$(TARGET_NAME)"`, `"1,2"`, `"gnu++20"`, `"-Onone"`); empty string is `""`. (knowledge + XcodeGen fixture ids (non-Xcode-style 24-hex ids accepted by Xcode): https://github.com/yonaskolb/XcodeGen/blob/master/Tests/Fixtures/TestProject/Project.xcodeproj/project.pbxproj)
```
4B494C495400000000000001  Project object
4B494C495400000000000002  mainGroup (no comment)
4B494C495400000000000003  Products group
4B494C495400000000000004  Kilit.app file ref
4B494C495400000000000005  KilitTests.xctest file ref
4B494C495400000000000006  Sources synced root group
4B494C495400000000000007  Tests synced root group
4B494C495400000000000008  exception set (Info.plist)
4B494C495400000000000010  app target      11/12/13 phases  14 cfg list  15/16 Debug/Release
4B494C495400000000000020  test target     21/22/23 phases  24 cfg list  25/26 Debug/Release  27 proxy  28 dependency
4B494C495400000000000030  project cfg list  31/32 Debug/Release
```
- [high] contents.xcworkspacedata: Xcode creates `Kilit.xcodeproj/project.xcworkspace/contents.xcworkspacedata` with a single self FileRef. Content is identical (135 bytes) in every Xcode-generated project fetched. It is optional (Xcode recreates it on open) but harmless to commit; do NOT commit `xcuserdata/` or `project.xcworkspace/xcuserdata/`. (https://github.com/DaviRain-Su/empty/blob/main/Empty.xcodeproj/project.xcworkspace/contents.xcworkspacedata, https://github.com/tfausak/Pylo/blob/main/Pylo.xcodeproj/project.xcworkspace/contents.xcworkspacedata)
```
<?xml version="1.0" encoding="UTF-8"?>
<Workspace
   version = "1.0">
   <FileRef
      location = "self:">
   </FileRef>
</Workspace>
```
- [medium] Shared scheme is REQUIRED for command-line builds: `xcodebuild` does not auto-create schemes (only Xcode.app does, on first open, into xcuserdata). Commit `Kilit.xcodeproj/xcshareddata/xcschemes/Kilit.xcscheme` so `xcodebuild -project ios/Kilit.xcodeproj -scheme Kilit -destination 'platform=iOS Simulator,name=iPhone 16' test` works on a fresh clone. BlueprintIdentifier values must equal the target object ids in project.pbxproj; BuildableName/BlueprintName are product/target names; ReferencedContainer is `container:Kilit.xcodeproj`. `shouldAutocreateTestPlan = "YES"` lets Xcode 16 run tests without a .xctestplan. Xcode may rewrite/upgrade the file on first open (harmless diff). (xcodebuild does not generate schemes: https://discuss.bitrise.io/t/project-does-not-contain-a-scheme/192 and https://cmake.org/Bug/view.php?id=15441 ; scheme XML structure cross-checked against https://github.com/tuist/XcodeProj/blob/main/Fixtures/iOS/Project.xcodeproj/xcshareddata/xcschemes/iOS.xcscheme ; exact Xcode-16 attribute values (version 1.7, buildArchitectures, shouldAutocreateTestPlan) from knowledge)
```
<?xml version="1.0" encoding="UTF-8"?>
<Scheme
   LastUpgradeVersion = "1600"
   version = "1.7">
   <BuildAction
      parallelizeBuildables = "YES"
      buildImplicitDependencies = "YES"
      buildArchitectures = "Automatic">
      <BuildActionEntries>
         <BuildActionEntry
            buildForTesting = "YES"
            buildForRunning = "YES"
            buildForProfiling = "YES"
            buildForArchiving = "YES"
            buildForAnalyzing = "YES">
            <BuildableReference
               BuildableIdentifier = "primary"
               BlueprintIdentifier = "4B494C495400000000000010"
               BuildableName = "Kilit.app"
               BlueprintName = "Kilit"
               ReferencedContainer = "container:Kilit.xcodeproj">
            </BuildableReference>
         </BuildActionEntry>
      </BuildActionEntries>
   </BuildAction>
   <TestAction
      buildConfiguration = "Debug"
      selectedDebuggerIdentifier = "Xcode.DebuggerFoundation.Debugger.LLDB"
      selectedLauncherIdentifier = "Xcode.DebuggerFoundation.Launcher.LLDB"
      shouldUseLaunchSchemeArgsEnv = "YES"
      shouldAutocreateTestPlan = "YES">
      <Testables>
         <TestableReference
            skipped = "NO">
            <BuildableReference
               BuildableIdentifier = "primary"
               BlueprintIdentifier = "4B494C495400000000000020"
               BuildableName = "KilitTests.xctest"
               BlueprintName = "KilitTests"
               ReferencedContainer = "container:Kilit.xcodeproj">
            </BuildableReference>
         </TestableReference>
      </Testables>
   </TestAction>
   <LaunchAction
      buildConfiguration = "Debug"
      selectedDebuggerIdentifier = "Xcode.DebuggerFoundation.Debugger.LLDB"
      selectedLauncherIdentifier = "Xcode.DebuggerFoundation.Launcher.LLDB"
      launchStyle = "0"
      useCustomWorkingDirectory = "NO"
      ignoresPersistentStateOnLaunch = "NO"
      debugDocumentVersioning = "YES"
      debugServiceExtension = "internal"
      allowLocationSimulation = "YES">
      <BuildableProductRunnable
         runnableDebuggingMode = "0">
         <BuildableReference
            BuildableIdentifier = "primary"
            BlueprintIdentifier = "4B494C495400000000000010"
            BuildableName = "Kilit.app"
            BlueprintName = "Kilit"
            ReferencedContainer = "container:Kilit.xcodeproj">
         </BuildableReference>
      </BuildableProductRunnable>
   </LaunchAction>
   <ProfileAction
      buildConfiguration = "Release"
      shouldUseLaunchSchemeArgsEnv = "YES"
      savedToolIdentifier = ""
      useCustomWorkingDirectory = "NO"
      debugDocumentVersioning = "YES">
      <BuildableProductRunnable
         runnableDebuggingMode = "0">
         <BuildableReference
            BuildableIdentifier = "primary"
            BlueprintIdentifier = "4B494C495400000000000010"
            BuildableName = "Kilit.app"
            BlueprintName = "Kilit"
            ReferencedContainer = "container:Kilit.xcodeproj">
         </BuildableReference>
      </BuildableProductRunnable>
   </ProfileAction>
   <AnalyzeAction
      buildConfiguration = "Debug">
   </AnalyzeAction>
   <ArchiveAction
      buildConfiguration = "Release"
      revealArchiveInOrganizer = "YES">
   </ArchiveAction>
</Scheme>
```
- [high] Info.plist strategy (Apple's documented semantics): with `GENERATE_INFOPLIST_FILE = YES` Xcode synthesizes Info.plist from build settings; each `INFOPLIST_KEY_<Key>` build setting 'When GENERATE_INFOPLIST_FILE is enabled, sets the value of the <Key> key in the Info.plist file to the value of this build setting' (special cases: `INFOPLIST_KEY_UILaunchScreen_Generation` -> empty UILaunchScreen dict; `INFOPLIST_KEY_UIApplicationSceneManifest_Generation` -> multi-window scene manifest; `_iPhone`/`_iPad` suffix -> `~iphone`/`~ipad` keys). If `INFOPLIST_FILE` is ALSO set while GENERATE_INFOPLIST_FILE = YES, Apple: 'Xcode merges the content of the property list file with the values from the Info.plist Values build settings' (and the INFOPLIST_FILE reference entry: 'The build system merges the values you specify in this file with other values it generates ... When GENERATE_INFOPLIST_FILE is enabled, the build system also includes content from build settings in the merge process'). With GENERATE_INFOPLIST_FILE = NO + INFOPLIST_FILE, Xcode only variable-substitutes your file and copies it (you then own CFBundle*, UILaunchScreen, scene manifest, etc. yourself). Important caveat from Apple: user-defined settings named INFOPLIST_KEY_<Anything> are NOT honored - only the ~96 keys Xcode knows about. The template uses the HYBRID form (YES + file), which is exactly what Xcode 16 itself writes when you add a custom key in the target's Info tab (verified in two real projects). (https://developer.apple.com/documentation/bundleresources/managing-your-app-s-information-property-list , https://developer.apple.com/documentation/xcode/build-settings-reference (INFOPLIST_FILE, INFOPLIST_KEY_* entries), real hybrid projects https://github.com/rkny6/echo/blob/master/echo.xcodeproj/project.pbxproj and https://github.com/tfausak/Pylo/blob/main/Pylo.xcodeproj/project.pbxproj)
```
// app target, both configurations
GENERATE_INFOPLIST_FILE = YES;
INFOPLIST_FILE = Sources/Info.plist;          // custom keys only (CADisableMinimumFrameDurationOnPhone)
INFOPLIST_KEY_NSCameraUsageDescription = "...";
INFOPLIST_KEY_NSFaceIDUsageDescription = "...";
INFOPLIST_KEY_NSPhotoLibraryUsageDescription = "...";
INFOPLIST_KEY_UIApplicationSceneManifest_Generation = YES;
INFOPLIST_KEY_UIApplicationSupportsIndirectInputEvents = YES;
INFOPLIST_KEY_UILaunchScreen_Generation = YES;
INFOPLIST_KEY_UISupportedInterfaceOrientations_iPhone = UIInterfaceOrientationPortrait;

// alternative (not used): full manual plist
GENERATE_INFOPLIST_FILE = NO;
INFOPLIST_FILE = Sources/Info.plist;   // must then contain CFBundleIdentifier=$(PRODUCT_BUNDLE_IDENTIFIER), CFBundleExecutable=$(EXECUTABLE_NAME), CFBundleName, CFBundlePackageType=$(PRODUCT_BUNDLE_PACKAGE_TYPE), CFBundleShortVersionString=$(MARKETING_VERSION), CFBundleVersion=$(CURRENT_PROJECT_VERSION), UILaunchScreen={}, UIApplicationSceneManifest, usage descriptions ...
```
- [high] Which of our keys have INFOPLIST_KEY_ build settings (verified against Apple's Build Settings Reference, 96 INFOPLIST_KEY_ settings total): NSCameraUsageDescription -> `INFOPLIST_KEY_NSCameraUsageDescription` (yes); NSPhotoLibraryUsageDescription -> `INFOPLIST_KEY_NSPhotoLibraryUsageDescription` (yes; also `INFOPLIST_KEY_NSPhotoLibraryAddUsageDescription`); NSFaceIDUsageDescription -> `INFOPLIST_KEY_NSFaceIDUsageDescription` (yes); CADisableMinimumFrameDurationOnPhone -> NO INFOPLIST_KEY_ setting exists, so it must live in the custom Info.plist file (hence INFOPLIST_FILE). Other relevant ones that exist: INFOPLIST_KEY_NSMicrophoneUsageDescription, INFOPLIST_KEY_NSLocalNetworkUsageDescription, INFOPLIST_KEY_ITSAppUsesNonExemptEncryption, INFOPLIST_KEY_CFBundleDisplayName, INFOPLIST_KEY_UIUserInterfaceStyle, INFOPLIST_KEY_UIRequiresFullScreen, INFOPLIST_KEY_UIStatusBarStyle/Hidden, INFOPLIST_KEY_LSApplicationCategoryType, INFOPLIST_KEY_UISupportedInterfaceOrientations(_iPhone/_iPad), INFOPLIST_KEY_UILaunchStoryboardName. Anything else (UIBackgroundModes, NSAppTransportSecurity, BGTaskSchedulerPermittedIdentifiers, CADisableMinimumFrameDurationOnPhone, custom URL types) goes in the plist file. (https://developer.apple.com/documentation/xcode/build-settings-reference (full INFOPLIST_KEY_ list extracted from the page JSON; CADisable* absent))
```
<!-- ios/Sources/Info.plist -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CADisableMinimumFrameDurationOnPhone</key>
	<true/>
</dict>
</plist>
```
- [high] CADisableMinimumFrameDurationOnPhone: Boolean Info.plist key, default NO, iOS 15.0+/iPadOS 15.0+. Apple: 'Devices with ProMotion displays allow apps to dynamically request a frame rate they prefer. If you set this key to YES, your app can request any frame rate the display supports. If you set this key to NO, frame rates higher than the system default are unavailable.' Without it, CADisplayLink.preferredFrameRateRange above 60 Hz is ignored on iPhone (iPad Pro does not need it). Relevant to the opt-in flicker experiment only; it does not raise the panel's physical refresh rate. (https://developer.apple.com/documentation/bundleresources/information-property-list/cadisableminimumframedurationonphone)
```
// Swift side (iOS 15+), only meaningful when the plist key is YES:
let link = CADisplayLink(target: self, selector: #selector(step(_:)))
link.preferredFrameRateRange = CAFrameRateRange(minimum: 80, maximum: 120, preferred: 120)
link.add(to: .main, forMode: .common)
```
- [high] Unit-test target wiring that makes `@testable import Kilit` and `xcodebuild test` work: productType `com.apple.product-type.bundle.unit-test`, `TEST_HOST = "$(BUILT_PRODUCTS_DIR)/Kilit.app/$(BUNDLE_EXECUTABLE_FOLDER_PATH)/Kilit"`, `BUNDLE_LOADER = "$(TEST_HOST)"`, `GENERATE_INFOPLIST_FILE = YES` (no plist file needed for the bundle), a PBXTargetDependency on the app, and `TestTargetID` in TargetAttributes. `ENABLE_TESTABILITY = YES` is set in the project Debug config (as in Xcode's template) and the scheme tests in Debug, so `@testable` compiles. Xcode 16's template puts Swift Testing (`import Testing`) in the generated test file, but plain XCTest classes in the same bundle work unchanged - use XCTest since the crypto test vectors are plain assertions. Tests are discovered from every .swift file under ios/Tests/ automatically (synced folder). (https://github.com/rkny6/echo/blob/master/echo.xcodeproj/project.pbxproj ; TEST_HOST/BUNDLE_LOADER semantics: https://developer.apple.com/documentation/xcode/build-settings-reference)
```
// ios/Tests/KilitTests.swift
import XCTest
@testable import Kilit

final class KilitTests: XCTestCase {
    func testSmoke() throws {
        XCTAssertTrue(true)
    }
}

// CLI on the Mac:
// xcodebuild -project ios/Kilit.xcodeproj -scheme Kilit -destination 'platform=iOS Simulator,name=iPhone 16' test
```
- [high] Build-setting choices and why: SWIFT_VERSION = 5.0 (Xcode 16.x templates still write 5.0; 6.0 switches on Swift 6 language mode where strict-concurrency diagnostics become errors - risky on a machine we cannot iterate on; Apple: 'SWIFT_STRICT_CONCURRENCY ... is always complete when in the Swift 6 language mode and produces errors instead of warnings'). TARGETED_DEVICE_FAMILY = 1 (Apple: 1 = iPhone/iPod touch, 2 = iPad; drives UIDeviceFamily). ENABLE_PREVIEWS = YES (Xcode template setting enabling SwiftUI previews; not documented in the build-settings reference but present in every SwiftUI template). CODE_SIGN_STYLE = Automatic with DEVELOPMENT_TEAM = "" (owner fills in Signing & Capabilities; simulator builds need no team). IPHONEOS_DEPLOYMENT_TARGET = 17.0 at project level AND on both targets (Xcode writes it on the test target too). SWIFT_EMIT_LOC_STRINGS YES on app / NO on tests, LOCALIZATION_PREFERS_STRING_CATALOGS = YES, ENABLE_USER_SCRIPT_SANDBOXING = YES, ASSETCATALOG_COMPILER_GENERATE_SWIFT_ASSET_SYMBOL_EXTENSIONS = YES (all Xcode 16 template defaults). Deliberately omitted: DEVELOPMENT_ASSET_PATHS / 'Preview Content' folder (if you add the setting the folder must exist or the build fails), STRING_CATALOG_GENERATE_SYMBOLS (Xcode 26 default, harmless to omit), SWIFT_APPROACHABLE_CONCURRENCY / SWIFT_DEFAULT_ACTOR_ISOLATION (Xcode 26 settings). (https://developer.apple.com/documentation/xcode/build-settings-reference (TARGETED_DEVICE_FAMILY, SWIFT_STRICT_CONCURRENCY, SWIFT_VERSION), https://github.com/rkny6/echo/blob/master/echo.xcodeproj/project.pbxproj, https://github.com/DaviRain-Su/empty/blob/main/Empty.xcodeproj/project.pbxproj (Xcode 26 template additions))
```
// Xcode 16.4 template (echo) vs this template, app target:
SWIFT_VERSION = 5.0;                 // keep; 6.0 only if the code is written for Swift 6 mode
TARGETED_DEVICE_FAMILY = 1;          // template had "1,2"
INFOPLIST_KEY_UISupportedInterfaceOrientations_iPhone = UIInterfaceOrientationPortrait;  // template listed 3 orientations
// removed: INFOPLIST_KEY_UISupportedInterfaceOrientations_iPad (iPhone-only), CODE_SIGN_ENTITLEMENTS (add when you add capabilities)
```
- [high] Minimal asset catalog so ASSETCATALOG_COMPILER_APPICON_NAME = AppIcon and ..._GLOBAL_ACCENT_COLOR_NAME = AccentColor resolve: ios/Sources/Assets.xcassets/ with three Contents.json files (catalog root, AppIcon.appiconset using the Xcode 15+ single 1024x1024 universal slot, AccentColor.colorset with no explicit color = system accent). The .xcassets folder inside the synced folder is compiled automatically (synced folders assign build phases by file type). An empty AppIcon slot only warns on debug builds; add a 1024x1024 PNG named in `filename` before App Store validation. (knowledge (Xcode 15/16 SwiftUI template contents); JSON validated locally)
```
// Assets.xcassets/Contents.json
{
  "info" : {
    "author" : "xcode",
    "version" : 1
  }
}
// Assets.xcassets/AppIcon.appiconset/Contents.json
{
  "images" : [
    {
      "idiom" : "universal",
      "platform" : "ios",
      "size" : "1024x1024"
    }
  ],
  "info" : {
    "author" : "xcode",
    "version" : 1
  }
}
// Assets.xcassets/AccentColor.colorset/Contents.json
{
  "colors" : [
    {
      "idiom" : "universal"
    }
  ],
  "info" : {
    "author" : "xcode",
    "version" : 1
  }
}
```
- [high] Minimal SwiftUI entry files that compile on iOS 17 (every .swift under ios/Sources/ is compiled into the app target without being listed anywhere).
```
// ios/Sources/KilitApp.swift
import SwiftUI

@main
struct KilitApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}

// ios/Sources/ContentView.swift
import SwiftUI

struct ContentView: View {
    var body: some View {
        Text("Kilit")
            .padding()
    }
}

#Preview {
    ContentView()
}
```
- [high] XcodeGen fallback: `syncedFolder` source type exists since XcodeGen 2.44.0 (2.44.1 fixed objectVersion 77), `excludes`/`explicitFolders` for synced folders + automatic Info.plist exclusion + `options.projectFormat` arrived in 2.45.0, synced-folder bug fixes in 2.45.3/2.45.4; latest release 2.46.0 - require >= 2.45.4. `projectFormat: xcode16_0` is the default and maps to objectVersion 77 (xcode16_3 also 77-family; master adds xcode26_3 = 100 and xcode27_0 = 110 - do not use those). Unit-test target: `type: bundle.unit-test` + `dependencies: [{target: Kilit}]` makes XcodeGen set TEST_HOST (and BUNDLE_LOADER) automatically; `scheme.testTargets` generates a shared scheme. Running `xcodegen generate` OVERWRITES the hand-written Kilit.xcodeproj (different object ids, so the hand-written Kilit.xcscheme must not be kept alongside - XcodeGen writes its own). Spec validated with PyYAML; file at /tmp/claude-0/-home-user-clawDbot/bdce7bc4-a479-5125-8ada-9eaadb92752b/scratchpad/template/ios/project.yml (https://github.com/yonaskolb/XcodeGen/blob/master/Docs/ProjectSpec.md (type: syncedFolder, explicitFolders, projectFormat, defaultSourceDirectoryType, scheme.testTargets, TEST_HOST auto-setting), https://github.com/yonaskolb/XcodeGen/blob/master/CHANGELOG.md, https://github.com/yonaskolb/XcodeGen/blob/master/Tests/Fixtures/TestProject/project.yml (real syncedFolder YAML))
```
# ios/project.yml  (XcodeGen >= 2.45.4;  brew install xcodegen && cd ios && xcodegen generate)
name: Kilit
options:
  bundleIdPrefix: com.example
  deploymentTarget:
    iOS: "17.0"
  xcodeVersion: "16.0"
  projectFormat: xcode16_0
  createIntermediateGroups: false
  generateEmptyDirectories: false
settings:
  SWIFT_VERSION: "5.0"
  IPHONEOS_DEPLOYMENT_TARGET: "17.0"
  CODE_SIGN_STYLE: Automatic
  DEVELOPMENT_TEAM: ""
  TARGETED_DEVICE_FAMILY: "1"
  ENABLE_USER_SCRIPT_SANDBOXING: YES
  LOCALIZATION_PREFERS_STRING_CATALOGS: YES
  ASSETCATALOG_COMPILER_GENERATE_SWIFT_ASSET_SYMBOL_EXTENSIONS: YES
targets:
  Kilit:
    type: application
    platform: iOS
    deploymentTarget: "17.0"
    sources:
      - path: Sources
        type: syncedFolder
        excludes:
          - Info.plist
    settings:
      PRODUCT_BUNDLE_IDENTIFIER: com.example.Kilit
      PRODUCT_NAME: "$(TARGET_NAME)"
      GENERATE_INFOPLIST_FILE: YES
      INFOPLIST_FILE: Sources/Info.plist
      INFOPLIST_KEY_NSCameraUsageDescription: "Kilit uses the camera to capture photos you send in protected conversations."
      INFOPLIST_KEY_NSFaceIDUsageDescription: "Kilit uses Face ID to unlock protected conversations."
      INFOPLIST_KEY_NSPhotoLibraryUsageDescription: "Kilit reads photos you choose to send; they are encrypted before leaving the device."
      INFOPLIST_KEY_UIApplicationSceneManifest_Generation: YES
      INFOPLIST_KEY_UIApplicationSupportsIndirectInputEvents: YES
      INFOPLIST_KEY_UILaunchScreen_Generation: YES
      INFOPLIST_KEY_UISupportedInterfaceOrientations_iPhone: UIInterfaceOrientationPortrait
      ASSETCATALOG_COMPILER_APPICON_NAME: AppIcon
      ASSETCATALOG_COMPILER_GLOBAL_ACCENT_COLOR_NAME: AccentColor
      ENABLE_PREVIEWS: YES
      SWIFT_EMIT_LOC_STRINGS: YES
      CURRENT_PROJECT_VERSION: 1
      MARKETING_VERSION: "1.0"
      LD_RUNPATH_SEARCH_PATHS: ["$(inherited)", "@executable_path/Frameworks"]
    scheme:
      testTargets:
        - KilitTests
      gatherCoverageData: false
  KilitTests:
    type: bundle.unit-test
    platform: iOS
    deploymentTarget: "17.0"
    sources:
      - path: Tests
        type: syncedFolder
    dependencies:
      - target: Kilit
    settings:
      PRODUCT_BUNDLE_IDENTIFIER: com.example.KilitTests
      PRODUCT_NAME: "$(TARGET_NAME)"
      GENERATE_INFOPLIST_FILE: YES
      SWIFT_EMIT_LOC_STRINGS: NO
      CURRENT_PROJECT_VERSION: 1
      MARKETING_VERSION: "1.0"
```
- [high] Xcode 16 release notes confirm the mechanism and its intent: 'Buildable folders only record the folder path into the project file without enumerating the contained files. This minimizes diffs to the project when files are added and removed'; the Project Navigator now creates folder-backed groups by default; 'To use a folder as an opaque copiable resource ... uncheck the Build Folder Contents option' (that is what `explicitFolders` records). Also: 'xcodebuild now validates the format version number of Xcode projects for compatibility when performing builds' - i.e. objectVersion 77 is rejected by Xcode 15. (https://developer.apple.com/documentation/xcode-release-notes/xcode-16-release-notes)
- [high] Deliverable file tree written and validated in the scratchpad (copy the `ios/` directory into the repo as-is): project.pbxproj, project.xcworkspace/contents.xcworkspacedata, xcshareddata/xcschemes/Kilit.xcscheme, Sources/{KilitApp.swift, ContentView.swift, Info.plist, Assets.xcassets/...}, Tests/KilitTests.swift, project.yml. Validation performed on Linux: pbxproj parsed by cordova `xcode` npm parser (which also parses the real Xcode 16.4 file), 27/27 ids resolve, per-isa attribute sets match Xcode 16.4 output, project-level Debug key set identical to Xcode's, XML/plist/JSON/YAML all parse. What could NOT be verified here: an actual `xcodebuild` run (no macOS). (local validation in this session)
```
/tmp/claude-0/-home-user-clawDbot/bdce7bc4-a479-5125-8ada-9eaadb92752b/scratchpad/template/ios/Kilit.xcodeproj/project.pbxproj
/tmp/claude-0/-home-user-clawDbot/bdce7bc4-a479-5125-8ada-9eaadb92752b/scratchpad/template/ios/Kilit.xcodeproj/project.xcworkspace/contents.xcworkspacedata
/tmp/claude-0/-home-user-clawDbot/bdce7bc4-a479-5125-8ada-9eaadb92752b/scratchpad/template/ios/Kilit.xcodeproj/xcshareddata/xcschemes/Kilit.xcscheme
/tmp/claude-0/-home-user-clawDbot/bdce7bc4-a479-5125-8ada-9eaadb92752b/scratchpad/template/ios/Sources/KilitApp.swift
/tmp/claude-0/-home-user-clawDbot/bdce7bc4-a479-5125-8ada-9eaadb92752b/scratchpad/template/ios/Sources/ContentView.swift
/tmp/claude-0/-home-user-clawDbot/bdce7bc4-a479-5125-8ada-9eaadb92752b/scratchpad/template/ios/Sources/Info.plist
/tmp/claude-0/-home-user-clawDbot/bdce7bc4-a479-5125-8ada-9eaadb92752b/scratchpad/template/ios/Sources/Assets.xcassets/Contents.json
/tmp/claude-0/-home-user-clawDbot/bdce7bc4-a479-5125-8ada-9eaadb92752b/scratchpad/template/ios/Sources/Assets.xcassets/AppIcon.appiconset/Contents.json
/tmp/claude-0/-home-user-clawDbot/bdce7bc4-a479-5125-8ada-9eaadb92752b/scratchpad/template/ios/Sources/Assets.xcassets/AccentColor.colorset/Contents.json
/tmp/claude-0/-home-user-clawDbot/bdce7bc4-a479-5125-8ada-9eaadb92752b/scratchpad/template/ios/Tests/KilitTests.swift
/tmp/claude-0/-home-user-clawDbot/bdce7bc4-a479-5125-8ada-9eaadb92752b/scratchpad/template/ios/project.yml
# reference downloads used for verification:
/tmp/claude-0/-home-user-clawDbot/bdce7bc4-a479-5125-8ada-9eaadb92752b/scratchpad/dl/echo.pbxproj   (real Xcode 16.4 app+tests)
/tmp/claude-0/-home-user-clawDbot/bdce7bc4-a479-5125-8ada-9eaadb92752b/scratchpad/dl/pylo.pbxproj   (real Xcode 26.2)
/tmp/claude-0/-home-user-clawDbot/bdce7bc4-a479-5125-8ada-9eaadb92752b/scratchpad/dl/empty.pbxproj  (real Xcode 26.3)
```
Pitfalls: Keep Info.plist out of target membership. Because Sources/Info.plist sits inside the synced folder, the PBXFileSystemSynchronizedBuildFileExceptionSet with `membershipExceptions = (Info.plist,)` is mandatory; without it the file is copied as a bundle resource and you get 'Multiple commands produce .../Info.plist'. Apple's doc explicitly says 'Don't add the property list file to your target'. Alternative that needs no exception set: put the plist outside the synced folder (e.g. ios/Config/Info.plist) and point INFOPLIST_FILE there - it does not need a PBXFileReference at all. | Define every Info.plist key in exactly one place. Apple documents that file content and INFOPLIST_KEY_* settings are merged but does not document precedence when the same key appears in both; keep NSCamera/NSPhotoLibrary/NSFaceID in INFOPLIST_KEY_* and only non-settable keys (CADisableMinimumFrameDurationOnPhone, UIBackgroundModes, NSAppTransportSecurity, URL types...) in the file. | INFOPLIST_KEY_<Custom> is ignored: Xcode only honors its built-in list (96 keys); a user-defined INFOPLIST_KEY_CADisableMinimumFrameDurationOnPhone does nothing. That is why INFOPLIST_FILE is required for the flicker key. | objectVersion 77 means Xcode >= 16.0 only. If the owner's Mac has Xcode 15 the project will not open and xcodebuild refuses it. Do not use XcodeGen's xcode26_3 (objectVersion 100) / xcode27_0 (110) formats, which would require Xcode 26.3+. | xcodebuild does not auto-create schemes; without the committed xcshareddata/xcschemes/Kilit.xcscheme a CLI build/test on a fresh clone fails with 'does not contain a scheme named Kilit'. Opening the project once in Xcode.app also creates (user) schemes, but commit the shared one. | Scheme BlueprintIdentifier values are the pbxproj target ids. If anyone regenerates the project with XcodeGen, ids change: delete the hand-written scheme (XcodeGen emits its own from `scheme:`), or keep the two workflows mutually exclusive. `xcodegen generate` overwrites Kilit.xcodeproj entirely. | Synced folders include EVERYTHING under the folder by type: every .swift is compiled, .xcassets compiled, other files copied as resources. Keep ios/Sources/ free of README.md, docs, scripts, test fixtures; put those elsewhere (or add them to membershipExceptions). Conversely, files in ios/Tests/ are only in KilitTests, never in the app. | SWIFT_VERSION = 6.0 switches the whole app to Swift 6 language mode, where strict-concurrency diagnostics are errors. Since nobody can iterate on the Mac build, stay on 5.0 (the Xcode 16 template default) and optionally set SWIFT_STRICT_CONCURRENCY = minimal/targeted later. | Do not add DEVELOPMENT_ASSET_PATHS = "\"Sources/Preview Content\"" unless that folder actually exists - a missing path is a hard build error. The template omits it; #Preview still works. | pbxproj quoting: any value containing spaces, `$`, `@`, `,`, `+`, `-`, `/`, `~` must be double-quoted (`"$(TARGET_NAME)"`, `"1,2"`, `"gnu++20"`, `"-Onone"`, `"<group>"`); empty values are `""`. Unquoted `TARGETED_DEVICE_FAMILY = 1;` and `SWIFT_VERSION = 5.0;` are fine. A single quoting mistake makes Xcode report 'project cannot be opened because it is damaged'. | Every id referenced must be defined and unique (24 uppercase hex chars). When adding objects (e.g. a Swift package, an .xcconfig, a UI-test target) mint new ids in the same 4B494C4954... series and update: mainGroup children, PBXProject targets/TargetAttributes, and for packages also `packageReferences` on PBXProject + `packageProductDependencies` on the target (XCRemoteSwiftPackageReference / XCSwiftPackageProductDependency). Prefer letting the owner add packages via Xcode's UI or XcodeGen's `packages:` rather than hand-editing. | Xcode will rewrite cosmetic parts on first open/save (comments, section order, LastUpgradeCheck, scheme attributes) and may prompt 'Update to recommended settings'. That diff is expected; do not try to prevent it. | DEVELOPMENT_TEAM is empty on purpose. Simulator builds and `xcodebuild test` on a simulator need no team; building to a physical iPhone or archiving requires the owner to select a team in Signing & Capabilities (writes DEVELOPMENT_TEAM into both targets). Automatic signing + App Groups/Keychain Sharing will later add a CODE_SIGN_ENTITLEMENTS file - that file can live in Sources/ and is NOT a resource, Xcode handles it via the setting. | XcodeGen specifics: `excludes` on a syncedFolder source needs >= 2.45.0 (2.44.x silently ignores it; 2.45.0+ also auto-excludes Info.plist); path handling bugs for synced folders were fixed in 2.45.3/2.45.4; use 2.46.0. Mixing a simple settings map with `base:`/`configs:` in one `settings` block makes XcodeGen silently ignore the simple map - the template uses simple maps only. | Testing framework: Xcode 16's new-test-target template uses Swift Testing; our Tests/ uses XCTest. Both run in the same bundle, but do not mix a `Testing` import on iOS 17 simulators older than the SDK's runtime without checking - plain XCTest avoids the question entirely. | The CADisableMinimumFrameDurationOnPhone key only lifts the 60 Hz cap for CADisplayLink/Core Animation on ProMotion iPhones (13 Pro and later); on non-ProMotion devices nothing changes, and it never exceeds the panel's refresh rate - consistent with the agreed 'deterrent at best' framing of the flicker feature.

### go-stack: Go 1.24 server stack for Kilit (WebSocket, pure-Go SQLite, ServeMux routing, rate limiting, crypto, signed-challenge auth, store-and-forward schema, blob TTL storage, graceful shutdown, Dockerfile, APNs hook) — verified against proxy.golang.org, pkg.go.dev, Apple docs and by compiling/running probe code on go1.24.7 linux/amd64 with CGO_ENABLED=0
- [high] CRITICAL VERSION REALITY (today 2026-10-21): the *latest* releases of golang.org/x/crypto (v0.58.0), x/time (v0.16.0), x/net (v0.61.0), x/sync (v0.24.0), x/sys (v0.49.0), modernc.org/sqlite (v1.60.1) and ncruces/go-sqlite3 (v0.35.6) all declare `go 1.26.0` in go.mod. With a Go 1.24 toolchain and GOTOOLCHAIN=local they fail: `modernc.org/sqlite@v1.60.1 requires go >= 1.26.0 (running go 1.24.7; GOTOOLCHAIN=local)`. The newest versions whose go directive is <= 1.24 (scanned every tag downward with `go mod download -json`): golang.org/x/crypto v0.48.0 (2026-02-09), golang.org/x/time v0.14.0 (2025-09-16), golang.org/x/sync v0.19.0 (2025-12-04), golang.org/x/net v0.50.0 (2026-02-09), golang.org/x/sys v0.41.0, modernc.org/sqlite v1.46.1 (2026-02-18, embeds SQLite 3.51.2). github.com/coder/websocket v1.8.15 (2026-06-15) declares `go 1.23` and is fine. Pin exactly these; `go get -u` will break the build. (https://proxy.golang.org (verified with `go list -m -versions` / `go mod download -json` under go1.24.7, GOTOOLCHAIN=local))
- [high] Concrete go.mod that is PROVEN to work: created a scratch module with this go.mod, ran `go mod tidy`, `go vet ./...`, `CGO_ENABLED=0 go test ./...` (6 probe tests: ServeMux routing, SQLite pragmas/schema/RETURNING/concurrency, WebSocket roundtrip, RFC crypto vectors, rate limiter) and `CGO_ENABLED=0 go build -trimpath -ldflags='-s -w'` -> statically linked ELF, 6.1 MB, prints `sqlite 3.51.2`. All transitive modules have go directives <= 1.24.0 (listed in the full `go list -m all` scan). `go mod tidy` on a 1.24.7 toolchain also appends `toolchain go1.24.7`; harmless. Add `golang.org/x/sync v0.19.0` to the first require block if errgroup is imported directly. (https://proxy.golang.org (verified by building and testing in /tmp/claude-0/-home-user-clawDbot/bdce7bc4-a479-5125-8ada-9eaadb92752b/scratchpad/kilitprobe on go1.24.7))
```
module github.com/tekinadakan-sudo/clawDbot/server

go 1.24.0

require (
	github.com/coder/websocket v1.8.15
	golang.org/x/crypto v0.48.0
	golang.org/x/time v0.14.0
	modernc.org/sqlite v1.46.1
)

require (
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	golang.org/x/exp v0.0.0-20251023183803-a4bb9ffd2546 // indirect
	golang.org/x/sync v0.19.0 // indirect
	golang.org/x/sys v0.41.0 // indirect
	modernc.org/libc v1.67.6 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
)
```
- [high] WebSocket library choice: github.com/coder/websocket v1.8.15 (import path `github.com/coder/websocket`, subpackage `github.com/coder/websocket/wsjson`), go 1.23, ZERO dependencies, context-first API, passes Autobahn, RFC 7692 compression, concurrent writes allowed. It is the continuation of nhooyr.io/websocket: Coder maintains it since 2024 (README: 'Coder now maintains this project... nhooyr authored it 2019-2024'). The old module nhooyr.io/websocket has a final tag v1.8.17 (2024-08-10) whose README is literally 'deprecated: Use https://github.com/coder/websocket instead'. Do not import nhooyr.io/websocket. (https://pkg.go.dev/github.com/coder/websocket (signatures also verified with `go doc` on the v1.8.15 module cache and by a compiled Accept/Dial/wsjson roundtrip test))
```
func Accept(w http.ResponseWriter, r *http.Request, opts *AcceptOptions) (*Conn, error)
func Dial(ctx context.Context, u string, opts *DialOptions) (*Conn, *http.Response, error)
func (c *Conn) Read(ctx context.Context) (MessageType, []byte, error)
func (c *Conn) Reader(ctx context.Context) (MessageType, io.Reader, error)
func (c *Conn) Write(ctx context.Context, typ MessageType, p []byte) error
func (c *Conn) Writer(ctx context.Context, typ MessageType) (io.WriteCloser, error)
func (c *Conn) Close(code StatusCode, reason string) (err error)   // close handshake: 5s write timeout + waits up to 5s for peer close frame; reason <= 125 bytes
func (c *Conn) CloseNow() (err error)
func (c *Conn) CloseRead(ctx context.Context) context.Context
func (c *Conn) Ping(ctx context.Context) error
func (c *Conn) SetReadLimit(n int64)   // default limit is 32768 bytes
func (c *Conn) Subprotocol() string
func NetConn(ctx context.Context, c *Conn, msgType MessageType) net.Conn
func CloseStatus(err error) StatusCode   // returns -1 if err is not a close error
type AcceptOptions struct { Subprotocols []string; InsecureSkipVerify bool; OriginPatterns []string; CompressionMode CompressionMode; CompressionThreshold int; OnPingReceived func(ctx context.Context, payload []byte) bool; OnPongReceived func(ctx context.Context, payload []byte) }
type DialOptions struct { HTTPClient *http.Client; HTTPHeader http.Header; Host string; Subprotocols []string; CompressionMode CompressionMode; CompressionThreshold int; OnPingReceived ...; OnPongReceived ... }
const MessageText MessageType = iota + 1; MessageBinary
const StatusNormalClosure StatusCode = 1000; StatusGoingAway = 1001; StatusProtocolError = 1002; StatusPolicyViolation = 1008; StatusMessageTooBig = 1009; StatusInternalError = 1011
wsjson.Read(ctx context.Context, c *websocket.Conn, v any) error
wsjson.Write(ctx context.Context, c *websocket.Conn, v any) error
```
- [high] gorilla/websocket status: latest release v1.5.3 (2024-06-14), go.mod `go 1.12`, repo not archived, last commit on main 2025-03-19 ('Implements HTTPS proxy functionality'); release notes for v1.4.2 said 'We are still looking for proactive maintainer(s)'. It works and is stable, but has no context.Context API, requires the read-pump/write-pump goroutine discipline (one concurrent writer), and sees roughly one commit per year. golang.org/x/net/websocket's own package doc says it 'currently lacks some features found in an alternative and more actively maintained WebSocket packages' and names github.com/gorilla/websocket and github.com/coder/websocket as those alternatives; it lacks RFC 7692 compression and a proper close handshake API. Recommendation: coder/websocket; gorilla only as a fallback. (https://github.com/gorilla/websocket/commits/main ; https://github.com/gorilla/websocket/releases ; https://pkg.go.dev/golang.org/x/net/websocket)
- [high] coder/websocket Accept() hijacks the HTTP/1.1 connection: accept.go line 130 returns `http.ResponseWriter does not implement http.Hijacker` when the ResponseWriter cannot be hijacked (HTTP/2 streams). Therefore the WebSocket endpoint must be served over HTTP/1.1. Go's net/http server enables HTTP/2 automatically on TLS; either terminate TLS in a reverse proxy (Caddy/nginx -> plain HTTP/1.1 to the Go process) or, when serving TLS directly, restrict protocols with the Go 1.24 `Server.Protocols` field so that URLSessionWebSocketTask never lands on an h2 stream. (https://pkg.go.dev/net/http#Protocols (field list verified with `go doc net/http.Server` on go1.24.7; Hijacker check verified in coder/websocket v1.8.15 accept.go))
```
var p http.Protocols
p.SetHTTP1(true)            // HTTP/1.0 and HTTP/1.1
p.SetHTTP2(false)
srv := &http.Server{Addr: ":8443", Handler: mux, Protocols: &p, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 1 << 16}
// Go 1.24 docs: 'If Protocols is nil, the default is usually HTTP/1 and HTTP/2. If TLSNextProto is non-nil and does not contain an "h2" entry, HTTP/2 is disabled.'
```
- [high] Pure-Go SQLite: modernc.org/sqlite registers database/sql driver name "sqlite" (`sql.Open("sqlite", dsn)`), no cgo, CGO_ENABLED=0 static build verified. The DSN parameters documented by `Driver.Open` in v1.46.1 are ONLY: `_pragma` (repeatable; value is run as `PRAGMA <value>`), `_time_format` (only "sqlite"), `_time_integer_format` (unix|unix_milli|unix_micro|unix_nano), `_inttotime`, `_texttotime`, and `_txlock` (deferred|immediate|exclusive). The shorthand parameters shown on pkg.go.dev for v1.60.x (`_busy_timeout`, `_journal_mode`, `_foreign_keys`, `StrictPragmas(bool)`) do NOT exist in v1.46.1 (`go doc modernc.org/sqlite.StrictPragmas` -> 'no symbol'). Use the `_pragma=name(value)` form only. Verified runtime: PRAGMA journal_mode=wal, busy_timeout=5000, foreign_keys=1, synchronous=1 (NORMAL), sqlite_version()=3.51.2. (https://pkg.go.dev/modernc.org/sqlite (DSN list verified with `go doc modernc.org/sqlite.Driver.Open` on v1.46.1; pragmas verified by running queries))
```
import _ "modernc.org/sqlite"

dsn := "file:/data/kilit.db?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)&_txlock=immediate"
db, err := sql.Open("sqlite", dsn)
db.SetMaxOpenConns(4)   // modernc doc: 'Bound the pool with sql.DB.SetMaxOpenConns'
db.SetMaxIdleConns(4)
db.SetConnMaxLifetime(0)
// error mapping:
var se *sqlite.Error            // import "modernc.org/sqlite"
if errors.As(err, &se) && se.Code() == sqlite3.SQLITE_CONSTRAINT_UNIQUE { /* 2067: username taken */ }   // import sqlite3 "modernc.org/sqlite/lib"
// observed error text: 'constraint failed: UNIQUE constraint failed: users.username (2067)'
```
- [high] `_txlock=immediate` is essential, not optional. Probe: 8 goroutines x 25 transactions each doing `SELECT count(*)` then `INSERT` inside one tx, WAL mode, busy_timeout=5000, pool of 4. With the default deferred locking: 149 of 200 transactions failed with `database is locked (5) (SQLITE_BUSY)` (a deferred tx that starts as a reader cannot upgrade to writer while another writer committed in between; the busy handler is not consulted for that upgrade). With `&_txlock=immediate`: 0 errors, 200 rows. Every tx then takes the write lock at BEGIN and waits politely up to busy_timeout. Readers (plain `db.Query` outside a tx) are never blocked in WAL mode. (https://pkg.go.dev/modernc.org/sqlite (empirically measured in the probe test TestSQLiteConcurrencyTxlock on v1.46.1))
- [high] SQLite features available (3.51.2 embedded): `RETURNING` (3.35+), `STRICT` tables (3.37+), partial indexes, `UPSERT`, window functions. Verified DDL + atomic one-time-prekey claim in a single statement (no explicit transaction needed): DELETE ... RETURNING returned key_id=1 and left 2 rows; STRICT rejected a TEXT value in a BLOB column with 'cannot store TEXT value in BLOB column (3091)'; `COLLATE NOCASE` UNIQUE on username rejected 'ALICE' after 'alice'. (https://pkg.go.dev/modernc.org/sqlite (run on v1.46.1 / SQLite 3.51.2))
```
-- atomic claim (verified):
DELETE FROM one_time_prekeys WHERE id = (SELECT id FROM one_time_prekeys WHERE user_id=? ORDER BY id LIMIT 1) RETURNING key_id, pub;
-- insert with id back:
INSERT INTO users(username, identity_sign_pub, identity_dh_pub, created_at) VALUES(?,?,?,?) RETURNING id;
```
- [high] mattn/go-sqlite3 v1.14.52 (2026-09-05, go 1.21) is the cgo driver: needs gcc and CGO_ENABLED=1, defeats the static single-binary/CGO_ENABLED=0 Dockerfile and makes cross-compiling painful; rejected. github.com/ncruces/go-sqlite3 (SQLite compiled to wasm, pure Go) is a credible alternative but its latest (v0.35.6) requires go 1.26; last 1.24-compatible is v0.32.0. modernc.org/sqlite is the mainstream pure-Go choice and is what the rest of this design assumes. (https://proxy.golang.org (go directives verified with `go mod download -json`))
- [high] Go 1.22+ net/http ServeMux routing (verified on go1.24.7): pattern grammar `[METHOD ][HOST]/[PATH]`; `{name}` matches exactly one segment, `{name...}` matches the rest of the path (only at the end), `{$}` matches only the end (so `GET /{$}` is root only while `/` matches everything); method GET also matches HEAD; literal parts match case-sensitively; most-specific pattern wins and conflicting registrations PANIC at Handle/HandleFunc time; a method mismatch yields an automatic 405 with an `Allow` header (verified: `GET /v1/messages/abc` -> 405, Allow: POST); wildcard values via `r.PathValue(name)`; trailing-slash redirect for subtree patterns; `GODEBUG=httpmuxgo121=1` restores 1.21 behaviour. Probe results: `POST /v1/messages/{id}` -> 200 id=abc; `GET /v1/attachments/{id}/{name...}` with /v1/attachments/x1/a/b.jpg -> name=a/b.jpg; unknown path -> 404. (https://pkg.go.dev/net/http#ServeMux (full pattern text verified with `go doc net/http.ServeMux` on go1.24.7 and by a running httptest probe))
```
mux := http.NewServeMux()
mux.HandleFunc("POST /v1/register", s.handleRegister)
mux.HandleFunc("POST /v1/auth/challenge", s.handleChallenge)
mux.HandleFunc("POST /v1/auth/login", s.handleLogin)
mux.HandleFunc("GET /v1/users/{username}/prekeys", s.handleFetchBundle)
mux.HandleFunc("PUT /v1/prekeys", s.handleUploadPrekeys)
mux.HandleFunc("POST /v1/messages", s.handleSend)
mux.HandleFunc("GET /v1/messages", s.handlePoll)          // REST fallback, ?after=<cursor>
mux.HandleFunc("POST /v1/messages/ack", s.handleAck)
mux.HandleFunc("POST /v1/attachments", s.handleUpload)
mux.HandleFunc("GET /v1/attachments/{id}", s.handleDownload)
mux.HandleFunc("DELETE /v1/attachments/{id}", s.handleDeleteAttachment)
mux.HandleFunc("GET /v1/ws", s.handleWS)
mux.HandleFunc("GET /healthz", ...)
id := r.PathValue("id")  // func (r *Request) PathValue(name string) string
// wrap: http.MaxBytesHandler(mux, 1<<20) for JSON routes; per-route http.MaxBytesReader(w, r.Body, 25<<20) for uploads
```
- [high] Rate limiting with golang.org/x/time/rate v0.14.0 (API unchanged for years, verified by compiling and a burst test: burst 3 -> [true true true false], refills after 1/rate). Design: a keyed limiter registry (sync.Mutex + map[string]*entry{lim *rate.Limiter, seen time.Time}) with a janitor goroutine evicting entries idle > 10 min; key = client IP (net.SplitHostPort(r.RemoteAddr); trust X-Forwarded-For/X-Real-IP ONLY when a trusted reverse proxy is configured) for unauthenticated routes, and user id for authenticated routes. Suggested tiers: register 3/hour per IP (rate.Every(20*time.Minute), burst 3); challenge+login rate.Every(2*time.Second) burst 10 per IP; send messages rate.Every(100*time.Millisecond) burst 50 per user; attachment upload rate.Every(2*time.Second) burst 5 per user; prekey bundle fetch rate.Every(time.Second) burst 20 per user. On rejection write 429 with `Retry-After` from `lim.Reserve().Delay()` (then `Cancel()`), or just 429. Also cap WebSocket message size with SetReadLimit (e.g. 128 KiB) and connections per user (e.g. 3). (https://pkg.go.dev/golang.org/x/time/rate (compiled and tested with v0.14.0))
```
type Limit float64
func Every(interval time.Duration) Limit
func NewLimiter(r Limit, b int) *Limiter
func (lim *Limiter) Allow() bool
func (lim *Limiter) AllowN(t time.Time, n int) bool
func (lim *Limiter) Reserve() *Reservation      // r.OK(), r.Delay(), r.Cancel()
func (lim *Limiter) Wait(ctx context.Context) error
func (lim *Limiter) SetLimit(newLimit Limit); func (lim *Limiter) SetBurst(newBurst int)
const Inf = Limit(math.MaxFloat64)   // burst 0 rejects everything unless limit == Inf

func (k *Keyed) Middleware(keyFn func(*http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !k.get(keyFn(r)).Allow() { w.Header().Set("Retry-After", "1"); http.Error(w, "rate limited", http.StatusTooManyRequests); return }
			next.ServeHTTP(w, r)
		})
	}
}
```
- [high] X25519: use stdlib crypto/ecdh (Go 1.20+), not golang.org/x/crypto/curve25519 (whose v0.48.0 package doc says it 'is a wrapper for the X25519 implementation in the crypto/ecdh package. It is frozen'). Key encoding is the raw 32-byte u-coordinate, identical to CryptoKit `Curve25519.KeyAgreement.PublicKey.rawRepresentation` / `PrivateKey.rawRepresentation`. Verified against RFC 7748 section 6.1: NewPrivateKey(alice) .PublicKey().Bytes() == 8520f009..., ECDH(bob pub) == 4a5d9d5b...; all-zero/low-order peer point returns error 'crypto/ecdh: bad X25519 remote ECDH input: low order point' (CryptoKit similarly throws) — treat as fatal, never derive from it. (https://pkg.go.dev/crypto/ecdh (RFC 7748 vectors verified on go1.24.7))
```
func X25519() ecdh.Curve
type Curve interface { GenerateKey(rand io.Reader) (*PrivateKey, error); NewPrivateKey(key []byte) (*PrivateKey, error); NewPublicKey(key []byte) (*PublicKey, error) }
func (k *PrivateKey) ECDH(remote *PublicKey) ([]byte, error)   // 32 bytes; error if all-zero
func (k *PrivateKey) PublicKey() *PublicKey
func (k *PrivateKey) Bytes() []byte; func (k *PublicKey) Bytes() []byte

priv, _ := ecdh.X25519().GenerateKey(rand.Reader)
peer, err := ecdh.X25519().NewPublicKey(peerBytes)   // len must be 32
shared, err := priv.ECDH(peer)
```
- [high] Ed25519: stdlib crypto/ed25519. PrivateKey is 64 bytes (seed||pub); the 32-byte seed is what CryptoKit `Curve25519.Signing.PrivateKey.rawRepresentation` holds, so interop is `ed25519.NewKeyFromSeed(seed)`. Signatures are 64 bytes, pure Ed25519 (RFC 8032), no prehash/context — do NOT use VerifyWithOptions with Ed25519ph/ctx because CryptoKit only does pure Ed25519. Verified RFC 8032 section 7.1 test 1 (seed 9d61b19d..., pub d75a9801..., sig e5564300...). There is no XEdDSA in Go stdlib or CryptoKit, hence the identity must carry two keys (see X3DH finding). (https://pkg.go.dev/crypto/ed25519 (RFC 8032 vector verified on go1.24.7))
```
func GenerateKey(rand io.Reader) (PublicKey, PrivateKey, error)
func NewKeyFromSeed(seed []byte) PrivateKey      // seed = 32 bytes
func (priv PrivateKey) Seed() []byte
func Sign(privateKey PrivateKey, message []byte) []byte   // 64 bytes
func Verify(publicKey PublicKey, message, sig []byte) bool
const PublicKeySize = 32; PrivateKeySize = 64; SignatureSize = 64; SeedSize = 32
```
- [high] HKDF: Go 1.24 added stdlib `crypto/hkdf` (verified present in go1.24.7 via `go doc crypto/hkdf`), so golang.org/x/crypto/hkdf is not needed. Note the generic signature and that `info` is a `string` (pass `string(infoBytes)` for arbitrary bytes). Verified RFC 5869 test case 1 (42-byte OKM 3cb25f25...). CryptoKit `HKDF<SHA256>.deriveKey(inputKeyMaterial:salt:info:outputByteCount:)` and `SharedSecret.hkdfDerivedSymmetricKey(using:salt:sharedInfo:outputByteCount:)` are plain RFC 5869 so the same vectors must match on iOS. x/crypto/hkdf v0.48.0 still exists with the old io.Reader API (`New(hash func() hash.Hash, secret, salt, info []byte) io.Reader`) if ever needed. (https://pkg.go.dev/crypto/hkdf (RFC 5869 vector verified on go1.24.7))
```
func Key[Hash hash.Hash](h func() Hash, secret, salt []byte, info string, keyLength int) ([]byte, error)
func Extract[H hash.Hash](h func() H, secret, salt []byte) ([]byte, error)
func Expand[H hash.Hash](h func() H, pseudorandomKey []byte, info string, keyLength int) ([]byte, error)

okm, err := hkdf.Key(sha256.New, ikm, salt, "Kilit-X3DH-v1", 32)
```
- [high] ChaCha20-Poly1305 is NOT in the Go stdlib (stdlib has AES-GCM via crypto/cipher.NewGCM only); use golang.org/x/crypto/chacha20poly1305 v0.48.0 — the one reason x/crypto stays in go.mod. Verified RFC 8439 section 2.8.2 AEAD vector (ciphertext prefix d31a8d34..., tag 1ae10b59...). Wire format decision for interop with CryptoKit `ChaChaPoly.SealedBox.combined` (= nonce(12) || ciphertext || tag(16)): store/transmit exactly `nonce || ciphertext || tag`; in Go that is `append(nonce, aead.Seal(nil, nonce, pt, ad)...)` and on open `aead.Open(nil, buf[:12], buf[12:], ad)`. CryptoKit AES.GCM.SealedBox.combined has the same layout, so AES-256-GCM is a drop-in alternative (`cipher.NewGCM(aesBlock)`, 12-byte nonce, 16-byte tag). (https://pkg.go.dev/golang.org/x/crypto/chacha20poly1305 (RFC 8439 vector verified with v0.48.0 on go1.24.7))
```
const KeySize = 32; NonceSize = 12; NonceSizeX = 24; Overhead = 16
func New(key []byte) (cipher.AEAD, error)
func NewX(key []byte) (cipher.AEAD, error)   // XChaCha20-Poly1305, 24-byte random-safe nonce
```
- [high] Randomness and tokens: `crypto/rand.Read` cannot fail in Go 1.24 (it aborts the process on an unrecoverable error), and Go 1.24 added `crypto/rand.Text() string` (RFC 4648 base32, >= 128 bits) — convenient for nonces/tokens in text form; `crypto/subtle.ConstantTimeCompare(x, y []byte) int` for comparing secrets. Verified present via `go doc` on go1.24.7. Other Go 1.24 stdlib confirmed locally: crypto/sha3, crypto/mlkem (ML-KEM-768/1024; NOT usable for phase 1 because CryptoKit on iOS 17 has no ML-KEM), encoding/json `omitzero` tag, testing.B.Loop, os.Root, http.Protocols. (https://pkg.go.dev/crypto/rand (verified with `go doc crypto/rand.Text` on go1.24.7))
```
token := rand.Text()                 // e.g. for the challenge nonce in text form
var nonce [32]byte; rand.Read(nonce[:])   // binary nonce
```
- [medium] X3DH/Double Ratchet constants for the Go reference library (signal.org was unreachable from this sandbox; these are from the specs as I know them — treat as knowledge). X3DH (spec section 2.2/3.3): curve X25519, hash SHA-256, Encode(PK) = raw 32 bytes (Signal prefixes a 0x05 type byte; our own protocol may use raw 32), KDF(KM) = HKDF-SHA256(salt = 32 zero bytes, IKM = F || KM where F = 32 bytes of 0xFF for X25519, info = application string, e.g. "Kilit-X3DH-v1", L = 32); DH1 = DH(IK_A, SPK_B), DH2 = DH(EK_A, IK_B), DH3 = DH(EK_A, SPK_B), DH4 = DH(EK_A, OPK_B) if an OPK was present; SK = KDF(DH1||DH2||DH3||DH4); AD = Encode(IK_A) || Encode(IK_B); Bob deletes the used OPK after deriving SK. Signal signs SPK with XEdDSA over the X25519 identity key; neither CryptoKit nor Go stdlib has XEdDSA, and the X3DH spec explicitly allows a separate signing identity key instead, so: identity = Ed25519 signing key (IK_sig) + X25519 agreement key (IK_dh); the bundle signature covers IK_dh || SPK_pub || SPK_id (domain-separated) and is verified by the server on upload and by clients on fetch; safety numbers hash (username, IK_sig, IK_dh). Double Ratchet (spec section 5.2 'recommended algorithms'): GENERATE_DH/DH = X25519; KDF_RK(rk, dh_out) = HKDF-SHA256(salt = rk, IKM = dh_out, info = "Kilit-DR-Root-v1", 64 bytes -> new rk || ck); KDF_CK(ck): mk = HMAC-SHA256(ck, 0x01), ck' = HMAC-SHA256(ck, 0x02); Signal's recommended ENCRYPT is AES-256-CBC + HMAC-SHA256 with 80 bytes from HKDF, but CryptoKit has no CBC/HMAC-then-encrypt convenience, so the justified deviation is: HKDF-SHA256(salt = 32 zero bytes, IKM = mk, info = "Kilit-DR-Msg-v1", 44 bytes) -> 32-byte key || 12-byte nonce, ChaCha20-Poly1305 Seal with AD = X3DH AD || header; header = ratchet_pub(32) || pn(uint32 BE) || n(uint32 BE); MAX_SKIP = 1000 with skipped-key eviction by count/age (spec section 6). All of these primitives have Go/CryptoKit-identical RFC behaviour (verified above), so Go-generated vectors transfer to XCTest. (knowledge (spec URLs for the design doc: https://signal.org/docs/specifications/x3dh/ and https://signal.org/docs/specifications/doubleratchet/ — unreachable from this sandbox; the Go primitives themselves were verified against RFC vectors))
```
// Go reference KDFs (crypto/hkdf, crypto/hmac, crypto/sha256):
sk, _ := hkdf.Key(sha256.New, append(bytes.Repeat([]byte{0xFF}, 32), dh1dh2dh3dh4...), make([]byte, 32), "Kilit-X3DH-v1", 32)
rkck, _ := hkdf.Key(sha256.New, dhOut, rk, "Kilit-DR-Root-v1", 64)   // rk' = rkck[:32], ck = rkck[32:]
mac := hmac.New(sha256.New, ck); mac.Write([]byte{0x01}); mk := mac.Sum(nil)
mac = hmac.New(sha256.New, ck); mac.Write([]byte{0x02}); ckNext := mac.Sum(nil)
kn, _ := hkdf.Key(sha256.New, mk, make([]byte, 32), "Kilit-DR-Msg-v1", 44)  // key = kn[:32], nonce = kn[32:44]
```
- [high] Signed-challenge authentication design (Ed25519, nonce + timestamp + replay protection). Registration `POST /v1/register` body: {username, identity_sign_pub(32), identity_dh_pub(32), signed_prekey{id, pub, sig}, one_time_prekeys[{id,pub}], proof} where proof = Ed25519 sig over `"kilit-register-v1" || 0x00 || username || 0x00 || identity_dh_pub` (proves possession of IK_sig and binds IK_dh); username must match `^[a-z0-9_]{3,32}$` and is stored UNIQUE COLLATE NOCASE. Login: (1) `POST /v1/auth/challenge {username}` -> server generates 32 random bytes, stores SHA-256(nonce) with user_id and expires_at = now+60s in auth_nonces, returns {nonce(base64url), expires_at}; respond identically (fake nonce) for unknown users to avoid enumeration. (2) client signs M = `"kilit-auth-v1" || 0x00 || username || 0x00 || nonce || 0x00 || uint64BE(unix_ts) || 0x00 || device_id` with IK_sig and sends `POST /v1/auth/login {username, nonce, ts, device_id, sig}`. (3) server checks |now - ts| <= 300 s, then atomically consumes the nonce with `DELETE FROM auth_nonces WHERE nonce_hash=? AND user_id=? AND expires_at>? RETURNING 1` (0 rows => expired, unknown, or replayed — single-use is enforced by the row deletion), then `ed25519.Verify(identity_sign_pub, M, sig)`; rebuild M server-side from the fields, never accept a client-supplied message blob. (4) On success issue a bearer session token: 32 random bytes, returned base64url, stored as SHA-256(token) in sessions(token_hash PK, user_id, device_id, created_at, expires_at = now+30d, last_seen); every request sends `Authorization: Bearer <token>`; WebSocket uses the same header (URLSessionWebSocketTask accepts a URLRequest with headers) — fall back to a `?token=` query param only if a proxy strips headers (log carefully). Logout = delete the row; sweeper deletes expired nonces and sessions. Domain-separation prefixes are mandatory because the same Ed25519 key also signs prekey bundles and screenshot-event receipts. (knowledge (standard challenge-response construction; primitives and SQL verified on go1.24.7 / SQLite 3.51.2))
```
CREATE TABLE auth_nonces (nonce_hash BLOB PRIMARY KEY, user_id INTEGER NOT NULL, expires_at INTEGER NOT NULL) STRICT;
CREATE TABLE sessions (token_hash BLOB PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, device_id TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, last_seen INTEGER NOT NULL) STRICT;
CREATE INDEX sessions_user ON sessions(user_id);

func loginMessage(username string, nonce []byte, ts uint64, deviceID string) []byte {
	var b []byte
	b = append(b, "kilit-auth-v1"...); b = append(b, 0)
	b = append(b, username...); b = append(b, 0)
	b = append(b, nonce...); b = append(b, 0)
	b = binary.BigEndian.AppendUint64(b, ts); b = append(b, 0)
	return append(b, deviceID...)
}
```
- [high] Store-and-forward schema (DDL verified to run on SQLite 3.51.2 via modernc v1.46.1; STRICT tables so types are enforced). Messages are opaque envelopes; `id` (rowid) is the delivery cursor, `msg_id` (16 random bytes from the client) makes send and ack idempotent. Fetch: `SELECT id, msg_id, sender_id, envelope, created_at FROM messages WHERE recipient_id=? AND id>? ORDER BY id LIMIT 100`; ack: `DELETE FROM messages WHERE recipient_id=? AND msg_id IN (?,?,...)` (recipient in WHERE = authorization); TTL sweeper every 60 s: `DELETE FROM messages WHERE expires_at < ?` (server TTL default 7 days; the per-conversation disappearing timer lives inside the encrypted payload and is enforced by clients). Delivery: an in-process hub `map[userID]map[*websocket.Conn]struct{}` — on send, insert row then notify the recipient's live sockets (push {id,msg_id,sender,envelope}); on WS connect, drain the queue from the client's last cursor first; REST `GET /v1/messages?after=<id>` is the fallback. Screenshot notifications and read/ack receipts are just envelope types; the server never interprets them. Envelope size cap 64 KiB (MaxBytesReader / SetReadLimit). (knowledge (DDL executed successfully in the probe on modernc.org/sqlite v1.46.1))
```
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  identity_sign_pub BLOB NOT NULL CHECK(length(identity_sign_pub)=32),
  identity_dh_pub BLOB NOT NULL CHECK(length(identity_dh_pub)=32),
  created_at INTEGER NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS signed_prekeys (
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  key_id INTEGER NOT NULL,
  pub BLOB NOT NULL CHECK(length(pub)=32),
  sig BLOB NOT NULL CHECK(length(sig)=64),
  created_at INTEGER NOT NULL,
  PRIMARY KEY(user_id, key_id)
) STRICT;
CREATE TABLE IF NOT EXISTS one_time_prekeys (
  id INTEGER PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  key_id INTEGER NOT NULL,
  pub BLOB NOT NULL CHECK(length(pub)=32),
  UNIQUE(user_id, key_id)
) STRICT;
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY,
  msg_id BLOB NOT NULL UNIQUE,
  recipient_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  sender_id INTEGER NOT NULL,
  envelope BLOB NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
) STRICT;
CREATE INDEX IF NOT EXISTS messages_recipient ON messages(recipient_id, id);
CREATE INDEX IF NOT EXISTS messages_expires ON messages(expires_at);
CREATE TABLE IF NOT EXISTS attachments (
  id TEXT PRIMARY KEY,               -- 32 hex chars (16 random bytes)
  owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  recipient_id INTEGER NOT NULL,
  size INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
) STRICT;
CREATE INDEX IF NOT EXISTS attachments_expires ON attachments(expires_at);
CREATE TABLE IF NOT EXISTS push_tokens (user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, device_id TEXT NOT NULL, token TEXT NOT NULL, env TEXT NOT NULL, updated_at INTEGER NOT NULL, PRIMARY KEY(user_id, device_id)) STRICT;
CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL) STRICT;
```
- [high] Encrypted attachment blob storage on disk with Go 1.24 `os.Root` (verified: `..` traversal and a symlink pointing outside both fail with 'path escapes from parent'). In go1.24.7 Root has ONLY: Close, Create, FS, Lstat, Mkdir, Name, Open, OpenFile, OpenRoot, Remove, Stat (verified with `go doc os.Root`); MkdirAll/RemoveAll/Rename/ReadFile/WriteFile exist only in later Go versions — do not use them. Layout: id = 16 random bytes hex; file path `<id[:2]>/<id>` (fan-out dir created with root.Mkdir, ignore fs.ErrExist); upload handler: `root.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)`, `io.Copy(f, http.MaxBytesReader(w, r.Body, maxUpload))`, `f.Sync()`, `f.Close()`, then INSERT attachments row (file-before-row; a failed insert removes the file). Download: authorize (owner or recipient), `root.Open`, `http.ServeContent(w, r, "", time.Time{}, f)` with `Content-Type: application/octet-stream`, `Cache-Control: no-store`. Deletion: on recipient ack (`DELETE /v1/attachments/{id}`) and by a TTL sweeper every 60 s: `SELECT id FROM attachments WHERE expires_at<? LIMIT 500` -> `root.Remove(path)` (ignore fs.ErrNotExist) -> delete row; at startup `filepath.WalkDir(dir)` reconciles orphan files that have no row. Ciphertext only — the server never has the per-file key (it travels inside the E2EE message). (https://pkg.go.dev/os#Root (method set and escape behaviour verified by running on go1.24.7))
```
root, err := os.OpenRoot(cfg.BlobDir)            // func OpenRoot(name string) (*Root, error)
f, err := root.OpenFile(id[:2]+"/"+id, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
n, err := io.Copy(f, http.MaxBytesReader(w, r.Body, 25<<20))  // *http.MaxBytesError on overflow -> 413
f.Sync(); f.Close()
// serve:
f, err := root.Open(id[:2]+"/"+id); defer f.Close()
http.ServeContent(w, r, "", time.Time{}, f)
// sweep:
err = root.Remove(path); if errors.Is(err, fs.ErrNotExist) { err = nil }
```
- [high] Graceful shutdown pattern (verified end-to-end on go1.24.7 with coder/websocket v1.8.15: client received close status 1001 StatusGoingAway with reason 'server shutting down', drain took ~1 ms). `http.Server.Shutdown` explicitly does NOT close or wait for hijacked connections (WebSockets), so the server keeps a registry of live sockets and uses `Server.RegisterOnShutdown` to start `Conn.Close(websocket.StatusGoingAway, ...)` on each (non-blocking, in goroutines, as the docs require), then waits on a WaitGroup. The anti-pattern was measured too: if the shutdown context is used as `Server.BaseContext` (or passed to `Conn.Read`), coder/websocket aborts the socket the moment the ctx is cancelled and the client sees a bare EOF (CloseStatus -1) instead of 1001 — so the handler reads with a non-cancelling context and lets the hub drive closes. Sequence: NotifyContext(SIGINT, SIGTERM) -> stop accepting -> Shutdown(10 s) -> hub.wg.Wait() -> stop sweeper goroutines -> db.Close(). (https://pkg.go.dev/net/http#Server.Shutdown (Shutdown/RegisterOnShutdown doc text verified with `go doc`; behaviour verified by running cmd/shutdown2 in the probe module))
```
ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
defer stop()
srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute}
srv.RegisterOnShutdown(hub.closeAll)   // for c := range conns { go c.Close(websocket.StatusGoingAway, "server shutting down") }
go func() { if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) { log.Fatal(err) } }()
<-ctx.Done()
shCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second); defer cancel()
_ = srv.Shutdown(shCtx)
hub.wg.Wait()
sweeperCancel(); db.Close()
// WS handler: h.add(c); defer h.remove(c); defer c.CloseNow(); for { if _, _, err := c.Read(context.Background()); err != nil { return } }  // use per-read timeouts via context.WithTimeout if idle-kill is wanted, not the shutdown ctx
```
- [high] Dockerfile (multi-stage, CGO_ENABLED=0, distroless nonroot). Docker Hub currently has tags golang:1.24, 1.24-alpine, 1.24-bookworm, 1.24-trixie (1.24 resolves to 1.24.13 today), and gcr.io/distroless/static-debian12 has tags `nonroot`, `latest`, `debug`, `debug-nonroot`. static-debian12 ships ca-certificates and tzdata (needed later for APNs TLS) and runs as uid 65532; with `FROM scratch` you would have to copy /etc/ssl/certs/ca-certificates.crt yourself. Set GOTOOLCHAIN=local in the image so the build never tries to download a newer toolchain. Binary size ~6.1 MB stripped (measured). (https://hub.docker.com/v2/repositories/library/golang/tags?name=1.24 and https://gcr.io/v2/distroless/static-debian12/tags/list (tag existence verified by HTTP; static binary verified locally))
```
# syntax=docker/dockerfile:1
FROM golang:1.24-alpine AS build
WORKDIR /src
ENV GOTOOLCHAIN=local CGO_ENABLED=0 GOFLAGS=-trimpath
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go build -ldflags="-s -w" -o /out/kilitd ./cmd/kilitd

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/kilitd /kilitd
VOLUME ["/data"]
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/kilitd", "-db", "/data/kilit.db", "-blobs", "/data/blobs", "-addr", ":8080"]
# compose: stop_grace_period: 15s ; the /data volume must be writable by uid 65532
```
- [high] APNs hook (phase 1: interface + token table only, no sending). Apple token-based auth: JWT header {"alg":"ES256","kid":"<10-char Key ID>"}, claims {"iss":"<10-char Team ID>","iat":<unix seconds>}; signed with the .p8 ECDSA P-256 key; header `authorization: bearer <jwt>`; refresh the token no more than once every 20 minutes and at least once every 60 minutes (iat older than 1 h -> 403 ExpiredProviderToken; too frequent -> 429 TooManyProviderTokenUpdates). Request: HTTP/2 + TLS 1.2+, `POST https://api.push.apple.com/3/device/<hex device token>` (sandbox: api.sandbox.push.apple.com; port 443 or 2197), headers `apns-topic` (bundle id), `apns-push-type` (alert|background|...; background must use apns-priority 5), `apns-priority` (10 default), `apns-expiration` (0 = one attempt), `apns-collapse-id` (<= 64 bytes), optional `apns-id` UUID; payload JSON <= 4096 bytes. Responses: 200; 400 BadDeviceToken/BadTopic/...; 403 ExpiredProviderToken/InvalidProviderToken/MissingProviderToken; 410 Unregistered or ExpiredToken (body has `timestamp` ms — delete the stored token); 413 PayloadTooLarge; 429 TooManyRequests/TooManyProviderTokenUpdates; 5xx retry with backoff (Apple: after 15 min). Do-not-retry reasons: BadDeviceToken, DeviceTokenNotForTopic, Forbidden, ExpiredToken, Unregistered, PayloadTooLarge. For an E2EE app send a content-free push (`{"aps":{"content-available":1}}` background, or an alert with `loc-key` and `mutable-content:1` for a future Notification Service Extension) — the server has no plaintext to put in it. Implementation can be stdlib-only (~150 lines): `x509.ParsePKCS8PrivateKey` on the .p8 PEM block -> *ecdsa.PrivateKey, `ecdsa.Sign(rand.Reader, key, sha256(signingInput))` -> raw r||s each left-padded to 32 bytes (JWS ES256 is NOT ASN.1), base64url; http.Client with TLS negotiates h2 automatically. Library alternative github.com/sideshow/apns2 v0.25.0 (2024-10-24, go 1.15) depends on golang-jwt/jwt/v4 v4.4.1 and an ancient golang.org/x/net pseudo-version; MVS would keep x/net at whatever you pin (must stay <= v0.50.0 for Go 1.24) — workable but the stdlib path avoids 3 extra deps. (https://developer.apple.com/documentation/usernotifications/establishing-a-token-based-connection-to-apns ; https://developer.apple.com/documentation/usernotifications/sending-notification-requests-to-apns ; https://developer.apple.com/documentation/usernotifications/handling-notification-responses-from-apns (fetched via Apple's JSON data endpoints); apns2 go.mod from proxy.golang.org)
```
type PushOptions struct { Background bool; CollapseID string; Expiration time.Time }
type Pusher interface { Push(ctx context.Context, deviceToken string, payload []byte, opts PushOptions) error }
type NoopPusher struct{}
func (NoopPusher) Push(context.Context, string, []byte, PushOptions) error { return nil }
// route: PUT /v1/devices/{id}/push-token {token, env:"sandbox"|"production"}
// ecdsa for ES256 JWS: r, s, err := ecdsa.Sign(rand.Reader, key, digest[:]); sig := make([]byte, 64); r.FillBytes(sig[:32]); s.FillBytes(sig[32:])
```
- [high] Testing strategy that works on Linux without Xcode: `httptest.NewServer(mux)` + `websocket.Dial` from tests (verified), one temp-file SQLite per test via `t.TempDir()` (verified; do NOT use `file::memory:` with a pool > 1 — each pooled connection gets its own private in-memory DB), table-driven handler tests, and the crypto reference library's tests emit JSON test vectors (X25519 keys, X3DH SK, ratchet message keys, ciphertexts with nonce||ct||tag) into `docs/vectors/*.json` that are copied into Swift XCTest. `go vet ./...` passes on the probe. `-race` requires cgo (CGO_ENABLED=1 + gcc): run it on the dev box / CI runner, not in the alpine build stage; the CGO_ENABLED=0 build stays race-detector-free by design. (knowledge (patterns executed in the probe module on go1.24.7))
```
func newTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "t.db") + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_txlock=immediate"
	db, err := sql.Open("sqlite", dsn); if err != nil { t.Fatal(err) }
	t.Cleanup(func() { db.Close() })
	return db
}
```
- [medium] Repository layout for server/ consistent with the above: cmd/kilitd/main.go (flags: -addr, -db, -blobs, -msg-ttl, -blob-ttl, -max-upload), internal/api (mux, middleware: recover, request-id, logging via log/slog, rate limit, auth), internal/auth (challenge/login/session), internal/store (sqlite open + migrations via schema_version table, queries), internal/ws (hub, per-conn writer goroutine, ping every 30 s with Conn.Ping(ctx 10 s)), internal/blob (os.Root store + sweeper), internal/push (Pusher, NoopPusher), pkg/kilitcrypto (X3DH + Double Ratchet reference lib, no server import, with vector generator under pkg/kilitcrypto/vectors). Logging: stdlib log/slog (Go 1.21+); config via flags + env; no framework needed.
Pitfalls: Do NOT run `go get -u` or `go get <module>@latest`: as of 2026-10-21 every golang.org/x/* module, modernc.org/sqlite and ncruces/go-sqlite3 require go >= 1.26.0 and the Go 1.24 toolchain refuses them (`requires go >= 1.26.0 (running go 1.24.7; GOTOOLCHAIN=local)`). Pin x/crypto v0.48.0, x/time v0.14.0, x/sync v0.19.0, x/sys v0.41.0, x/net v0.50.0 (if ever needed), modernc.org/sqlite v1.46.1, coder/websocket v1.8.15. Without GOTOOLCHAIN=local, Go 1.24 would silently try to download a 1.26 toolchain at build time (fails in an offline/distroless build). | Security trade-off to state in the design doc: pinning x/crypto v0.48.0 (Feb 2026) means you will not receive x/crypto fixes released for Go >= 1.26 until the owner decides to raise the toolchain; mitigate by using stdlib crypto wherever possible (crypto/ecdh, crypto/ed25519, crypto/hkdf, crypto/hmac) so x/crypto is only used for chacha20poly1305 — or drop x/crypto entirely by choosing AES-256-GCM (crypto/cipher.NewGCM), which CryptoKit also supports with the identical nonce||ct||tag combined layout. | modernc.org/sqlite v1.46.1 does NOT support the `_busy_timeout`, `_journal_mode`, `_foreign_keys` DSN shorthands or `StrictPragmas` that pkg.go.dev shows for v1.60.x; only `_pragma=busy_timeout(5000)`, `_pragma=journal_mode(WAL)`, `_pragma=foreign_keys(1)` and `_txlock=immediate` exist. The `_pragma` value is run as raw SQL, so never build the DSN from user input. | Without `_txlock=immediate`, deferred transactions that read then write fail with SQLITE_BUSY even with busy_timeout set (measured 149/200 failures with 8 concurrent writers). Any transaction that may write must be IMMEDIATE; keep write transactions short; readers outside transactions are never blocked in WAL mode. | `file::memory:` plus a connection pool gives each pooled connection its own empty database; use a temp file (t.TempDir()) in tests or `SetMaxOpenConns(1)` for in-memory. | PRAGMAs and other per-connection state persist on pooled connections (modernc doc), which is why they must be set in the DSN, not with a one-off Exec after Open. | coder/websocket: the default read limit is 32 KiB — call SetReadLimit explicitly (both for envelopes and to reject abuse). Cancelling the context passed to Conn.Read/Write/Ping closes the whole connection abruptly (verified: peer sees EOF, CloseStatus -1), so never pass a shutdown/BaseContext-derived ctx to Read; use the registry + RegisterOnShutdown + Close(StatusGoingAway) pattern. Close() reasons must be <= 125 bytes. Accept requires http.Hijacker, i.e. HTTP/1.1: keep HTTP/2 off on the Go listener (Server.Protocols SetHTTP2(false)) or terminate TLS at a reverse proxy that speaks HTTP/1.1 to the Go process. | Native iOS clients (URLSessionWebSocketTask) send no Origin header; coder/websocket's origin check only applies when Origin is present, so leave AcceptOptions.OriginPatterns nil in production and never set InsecureSkipVerify outside tests (medium confidence on the exact absent-Origin behaviour; verify with the first device test). | http.Server.Shutdown ignores hijacked WebSocket connections entirely; also stop the sweeper goroutines and close the DB after Shutdown returns, otherwise the sweeper may hit a closed DB or a half-closed conn panics on write. Set Docker `stop_grace_period` >= your Shutdown timeout (SIGTERM is the default STOPSIGNAL). | ServeMux patterns: conflicting registrations panic at startup (good — covered by a `TestRoutesRegister` test); `GET` patterns also match HEAD; a method mismatch returns 405 with `Allow` automatically, so do not add your own 405 logic; `{name}` must be a whole segment (`/b_{bucket}` is invalid and panics); a trailing-slash pattern redirects `/x` to `/x/`. | go1.24's os.Root lacks MkdirAll, RemoveAll, Rename, ReadFile, WriteFile (they are in later Go releases and pkg.go.dev shows the newest docs) — write code against the go1.24 method set only: Open, OpenFile, Create, Mkdir, Remove, Stat, Lstat, OpenRoot, FS, Close, Name. | crypto/hkdf's `info` parameter is a Go string; pass `string(bytes)` for binary info — it is byte-exact, no UTF-8 validation. Keep every HKDF info and domain-separation prefix as fixed ASCII constants shared with Swift, and put them in the test vectors so a typo is caught by XCTest. | Ed25519 interop: CryptoKit `Curve25519.Signing.PrivateKey.rawRepresentation` is the 32-byte seed, Go's ed25519.PrivateKey is 64 bytes (seed||pub); convert with ed25519.NewKeyFromSeed / PrivateKey.Seed(). Never use Ed25519ph/ctx (VerifyWithOptions) — CryptoKit has only pure Ed25519. No XEdDSA anywhere, hence separate Ed25519 signing identity + X25519 DH identity (allowed by the X3DH spec). | X25519 low-order / all-zero shared secrets: crypto/ecdh returns an error (and CryptoKit throws); treat as a hard failure, never fall back to the zero secret. Validate that all received public keys are exactly 32 bytes before NewPublicKey. | Replay protection must be atomic: consume the nonce with a single `DELETE ... RETURNING` (or UPDATE used=1 WHERE used=0) BEFORE verifying the signature; checking then deleting in two statements under a deferred transaction is racy. Bind the nonce to the username in the row so a nonce issued for user A cannot be used for user B. Always rebuild the signed message server-side from the submitted fields. | Store only SHA-256(session token) and SHA-256(nonce) in SQLite; a DB leak must not yield usable bearer tokens. | Rate-limit keys: `r.RemoteAddr` is the proxy's address behind Caddy/nginx — only trust X-Forwarded-For when you control the proxy; otherwise one proxy IP shares a bucket. Keyed limiters must be evicted (janitor) or the map grows without bound. | Attachment uploads: wrap r.Body with http.MaxBytesReader and map *http.MaxBytesError to 413; use O_EXCL to avoid id collisions/overwrites; always delete the file before the row (an orphan row is harmless, an orphan file is reconciled at startup); never serve with `Content-Disposition` inline guesses — plain application/octet-stream, Cache-Control: no-store. | APNs is phase-2, but reserve the schema and interface now; when implemented, cache the ES256 JWT and rotate it every 20-60 minutes (both too-frequent and too-old tokens are rejected), and delete device tokens on 410 Unregistered. JWS ES256 signatures are raw r||s (64 bytes), not ASN.1 DER — do not use ecdsa.SignASN1 for the JWT. | The race detector needs cgo; the CGO_ENABLED=0 alpine build stage cannot run `go test -race` — run it in CI on a normal Linux runner (gcc present) with CGO_ENABLED=1, which is fine because the test binary is not what ships. | Docker: distroless `nonroot` runs as uid 65532; the /data volume (SQLite file + WAL/SHM sidecar files + blobs) must be writable by that uid, and the SQLite DB must not live on a network filesystem (WAL requires shared-memory file locking on a local disk).

### threat-model: phase-1 "anti-recording" E2E messenger (Kilit) — assets, adversaries, required iOS/server mechanisms (verified API names), forensic-watermark design, and explicit limits
- [high] ASSETS (what we protect, in priority order): (1) message plaintext and decrypted media in RAM and on screen; (2) long-term identity private keys (Ed25519 signing + X25519 agreement), signed-prekey and one-time-prekey private keys, Double-Ratchet session state (root/chain keys, skipped message keys); (3) per-file media keys and the local DB master key; (4) the ciphertext store at rest (SQLite + blob dir) — leaking it alone is bounded by forward secrecy but still reveals sizes/timestamps; (5) social graph and metadata (who talks to whom, when, how much) — the server necessarily sees this; (6) the per-conversation watermark secret (if leaked, a leaker can scrub/forge the tag); (7) capture-event logs (screenshot/recording events) and their delivery to the counterparty; (8) APNs device token and server auth key. TRUST BOUNDARIES: server = untrusted for confidentiality/integrity, trusted only for availability; network = hostile; iOS kernel/Secure Enclave/Data Protection = trusted; the counterparty's device = cooperative-at-best (every client-enforced rule on the other side is defeatable).
- [high] ADVERSARY: curious/compromised server operator. Sees: usernames, IPs, APNs tokens, prekey bundles, envelope sizes/timing, attachment blob sizes, ack/TTL timing, and the social graph. Must NOT be able to: read plaintext, forge or silently substitute keys undetected, or learn the disappearing-message timer or capture events (all of those travel inside encrypted envelopes as control messages, never as server-visible fields). Design: opaque envelopes only; pad plaintext to 256-byte buckets before AEAD so size leaks are coarse; server stores {recipient, envelope_blob, created_at, expires_at} and nothing else; delete on ack and on TTL; SQLite with PRAGMA secure_delete=ON and WAL checkpointing so deleted ciphertext is not trivially recoverable from the VPS disk; log only hashed/truncated IPs for the rate-limit window; never log usernames together with IPs or envelope ids. Prekey-bundle substitution by the server is the realistic active attack: it is detected only by out-of-band safety-number verification (identity-key fingerprints), so the UI must surface 'safety number changed' and (optionally, strict mode) block sending until acknowledged. The server CAN serve a stale signed prekey or exhaust one-time prekeys (serve none): clients must accept SPK-only sessions (X3DH DH4 optional) but rotate SPK weekly and replenish OPKs, and the server rate-limits bundle fetches per fetcher to slow OPK-depletion. (https://signal.org/docs/specifications/x3dh/)
- [high] ADVERSARY: network attacker (passive/active on the path, hostile Wi-Fi, TLS-intercepting proxy). Defense in depth: E2E (X3DH + Double Ratchet) is the real confidentiality layer; TLS protects metadata and auth tokens. ATS already requires TLS 1.2+ with forward-secret ciphers for URLSession/WebSocket. Pin the server certificate chain declaratively with the Info.plist key NSPinnedDomains (iOS 14+): NSPinnedDomains -> {"api.example": {NSIncludesSubdomains: true, NSPinnedCAIdentities: [{"SPKI-SHA256-BASE64": "<base64 of SHA-256 over the CA's SubjectPublicKeyInfo>"}]}}. For a Let's Encrypt VPS, pin the ISRG root/intermediate SPKI (CA pinning), not the 90-day leaf. Alternative (if you need runtime rotation): implement urlSession(_:didReceive:completionHandler:) on URLSessionDelegate and compare SecCertificate SPKI hashes. Signed-challenge auth must bind a server nonce (32 random bytes, single-use, 60 s expiry) and a domain-separation prefix ('kilit-auth-v1') so signatures cannot be replayed or cross-protocol reused; the Ed25519 identity key signs it (Curve25519.Signing.PrivateKey.signature(for:)). (https://developer.apple.com/documentation/bundleresources/information-property-list/nsapptransportsecurity/nspinneddomains)
```
<key>NSAppTransportSecurity</key><dict><key>NSPinnedDomains</key><dict><key>kilit.example.com</key><dict><key>NSIncludesSubdomains</key><true/><key>NSPinnedCAIdentities</key><array><dict><key>SPKI-SHA256-BASE64</key><string>BASE64_SPKI_HASH</string></dict></array></dict></dict></dict>
```
- [high] ADVERSARY: device thief WITHOUT the passcode (or forensic extraction, BFU/AFU). iOS Data Protection class Complete (NSFileProtectionComplete) wraps per-file keys with a class key derived from the passcode+UID; Apple's Platform Security guide states the decrypted Complete class key is discarded shortly after lock (10 seconds, if Require Password is Immediately), after which files are unreadable until the user authenticates. Design: (a) enable the Data Protection capability so the entitlement com.apple.developer.default-data-protection = NSFileProtectionComplete makes every file the app creates default to Complete; (b) additionally write explicitly with Data.WritingOptions.completeFileProtection and set FileAttributeKey.protectionKey = FileProtectionType.complete on the SQLite main file and its -wal/-shm/-journal siblings (set it on the containing directory too so new files inherit); (c) close the DB and zero in-memory keys on UIApplication.protectedDataWillBecomeUnavailableNotification and reopen on protectedDataDidBecomeAvailableNotification, because handles to Complete-class files fail after lock; (d) Keychain items for identity/prekey/DB-master keys use kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly (never migrates, deleted if the passcode is removed, cannot be created on a device without a passcode - which is exactly the fail-closed behaviour we want); (e) refuse registration on devices with no passcode: LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error:) returns false with LAError.Code.passcodeNotSet. A phone with NO passcode has no meaningful at-rest protection regardless of what the app does — say so in onboarding. Trade-off accepted for phase 1: with Complete protection the app cannot decrypt pushes while locked (no Notification Service Extension); messages are fetched when the app is opened. If an NSE is added later, ratchet state must move to .completeUntilFirstUserAuthentication / kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, which weakens AFU-extraction resistance. (https://developer.apple.com/documentation/security/ksecattraccessiblewhenpasscodesetthisdeviceonly)
```
try data.write(to: url, options: [.atomic, .completeFileProtection])
try FileManager.default.setAttributes([.protectionKey: FileProtectionType.complete], ofItemAtPath: dbPath)
// Keychain attribute
kSecAttrAccessible as String: kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
// Passcode check
var err: NSError?; let ok = LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: &err)
if !ok, (err as? LAError)?.code == .passcodeNotSet { /* block registration */ }
```
- [high] ADVERSARY: device thief WITH the passcode (shoulder-surfed, coerced). Data Protection is fully unlocked for them. The only extra barrier the app can add is an app-level lock bound to biometrics via the Secure Enclave: wrap the DB master key with a SecureEnclave.P256.KeyAgreement.PrivateKey created with SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, [.privateKeyUsage, .biometryCurrentSet], &err). ECIES-style wrap: generate one software P256.KeyAgreement.PrivateKey, compute sharedSecretFromKeyAgreement with the SE key's publicKey, HKDF-SHA256 -> AES.GCM key, seal the 32-byte master key, store {ephemeral public key, sealed box, SE key dataRepresentation} in Keychain; unwrap requires Face ID/Touch ID (passcode fallback impossible with .biometryCurrentSet; enrolling a new face/finger invalidates the key, i.e. data is lost by design). Note: CryptoKit's Secure Enclave support is P-256 only, so the Curve25519 identity keys themselves cannot live in the SE; they live in Keychain (WhenPasscodeSetThisDeviceOnly) encrypted under the SE-wrapped master key. Offer a less strict option (.biometryAny or .userPresence) and document the data-loss trade-off. Complementary OS feature: iOS 17.3 Stolen Device Protection (user-enabled) requires biometrics and adds a 1-hour delay for biometric/passcode changes away from familiar locations. Disappearing messages and a local 'panic wipe' (delete DB + Keychain items + deregister push token) bound the exposure window. Remote wipe is out of phase 1. (https://developer.apple.com/documentation/cryptokit/secureenclave/p256/keyagreement/privatekey)
```
var cfErr: Unmanaged<CFError>?
let ac = SecAccessControlCreateWithFlags(kCFAllocatorDefault, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, [.privateKeyUsage, .biometryCurrentSet], &cfErr)!
let ctx = LAContext(); ctx.localizedReason = "Unlock Kilit"
let seKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(compactRepresentable: true, accessControl: ac, authenticationContext: ctx)
let eph = P256.KeyAgreement.PrivateKey()
let ss = try eph.sharedSecretFromKeyAgreement(with: seKey.publicKey)
let wrapKey = ss.hkdfDerivedSymmetricKey(using: SHA256.self, salt: Data(), sharedInfo: Data("kilit-dbkey-wrap-v1".utf8), outputByteCount: 32)
let sealed = try AES.GCM.seal(masterKeyData, using: wrapKey)
// persist: seKey.dataRepresentation, eph.publicKey.rawRepresentation, sealed.combined
```
- [high] ADVERSARY: malicious contact photographing the screen with a second phone (the 'analog hole'). CANNOT BE DEFENDED. No software control on the viewer's phone can stop a second camera; Apple DTS says the same ('Imagine a case where the user uses a second device to take a photo of the screen and you can't stop the capture'). Everything we do here is deterrence, attribution, and shrinking the exposed surface: hold-to-reveal (content rendered only during an active long-press, so the leaker needs two hands/two devices and gets a short window), partial reveal (reveal one message or one slice of an image at a time so a single photo captures less), disappearing timers (bound how long the content exists), no copy/forward/save/share UI, the per-viewer forensic watermark (attribution after the fact), and the opt-in flicker mode (deterrent, degrades a fraction of photos, never a guarantee). The product copy must say this plainly; do not market 'cannot be recorded'. (https://developer.apple.com/forums/thread/838583)
- [high] ADVERSARY: malicious contact using iOS screen recording, AirPlay/mirroring, QuickTime/USB mirroring, or (iOS 26+) remote-control screen sharing. SUPPORTED mechanism: capture state. iOS 17+: UITraitCollection.sceneCaptureState (enum UISceneCaptureState { case active, inactive, unspecified }) and SwiftUI @Environment(\.isSceneCaptured) (iOS 17+, 'actively being cloned to another destination (like during AirPlay) or is being mirrored or recorded'). Legacy: UIScreen.isCaptured + UIScreen.capturedDidChangeNotification (iOS 11+, works on iOS 17-26, formally deprecated in iOS 27 in favour of sceneCaptureState). UIScreen.main is deprecated in iOS 26: obtain the screen via view.window?.windowScene?.screen. Design: when captured == true, replace every message/media view with a placeholder ('Recording detected') via .privacySensitive() on content views plus .redacted(reason: .privacy) at the root, stop the protected media viewer, send an encrypted control message {type: capture, kind: recording_started|recording_stopped} to the counterparty, and append to the local encrypted event log. Honest limits: the state flips asynchronously (a few frames of content can be captured before the flip, so content shown at the moment recording starts is already lost), and a jailbroken device or a Mac screen-recording a mirrored iPhone via private paths may not set it. (https://developer.apple.com/documentation/swiftui/environmentvalues/isscenecaptured)
```
// SwiftUI (iOS 17+)
@Environment(\.isSceneCaptured) private var isSceneCaptured
var body: some View { MessageList().privacySensitive().redacted(reason: isSceneCaptured ? .privacy : []) }
// UIKit probe (iOS 17+)
let captured = view.traitCollection.sceneCaptureState == .active
registerForTraitChanges([UITraitSceneCaptureState.self]) { (self: Self, _: UITraitCollection) in self.updateCaptureState() }
// Legacy fallback (works iOS 17-26)
NotificationCenter.default.addObserver(forName: UIScreen.capturedDidChangeNotification, object: nil, queue: .main) { _ in /* re-read isCaptured */ }
```
- [high] SCREENSHOTS: there is NO public API to prevent a screenshot. UIApplication.userDidTakeScreenshotNotification (iOS 7+, not deprecated; 'This notification posts after the screenshot is taken', no userInfo) only tells you after the fact, and only while the app is in the foreground. Design: on this notification, (a) send an encrypted control message {type: capture, kind: screenshot, ts} to the counterparty, (b) append to the local event log, (c) optionally auto-hide the conversation and require re-authentication (configurable). The 'secure UITextField layer' blanking technique (host content inside the private canvas subview of a UITextField with isSecureTextEntry = true so the compositor blacks it out in screenshots/recordings) is UNDOCUMENTED and explicitly discouraged by Apple DTS ('relying on it that way is using it outside its intended purpose'); developers report it 'no longer works in iOS 18' and causes hangs/black transitions in other setups. Treat it strictly as best-effort hardening that must be feature-flagged, verified by the owner on the actual target iOS version, and never relied upon by any other control. The documented property of isSecureTextEntry is only: 'disables the user's ability to copy the text in the view and, in some cases, also disables the user's ability to record and broadcast the text in the view'. (https://developer.apple.com/forums/thread/767320)
```
NotificationCenter.default.addObserver(forName: UIApplication.userDidTakeScreenshotNotification, object: nil, queue: .main) { _ in captureEvents.record(.screenshot) }
// Secure-layer hosting (undocumented, best-effort, flag-gated):
let tf = UITextField(); tf.isSecureTextEntry = true; tf.isUserInteractionEnabled = false
// iOS 15-17: the first subview is the private _UITextLayoutCanvasView; add content there
if let canvas = tf.subviews.first(where: { String(describing: type(of: $0)).contains("CanvasView") }) { canvas.addSubview(contentView) }
```
- [medium] ADVERSARY: jailbroken (or developer-mode-tampered) viewer device. All client-side guarantees are void: a tweak can hook the app, dump RAM (plaintext, keys, ratchet state), disable the secure layer, record the screen through private APIs, and suppress capture-event messages, disappearing-message deletion and screenshot notifications. Design position: do not pretend to defend. Optional light heuristics (fileExists at /Applications/Cydia.app, /Library/MobileSubstrate/MobileSubstrate.dylib, /private/var/lib/apt, a write test outside the sandbox, canOpenURL(cydia://) with LSApplicationQueriesSchemes) may show a warning to the local user but must never be treated as a security control, and must never block (false positives, trivially bypassed). The sound mechanism for the SERVER to gate registration on an unmodified app on a genuine device is App Attest (DCAppAttestService, iOS 14+); it requires the Go server to validate Apple's attestation object/receipt and is deferred to phase 2. Note that Apple does not position App Attest as jailbreak detection either.
- [high] ADVERSARY: iCloud/iTunes (Finder) backup leakage and device-to-device migration. Three independent controls: (1) exclude the app's data root from backups with URLResourceValues.isExcludedFromBackup = true (iOS 8+, settable; Apple warns it can be reset by 'operations commonly made to user documents' — we never use document APIs on these files, and we re-apply it on every launch); (2) all files are Complete-protection, so even a backup that did include them is passcode/UID bound (local encrypted backups still decrypt with the backup password on the same device class — hence control 1 is required, not optional); (3) Keychain items use ...ThisDeviceOnly accessibility ('Items with this attribute never migrate to a new device. After a backup is restored to a new device, these items are missing') and kSecAttrSynchronizable must stay false so nothing enters iCloud Keychain. Consequence to document: there is no account recovery in phase 1 — a new phone means a new identity key and a 'safety number changed' warning for contacts; this is the intended fail-closed behaviour. (https://developer.apple.com/documentation/foundation/urlresourcevalues/isexcludedfrombackup)
```
var dir = appSupportURL.appendingPathComponent("Kilit", isDirectory: true)
try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.protectionKey: FileProtectionType.complete])
var rv = URLResourceValues(); rv.isExcludedFromBackup = true
try dir.setResourceValues(rv)  // note: setResourceValues is mutating -> `var dir`
```
- [high] ADVERSARY: push-notification content leakage (APNs sees the payload; the lock screen, Notification Center, Apple Watch, Mac mirroring, and iOS 18 Apple Intelligence notification summaries display whatever text is in it; the OS keeps delivered notifications). Design: the APNs payload carries NO sender, NO conversation id, NO ciphertext — only a localized generic alert and a fixed thread id, e.g. {"aps":{"alert":{"loc-key":"PUSH_NEW_MESSAGE"},"sound":"default","thread-id":"kilit"}}; the app fetches real envelopes over WebSocket/REST on foreground. Register a UNNotificationCategory with hiddenPreviewsBodyPlaceholder (iOS 11+) so that even if the user enables previews the text is generic; the app cannot force Settings > Notifications > Show Previews = Never, so onboarding should recommend it. Never build local notifications (UNMutableNotificationContent) containing message text. Server stores the APNs token in the user row, overwrites it on re-registration, and deletes it on logout/wipe; APNs tokens are per-app-per-device and must not be logged. Decrypting inside a Notification Service Extension (mutable-content:1) is explicitly out of phase 1 because it would require ratchet state readable while locked (see Data Protection trade-off). (https://developer.apple.com/documentation/usernotifications/unnotificationcategory/hiddenpreviewsbodyplaceholder)
```
let cat = UNNotificationCategory(identifier: "KILIT_MSG", actions: [], intentIdentifiers: [], hiddenPreviewsBodyPlaceholder: "New message", options: [])
UNUserNotificationCenter.current().setNotificationCategories([cat])
```
- [high] ADVERSARY: clipboard (other apps reading UIPasteboard, Universal Clipboard/Handoff to the user's Mac, clipboard-manager apps). Design: message bubbles and the protected viewer offer no Copy/Share/Save/Drag actions at all: SwiftUI Text is non-selectable by default (do not add .textSelection(.enabled)), no contextMenu with copy, no .onDrag, no UIActivityViewController, no PHPhotoLibrary writes. If a deliberate 'copy this message' action is ever added, it must use setItems(_:options:) with UIPasteboard.OptionsKey.expirationDate (iOS 10+, 'the time and date that you want the system to remove the pasteboard items') set to ~60 s and .localOnly = true ('should not be available to other devices through the Handoff feature'). Pasting INTO the composer is allowed (user's own clipboard). (https://developer.apple.com/documentation/uikit/uipasteboard/optionskey/expirationdate)
```
UIPasteboard.general.setItems([[UTType.utf8PlainText.identifier: text]], options: [.expirationDate: Date().addingTimeInterval(60), .localOnly: true])
```
- [high] ADVERSARY: keyboard learning (QuickType dynamic lexicon, autocorrect, inline predictions, third-party keyboards that may phone home, Writing Tools/Apple Intelligence, dictation audio). Build the composer as a UIViewRepresentable around UITextView (SwiftUI has modifiers only for autocorrection/capitalization, not for inlinePredictionType) and set: autocorrectionType = .no, spellCheckingType = .no, smartQuotesType = .no, smartDashesType = .no, smartInsertDeleteType = .no, inlinePredictionType = .no (iOS 17+), textContentType = nil, and if #available(iOS 18) writingToolsBehavior = .none (iOS 18+; UIWritingToolsBehavior.none = 'prevent the writing tools from modifying the text'). Block custom keyboards app-wide by returning false for UIApplication.ExtensionPointIdentifier.keyboard in application(_:shouldAllowExtensionPointIdentifier:) — in a SwiftUI app this needs @UIApplicationDelegateAdaptor. Honest limits: none of the trait flags is documented to stop the system keyboard from learning typed words; the only documented 'no copy / no record' behaviour is isSecureTextEntry, which masks the text with bullets and is unusable for chat. Optional 'hardened composer' mode: isSecureTextEntry = true on the input view with the app drawing its own plaintext preview label above it (the app can still read textView.text) — this also forces the system keyboard and disables dictation/QuickType. Dictation (mic key) sends audio to Apple or on-device recognition; only secure entry removes the key. (https://developer.apple.com/documentation/uikit/uitextinputtraits/inlinepredictiontype)
```
func application(_ application: UIApplication, shouldAllowExtensionPointIdentifier id: UIApplication.ExtensionPointIdentifier) -> Bool { id != .keyboard }
// composer
tv.autocorrectionType = .no; tv.spellCheckingType = .no; tv.smartQuotesType = .no; tv.smartDashesType = .no; tv.smartInsertDeleteType = .no
tv.inlinePredictionType = .no            // iOS 17+
if #available(iOS 18.0, *) { tv.writingToolsBehavior = .none }
```
- [high] ADVERSARY: Spotlight indexing and Siri/App Shortcut suggestions (on-device index, Lock-Screen suggestions, Siri 'read my messages', Share-sheet suggestions, iOS 18+ on-screen awareness). iOS indexes app content only when the app contributes it, so the control is abstention: never call CSSearchableIndex, never create NSUserActivity for conversations (no SwiftUI .userActivity(_:) modifier, no NSUserActivityTypes in Info.plist), never donate INSendMessageIntent/App Intents or adopt SiriKit messaging, never implement App Shortcuts, never expose message content through Transferable to the system. If an NSUserActivity is ever needed (e.g. Handoff for a settings screen), set isEligibleForSearch = false, isEligibleForPublicIndexing = false, isEligibleForPrediction = false (documented default false) and isEligibleForHandoff = false (default is true). Also avoid QLPreviewController/UIDocumentInteractionController for media: QuickLook writes thumbnails to a system cache outside our control — use our own viewer. (https://developer.apple.com/documentation/foundation/nsuseractivity/iseligibleforprediction)
```
let act = NSUserActivity(activityType: "com.kilit.settings")
act.isEligibleForSearch = false; act.isEligibleForPublicIndexing = false; act.isEligibleForPrediction = false; act.isEligibleForHandoff = false
```
- [high] ADVERSARY: app-switcher snapshot (UIKit captures the scene image 'shortly after [sceneDidEnterBackground] returns' for the app switcher; the snapshot file persists on disk and is shown in the multitasking UI and in the Full-Screen app preview). Design: install an opaque cover synchronously in sceneWillResignActive(_:) (called for Control Center/notification pulls/incoming calls and before backgrounding) and remove it in sceneDidBecomeActive(_:); implement this in a UIKit UIWindowSceneDelegate (via @UIApplicationDelegateAdaptor + UISceneDelegate class name in Info.plist/UIApplicationSceneManifest) because adding a UIView to the key window is synchronous, whereas a SwiftUI @Environment(\.scenePhase) state change renders on a later run-loop pass and is a race. Keep the SwiftUI path too (scenePhase != .active -> .redacted(reason: .privacy)) as belt and braces. Do not adopt state restoration (no stateRestorationActivity, no @SceneStorage of drafts); if it is ever added, call UIApplication.shared.ignoreSnapshotOnNextApplicationLaunch() during state saving. Set UIApplicationSupportsMultipleScenes = false and ship iPhone-only (TARGETED_DEVICE_FAMILY = 1) to avoid Stage Manager/side-by-side captures on iPad. (https://developer.apple.com/documentation/uikit/uiscenedelegate/scenedidenterbackground(_:))
```
func sceneWillResignActive(_ scene: UIScene) {
  guard let ws = scene as? UIWindowScene, let w = ws.keyWindow else { return }
  let cover = UIView(frame: w.bounds); cover.backgroundColor = .systemBackground; cover.tag = 0xC0FE; w.addSubview(cover)
}
func sceneDidBecomeActive(_ scene: UIScene) { (scene as? UIWindowScene)?.keyWindow?.viewWithTag(0xC0FE)?.removeFromSuperview() }
```
- [high] ADVERSARY: on-device leftovers — image/URL caches, temp files, Photos picker spools, Live Text, logs, crash dumps, RAM after use. Design for the encrypted media pipeline: networking uses URLSessionConfiguration.ephemeral with urlCache = nil and requestCachePolicy = .reloadIgnoringLocalCacheData so blobs never hit Caches/; encrypted blobs are written with .completeFileProtection into the backup-excluded dir; per-file key = 32 random bytes (SymmetricKey(size: .bits256)), ChaChaPoly.seal in 1 MiB chunks with a 12-byte nonce = 4-byte random prefix || 8-byte chunk counter and chunk index as AAD, so large files never need to be whole in RAM; decrypt into Data and build the image with CGImageSourceCreateWithData(data, [kCGImageSourceShouldCache: false]) — never UIImage(contentsOfFile:) and never a file round-trip; strip EXIF/GPS before encryption by re-encoding (UIImage.jpegData(compressionQuality:) or CGImageDestination with no metadata dictionary); pick photos with SwiftUI PhotosPicker + loadTransferable(type: Data.self) and camera via UIImagePickerController(.camera) (image delivered in memory, not saved to Photos); clear FileManager.default.temporaryDirectory on launch and on background; never add ImageAnalysisInteraction (Live Text); zero decrypted buffers with withUnsafeMutableBytes { memset_s } when the viewer closes (CryptoKit SymmetricKey storage is zeroed on deallocation, but plain Data is not); log only with Logger and privacy: .private; no third-party crash/analytics SDKs. Video playback of encrypted files is deferred to phase 2 (needs AVAssetResourceLoader).
```
let cfg = URLSessionConfiguration.ephemeral; cfg.urlCache = nil; cfg.requestCachePolicy = .reloadIgnoringLocalCacheData
let key = SymmetricKey(size: .bits256)
let box = try ChaChaPoly.seal(chunk, using: key, nonce: try ChaChaPoly.Nonce(data: noncePrefix + counterBE), authenticating: aad)
guard let src = CGImageSourceCreateWithData(plain as CFData, [kCGImageSourceShouldCache: false] as CFDictionary), let cg = CGImageSourceCreateImageAtIndex(src, 0, nil) else { ... }
```
- [medium] ADVERSARY: accessibility and system features that re-emit content: VoiceOver/Speak Screen read messages aloud (recordable with any microphone), Screen Mirroring to TV, Back Tap/AssistiveTouch screenshot (same path as any screenshot), iOS 18.2+ Visual Intelligence 'ask about screenshot' (it is a screenshot), Guided Access (harmless). Design: do not break accessibility by default; offer a 'Mute assistive speech in protected view' option that sets accessibilityElementsHidden = true on the protected content and warn that it degrades VoiceOver. Nothing else is controllable; document it.
- [high] DISAPPEARING MESSAGES threat notes: the timer is a per-conversation setting negotiated inside the encrypted channel (control message), so the server never learns it. Enforcement is cooperative: our client deletes ciphertext rows (and the media blob + key) when the timer elapses after the message was first displayed, and purges on next launch if the app was not running (no reliable background execution; acceptable because at-rest data is Complete-protected). The server deletes an envelope on the recipient's ack (and on a hard TTL, e.g. 14 days, if never acked). A recipient with a modified client can keep everything, and both parties can photograph the screen — disappearing messages reduce accidental exposure and device-seizure exposure, they do not bind the counterparty. Deleted rows: enable PRAGMA secure_delete=ON on the iOS SQLite DB as well so plaintext-free but still-sensitive ciphertext/metadata pages are overwritten.
- [high] IDENTITY/PROTOCOL threat notes (phase 1, 1:1 only): usernames are first-come (squatting/impersonation is possible), so identity = the Ed25519 key, and the safety number (fingerprint over both parties' identity public keys, e.g. Signal-style iterated SHA-512 rendered as 60 digits, plus a QR) is the only binding; show it, make key changes loud. CryptoKit has no XEdDSA/Ed25519-to-X25519 conversion, so unlike Signal the bundle carries TWO long-term keys: IK_sign (Curve25519.Signing) and IK_dh (Curve25519.KeyAgreement); IK_sign signs IK_dh and each signed prekey; the safety number covers IK_sign only if IK_dh is bound to it by that signature — the Go reference and the Swift implementation must verify both signatures before X3DH. X3DH per spec: DH1 = DH(IK_A, SPK_B), DH2 = DH(EK_A, IK_B), DH3 = DH(EK_A, SPK_B), DH4 = DH(EK_A, OPK_B) if present; SK = KDF(F || DH1 || DH2 || DH3 [|| DH4]) with F = 32 bytes of 0xFF for Curve25519 and AD = Encode(IK_A) || Encode(IK_B); then Double Ratchet (root/sending/receiving chains, X25519 DH ratchet, HKDF-SHA256 root KDF, HMAC-SHA256 chain KDF, AEAD = ChaChaPoly or AES-GCM with the header as AAD, MAX_SKIP ~1000 skipped keys, skipped keys stored encrypted and bounded). Compromise of a device yields past messages still on disk and the ability to read until the next DH ratchet step; forward secrecy protects messages already deleted. Replay: the (dh, pn, n) header plus one-time message keys make replays undecryptable; the server-level dedupe by envelope id is a bonus. Unknown-key-share/identity-misbinding is prevented by AD including both identity keys. (https://signal.org/docs/specifications/x3dh/)
```
let ikSign = Curve25519.Signing.PrivateKey(); let ikDH = Curve25519.KeyAgreement.PrivateKey()
let sig = try ikSign.signature(for: Data("kilit-ikdh-v1".utf8) + ikDH.publicKey.rawRepresentation)
let ss = try ekA.sharedSecretFromKeyAgreement(with: spkB)
let sk = HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: f + dh1 + dh2 + dh3 + dh4), salt: Data(repeating: 0, count: 32), info: Data("kilit-x3dh-v1".utf8), outputByteCount: 32)
```
- [high] CAPTURE-EVENT NOTIFICATION design (feature 1, 'notify both parties, log'): events {screenshot, recording_started, recording_stopped, airplay_started} are sent as ordinary ratchet-encrypted control messages so the server learns nothing, are shown inline in the conversation on both sides ('Ayşe took a screenshot'), and are appended to the local encrypted event log with a monotonic counter so a tampering client cannot silently drop one without a gap being visible to its own user. Honest limit: the counterparty's modified client can simply not send the event; the sender's UI must not imply 'no screenshot was taken' — only 'no screenshot was reported'.
- [medium] FORENSIC WATERMARK — what survives a phone photo of an OLED iPhone screen. Geometry: an iPhone 15 panel is ~460 ppi (1179 px over ~65 mm). A 12 MP phone camera (26 mm-equivalent, ~69 deg horizontal FOV) at 25-40 cm resolves the 65 mm screen width into roughly 470-760 camera pixels, i.e. 0.4-0.65 camera px per screen px (up to ~1.3 in 48 MP mode, ~0.3 in portrait framing). Everything below ~6-8 screen px is therefore below Nyquist and is converted into moire (beat patterns between the OLED subpixel grid and the Bayer sensor), then smeared by demosaicing and luma noise reduction. JPEG then applies 4:2:0 chroma subsampling (chroma resolution halved) and 8x8 DCT quantization; social-media re-encoding downsizes to ~1280-2048 px long edge (another 0.3-0.5x). PWM dimming on iPhone OLEDs (~240-480 Hz) plus rolling shutter produce horizontal luminance bands at fast exposures. Auto-exposure/white balance/Smart HDR make ABSOLUTE luminance unreliable but preserve (and often enhance) local relative contrast. Conclusions: micro-text (<= ~6 pt, i.e. glyph strokes 1-3 px) is destroyed; chroma-only marks are destroyed; absolute-level codes are destroyed; LARGE luminance features (>= ~24 pt = 72 px @3x, i.e. 25-90 camera px before downscale, >= 8 px after a 0.3x re-encode) with a LOCAL reference survive.
- [medium] FORENSIC WATERMARK — recommended practical design. Payload 16 bits = 8-bit viewer tag + 4-bit time nibble + 4-bit checksum. viewer tag = HKDF-SHA256(ikm: WS, info: 'kilit-wm-v1' || viewerUserID)[0] where WS is a per-conversation watermark secret derived from the X3DH SK (HKDF info 'kilit-wm-secret-v1'); time nibble = (UTC day number mod 16) so the leak can be dated to the day within a 16-day cycle; checksum = CRC-4 (poly 0x3) over the 12 payload bits. Layout: a tile of 6x6 cells, cell size 28 pt (84 px @3x), tile 168 pt, tiled with a per-viewing-session random phase offset; the 20 border cells carry a fixed sync sequence with no rotational symmetry (so orientation/mirroring is recovered), the inner 4x4 = 16 data cells. Bit encoding is Manchester-within-cell: each cell is split into LEFT and RIGHT halves; bit 1 = left half +d, right half -d; bit 0 = the reverse. The within-cell differential makes decoding invariant to exposure, gradients, vignetting and, because the split is horizontal (left/right), to the horizontal PWM/rolling-shutter bands. Amplitude d = 4% of the display code value (about +-5/255 at mid-grey), edges softened with a Gaussian of sigma = cell/6 so no hard edge is visible; rendered as a SwiftUI Canvas/CALayer overlay with .allowsHitTesting(false) in .overlay blend mode over the WHOLE content area, inside the secure layer when that is active. Do NOT draw it on pure black: specify a mid-tone surface (sRGB ~90-170, e.g. bubbles #4A4A4F on a #2C2C30 card) behind text and behind image letterboxing; a 4% code-value delta on near-black is ~1 code value and vanishes in sensor noise. Capacity/robustness: 16 bits with 2 tiles across a 393-pt screen and ~4 down gives ~8 full copies for majority voting; a crop containing any single complete tile decodes. Expected camera-side SNR: sensor noise sigma ~1-2 code values at ISO 100-400; averaging a half-cell of >= 10x20 camera px improves SNR by >14x, so a 5-code-value signal survives JPEG Q75 (DC quantization ~1 level) and a 0.3x social-media resize. Text ink inside a cell swamps the signal: the decoder rejects cells whose variance exceeds a threshold and relies on redundancy. A faint, cropped-away-able VISIBLE watermark (viewer name at 8-10% alpha, diagonal) is a cheap complement and a stronger deterrent for casual leakers.
```
// tag derivation
let ws = HKDF<SHA256>.deriveKey(inputKeyMaterial: sk, salt: Data(), info: Data("kilit-wm-secret-v1".utf8), outputByteCount: 32)
let tag = HKDF<SHA256>.deriveKey(inputKeyMaterial: ws, salt: Data(), info: Data("kilit-wm-v1".utf8) + viewerID, outputByteCount: 1).withUnsafeBytes { $0[0] }
let day = UInt8((UInt64(Date().timeIntervalSince1970) / 86_400) % 16)
let payload16 = UInt16(tag) << 8 | UInt16(day) << 4 | UInt16(crc4(UInt16(tag) << 4 | UInt16(day)))
```
- [medium] FORENSIC WATERMARK — decoder and test plan. Decoder is an offline Go tool in the server repo (cmd/wmdecode, pure Go, image/jpeg + image/png): inputs a photo and either the 4 screen-corner coordinates or an automatic bright-quadrilateral detection; perspective-warps to a canonical 1179x2556 grid; converts to luma; high-pass filters (subtract Gaussian blur with sigma = one cell) to remove exposure gradients; integrates left/right half-cell means; searches tile phase (and small scale/rotation) by correlating the 20-cell sync sequence; votes each data bit across all tiles; checks CRC-4; outputs {tag, day} and a confidence. Attribution step: the sender computes the expected tag for each contact in the conversation (both parties know WS) and matches. Owner acceptance test on the Mac/iPhone: render the test pattern screen, photograph with a second iPhone at 25/40/70 cm, straight and at 30 degrees, in a dark and a lit room, with and without 2x zoom; pass each photo through WhatsApp/Instagram/iMessage (re-encode) and decode. Target: >= 95% correct decode at <= 40 cm straight-on after one social-media re-encode, and no false decodes (CRC + sync) on photos of other screens. Tune d (3-6% code value) and cell size (24-32 pt) from the results; these two numbers are the only calibration knobs.
- [high] FORENSIC WATERMARK — honest limits. (1) It is attribution, not proof: in a 1:1 conversation both parties can compute WS and the tag, so party A could render B's tag and 'leak' it to frame B; the mark shows which account's device rendered the photographed frame only if the parties are not adversarial toward each other in that way; against a third-party over-the-shoulder photographer it identifies whose screen was shot. (2) A determined leaker can remove it: median/Gaussian filtering at the cell scale, retyping the text, heavy crops that miss a full tile, extreme angles, or very dark/noisy photos; a 16-bit code with 8 copies tolerates moderate degradation, not deliberate scrubbing. (3) 8-bit tags collide (1/256 per contact); the time nibble and CRC reduce random matches but it remains probabilistic evidence. (4) The mark is useless against screen recording/screenshots — those are blanked by the capture-state path or are pixel-perfect copies where any mark survives trivially anyway. (5) It is visible as a faint texture at 4% in uniform areas; users must be told it exists (it also acts as a deterrent).
- [high] FLICKER (temporal sub-frame) mode — honest physics and safety gating. Implementation: pre-render two complementary CGImages (content split so that each sub-frame alone is unreadable, e.g. alternating glyph fragments on a checkerboard), swap CALayer.contents in a CADisplayLink callback with CATransaction.setDisableActions(true); request the panel rate with displayLink.preferredFrameRateRange = CAFrameRateRange(minimum: 120, maximum: 120, preferred: 120) (iOS 15+, 'best effort'; Low Power Mode, thermal state and accessibility settings can lower it); on iPhone, rates above 60 Hz are ignored unless Info.plist has CADisableMinimumFrameDurationOnPhone = true (iOS 15+); read the panel rate from view.window?.windowScene?.screen.maximumFramesPerSecond (UIScreen.main is deprecated in iOS 26). Why it is only a deterrent: a 120 Hz panel alternates sub-frames at 60 Hz; a camera exposing >= 1/60 s integrates both and records the full image at reduced contrast; typical auto-exposure for a bright screen in a dim room lands at 1/60-1/250 s, so some photos show one sub-frame or rolling-shutter stripes, but a burst or a video followed by frame averaging recovers everything; on a 60 Hz panel the alternation is 30 Hz and almost every photo integrates both frames. Safety: 30 Hz alternation sits inside the 3-50 Hz photosensitive band, so REFUSE to enable on panels with maximumFramesPerSecond < 120; force-off when UIAccessibility.isReduceMotionEnabled or ProcessInfo.processInfo.isLowPowerModeEnabled; monitor displayLink.timestamp deltas and abort the mode if frames are dropped (a dropped frame shows one sub-frame twice = a visible low-frequency flash, which is the real seizure risk); keep luminance modulation depth modest; default OFF, behind an explicit photosensitivity warning with a confirm step. Phase-1 scope is 'experimental', and the UI must say 'may reduce the quality of some camera photos; does not prevent recording'. (https://developer.apple.com/documentation/bundleresources/information-property-list/cadisableminimumframedurationonphone)
```
let link = CADisplayLink(target: self, selector: #selector(tick(_:)))
link.preferredFrameRateRange = CAFrameRateRange(minimum: 120, maximum: 120, preferred: 120)
link.add(to: .main, forMode: .common)
// Info.plist: <key>CADisableMinimumFrameDurationOnPhone</key><true/>
guard (view.window?.windowScene?.screen.maximumFramesPerSecond ?? 60) >= 120, !UIAccessibility.isReduceMotionEnabled else { disableFlicker() }
```
- [high] HOLD-TO-REVEAL and PARTIAL REVEAL threat notes: render the real content only while a long-press gesture is active (SwiftUI .onLongPressGesture(minimumDuration:perform:onPressingChanged:) or a UILongPressGestureRecognizer with .began/.ended) and blur/hide otherwise; the blurred placeholder must be a pre-rendered opaque placeholder (not a live .blur(radius:) of the real text, which can be partially deblurred and which still exists in the view tree for accessibility and snapshots); partial reveal exposes one message (or one horizontal band of an image, ~1/4) at a time around the finger. Threat value: forces the camera-wielding leaker to hold the phone with one hand while photographing with another device, and limits how much content any single photo contains; it does nothing against a patient leaker or a tripod. Screenshot while pressing: the secure layer (if working) blanks it; otherwise the screenshot notification fires.
- [high] SERVER-SIDE abuse threats the Go design must cover: username enumeration (rate-limit lookups per IP and per account, constant-time 'not found' responses), registration flooding (per-IP token bucket + optional invite codes), prekey exhaustion (per-fetcher limits, SPK-only fallback), envelope flooding/storage DoS (per-recipient queue caps and per-sender rate, max envelope size, blob size cap and TTL), blob enumeration (random 128-bit blob ids, download requires an auth-bound capability token issued with the upload), replay of the auth challenge (single-use nonce table with expiry), WebSocket hijack (auth before upgrade or first frame, idle timeouts, per-connection rate), and log/metadata minimisation (no bodies, no tokens, truncated IPs, retention <= 24 h). Server validates SPK/IK_dh signatures on upload to reject garbage bundles, but clients must still verify them because the server is untrusted.
- [medium] iOS 17 trait-change observation: the iOS 17 API is registerForTraitChanges(_:handler:) on UITraitChangeObservable (UIView/UIViewController/UIWindow), closure typed (self: Self, previousTraitCollection: UITraitCollection), returning a UITraitChangeRegistration that unregisterForTraitChanges(_:) cancels; traitCollectionDidChange(_:) is deprecated in iOS 17. The trait class for capture state is spelled UITraitSceneCaptureState (not fetched directly; name inferred from the UITraitHorizontalSizeClass naming convention and WWDC23 material — confirm in Xcode autocomplete). The verified, zero-risk alternatives for iOS 17 are SwiftUI @Environment(\.isSceneCaptured) and UIScreen.capturedDidChangeNotification, so the design should prefer those. (https://developer.apple.com/documentation/uikit/adapting-your-app-when-traits-change)
```
registerForTraitChanges([UITraitSceneCaptureState.self]) { (self: Self, _: UITraitCollection) in self.captureChanged(self.traitCollection.sceneCaptureState == .active) }
```
- [high] WHAT CANNOT BE DEFENDED (must be stated in docs and onboarding, verbatim-level honesty): (1) a second camera pointed at the screen; (2) a jailbroken or instrumented viewer device; (3) a counterparty who modifies the client to ignore disappearing timers, suppress capture events, or persist plaintext; (4) screenshots on iOS 18+ where the undocumented secure-layer blanking does not work — detection after the fact is all that remains; (5) the few frames between recording start and the capture-state flip; (6) metadata (who/when/how much) seen by the server and the network; (7) coercion of either party; (8) a device with no passcode; (9) a watermark deliberately scrubbed or forged by the other party in a 1:1 chat; (10) VoiceOver/Speak Screen audio recorded by a microphone. The product promise is: 'the server can never read your messages; recording on the recipient's phone is blanked or detected and reported; a photo taken with another camera is attributable, not preventable.' (https://developer.apple.com/forums/thread/838583)
Pitfalls: UIScreen.main is deprecated in iOS 26 and UIScreen.isCaptured in iOS 27: on iOS 17 both still compile and work, but get the screen via view.window?.windowScene?.screen and prefer @Environment(\.isSceneCaptured) / UITraitCollection.sceneCaptureState to avoid deprecation warnings being promoted to errors by SWIFT_TREAT_WARNINGS_AS_ERRORS. | The secure-UITextField blanking trick is undocumented, discouraged by Apple DTS, and reported broken in iOS 18; it must be behind a feature flag, must never be the only control, and the owner must verify it on the exact target iOS version — the private subview class name (_UITextLayoutCanvasView on iOS 15-17) can change, so locate it by a String(describing: type(of:)) contains("CanvasView") search and fall back gracefully when not found. | UIApplication.userDidTakeScreenshotNotification fires only after the screenshot exists and only while the app is foreground; it has no userInfo. Never phrase the UI as 'no screenshot was taken'. | sceneWillResignActive(_:) / sceneDidEnterBackground(_:) only run if the app actually uses a scene delegate: in a SwiftUI @main App you need @UIApplicationDelegateAdaptor plus application(_:configurationForConnecting:options:) returning a UISceneConfiguration with delegateClass set (or UIApplicationSceneManifest in Info.plist); otherwise implement the overlay from UIApplication.willResignActiveNotification instead. | application(_:shouldAllowExtensionPointIdentifier:) (to block third-party keyboards) also requires the UIApplicationDelegateAdaptor; SwiftUI alone cannot block custom keyboards. | inlinePredictionType (iOS 17) and writingToolsBehavior (iOS 18) have no SwiftUI TextField modifiers on iOS 17; wrap UITextView in a UIViewRepresentable for the composer. Guard writingToolsBehavior with if #available(iOS 18.0, *). | isSecureTextEntry on the composer masks text with bullets; do not use it as the default composer. Trait flags (.no autocorrection/prediction) are not documented to stop keyboard learning — say so. | URL.setResourceValues(_:) is a mutating method: the URL must be a var. Re-apply isExcludedFromBackup on every launch because Apple documents it can be reset by document-style operations. | FileProtectionType.complete on the SQLite file must also be applied to -wal, -shm and -journal files (or set on the directory before creating the DB so they inherit); otherwise WAL pages holding ciphertext/metadata are only CompleteUntilFirstUserAuthentication. Close the DB on protectedDataWillBecomeUnavailableNotification or writes will fail after lock. | kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly items are DELETED by iOS when the user removes the passcode and cannot be created without one: the app must handle 'keys vanished' by forcing re-registration, not by crashing. SecAccessControlCreateWithFlags with .biometryCurrentSet makes the wrapped data unrecoverable after any Face ID/Touch ID re-enrolment — document this and offer a weaker option. | CryptoKit Secure Enclave keys are P-256 only (SecureEnclave.P256.*): Curve25519 identity keys cannot be generated in the Secure Enclave; they must be stored in Keychain and wrapped under an SE-protected key. CryptoKit also has no Ed25519<->X25519 conversion, so the prekey bundle needs separate Curve25519.Signing and Curve25519.KeyAgreement identity keys with a signature binding them — the Go reference must mirror this exactly or test vectors will not match. | ChaChaPoly.Nonce(data:) requires exactly 12 bytes; HKDF<SHA256>.deriveKey(inputKeyMaterial:salt:info:outputByteCount:) takes a SymmetricKey as IKM, not Data. AES.GCM.SealedBox.combined is nonce||ciphertext||tag (12+n+16). | For 120 Hz CADisplayLink on iPhone you need BOTH preferredFrameRateRange and the Info.plist key CADisableMinimumFrameDurationOnPhone = true; without the key the link silently runs at 60 Hz, which turns the flicker into a 30 Hz alternation inside the photosensitive band. Gate flicker on maximumFramesPerSecond >= 120, isReduceMotionEnabled == false, and abort on dropped frames. | The forensic watermark must sit on mid-tone surfaces: a 4% code-value delta on near-black OLED pixels is ~1/255 and disappears in camera noise. Do not encode in chroma (JPEG 4:2:0 halves it) and do not use micro-text (sub-Nyquist from 25-40 cm, destroyed by moire/demosaic/JPEG). | Push payloads must not contain sender, conversation id or ciphertext — not even 'from: ali' — because Notification Center, Apple Watch, Mac mirroring and Apple Intelligence summaries all re-display them; hiddenPreviewsBodyPlaceholder only helps when the user has previews off. | Never use QLPreviewController, UIImage(contentsOfFile:), UIImage(named:), URLCache defaults, or UIActivityViewController for protected content — each leaves a plaintext or thumbnail artifact outside the app's protected directory. | PhotosPicker/loadTransferable may spool a temporary copy into the app's tmp directory and PHPicker-delivered images carry EXIF GPS: strip metadata by re-encoding before encryption and clear temporaryDirectory on launch and on background. | Disappearing-message deletion and capture-event reporting on the OTHER device are cooperative; the UI must never present them as guarantees. Likewise jailbreak heuristics are informational only — blocking on them produces false positives and no security. | signal.org and support.apple.com were not reachable from the build container; X3DH/Double Ratchet equations and the '10 seconds' Complete-protection statement are cited from search snippets and knowledge (high confidence) rather than a direct page fetch — have the owner glance at those two pages once.