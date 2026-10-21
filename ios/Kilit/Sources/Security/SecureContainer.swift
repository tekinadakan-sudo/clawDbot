//  SecureContainer.swift
//  Kilit — Security/ (WP6), §5.5.
//
//  `SecureContainer` hosts SwiftUI content in a `UIHostingController<AnyView>`
//  inside `SecureHostingController`. Mode `.canvas` places the hosted view inside
//  the `SecureCanvasView` canvas; mode `.layerSwap` applies `CaptureShield` to the
//  hosted view's layer. `enabled == false` hosts the content unprotected and
//  reports `isProtected == false` (badge amber, `blanking_unavailable`).
//
//  Environment forwarding: the root is rebuilt as
//  `AnyView(content.environment(\.self, context.environment))` in both
//  `makeUIViewController` and `updateUIViewController`, so every environment
//  value and `@Observable` object of the outer hierarchy is re-applied inside.
//  Sizing: one mode, `.fill` — `sizingOptions = []`, `sizeThatFits` returns nil,
//  the caller gives the container `.frame(maxWidth: .infinity, maxHeight: .infinity)`.

import SwiftUI
import UIKit

/// Root view of `SecureHostingController`; reports window changes so the
/// layer-swap flag can be re-applied (`CaptureShield` must be re-run per layer).
final class SecureRootView: UIView {
    var onDidMoveToWindow: (() -> Void)?

    override func didMoveToWindow() {
        super.didMoveToWindow()
        onDidMoveToWindow?()
    }
}

final class SecureHostingController: UIViewController {

    let hosting: UIHostingController<AnyView>
    let secureView: SecureCanvasView = SecureCanvasView(frame: .zero)

    private(set) var mode: SecureLayerMode
    private(set) var enabled: Bool

    /// Canary: true when the active mode reports its blanking hook present.
    private(set) var isProtected: Bool = false
    var onProtectionChange: ((Bool) -> Void)?

    private let rootView: SecureRootView = SecureRootView(frame: .zero)
    private var mountedMode: SecureLayerMode?
    private var mountedEnabled: Bool?
    private var hostingConstraints: [NSLayoutConstraint] = []
    private var secureConstraints: [NSLayoutConstraint] = []

    init(rootView content: AnyView, mode: SecureLayerMode, enabled: Bool) {
        hosting = UIHostingController(rootView: content)
        self.mode = mode
        self.enabled = enabled
        super.init(nibName: nil, bundle: nil)
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        return nil
    }

    override func loadView() {
        rootView.backgroundColor = .clear
        view = rootView
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        hosting.view.backgroundColor = .clear
        hosting.sizingOptions = []                 // .fill: adopt whatever SwiftUI proposes
        hosting.safeAreaRegions = .container       // only the outer hierarchy avoids the keyboard
        addChild(hosting)
        hosting.view.translatesAutoresizingMaskIntoConstraints = false
        secureView.translatesAutoresizingMaskIntoConstraints = false
        secureView.onProtectionChange = { [weak self] ok in
            guard let self, self.mountedMode == .canvas, self.mountedEnabled == true else { return }
            self.report(ok)
        }
        rootView.onDidMoveToWindow = { [weak self] in
            guard let self, self.rootView.window != nil else { return }
            self.reapplyShieldIfNeeded()
        }
        mount()
        hosting.didMove(toParent: self)
    }

    // MARK: - Public

    func apply(mode newMode: SecureLayerMode, enabled newEnabled: Bool) {
        mode = newMode
        enabled = newEnabled
        guard isViewLoaded else { return }
        if mountedMode != newMode || mountedEnabled != newEnabled {
            mount()
        } else {
            reapplyShieldIfNeeded()
        }
    }

    /// Setting "Korumalı içeriği erişilebilirlikten gizle" (§2, default off).
    func setAccessibilityHidden(_ hidden: Bool) {
        secureView.contentView.accessibilityElementsHidden = hidden
        hosting.view.accessibilityElementsHidden = hidden
    }

    // MARK: - Mounting

    private func mount() {
        NSLayoutConstraint.deactivate(hostingConstraints)
        NSLayoutConstraint.deactivate(secureConstraints)
        hostingConstraints = []
        secureConstraints = []
        hosting.view.removeFromSuperview()
        secureView.removeFromSuperview()

        let host: UIView
        switch (enabled, mode) {
        case (true, .canvas):
            rootView.addSubview(secureView)
            secureConstraints = SecureHostingController.pin(secureView, to: rootView)
            NSLayoutConstraint.activate(secureConstraints)
            host = secureView.contentView
        case (true, .layerSwap), (false, _):
            host = rootView
        }
        host.addSubview(hosting.view)
        hostingConstraints = SecureHostingController.pin(hosting.view, to: host)
        NSLayoutConstraint.activate(hostingConstraints)

        mountedMode = mode
        mountedEnabled = enabled

        switch (enabled, mode) {
        case (true, .canvas):
            secureView.evaluateCanary()
            report(secureView.isProtected)
        case (true, .layerSwap):
            let found: Bool = CaptureShield.setHidden(true, layerOf: hosting.view)
            report(found)
        case (false, _):
            report(false)
        }
    }

    private func reapplyShieldIfNeeded() {
        guard mountedEnabled == true, mountedMode == .layerSwap else { return }
        let found: Bool = CaptureShield.setHidden(true, layerOf: hosting.view)
        report(found)
    }

    private func report(_ ok: Bool) {
        guard ok != isProtected else { return }
        isProtected = ok
        onProtectionChange?(ok)
    }

    private static func pin(_ child: UIView, to parent: UIView) -> [NSLayoutConstraint] {
        [
            child.leadingAnchor.constraint(equalTo: parent.leadingAnchor),
            child.trailingAnchor.constraint(equalTo: parent.trailingAnchor),
            child.topAnchor.constraint(equalTo: parent.topAnchor),
            child.bottomAnchor.constraint(equalTo: parent.bottomAnchor),
        ]
    }
}

/// Everything inside `content` is blanked in screenshots / recordings / AirPlay
/// (best effort, canary-checked). Exactly two instances exist in the app: the
/// message list and the protected image viewer.
struct SecureContainer<Content: View>: UIViewControllerRepresentable {

    let mode: SecureLayerMode
    let enabled: Bool
    let hidesFromAssistiveTechnologies: Bool
    let onProtectionChange: ((Bool) -> Void)?
    private let content: Content

    init(mode: SecureLayerMode = .canvas,
         enabled: Bool = true,
         hidesFromAssistiveTechnologies: Bool = false,
         onProtectionChange: ((Bool) -> Void)? = nil,
         @ViewBuilder content: () -> Content) {
        self.mode = mode
        self.enabled = enabled
        self.hidesFromAssistiveTechnologies = hidesFromAssistiveTechnologies
        self.onProtectionChange = onProtectionChange
        self.content = content()
    }

    func makeUIViewController(context: Context) -> SecureHostingController {
        let root: AnyView = AnyView(content.environment(\.self, context.environment))
        let controller: SecureHostingController =
            SecureHostingController(rootView: root, mode: mode, enabled: enabled)
        controller.onProtectionChange = onProtectionChange
        controller.setAccessibilityHidden(hidesFromAssistiveTechnologies)
        return controller
    }

    func updateUIViewController(_ uiViewController: SecureHostingController, context: Context) {
        uiViewController.onProtectionChange = onProtectionChange
        uiViewController.hosting.rootView = AnyView(content.environment(\.self, context.environment))
        uiViewController.apply(mode: mode, enabled: enabled)
        uiViewController.setAccessibilityHidden(hidesFromAssistiveTechnologies)
    }

    func sizeThatFits(_ proposal: ProposedViewSize,
                      uiViewController: SecureHostingController,
                      context: Context) -> CGSize? {
        nil                                    // .fill: adopt the proposal (§5.5)
    }
}
