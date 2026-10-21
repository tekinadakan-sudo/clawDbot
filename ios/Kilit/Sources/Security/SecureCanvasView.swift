//  SecureCanvasView.swift
//  Kilit — Security/ (WP6), §5.5.
//
//  Container whose `contentView` is rendered inside the secure canvas of a
//  `SecureHostField`. Subviews of `contentView` are blanked by the render server
//  in screenshots, screen recordings, AirPlay mirroring and the App Switcher
//  snapshot (physical devices only; the Simulator bypasses the render server).
//
//  The canary (`isProtected`) is re-evaluated on EVERY `layoutSubviews()` and
//  `didMoveToWindow()`, not once: UITextField may discard and recreate its private
//  canvas, and a stale canvas would make the content vanish while the badge stays
//  green. In the same pass every gesture recognizer on the field and on the
//  current canvas is disabled (UITextInteraction installs them lazily).

import UIKit

final class SecureCanvasView: UIView {

    /// Hosted content. Auto Layout works normally inside it.
    let contentView: UIView = UIView()

    /// true when `contentView` really sits inside the current secure canvas.
    private(set) var isProtected: Bool = false

    /// Fired on every transition of `isProtected` in either direction, and once
    /// when the view enters a window (with the state at that moment).
    var onProtectionChange: ((Bool) -> Void)?

    /// The hidden secure field (internal so tests can set `text` and inspect it).
    let hostField: SecureHostField = SecureHostField(frame: .zero)

    private var contentConstraints: [NSLayoutConstraint] = []

    override init(frame: CGRect) {
        super.init(frame: frame)
        backgroundColor = .clear
        hostField.translatesAutoresizingMaskIntoConstraints = false
        addSubview(hostField)
        NSLayoutConstraint.activate([
            hostField.leadingAnchor.constraint(equalTo: leadingAnchor),
            hostField.trailingAnchor.constraint(equalTo: trailingAnchor),
            hostField.topAnchor.constraint(equalTo: topAnchor),
            hostField.bottomAnchor.constraint(equalTo: bottomAnchor),
        ])
        contentView.backgroundColor = .clear
        contentView.translatesAutoresizingMaskIntoConstraints = false
        hostField.hostedContent = contentView
        attachContent()
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        return nil
    }

    // MARK: - UIView

    override func didMoveToWindow() {
        super.didMoveToWindow()
        hostField.layoutIfNeeded()          // forces lazy creation of the private canvas
        let fired: Bool = evaluateCanary()
        if window != nil && !fired {
            onProtectionChange?(isProtected)
        }
    }

    override func layoutSubviews() {
        super.layoutSubviews()
        _ = evaluateCanary()
    }

    override var intrinsicContentSize: CGSize { contentView.intrinsicContentSize }

    // MARK: - Canary

    /// Re-evaluates the canary, re-attaches the content when the canvas changed,
    /// disables every recognizer on field and canvas, and returns whether
    /// `onProtectionChange` fired (i.e. whether `isProtected` transitioned).
    @discardableResult
    func evaluateCanary() -> Bool {
        let canvas: UIView? = hostField.secureCanvas
        let ok: Bool = canvas != nil
            && contentView.superview === canvas
            && canvas?.superview === hostField
        if !ok {
            attachContent()
        }
        disableRecognizers(canvas: hostField.secureCanvas)
        let nowProtected: Bool = hostField.secureCanvas != nil
            && contentView.superview === hostField.secureCanvas
        if nowProtected != isProtected {
            isProtected = nowProtected
            onProtectionChange?(nowProtected)
            return true
        }
        return false
    }

    private func attachContent() {
        let canvas: UIView? = hostField.secureCanvas
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
    }

    private func disableRecognizers(canvas: UIView?) {
        let recognizers: [UIGestureRecognizer] =
            (hostField.gestureRecognizers ?? []) + (canvas?.gestureRecognizers ?? [])
        for recognizer in recognizers where recognizer.isEnabled {
            recognizer.isEnabled = false
        }
    }

    /// All recognizers currently installed on the field and on the current canvas
    /// (for the canary test; every one of them must be disabled).
    var installedRecognizers: [UIGestureRecognizer] {
        (hostField.gestureRecognizers ?? []) + (hostField.secureCanvas?.gestureRecognizers ?? [])
    }
}
