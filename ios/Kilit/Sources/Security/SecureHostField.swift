//  SecureHostField.swift
//  Kilit — Security/ (WP6), §5.5.
//
//  A UITextField that never takes focus, hides all of its own chrome, forwards
//  hit-testing to the hosted content and keeps UIKit's private secure canvas
//  (`_UITextLayoutCanvasView` on iOS 15–26) sized to its own bounds. Public API
//  only; the private subview is located by class-name suffix, never by layer index.

import UIKit

final class SecureHostField: UITextField {

    /// The private secure canvas, looked up by class-name suffix on every call
    /// (UIKit may discard and recreate it on text, trait or window changes).
    var secureCanvas: UIView? {
        subviews.first { String(describing: type(of: $0)).hasSuffix("CanvasView") }
    }

    /// Hit-testing is forwarded to this view (the hosted content) so gestures
    /// inside the canvas (hold-to-reveal, scrolling) still work.
    weak var hostedContent: UIView?

    override init(frame: CGRect) {
        super.init(frame: frame)
        isSecureTextEntry = true
        borderStyle = .none
        backgroundColor = .clear
        textColor = .clear          // never `alpha`: it multiplies into the canvas and the content
        tintColor = .clear
        clipsToBounds = true
        autocorrectionType = .no
        spellCheckingType = .no
        textContentType = nil       // a focused secure field would trigger Password AutoFill
        isAccessibilityElement = false
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        return nil
    }

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

    override func gestureRecognizerShouldBegin(_ gestureRecognizer: UIGestureRecognizer) -> Bool {
        false
    }
}
