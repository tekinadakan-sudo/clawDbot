//  CaptureShield.swift
//  Kilit — Security/ (WP6), §5.5 alternative blanking mode (`SecureLayerMode.layerSwap`).
//
//  The Signal/Telegram variant: a throwaway UITextField, its private
//  `TextLayoutCanvasView` subview, KVC-swap that subview's `layer` with the target
//  layer, toggle `isSecureTextEntry` off→on so UITextField stamps the capture
//  flag onto the target layer, then restore the original layer. Public calls only.
//
//  GREP GATE: `setValue(_:forKey: "layer")` on a UIView is permitted ONLY in this
//  file; the raw CALayer key `disableUpdateMask` is forbidden everywhere.

import UIKit

enum CaptureShield {

    /// Result of one application: whether the private canvas was found (the
    /// canary — `isProtected` has the same meaning as for `SecureCanvasView`).
    @MainActor
    @discardableResult
    static func setHidden(_ hidden: Bool, layerOf view: UIView) -> Bool {
        let field: UITextField = UITextField()
        guard let canvas = field.subviews.first(where: {
            String(describing: type(of: $0)).contains("TextLayoutCanvasView")
        }) else {
            return false
        }
        let original: CALayer = canvas.layer
        let delegate: CALayerDelegate? = view.layer.delegate
        canvas.setValue(view.layer, forKey: "layer")
        field.isSecureTextEntry = !hidden
        field.isSecureTextEntry = hidden
        canvas.setValue(original, forKey: "layer")
        view.layer.delegate = delegate      // defensive: keep the view drawing / laying out
        return true
    }

    /// Canary without side effects: can this OS build supply the canvas view?
    @MainActor
    static func isAvailable() -> Bool {
        let field: UITextField = UITextField()
        return field.subviews.contains {
            String(describing: type(of: $0)).contains("TextLayoutCanvasView")
        }
    }
}
