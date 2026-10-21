//  WatermarkLayers.swift
//  Kilit — Security/ (WP6), §5.9 placement (2): the protected image viewer.
//
//  Two CALayers above the AVSampleBufferDisplayLayer: `backgroundColor` is a
//  pattern colour built from the tile, `compositingFilter` is "plusL" / "plusD"
//  (the Core Animation names SwiftUI's `.plusLighter` / `.plusDarker` map to).
//  Each layer's frame is the content bounds inset by −168 pt on every side (one
//  tile larger), and the phase is applied with `bounds.origin = phase` — never by
//  moving `frame.origin` — with `masksToBounds = true` on the parent.

import QuartzCore
import UIKit

final class WatermarkLayers {

    let lighterLayer: CALayer = CALayer()
    let darkerLayer: CALayer = CALayer()

    let lighter: CGImage
    let darker: CGImage
    let phase: CGPoint

    private(set) var displayScale: CGFloat = 1

    init(lighter: CGImage, darker: CGImage, phase: CGPoint) {
        self.lighter = lighter
        self.darker = darker
        self.phase = phase
        for layer in [lighterLayer, darkerLayer] {
            layer.actions = ["bounds": NSNull(), "position": NSNull(),
                             "backgroundColor": NSNull(), "contents": NSNull()]
            layer.isOpaque = false
            layer.allowsGroupOpacity = false
        }
        lighterLayer.compositingFilter = "plusL"
        darkerLayer.compositingFilter = "plusD"
        lighterLayer.name = "kilit.watermark.lighter"
        darkerLayer.name = "kilit.watermark.darker"
    }

    /// Adds both layers to `parent` (which masks to its bounds) and builds the
    /// pattern colours for `displayScale`.
    func install(in parent: CALayer, displayScale: CGFloat) {
        parent.masksToBounds = true
        updateDisplayScale(displayScale)
        // AVSampleBufferDisplayLayer keeps a private content sublayer of its own;
        // a high zPosition keeps the mark above it whatever order layers are added in.
        lighterLayer.zPosition = 1000
        darkerLayer.zPosition = 1001
        parent.addSublayer(lighterLayer)
        parent.addSublayer(darkerLayer)
    }

    func removeFromSuperlayer() {
        lighterLayer.removeFromSuperlayer()
        darkerLayer.removeFromSuperlayer()
    }

    /// Rebuilds the pattern colours so one tile measures 168 pt on this screen.
    func updateDisplayScale(_ scale: CGFloat) {
        displayScale = scale
        lighterLayer.contentsScale = scale
        darkerLayer.contentsScale = scale
        lighterLayer.backgroundColor = WatermarkLayers.patternColor(lighter, scale: scale)
        darkerLayer.backgroundColor = WatermarkLayers.patternColor(darker, scale: scale)
    }

    /// Positions both layers one tile larger than `contentBounds` on every side
    /// and applies the phase through `bounds.origin`.
    func layout(contentBounds: CGRect) {
        let side: CGFloat = WatermarkTile.sidePoints
        let frame: CGRect = contentBounds.insetBy(dx: -side, dy: -side)
        CATransaction.begin()
        CATransaction.setDisableActions(true)
        for layer in [lighterLayer, darkerLayer] {
            layer.frame = frame
            layer.bounds = CGRect(origin: phase, size: frame.size)
        }
        CATransaction.commit()
    }

    private static func patternColor(_ tile: CGImage, scale: CGFloat) -> CGColor {
        let image: UIImage = UIImage(cgImage: tile, scale: scale, orientation: .up)
        return UIColor(patternImage: image).cgColor
    }
}
