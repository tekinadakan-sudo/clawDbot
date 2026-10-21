//  WatermarkOverlay.swift
//  Kilit — Security/ (WP6), §5.9 placement (1): the message list.
//
//  Must be the LAST child of the ZStack inside the hosted content (not an
//  `.overlay` on the representable), so it composites against ordinary SwiftUI
//  layers inside the same UIHostingController. The tiles are over-sized by one
//  tile (`.padding(-168)`) BEFORE the offset so the phase shift leaves no
//  unmarked strip along two edges; the enclosing ZStack is `.clipped()`.

import CoreGraphics
import SwiftUI

struct WatermarkOverlay: View {

    let lighter: CGImage
    let darker: CGImage
    /// Per-viewing-session random point in [0, 168)².
    let phase: CGPoint
    /// Visible diagonal complement, e.g. "@ayse · 21 Eki" (9 % alpha).
    let visibleString: String

    @Environment(\.displayScale) private var displayScale: CGFloat

    init(lighter: CGImage, darker: CGImage, phase: CGPoint, visibleString: String) {
        self.lighter = lighter
        self.darker = darker
        self.phase = phase
        self.visibleString = visibleString
    }

    /// Draws a fresh phase in [0, 168)² (one per viewing session).
    static func randomPhase() -> CGPoint {
        CGPoint(x: CGFloat.random(in: 0..<WatermarkTile.sidePoints),
                y: CGFloat.random(in: 0..<WatermarkTile.sidePoints))
    }

    var body: some View {
        ZStack {
            tiled(lighter)
                .blendMode(.plusLighter)
            tiled(darker)
                .blendMode(.plusDarker)
            Text(visibleString)
                .font(.system(size: 13, weight: .regular, design: .default))
                .foregroundStyle(.primary)
                .rotationEffect(.degrees(-30))
                .opacity(0.09)
        }
        .clipped()
        .allowsHitTesting(false)
        .accessibilityHidden(true)
    }

    private func tiled(_ tile: CGImage) -> some View {
        Image(decorative: tile, scale: displayScale)
            .resizable(resizingMode: .tile)
            .padding(-WatermarkTile.sidePoints)
            .offset(x: -phase.x, y: -phase.y)
            .allowsHitTesting(false)
            .accessibilityHidden(true)
    }
}
