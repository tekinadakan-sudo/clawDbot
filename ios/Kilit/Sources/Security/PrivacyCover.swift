//  PrivacyCover.swift
//  Kilit — Security/ (WP6), §5.5 / §5.11.
//
//  Opaque cover for the App Switcher snapshot. `SceneDelegate` adds it
//  SYNCHRONOUSLY in `sceneWillResignActive(_:)` and removes it in
//  `sceneDidBecomeActive(_:)`. It is only the snapshot cover, never the lock UI
//  (`AppLock` owns that). The SwiftUI counterpart redacts the hierarchy while
//  `scenePhase != .active` for views that live outside the UIKit window path.

import SwiftUI
import UIKit

final class PrivacyCoverView: UIView {

    static let tag: Int = 0x4B494C49           // "KILI"
    static let background: UIColor = UIColor(red: 0x2C / 255.0, green: 0x2C / 255.0,
                                             blue: 0x30 / 255.0, alpha: 1)

    private let symbol: UIImageView = UIImageView(image: UIImage(systemName: "lock.fill"))

    override init(frame: CGRect) {
        super.init(frame: frame)
        tag = PrivacyCoverView.tag
        isOpaque = true
        backgroundColor = PrivacyCoverView.background
        isAccessibilityElement = false
        accessibilityElementsHidden = true
        symbol.tintColor = UIColor(white: 1, alpha: 0.6)
        symbol.contentMode = .scaleAspectFit
        symbol.translatesAutoresizingMaskIntoConstraints = false
        addSubview(symbol)
        NSLayoutConstraint.activate([
            symbol.centerXAnchor.constraint(equalTo: centerXAnchor),
            symbol.centerYAnchor.constraint(equalTo: centerYAnchor),
            symbol.widthAnchor.constraint(equalToConstant: 44),
            symbol.heightAnchor.constraint(equalToConstant: 44),
        ])
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        return nil
    }
}

enum PrivacyCover {

    /// Adds the opaque cover above everything in `window` (idempotent).
    @MainActor
    static func show(in window: UIWindow) {
        if window.viewWithTag(PrivacyCoverView.tag) != nil { return }
        let cover: PrivacyCoverView = PrivacyCoverView(frame: window.bounds)
        cover.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        window.addSubview(cover)
        window.bringSubviewToFront(cover)
    }

    /// Removes the cover added by `show(in:)` (no-op when absent).
    @MainActor
    static func hide(in window: UIWindow) {
        window.viewWithTag(PrivacyCoverView.tag)?.removeFromSuperview()
    }

    @MainActor
    static func isShowing(in window: UIWindow) -> Bool {
        window.viewWithTag(PrivacyCoverView.tag) != nil
    }
}

/// SwiftUI counterpart: covers the modified view while the scene is not active.
struct PrivacyRedaction: ViewModifier {
    @Environment(\.scenePhase) private var scenePhase: ScenePhase

    func body(content: Content) -> some View {
        content.overlay {
            if scenePhase != .active {
                Rectangle()
                    .fill(Color(uiColor: PrivacyCoverView.background))
                    .ignoresSafeArea()
                    .accessibilityHidden(true)
            }
        }
    }
}

extension View {
    /// Opaque cover while `scenePhase != .active` (App Switcher snapshot, §2).
    func privacyRedacted() -> some View {
        modifier(PrivacyRedaction())
    }
}
