//  SceneDelegate.swift
//  Kilit — App/ (WP8), §5.5 / §5.6 / §5.11.
//
//  Opaque `PrivacyCover` added SYNCHRONOUSLY in `sceneWillResignActive` and
//  removed in `sceneDidBecomeActive`; `UITraitSceneCaptureState` observation on
//  the window scene feeds `CaptureMonitor.update(captured:)`; tmp cleanup and
//  `MessageSync.background()` on `sceneDidEnterBackground`.

import SwiftUI
import UIKit

final class SceneDelegate: NSObject, UIWindowSceneDelegate {

    private var captureRegistration: (any UITraitChangeRegistration)?

    func scene(_ scene: UIScene, willConnectTo session: UISceneSession, options connectionOptions: UIScene.ConnectionOptions) {
        guard let windowScene = scene as? UIWindowScene else { return }
        let model: AppModel = AppModel.shared
        model.diagnostics.panelHz = windowScene.screen.maximumFramesPerSecond
        model.captureMonitor.update(captured: windowScene.traitCollection.sceneCaptureState == .active)
        captureRegistration = windowScene.registerForTraitChanges([UITraitSceneCaptureState.self]) {
            (observed: UIWindowScene, _: UITraitCollection) in
            let captured: Bool = observed.traitCollection.sceneCaptureState == .active
            AppModel.shared.captureMonitor.update(captured: captured)
            AppModel.shared.diagnostics.isCaptured = captured
        }
    }

    func sceneWillResignActive(_ scene: UIScene) {
        guard let windowScene = scene as? UIWindowScene else { return }
        for window in windowScene.windows {
            PrivacyCover.show(in: window)
        }
    }

    func sceneDidBecomeActive(_ scene: UIScene) {
        guard let windowScene = scene as? UIWindowScene else { return }
        for window in windowScene.windows {
            PrivacyCover.hide(in: window)
        }
    }

    func sceneDidEnterBackground(_ scene: UIScene) {
        TemporaryFiles.clear()
        let model: AppModel = AppModel.shared
        model.captureGlue?.flush(force: true)
        Task {
            await model.sync?.background()
        }
    }
}
