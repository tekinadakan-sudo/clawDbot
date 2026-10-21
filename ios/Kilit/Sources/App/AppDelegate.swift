//  AppDelegate.swift
//  Kilit — App/ (WP8), §2 / §3.5b / §6.
//
//  Attaches `SceneDelegate` through `configurationForConnecting`, blocks
//  third-party keyboards (`shouldAllowExtensionPointIdentifier`) and empties
//  `temporaryDirectory` at launch (PhotosPicker spools land there).

import UIKit

final class AppDelegate: NSObject, UIApplicationDelegate {

    func application(_ application: UIApplication,
                     didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil) -> Bool {
        TemporaryFiles.clear()
        return true
    }

    func application(_ application: UIApplication,
                     configurationForConnecting connectingSceneSession: UISceneSession,
                     options: UIScene.ConnectionOptions) -> UISceneConfiguration {
        let configuration: UISceneConfiguration = UISceneConfiguration(name: nil, sessionRole: connectingSceneSession.role)
        configuration.delegateClass = SceneDelegate.self
        return configuration
    }

    /// Third-party keyboards are blocked app-wide (§2 clipboard/keyboard row).
    func application(_ application: UIApplication,
                     shouldAllowExtensionPointIdentifier extensionPointIdentifier: UIApplication.ExtensionPointIdentifier) -> Bool {
        extensionPointIdentifier != .keyboard
    }
}

/// `FileManager.default.temporaryDirectory` is emptied at launch and on
/// `sceneDidEnterBackground` (§3.5b).
enum TemporaryFiles {
    static func clear() {
        let manager: FileManager = FileManager.default
        let directory: URL = manager.temporaryDirectory
        guard let items = try? manager.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil,
                                                           options: []) else { return }
        for item in items {
            _ = try? manager.removeItem(at: item)
        }
    }
}
