//  AppLock.swift
//  Kilit — App/ (WP8), §5.11.
//
//  Explicit `locked → authenticating → unlocked` state machine around
//  `LAContext.evaluatePolicy(.deviceOwnerAuthentication, localizedReason:)`.
//  Authentication starts only on launch and on a `.background → .active`
//  scene-phase transition; `.inactive ↔ .active` flips while authenticating are
//  ignored (the system prompt itself makes the scene inactive). Success →
//  `unlocked`; cancel or failure → `locked` with the explicit "Kilidi aç" retry.
//  `PrivacyCover` is only the snapshot cover; it is never the lock UI.

import Foundation
import LocalAuthentication
import Observation
import SwiftUI

/// Injected so `AppLockTests` runs without a device prompt.
protocol AppLockAuthenticator: AnyObject {
    /// true on success; false on cancel, failure or any LocalAuthentication error.
    func authenticate(reason: String) async -> Bool
}

/// Device implementation: one fresh `LAContext` per attempt.
final class DeviceAuthenticator: AppLockAuthenticator {
    init() {}

    func authenticate(reason: String) async -> Bool {
        let context: LAContext = LAContext()
        context.localizedReason = reason
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else { return false }
        do {
            return try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason)
        } catch {
            return false
        }
    }
}

@MainActor
@Observable
final class AppLock {

    enum State: Equatable {
        case locked
        case authenticating
        case unlocked
    }

    private(set) var state: State
    /// Settings › "Uygulama kilidi" (default on). When off the lock is always `unlocked`.
    private(set) var isEnabled: Bool

    @ObservationIgnored private let authenticator: AppLockAuthenticator
    @ObservationIgnored private let reason: String
    @ObservationIgnored private var lastPhase: ScenePhase?
    /// Set while the scene has been in the background since the last unlock.
    @ObservationIgnored private var needsPromptOnActive: Bool = false
    @ObservationIgnored private(set) var promptCount: Int = 0
    /// The in-flight prompt (tests await it).
    @ObservationIgnored private(set) var authenticationTask: Task<Void, Never>?

    init(authenticator: AppLockAuthenticator, enabled: Bool, reason: String) {
        self.authenticator = authenticator
        self.isEnabled = enabled
        self.reason = reason
        self.state = enabled ? .locked : .unlocked
    }

    var isUnlocked: Bool { state == .unlocked }

    /// Settings toggle: turning the lock off unlocks immediately; turning it on
    /// keeps the current session unlocked until the next background → active.
    func setEnabled(_ enabled: Bool) {
        isEnabled = enabled
        if !enabled {
            authenticationTask?.cancel()
            authenticationTask = nil
            state = .unlocked
        }
    }

    // MARK: - Triggers

    /// Launch: prompt once (when enabled).
    func handleLaunch() {
        guard isEnabled else { return }
        state = .locked
        needsPromptOnActive = false
        startAuthentication()
    }

    /// Scene-phase transitions. Only `.background → .active` re-prompts.
    func handleScenePhase(_ phase: ScenePhase) {
        defer { lastPhase = phase }
        guard isEnabled else { return }
        switch phase {
        case .background:
            // Re-lock while in the background; the snapshot cover is PrivacyCover's job.
            if state == .unlocked { state = .locked }
            needsPromptOnActive = true
        case .active:
            if state == .authenticating { return }        // .inactive → .active flip during the prompt
            if state == .locked && needsPromptOnActive {
                needsPromptOnActive = false
                startAuthentication()
            }
        case .inactive:
            break                                          // ignored in every state
        @unknown default:
            break
        }
    }

    /// "Kilidi aç" button after a cancel or failure.
    func retry() {
        guard isEnabled, state == .locked else { return }
        startAuthentication()
    }

    /// Explicit lock (e.g. Settings toggled on).
    func lock() {
        guard isEnabled else { return }
        authenticationTask?.cancel()
        authenticationTask = nil
        state = .locked
        needsPromptOnActive = true
    }

    // MARK: - Authentication

    private func startAuthentication() {
        guard state != .authenticating else { return }
        state = .authenticating
        promptCount += 1
        authenticationTask = Task { [weak self] in
            guard let self else { return }
            await self.runAuthentication()
        }
    }

    /// Awaits the injected authenticator and applies the verdict.
    func runAuthentication() async {
        let ok: Bool = await authenticator.authenticate(reason: reason)
        authenticationTask = nil
        guard state == .authenticating else { return }
        state = ok ? .unlocked : .locked
        if ok { needsPromptOnActive = false }
    }
}
