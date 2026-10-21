//  AppLockTests.swift
//  Kilit — WP8 tests (§5.12): the `locked → authenticating → unlocked` state
//  machine with an injected authenticator; no re-prompt on `.inactive ↔ .active`
//  while authenticating; re-prompt only after `.background → .active`.

import SwiftUI
import XCTest
@testable import Kilit

final class ScriptedAuthenticator: AppLockAuthenticator {
    var results: [Bool]
    private(set) var prompts: Int = 0

    init(results: [Bool]) {
        self.results = results
    }

    func authenticate(reason: String) async -> Bool {
        prompts += 1
        if results.isEmpty { return false }
        return results.removeFirst()
    }
}

final class AppLockTests: XCTestCase {

    @MainActor
    private func makeLock(_ results: [Bool], enabled: Bool = true) -> (AppLock, ScriptedAuthenticator) {
        let auth: ScriptedAuthenticator = ScriptedAuthenticator(results: results)
        let lock: AppLock = AppLock(authenticator: auth, enabled: enabled, reason: "test")
        return (lock, auth)
    }

    @MainActor
    func testLaunchSuccessUnlocks() async {
        let (lock, auth) = makeLock([true])
        XCTAssertEqual(lock.state, .locked)
        lock.handleLaunch()
        XCTAssertEqual(lock.state, .authenticating)
        await lock.authenticationTask?.value
        XCTAssertEqual(lock.state, .unlocked)
        XCTAssertEqual(auth.prompts, 1)
    }

    @MainActor
    func testFailureLocksAndRetryPromptsAgain() async {
        let (lock, auth) = makeLock([false, true])
        lock.handleLaunch()
        await lock.authenticationTask?.value
        XCTAssertEqual(lock.state, .locked)              // "Kilidi aç" button shown
        XCTAssertEqual(auth.prompts, 1)
        lock.retry()
        XCTAssertEqual(lock.state, .authenticating)
        await lock.authenticationTask?.value
        XCTAssertEqual(lock.state, .unlocked)
        XCTAssertEqual(auth.prompts, 2)
    }

    @MainActor
    func testInactiveActiveFlipWhileAuthenticatingDoesNotRePrompt() async {
        let (lock, auth) = makeLock([true])
        lock.handleLaunch()
        XCTAssertEqual(lock.state, .authenticating)
        lock.handleScenePhase(.inactive)                 // the system prompt itself
        lock.handleScenePhase(.active)
        lock.handleScenePhase(.inactive)
        lock.handleScenePhase(.active)
        XCTAssertEqual(lock.state, .authenticating)
        XCTAssertEqual(lock.promptCount, 1)              // the prompt Task may not have run yet
        await lock.authenticationTask?.value
        XCTAssertEqual(lock.state, .unlocked)
        XCTAssertEqual(auth.prompts, 1)
    }

    @MainActor
    func testBackgroundThenActiveRePromptsOnce() async {
        let (lock, auth) = makeLock([true, true])
        lock.handleLaunch()
        await lock.authenticationTask?.value
        XCTAssertEqual(lock.state, .unlocked)
        lock.handleScenePhase(.inactive)                 // inactive alone never locks
        lock.handleScenePhase(.active)
        XCTAssertEqual(lock.state, .unlocked)
        XCTAssertEqual(auth.prompts, 1)
        lock.handleScenePhase(.background)
        XCTAssertEqual(lock.state, .locked)
        lock.handleScenePhase(.inactive)
        lock.handleScenePhase(.active)
        XCTAssertEqual(lock.state, .authenticating)
        XCTAssertEqual(lock.promptCount, 2)              // the prompt Task may not have run yet
        await lock.authenticationTask?.value
        XCTAssertEqual(lock.state, .unlocked)
        XCTAssertEqual(auth.prompts, 2)
    }

    @MainActor
    func testCancelledPromptStaysLockedUntilRetry() async {
        let (lock, auth) = makeLock([true, false])
        lock.handleLaunch()
        await lock.authenticationTask?.value
        lock.handleScenePhase(.background)
        lock.handleScenePhase(.active)
        await lock.authenticationTask?.value             // cancelled → locked
        XCTAssertEqual(lock.state, .locked)
        lock.handleScenePhase(.inactive)
        lock.handleScenePhase(.active)                   // no background in between: no prompt
        XCTAssertEqual(lock.state, .locked)
        XCTAssertEqual(auth.prompts, 2)
    }

    @MainActor
    func testDisabledLockIsAlwaysUnlocked() async {
        let (lock, auth) = makeLock([true], enabled: false)
        XCTAssertEqual(lock.state, .unlocked)
        lock.handleLaunch()
        lock.handleScenePhase(.background)
        lock.handleScenePhase(.active)
        XCTAssertEqual(lock.state, .unlocked)
        XCTAssertEqual(auth.prompts, 0)
        lock.setEnabled(true)
        XCTAssertEqual(lock.state, .unlocked)            // stays unlocked until background → active
        lock.handleScenePhase(.background)
        lock.handleScenePhase(.active)
        XCTAssertEqual(lock.state, .authenticating)
        await lock.authenticationTask?.value
        XCTAssertEqual(lock.state, .unlocked)
        lock.setEnabled(false)
        XCTAssertEqual(lock.state, .unlocked)
    }
}
