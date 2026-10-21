import XCTest
@testable import Kilit

/// §4.5: a persistent `401 unknown_user`/`bad_signature` on `POST /v1/auth/login` stops re-login for good and emits
/// `.authInvalid` once (the UI returns to onboarding); any other login failure stays transient.
final class AuthRecoveryTests: XCTestCase {
    private static let deviceId: String = "0b6f2b1e-8a4c-4d2e-9f3a-1c2d3e4f5a6b"

    private func harness(loginError code: String) throws -> SyncHarness {
        let h: SyncHarness = try SyncHarness()
        try h.keychain.writeString(KeychainAccount.deviceId, AuthRecoveryTests.deviceId)
        h.override = { request in
            switch request.url?.path ?? "" {
            case "/v1/auth/challenge":
                let challenge: ChallengeResponse = ChallengeResponse(nonce: Bytes.random(32), expiresAt: SyncHarness.now0 + 60,
                                                                     serverTime: SyncHarness.now0)
                return try StubTransport.encoded(200, request, challenge)
            case "/v1/auth/login":
                return try StubTransport.json(401, request, ["error": code, "message": "rejected"])
            default:
                return nil
            }
        }
        return h
    }

    func testPersistentLoginRejectionLatchesAndEmitsAuthInvalidOnce() async throws {
        for code in ["unknown_user", "bad_signature"] {
            let h: SyncHarness = try harness(loginError: code)
            var events: AsyncStream<SyncEvent>.Iterator = h.sync.events.makeAsyncIterator()
            await h.sync.reauthenticateIfNeeded()
            let first: SyncEvent? = await events.next()
            XCTAssertEqual(first, .authInvalid)
            let rejected: Bool = await h.sync.loginRejected
            XCTAssertTrue(rejected)
            XCTAssertEqual(h.requests("POST", pathSuffix: "/v1/auth/login").count, MessageSync.loginRejectionAttempts)
            // A later pump (which re-arms the once-per-pump re-login) never logs in again: no re-login loop.
            await h.sync.pumpOutbox()
            await h.sync.reauthenticateIfNeeded()
            XCTAssertEqual(h.requests("POST", pathSuffix: "/v1/auth/login").count, MessageSync.loginRejectionAttempts)
        }
    }

    func testOtherLoginFailuresStayTransient() async throws {
        let h: SyncHarness = try harness(loginError: "nonce_invalid")
        await h.sync.reauthenticateIfNeeded()
        let rejected: Bool = await h.sync.loginRejected
        XCTAssertFalse(rejected)
        XCTAssertEqual(h.requests("POST", pathSuffix: "/v1/auth/login").count, 1)
        await h.sync.pumpOutbox()
        await h.sync.reauthenticateIfNeeded()
        XCTAssertEqual(h.requests("POST", pathSuffix: "/v1/auth/login").count, 2)
    }
}
