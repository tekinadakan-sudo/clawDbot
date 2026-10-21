import Foundation
import OSLog

// MARK: - Account: register / login / delete / reinstall wipe (§4.3, §4.5, §5.3, §5.11)

extension MessageSync {
    /// `POST /v1/auth/challenge` + `POST /v1/register` with keys that were persisted before the upload. On
    /// `409 username_taken` the caller re-prompts and calls again: nothing was stored on the server and the keys
    /// are reused (§4.3). On success the token, username, origin and device id are kept in the Keychain.
    func register(username name: String, deviceId: String) async throws -> RegisterResponse {
        guard store.isOpen else { throw SyncError.notOpen }
        let now: UInt64 = clock.now
        let challenge: ChallengeResponse = try await api.challenge(username: name, localNow: now)
        let offset: Int64 = await api.clockOffset
        if store.index.prekeys.currentSPK == nil {
            let source: KeySource = keySource
            try store.commitIndex { idx in
                _ = idx.prekeys.initialBatch(now: now, keySource: source)
            }
        }
        guard let spk = store.index.prekeys.currentSPK else { throw SyncError.notRegistered }
        let opks: [OneTimePrekey] = store.index.prekeys.pendingUpload
        let ts: UInt64 = await api.correctedTime(localNow: clock.now)
        let body: RegisterRequest = try AuthRequests.register(username: name, local: local, deviceId: deviceId,
                                                              nonce: challenge.nonce, ts: ts, origin: api.origin,
                                                              spk: spk, opks: opks)
        let response: RegisterResponse
        do {
            response = try await api.register(body)
        } catch let e as APIError where e.status == 409 && e.code == "username_taken" {
            throw SyncError.usernameTaken
        }
        try keychain.writeIdentity(local)
        try keychain.writeString(KeychainAccount.token, response.token)
        try keychain.writeString(KeychainAccount.username, name)
        try keychain.writeString(KeychainAccount.serverOrigin, api.origin)
        try keychain.writeString(KeychainAccount.deviceId, deviceId)
        let ids: [UInt32] = opks.map { $0.id }
        let origin: String = api.origin
        try store.commitIndex { idx in
            idx.username = name
            idx.serverOrigin = origin
            idx.clockOffset = offset
            idx.prekeys.markUploaded(ids: ids)
            idx.prekeys.lastServerCount = ids.count
        }
        store.markInstalled()
        return response
    }

    /// Challenge + `POST /v1/auth/login` with the Keychain identity; stores the new token.
    func login() async throws -> LoginResponse {
        guard let name = store.index.username ?? (try? keychain.readString(KeychainAccount.username)) ?? nil,
              let deviceId = try keychain.readString(KeychainAccount.deviceId) else { throw SyncError.notRegistered }
        let challenge: ChallengeResponse = try await api.challenge(username: name, localNow: clock.now)
        let offset: Int64 = await api.clockOffset
        let ts: UInt64 = await api.correctedTime(localNow: clock.now)
        let body: LoginRequest = try AuthRequests.login(username: name, local: local, deviceId: deviceId,
                                                        nonce: challenge.nonce, ts: ts, origin: api.origin)
        let response: LoginResponse = try await api.login(body)
        try keychain.writeString(KeychainAccount.token, response.token)
        if store.isOpen {
            _ = try? store.commitIndex { idx in idx.clockOffset = offset }
        }
        return response
    }

    /// Fresh-challenge login attempts that must all answer `401 unknown_user`/`bad_signature` before the rejection
    /// counts as persistent (§4.5).
    static let loginRejectionAttempts: Int = 2

    /// `401 invalid_token` → re-challenge/login once per outbox pump. A login answered `401 unknown_user` or
    /// `bad_signature` is retried once with a fresh challenge; when it persists, `loginRejected` is latched (no
    /// re-login ever again, so no loop), the sync stops and `.authInvalid` is emitted once: the UI returns to
    /// onboarding. Every other failure (`clock_skew`, `nonce_invalid`, 408, 429, 5xx, offline) stays transient.
    func reauthenticateIfNeeded() async {
        guard !loginRejected, !reauthenticatedThisPump else { return }
        reauthenticatedThisPump = true
        var rejections: Int = 0
        while rejections < MessageSync.loginRejectionAttempts {
            do {
                _ = try await login()
                return
            } catch let e as APIError where e.isLoginRejection {
                rejections += 1
                MessageSync.logger.error("re-login rejected \(e.code ?? "", privacy: .public)")
            } catch {
                MessageSync.logger.error("re-login failed: \(String(describing: error), privacy: .public)")
                return
            }
        }
        guard !loginRejected else { return }
        loginRejected = true
        await stop()
        emit(.authInvalid)
    }

    /// `DELETE /v1/auth/session` (best effort) — the local data stays.
    func logout() async {
        do {
            try await api.logout()
        } catch {
            MessageSync.logger.notice("logout failed: \(String(describing: error), privacy: .public)")
        }
        _ = try? keychain.delete(KeychainAccount.token)
    }

    /// "Hesabı sil ve sıfırla": challenge + `DELETE /v1/users/me` with `delete_sig`, then the local wipe.
    func deleteAccountAndWipe() async throws {
        try await deleteAccountOnServer()
        await wipe()
    }

    func deleteAccountOnServer() async throws {
        guard let name = store.index.username ?? (try? keychain.readString(KeychainAccount.username)) ?? nil else {
            throw SyncError.notRegistered
        }
        if await api.token == nil {
            if let tok = try keychain.readString(KeychainAccount.token) { await api.setToken(tok) }
        }
        let challenge: ChallengeResponse = try await api.challenge(username: name, localNow: clock.now)
        let ts: UInt64 = await api.correctedTime(localNow: clock.now)
        let body: DeleteAccountRequest = try AuthRequests.deleteAccount(username: name, local: local, nonce: challenge.nonce,
                                                                        ts: ts, origin: api.origin)
        do {
            try await api.deleteAccount(body)
        } catch let e as APIError where e.status == 401 && e.code == "invalid_token" {
            _ = try await login()
            try await api.deleteAccount(body)
        }
    }

    /// Removes every file, Keychain item and the install marker; cursor and generations reset with the index.
    func wipe() async {
        await stop()
        do {
            try store.wipe()
        } catch {
            MessageSync.logger.error("wipe failed: \(String(describing: error), privacy: .public)")
        }
        _ = try? blobs.deleteAll()
        await api.setToken(nil)
        deduper = InboundDeduper()
        coalescer = ControlCoalescer()
        lookupRetries = [:]
        emit(.contactsChanged)
    }

    /// Reinstall (files gone, Keychain kept, `installMarker` missing): the account is deleted on the server
    /// first (best effort, so the username is freed) and then everything local is wiped. Returns true when a
    /// reinstall was detected and handled; the caller then shows onboarding.
    func wipeAfterReinstall() async -> Bool {
        guard store.reinstallDetected() else { return false }
        let storedOrigin: String? = (try? keychain.readString(KeychainAccount.serverOrigin)) ?? nil
        if storedOrigin == nil || storedOrigin == api.origin {
            do {
                try await deleteAccountOnServer()
            } catch {
                MessageSync.logger.error("reinstall: account delete failed: \(String(describing: error), privacy: .public)")
            }
        }
        await wipe()
        return true
    }
}
