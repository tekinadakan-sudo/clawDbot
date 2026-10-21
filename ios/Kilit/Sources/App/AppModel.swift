//  AppModel.swift
//  Kilit — App/ (WP8), §5.2 / §5.11.
//
//  The single `@Observable` root: phase (onboarding / locked / main / wipe
//  prompt), the app lock, the `MessageSync` actor, contacts, conversations,
//  settings, diagnostics, the capture monitor + glue, the reveal controller, the
//  disappearing scheduler and the watermark tile cache. UI updates hop to the
//  main actor through the `SyncEvent` stream.

import CoreGraphics
import Foundation
import LocalAuthentication
import Observation
import SwiftUI

@MainActor
@Observable
final class AppModel {

    enum Phase: Equatable {
        case loading
        case onboarding
        case locked
        case main
        /// `LocalStoreError.rollback(index.json)` at open: the user must wipe.
        case wipeRequired
    }

    static let shared: AppModel = AppModel()

    private(set) var phase: Phase = .loading
    let lock: AppLock
    let captureMonitor: CaptureMonitor
    let reveal: RevealController
    let diagnostics: Diagnostics = Diagnostics()

    private(set) var sync: MessageSync?
    private(set) var captureGlue: CaptureGlue?
    private(set) var scheduler: DisappearingScheduler?

    private(set) var contacts: [ContactRecord] = []
    private(set) var conversations: [Conversation] = []
    private(set) var settings: Settings = Settings()
    private(set) var username: String = ""
    private(set) var serverOrigin: String = ""
    private(set) var connection: WSState = .stopped
    private(set) var authInvalid: Bool = false
    /// Version counter bumped on every `conversationChanged(peer:)` so open views reload.
    private(set) var conversationVersion: [String: Int] = [:]
    var toast: String? = nil
    /// Per-viewing-session random watermark phase (§5.9).
    let watermarkPhase: CGPoint = WatermarkOverlay.randomPhase()

    @ObservationIgnored let keychain: Keychain = Keychain()
    @ObservationIgnored let clock: SystemClock = SystemClock()
    @ObservationIgnored let tileCache: WatermarkTileCache = WatermarkTileCache()
    @ObservationIgnored private var eventTask: Task<Void, Never>?
    @ObservationIgnored private var toastTask: Task<Void, Never>?
    @ObservationIgnored private var identity: IdentityKeys?
    @ObservationIgnored private var store: LocalStore?
    @ObservationIgnored private var blobs: BlobStore?

    init() {
        lock = AppLock(authenticator: DeviceAuthenticator(), enabled: true,
                       reason: String(localized: "lock.reason", defaultValue: "Kilit'i açmak için kimliğini doğrula"))
        captureMonitor = CaptureMonitor()
        reveal = RevealController()
    }

    var secureLayerMode: SecureLayerMode {
        SecureLayerMode(rawValue: settings.secureLayerMode) ?? .canvas
    }

    var isCaptured: Bool { captureMonitor.isCaptured }

    /// Own identity public keys (safety number).
    var localPublicKeys: IdentityPublicKeys? { identity?.publicKeys }

    // MARK: - Launch

    /// Called once from `KilitApp`: Keychain → reinstall check → store → lock → sync.
    func bootstrap() async {
        guard phase == .loading else { return }
        let storedIdentity: IdentityKeys? = (try? keychain.readIdentity()) ?? nil
        let storedUsername: String? = (try? keychain.readString(KeychainAccount.username)) ?? nil
        let storedOrigin: String? = (try? keychain.readString(KeychainAccount.serverOrigin)) ?? nil
        let storedToken: String? = (try? keychain.readString(KeychainAccount.token)) ?? nil
        guard let keys = storedIdentity, let name = storedUsername, let origin = storedOrigin else {
            phase = .onboarding
            return
        }
        let sync: MessageSync = makeSync(identity: keys, username: name, origin: origin, token: storedToken)
        if await sync.wipeAfterReinstall() {
            showToast(String(localized: "reinstall.wiped",
                             defaultValue: "Eski hesap sunucudan silinemedi; bu kullanıcı adı dolu kalabilir"))
            self.sync = nil
            phase = .onboarding
            return
        }
        do {
            try await sync.openStore()
        } catch {
            self.sync = sync
            phase = .wipeRequired
            return
        }
        username = name
        serverOrigin = origin
        await attach(sync)
        lock.setEnabled(settings.appLock)
        if lock.isEnabled {
            phase = .locked
            lock.handleLaunch()
        } else {
            phase = .main
        }
    }

    private func makeSync(identity keys: IdentityKeys, username name: String, origin: String, token: String?) -> MessageSync {
        let store: LocalStore = self.store ?? LocalStore(directory: LocalStore.defaultDirectory(), keychain: keychain)
        let blobs: BlobStore = self.blobs ?? BlobStore(directory: store.directory.appendingPathComponent("blobs", isDirectory: true))
        self.store = store
        self.blobs = blobs
        self.identity = keys
        let api: APIClient = APIClient(origin: origin, transport: URLSessionTransport(session: APIClient.restSession()),
                                       token: token)
        let factory: URLSessionWebSocketFactory = URLSessionWebSocketFactory(session: APIClient.webSocketSession())
        let box: SyncBox = SyncBox()
        let webSocket: WebSocketClient = WebSocketClient(
            factory: factory,
            request: { await api.webSocketRequest() },
            cursor: { await box.sync?.index().ledger.cursor ?? 0 })
        let sync: MessageSync = MessageSync(store: store, blobs: blobs, api: api, keychain: keychain, clock: clock,
                                            keySource: RandomKeySource(), local: keys, username: name,
                                            webSocket: webSocket)
        box.sync = sync
        return sync
    }

    /// Wires events, glue and scheduler, loads the index and starts the sync.
    private func attach(_ sync: MessageSync) async {
        self.sync = sync
        await refresh()
        let glue: CaptureGlue = CaptureGlue(clock: clock, sink: SyncCaptureSink(sync: sync),
                                            seq: await sync.index().captureSeq)
        glue.reportsEnabled = settings.captureReports
        captureGlue = glue
        captureMonitor.onEvent = { [weak self] kind, timestamp in
            guard let self else { return }
            self.diagnostics.isCaptured = self.captureMonitor.isCaptured
            self.captureGlue?.handle(kind, at: timestamp)
            if kind == .recordingStarted { self.reveal.endAll() }
        }
        reveal.onRevealBegan = { [weak self] id in
            self?.revealBegan(id: id)
        }
        let scheduler: DisappearingScheduler = DisappearingScheduler(clock: clock) { [weak self] in
            self?.purgeNow()
        }
        self.scheduler = scheduler
        observeEvents(sync)
        let next: UInt64? = await sync.start()
        scheduler.schedule(deadline: next)
    }

    private func observeEvents(_ sync: MessageSync) {
        eventTask?.cancel()
        eventTask = Task { [weak self] in
            for await event in sync.events {
                guard let self else { return }
                await self.handle(event)
            }
        }
    }

    private func handle(_ event: SyncEvent) async {
        switch event {
        case .conversationChanged(let peer):
            conversationVersion[peer] = (conversationVersion[peer] ?? 0) + 1
            await refresh()
        case .contactsChanged, .keyChangeDetected:
            await refresh()
        case .connection(let state):
            connection = state
            diagnostics.connection = state
        case .prekeys(let count):
            diagnostics.opkCount = count
        case .authInvalid:
            // Persistent `401 unknown_user`/`bad_signature` on login. Sync has stopped (MessageSync.loginRejected).
            // Deviation from §4.5: no automatic wipe and no forced onboarding, because an untrusted server could
            // otherwise erase local history just by answering 401. The user resets from Settings if they choose to.
            authInvalid = true
            showToast(String(localized: "auth.invalid",
                             defaultValue: "Oturum geçersiz; sunucu bu cihazı tanımıyor. Hesabı sil ve sıfırla gerekebilir."))
        }
    }

    /// Reloads contacts, conversations, settings and diagnostics from the index.
    func refresh() async {
        guard let sync else { return }
        let index: StoreIndex = await sync.index()
        contacts = index.contacts
        conversations = index.conversations.sorted { $0.lastActivityAt > $1.lastActivityAt }
        settings = index.settings
        captureGlue?.reportsEnabled = index.settings.captureReports
        diagnostics.apply(index: index)
    }

    // MARK: - Scene phases

    func scenePhaseChanged(_ scenePhase: ScenePhase) {
        lock.handleScenePhase(scenePhase)
        switch scenePhase {
        case .active:
            if phase == .main || phase == .locked {
                phase = lock.isUnlocked ? .main : .locked
                Task { [weak self] in
                    guard let self, let sync = self.sync else { return }
                    let next: UInt64? = await sync.foreground()
                    self.scheduler?.schedule(deadline: next)
                    await self.refresh()
                }
            }
        case .background:
            reveal.endAll()
            captureGlue?.flush(force: true)
            if phase == .main { phase = .locked }
            if phase == .locked && !lock.isEnabled { phase = .main }
            Task { [weak self] in
                await self?.sync?.background()
            }
        case .inactive:
            break
        @unknown default:
            break
        }
    }

    /// `AppLock` reached `unlocked` (observed by RootView).
    func lockStateChanged() {
        guard phase == .locked || phase == .main else { return }
        phase = lock.isUnlocked ? .main : .locked
    }

    private func purgeNow() {
        Task { [weak self] in
            guard let self, let sync = self.sync else { return }
            let next: UInt64? = await sync.purgeExpired()
            self.scheduler?.schedule(deadline: next)
        }
    }

    private func revealBegan(id: String) {
        guard let glue = captureGlue, let peer = glue.activePeer, let sync else { return }
        Task { try? await sync.markRevealed(peer: peer, id: id) }
    }

    // MARK: - Onboarding / registration (§5.11)

    enum PasscodeGate: Equatable {
        case ok
        case passcodeNotSet
        case unavailable
    }

    static func passcodeGate() -> PasscodeGate {
        #if targetEnvironment(simulator)
        return .ok
        #else
        var error: NSError?
        if LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) { return .ok }
        if let e = error, let la = e as? LAError, la.code == .passcodeNotSet {
            return .passcodeNotSet
        }
        return .unavailable
        #endif
    }

    enum RegistrationError: Error, Equatable {
        case badUsername
        case badServer
        case usernameTaken
        case clockSkew
        case staleKeys
        case failed(String)
    }

    /// Challenge + register with fresh keys (reused when the server answers 409).
    func register(username rawName: String, server rawServer: String) async throws {
        guard let name = Canonical.username(rawName) else { throw RegistrationError.badUsername }
        guard let origin = APIClient.canonicalOrigin(rawServer) else { throw RegistrationError.badServer }
        let keys: IdentityKeys = identity ?? IdentityKeys()
        identity = keys
        let sync: MessageSync = makeSync(identity: keys, username: name, origin: origin, token: nil)
        do {
            try await sync.openStore()
            _ = try await sync.register(username: name, deviceId: Identifiers.deviceId())
        } catch SyncError.usernameTaken {
            throw RegistrationError.usernameTaken
        } catch let e as APIError {
            if e.code == "clock_skew" { throw RegistrationError.clockSkew }
            throw RegistrationError.failed(String(describing: e))
        } catch {
            throw RegistrationError.failed(String(describing: error))
        }
        username = name
        serverOrigin = origin
        await attach(sync)
        lock.setEnabled(settings.appLock)
    }

    func finishOnboarding() {
        guard sync != nil else { return }
        phase = .main
    }

    // MARK: - Settings

    func updateSettings(_ new: Settings) async {
        guard let sync else { return }
        do {
            try await sync.updateSettings(new)
        } catch {
            showToast(String(localized: "error.generic", defaultValue: "İşlem başarısız oldu"))
        }
        settings = new
        captureGlue?.reportsEnabled = new.captureReports
        lock.setEnabled(new.appLock)
        if !new.appLock && phase == .locked { phase = .main }
        diagnostics.apply(index: await sync.index())
    }

    // MARK: - Contacts

    func addContact(username rawName: String) async throws {
        guard let name = Canonical.username(rawName) else { throw RegistrationError.badUsername }
        guard let sync else { throw SyncError.notOpen }
        try await sync.addContact(username: name)
        await refresh()
    }

    func acceptRequest(peer: String) async {
        guard let sync else { return }
        try? await sync.setContactFlags(peer: peer, accepted: true, blocked: false)
        await refresh()
    }

    func blockContact(peer: String) async {
        guard let sync else { return }
        try? await sync.setContactFlags(peer: peer, accepted: false, blocked: true)
        await refresh()
    }

    func setVerified(peer: String, verified: Bool) async {
        guard let sync else { return }
        try? await sync.setVerified(peer: peer, verified: verified)
        await refresh()
    }

    func acceptKeyChange(peer: String) async {
        guard let sync else { return }
        do {
            try await sync.acceptKeyChange(peer: peer)
        } catch {
            showToast(String(localized: "error.generic", defaultValue: "İşlem başarısız oldu"))
        }
        await refresh()
    }

    // MARK: - Watermark (§5.9)

    /// Tiles for the conversation with `peer` (nil until a session exists).
    func watermarkTiles(peer: String, displayScale: CGFloat) -> (lighter: CGImage, darker: CGImage)? {
        guard let contact = contacts.first(where: { $0.username == peer }),
              let ws = contact.canonicalWMSecret else { return nil }
        let payload: WatermarkPayload = WatermarkPayload(ws: ws, viewer: username, unix: clock.now)
        return tileCache.tiles(for: payload, displayScale: displayScale)
    }

    /// "@ayse · 21 Eki" (9 % alpha diagonal complement).
    var watermarkVisibleString: String {
        let formatter: DateFormatter = DateFormatter()
        formatter.setLocalizedDateFormatFromTemplate("d MMM")
        return "@" + username + " · " + formatter.string(from: Date())
    }

    // MARK: - Wipe (§5.11)

    /// "Hesabı sil ve sıfırla": server delete, then everything local.
    func deleteAccountAndReset() async {
        guard let sync else { return }
        do {
            try await sync.deleteAccountAndWipe()
        } catch {
            await sync.wipe()
            showToast(String(localized: "reinstall.wiped",
                             defaultValue: "Eski hesap sunucudan silinemedi; bu kullanıcı adı dolu kalabilir"))
        }
        resetAfterWipe()
    }

    /// Wipe prompt after a rolled-back `index.json` (no server call possible without the store).
    func wipeLocal() async {
        guard let sync else { return }
        await sync.wipe()
        resetAfterWipe()
    }

    private func resetAfterWipe() {
        eventTask?.cancel()
        eventTask = nil
        scheduler?.cancel()
        scheduler = nil
        captureGlue = nil
        captureMonitor.onEvent = nil
        sync = nil
        identity = nil
        store = nil
        blobs = nil
        contacts = []
        conversations = []
        settings = Settings()
        conversationVersion = [:]
        username = ""
        serverOrigin = ""
        authInvalid = false
        tileCache.removeAll()
        lock.setEnabled(false)
        phase = .onboarding
    }

    // MARK: - Flicker (§5.10)

    func flickerStopped(_ reason: FlickerMaskView.StopReason) {
        if case .rateTooLow(let hz) = reason { diagnostics.measuredHz = hz }
        guard let text = FlickerReasons.text(reason) else { return }
        diagnostics.flickerStopReason = text
        showToast(text)
    }

    // MARK: - Toasts

    func showToast(_ text: String) {
        toast = text
        toastTask?.cancel()
        toastTask = Task { [weak self] in
            try? await Task.sleep(for: .seconds(4))
            guard !Task.isCancelled else { return }
            self?.toast = nil
        }
    }
}

/// Lets the WebSocket cursor closure reach the sync actor created after it.
final class SyncBox {
    var sync: MessageSync?
    init() {}
}
