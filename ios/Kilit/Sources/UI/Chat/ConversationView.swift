//  ConversationView.swift
//  Kilit — UI/Chat (WP8), §5.2 / §5.5 / §5.6 / §5.9.
//
//  `VStack { CaptureBanner; SecureContainer { ZStack { MessageList;
//  WatermarkOverlay } }.frame(max); ComposerView }` with `ProtectionBadge` in the
//  toolbar. The watermark overlay is the LAST ZStack child inside the hosted
//  content. The composer sits outside the container. `ConversationModel` holds
//  the decrypted messages in memory only while the view is on screen.

import SwiftUI

@MainActor
@Observable
final class ConversationModel {
    let peer: String
    private(set) var messages: [Message] = []
    private(set) var gapIds: Set<String> = []
    private(set) var dimmedIds: Set<String> = []
    var draft: String = ""
    var viewerMessage: Message? = nil
    var errorText: String? = nil

    init(peer: String) {
        self.peer = peer
    }

    func reload(_ app: AppModel) async {
        guard let sync = app.sync else { return }
        let loaded: [Message] = await sync.messages(peer: peer)
        messages = loaded
        gapIds = CaptureGlue.gapRowIds(loaded)
        var dimmed: Set<String> = []
        for m in loaded where m.kind == .capture && m.author == .peer {
            for id in m.capture?.ref ?? [] { dimmed.insert(id) }
        }
        dimmedIds = dimmed
        app.captureGlue?.visibleMessageIds = loaded.filter { $0.isContent }.map { $0.id }
        try? await sync.markConversationRead(peer: peer)
    }

    func sendText(_ app: AppModel) async {
        let text: String = draft.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty, let sync = app.sync else { return }
        draft = ""
        do {
            _ = try await sync.sendText(to: peer, text: text)
        } catch {
            draft = text
            errorText = ConversationModel.describe(error)
        }
    }

    func sendImage(data: Data, _ app: AppModel) async {
        guard let sync = app.sync else { return }
        do {
            let normalized: NormalizedImage = try ImageNormalizer.normalize(pickedData: data)
            _ = try await sync.sendImage(to: peer, image: normalized)
        } catch {
            errorText = ConversationModel.describe(error)
        }
    }

    func setTimer(_ seconds: UInt32, _ app: AppModel) async {
        guard let sync = app.sync else { return }
        do {
            try await sync.setTimer(peer: peer, seconds: seconds)
        } catch {
            errorText = ConversationModel.describe(error)
        }
    }

    func deleteForMe(_ message: Message, _ app: AppModel) async {
        guard let sync = app.sync else { return }
        try? await sync.deleteLocally(peer: peer, ids: [message.id])
    }

    /// The only `ctrl.delete` source (own messages only).
    func deleteForBoth(_ message: Message, _ app: AppModel) async {
        guard message.author == .me, let sync = app.sync else { return }
        do {
            try await sync.deleteForBoth(peer: peer, ids: [message.id])
        } catch {
            errorText = ConversationModel.describe(error)
        }
    }

    static func describe(_ error: Error) -> String {
        if let e = error as? KilitCryptoError, e == .staleSPK {
            return String(localized: "stale_spk", defaultValue: "Sunucu eski bir anahtar sunuyor; daha sonra tekrar deneyin")
        }
        if let e = error as? APIError, e.code == "clock_skew" {
            return String(localized: "clock.skew", defaultValue: "Cihaz saati yanlış. Tarih ve saati düzeltip tekrar deneyin.")
        }
        if let e = error as? SyncError {
            switch e {
            case .keyChangePending:
                return String(localized: "error.key_change_pending", defaultValue: "Önce yeni anahtarı kabul et")
            case .blocked:
                return String(localized: "error.blocked", defaultValue: "Bu kişi engellendi")
            case .notOpen, .usernameTaken, .notRegistered, .unknownContact:
                break
            }
        }
        if error is ImageNormalizerError {
            return String(localized: "error.image", defaultValue: "Fotoğraf işlenemedi")
        }
        return String(localized: "error.send", defaultValue: "Gönderilemedi; daha sonra tekrar denenecek")
    }
}

struct ConversationView: View {
    let peer: String

    @Environment(AppModel.self) private var model: AppModel
    @Environment(\.displayScale) private var displayScale: CGFloat
    @State private var conv: ConversationModel
    @State private var isProtected: Bool = false
    @State private var showingSafety: Bool = false

    init(peer: String) {
        self.peer = peer
        _conv = State(initialValue: ConversationModel(peer: peer))
    }

    private var conversation: Conversation? { model.conversations.first { $0.peer == peer } }
    private var contact: ContactRecord? { model.contacts.first { $0.username == peer } }

    private var canSend: Bool {
        guard let c = contact else { return false }
        return c.accepted && !c.blocked && conversation?.pendingKeyChange == nil && !model.authInvalid
    }

    private var protection: ProtectionState {
        ProtectionState.current(isCaptured: model.isCaptured, isProtected: isProtected)
    }

    var body: some View {
        VStack(spacing: 0) {
            CaptureBanner(state: protection)
            if conversation?.pendingKeyChange != nil {
                keyChangeBanner
            } else if let c = contact, !c.accepted, !c.blocked {
                requestBanner
            }
            SecureContainer(mode: model.secureLayerMode,
                            enabled: model.settings.secureLayer,
                            hidesFromAssistiveTechnologies: model.settings.accessibilityHide,
                            onProtectionChange: { ok in
                                isProtected = ok
                                model.diagnostics.secureCanvasAvailable = ok
                            }) {
                ZStack {
                    if model.isCaptured {
                        CaptureHiddenView()
                    } else {
                        messageList
                    }
                    if let tiles = model.watermarkTiles(peer: peer, displayScale: displayScale) {
                        WatermarkOverlay(lighter: tiles.lighter, darker: tiles.darker,
                                         phase: model.watermarkPhase, visibleString: model.watermarkVisibleString)
                    }
                }
                .clipped()
                .environment(model)
                .environment(model.reveal)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            if let text = conv.errorText {
                Text(text)
                    .font(.footnote)
                    .foregroundStyle(.red)
                    .padding(.horizontal, 12)
                    .onTapGesture { conv.errorText = nil }
            }
            ComposerView(text: $conv.draft, isEnabled: canSend,
                         onSend: { Task { await conv.sendText(model) } },
                         onImage: { data in Task { await conv.sendImage(data: data, model) } })
        }
        .background(KilitPalette.background)
        .navigationTitle(peer)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                ProtectionBadge(state: protection)
            }
            ToolbarItem(placement: .topBarTrailing) {
                Menu {
                    Section(String(localized: "timer.section", defaultValue: "Kaybolan mesajlar")) {
                        ForEach(TimerOptions.all, id: \.self) { seconds in
                            Button {
                                Task { await conv.setTimer(seconds, model) }
                            } label: {
                                if (conversation?.timer ?? 0) == seconds {
                                    Label(TimerOptions.label(seconds), systemImage: "checkmark")
                                } else {
                                    Text(TimerOptions.label(seconds))
                                }
                            }
                        }
                    }
                    Button {
                        showingSafety = true
                    } label: {
                        Label(String(localized: "keychange.verify", defaultValue: "Güvenlik numarasını göster"),
                              systemImage: "number")
                    }
                } label: {
                    Image(systemName: "ellipsis.circle")
                }
            }
        }
        .fullScreenCover(item: $conv.viewerMessage) { message in
            ProtectedImageViewer(message: message, peer: peer)
                .environment(model)
        }
        .sheet(isPresented: $showingSafety) {
            SafetyNumberView(peer: peer)
                .environment(model)
        }
        .task(id: model.conversationVersion[peer] ?? 0) {
            await conv.reload(model)
        }
        .onAppear {
            model.captureGlue?.activePeer = peer
        }
        .task {
            // The canary reports only transitions; give it a second before concluding "unavailable".
            try? await Task.sleep(for: .seconds(1))
            reportBlankingIfNeeded()
        }
        .onDisappear {
            if model.captureGlue?.activePeer == peer { model.captureGlue?.activePeer = nil }
            model.reveal.endAll()
        }
        .onChange(of: isProtected) { _, _ in
            reportBlankingIfNeeded()
        }
    }

    // MARK: - List

    private var messageList: some View {
        List {
            ForEach(conv.messages) { message in
                MessageRow(message: message, peer: peer,
                           isGap: conv.gapIds.contains(message.id),
                           isDimmed: conv.dimmedIds.contains(message.id),
                           flickerEnabled: model.settings.flicker,
                           onOpenImage: { m in conv.viewerMessage = m },
                           onDeleteForMe: { m in Task { await conv.deleteForMe(m, model) } },
                           onDeleteForBoth: { m in Task { await conv.deleteForBoth(m, model) } })
            }
            if conv.messages.isEmpty {
                Text(String(localized: "capture.none", defaultValue: "Bildirilen ekran görüntüsü yok"))
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity)
                    .listRowBackground(Color.clear)
                    .listRowSeparator(.hidden)
            }
        }
        .listStyle(.plain)
        .scrollContentBackground(.hidden)
        .background(KilitPalette.background)
        .defaultScrollAnchor(.bottom)
    }

    // MARK: - Banners (§10.3)

    private var keyChangeBanner: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(String(localized: "keychange.banner",
                        defaultValue: "Güvenlik numarası değişti. \(peer) yeni bir cihaz ya da kimlik kullanıyor olabilir. Göndermeden önce doğrulayın."))
                .font(.footnote)
            HStack {
                Button(String(localized: "keychange.accept", defaultValue: "Yeni anahtarı kabul et")) {
                    Task { await model.acceptKeyChange(peer: peer) }
                }
                .buttonStyle(.borderedProminent)
                Button(String(localized: "keychange.verify", defaultValue: "Güvenlik numarasını göster")) {
                    showingSafety = true
                }
                .buttonStyle(.bordered)
            }
            .font(.footnote)
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.yellow.opacity(0.18))
    }

    private var requestBanner: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(String(localized: "request.banner", defaultValue: "Bilinmeyen gönderen"))
                .font(.footnote.bold())
            HStack {
                Button(String(localized: "request.accept", defaultValue: "Kabul et")) {
                    Task { await model.acceptRequest(peer: peer) }
                }
                .buttonStyle(.borderedProminent)
                Button(String(localized: "request.block", defaultValue: "Engelle"), role: .destructive) {
                    Task { await model.blockContact(peer: peer) }
                }
                .buttonStyle(.bordered)
            }
            .font(.footnote)
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.blue.opacity(0.15))
    }

    // MARK: - blanking_unavailable (§3.4: once per launch per peer)

    private func reportBlankingIfNeeded() {
        guard !isProtected, let glue = model.captureGlue else { return }
        if glue.markBlankingReport(peer: peer) {
            model.captureMonitor.reportBlankingUnavailable()
        }
    }
}
