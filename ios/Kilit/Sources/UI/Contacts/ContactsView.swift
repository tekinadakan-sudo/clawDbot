//  ContactsView.swift
//  Kilit — UI/Contacts (WP8), §5.2 / §10.3.
//
//  Conversation list (one per contact, ordered by local activity), message
//  requests ("Bilinmeyen gönderen" → Kabul et / Engelle), key-change state,
//  add by username (`GET /v1/users/{name}`), Settings sheet.

import SwiftUI

struct ContactsView: View {
    @Environment(AppModel.self) private var model: AppModel
    @State private var showingAdd: Bool = false
    @State private var showingSettings: Bool = false

    private var requests: [ContactRecord] { model.contacts.filter { !$0.accepted && !$0.blocked } }
    private var accepted: [ContactRecord] {
        model.contacts.filter { $0.accepted && !$0.blocked }.sorted { a, b in
            activity(a.username) > activity(b.username)
        }
    }
    private var blocked: [ContactRecord] { model.contacts.filter { $0.blocked } }

    private func activity(_ peer: String) -> UInt64 {
        model.conversations.first { $0.peer == peer }?.lastActivityAt ?? 0
    }

    var body: some View {
        List {
            if model.authInvalid {
                Section {
                    Text(String(localized: "auth.invalid",
                                defaultValue: "Oturum geçersiz; sunucu bu cihazı tanımıyor. Hesabı sil ve sıfırla gerekebilir."))
                        .font(.footnote)
                        .foregroundStyle(.red)
                }
            }
            if !requests.isEmpty {
                Section(String(localized: "contacts.requests", defaultValue: "Mesaj istekleri")) {
                    ForEach(requests, id: \.username) { contact in
                        requestRow(contact)
                    }
                }
            }
            Section(String(localized: "contacts.title", defaultValue: "Sohbetler")) {
                if accepted.isEmpty {
                    Text(String(localized: "contacts.empty", defaultValue: "Henüz kişi yok. Kullanıcı adıyla ekle."))
                        .foregroundStyle(.secondary)
                }
                ForEach(accepted, id: \.username) { contact in
                    NavigationLink(value: contact.username) {
                        contactRow(contact)
                    }
                }
            }
            if !blocked.isEmpty {
                Section(String(localized: "contacts.blocked", defaultValue: "Engellenenler")) {
                    ForEach(blocked, id: \.username) { contact in
                        HStack {
                            Text(contact.username)
                            Spacer()
                            Button(String(localized: "contacts.unblock", defaultValue: "Engeli kaldır")) {
                                Task { await model.acceptRequest(peer: contact.username) }
                            }
                            .font(.footnote)
                        }
                    }
                }
            }
        }
        .navigationTitle("Kilit")
        .navigationDestination(for: String.self) { peer in
            ConversationView(peer: peer)
        }
        .toolbar {
            ToolbarItem(placement: .topBarLeading) {
                Button {
                    showingSettings = true
                } label: {
                    Image(systemName: "gearshape")
                }
                .accessibilityLabel(String(localized: "settings.title", defaultValue: "Ayarlar"))
            }
            ToolbarItem(placement: .topBarTrailing) {
                HStack(spacing: 12) {
                    connectionDot
                    Button {
                        showingAdd = true
                    } label: {
                        Image(systemName: "person.badge.plus")
                    }
                    .accessibilityLabel(String(localized: "contacts.add", defaultValue: "Kişi ekle"))
                }
            }
        }
        .sheet(isPresented: $showingAdd) {
            AddContactSheet()
                .environment(model)
        }
        .sheet(isPresented: $showingSettings) {
            SettingsView()
                .environment(model)
        }
        .refreshable {
            await model.refresh()
        }
    }

    private var connectionDot: some View {
        let live: Bool
        if case .live = model.connection { live = true } else { live = false }
        return Circle()
            .fill(live ? Color.green : Color.gray)
            .frame(width: 8, height: 8)
            .accessibilityLabel(live
                                ? String(localized: "connection.live", defaultValue: "Bağlı")
                                : String(localized: "connection.down", defaultValue: "Bağlantı yok"))
    }

    private func contactRow(_ contact: ContactRecord) -> some View {
        let conversation: Conversation? = model.conversations.first { $0.peer == contact.username }
        return HStack {
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(contact.username).font(.body)
                    if contact.verified {
                        Image(systemName: "checkmark.seal.fill").foregroundStyle(.green).font(.caption)
                    }
                    if conversation?.pendingKeyChange != nil {
                        Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.yellow).font(.caption)
                    }
                }
                if let t = conversation?.timer, t > 0 {
                    Label(TimerOptions.label(t), systemImage: "timer")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            Spacer()
            if let unread = conversation?.unreadCount, unread > 0 {
                Text(String(unread))
                    .font(.caption.bold())
                    .padding(.horizontal, 8)
                    .padding(.vertical, 2)
                    .background(Color.accentColor, in: Capsule())
                    .foregroundStyle(.white)
            }
        }
    }

    private func requestRow(_ contact: ContactRecord) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text(contact.username).font(.body)
                Spacer()
                Text(String(localized: "request.banner", defaultValue: "Bilinmeyen gönderen"))
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            HStack {
                Button(String(localized: "request.accept", defaultValue: "Kabul et")) {
                    Task { await model.acceptRequest(peer: contact.username) }
                }
                .buttonStyle(.borderedProminent)
                Button(String(localized: "request.block", defaultValue: "Engelle"), role: .destructive) {
                    Task { await model.blockContact(peer: contact.username) }
                }
                .buttonStyle(.bordered)
                Spacer()
                NavigationLink(value: contact.username) {
                    Text(String(localized: "request.open", defaultValue: "Aç"))
                }
                .font(.footnote)
            }
            .font(.footnote)
        }
        .padding(.vertical, 4)
    }
}

struct AddContactSheet: View {
    @Environment(AppModel.self) private var model: AppModel
    @Environment(\.dismiss) private var dismiss: DismissAction
    @State private var username: String = ""
    @State private var errorText: String? = nil
    @State private var working: Bool = false

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField(String(localized: "contacts.username", defaultValue: "kullanıcı adı"), text: $username)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled(true)
                        .keyboardType(.asciiCapable)
                } footer: {
                    Text(String(localized: "contacts.add.footer",
                                defaultValue: "Küçük harf, rakam ve alt çizgi; 3–32 karakter. Kimlik anahtarları sunucudan alınır; güvenlik numarasını karşılaştırarak doğrula."))
                }
                if let errorText {
                    Text(errorText).foregroundStyle(.red).font(.footnote)
                }
            }
            .navigationTitle(String(localized: "contacts.add", defaultValue: "Kişi ekle"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(String(localized: "common.cancel", defaultValue: "Vazgeç")) { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button(String(localized: "contacts.add.action", defaultValue: "Ekle")) {
                        add()
                    }
                    .disabled(working || username.isEmpty)
                }
            }
        }
    }

    private func add() {
        working = true
        errorText = nil
        Task {
            do {
                try await model.addContact(username: username)
                dismiss()
            } catch let e as AppModel.RegistrationError where e == .badUsername {
                errorText = String(localized: "onboarding.bad_username", defaultValue: "Geçersiz kullanıcı adı")
            } catch let e as APIError where e.status == 404 {
                errorText = String(localized: "contacts.not_found", defaultValue: "Kullanıcı bulunamadı")
            } catch {
                errorText = String(localized: "error.network", defaultValue: "Sunucuya ulaşılamadı")
            }
            working = false
        }
    }
}

// MARK: - Contact operations the UI needs (actor-isolated, same module)

extension MessageSync {
    /// Add by username: `GET /v1/users/{name}`, verify the binding, store an accepted contact.
    func addContact(username name: String) async throws {
        guard store.isOpen else { throw SyncError.notOpen }
        let user: UserResponse = try await api.lookup(username: name)
        try user.verifyBinding()
        let now: UInt64 = clock.now
        var record: ContactRecord = store.index.contact(name)
            ?? ContactRecord(username: name, identity: user.identity, verified: false, accepted: true)
        if record.identity != user.identity {
            // Key change detected on fetch: banner, sending disabled until accepted.
            let pending: IdentityPublicKeys = user.identity
            try store.commitIndex { idx in
                let i: Int = idx.conversationIndex(name, now: now)
                idx.conversations[i].pendingKeyChange = pending
            }
            emit(.keyChangeDetected(peer: name))
            return
        }
        record.accepted = true
        record.blocked = false
        let updated: ContactRecord = record
        try store.commitIndex { idx in
            idx.upsertContact(updated)
            _ = idx.conversationIndex(name, now: now)
        }
        emit(.contactsChanged)
    }

    /// Message request: "Kabul et" / "Engelle".
    func setContactFlags(peer: String, accepted: Bool, blocked: Bool) throws {
        guard store.isOpen else { throw SyncError.notOpen }
        guard var record = store.index.contact(peer) else { throw SyncError.unknownContact(peer) }
        record.accepted = accepted
        record.blocked = blocked
        let updated: ContactRecord = record
        try store.commitIndex { idx in idx.upsertContact(updated) }
        emit(.contactsChanged)
        if accepted {
            Task { [weak self] in
                await self?.pumpOutbox()
            }
        }
    }

    /// "Doğrulandı" after comparing safety numbers.
    func setVerified(peer: String, verified: Bool) throws {
        guard store.isOpen else { throw SyncError.notOpen }
        guard var record = store.index.contact(peer) else { throw SyncError.unknownContact(peer) }
        record.verified = verified
        let updated: ContactRecord = record
        try store.commitIndex { idx in idx.upsertContact(updated) }
        emit(.contactsChanged)
    }
}
