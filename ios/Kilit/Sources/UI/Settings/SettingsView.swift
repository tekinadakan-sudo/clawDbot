//  SettingsView.swift
//  Kilit — UI/Settings (WP8), §5.11 / §10.6 / §10.7.
//
//  Default timer (off), app lock (on), secure layer (on) + mode, capture
//  reports to peer (on, disclosed), read receipts (off), accessibility hide
//  (off, warning sheet), Deneysel, Tanılama, server URL (read-only), Sınırlar,
//  "Hesabı sil ve sıfırla".

import SwiftUI

struct SettingsView: View {
    @Environment(AppModel.self) private var model: AppModel
    @Environment(\.dismiss) private var dismiss: DismissAction
    @State private var showingA11yWarning: Bool = false
    @State private var confirmingDelete: Bool = false
    @State private var deleting: Bool = false

    var body: some View {
        NavigationStack {
            Form {
                Section(String(localized: "settings.account", defaultValue: "Hesap")) {
                    LabeledContent(String(localized: "contacts.username", defaultValue: "kullanıcı adı"), value: model.username)
                    LabeledContent(String(localized: "settings.server", defaultValue: "Sunucu"), value: model.serverOrigin)
                }
                Section(String(localized: "timer.section", defaultValue: "Kaybolan mesajlar")) {
                    Picker(String(localized: "settings.default_timer", defaultValue: "Varsayılan süre"),
                           selection: binding(\.defaultTimer)) {
                        ForEach(TimerOptions.all, id: \.self) { seconds in
                            Text(TimerOptions.label(seconds)).tag(seconds)
                        }
                    }
                }
                Section {
                    Toggle(String(localized: "settings.app_lock", defaultValue: "Uygulama kilidi"), isOn: binding(\.appLock))
                    Toggle(String(localized: "settings.secure_layer", defaultValue: "Güvenli katman (karartma)"),
                           isOn: binding(\.secureLayer))
                    Picker(String(localized: "settings.secure_mode", defaultValue: "Karartma yöntemi"),
                           selection: binding(\.secureLayerMode)) {
                        Text(String(localized: "settings.mode.canvas", defaultValue: "Güvenli tuval (varsayılan)"))
                            .tag(SecureLayerMode.canvas.rawValue)
                        Text(String(localized: "settings.mode.layer_swap", defaultValue: "Katman değişimi"))
                            .tag(SecureLayerMode.layerSwap.rawValue)
                    }
                    .disabled(!model.settings.secureLayer)
                } header: {
                    Text(String(localized: "settings.protection", defaultValue: "Koruma"))
                } footer: {
                    Text(String(localized: "settings.secure_layer.footer",
                                defaultValue: "Karartma iOS'un belgelenmemiş bir davranışına dayanır; çalışmadığında rozet sarıya döner ve yalnızca algılama kalır."))
                }
                Section {
                    Toggle(String(localized: "settings.capture_reports", defaultValue: "Ekran yakalamayı karşı tarafa bildir"),
                           isOn: binding(\.captureReports))
                    Toggle(String(localized: "settings.read_receipts", defaultValue: "Okundu bilgisi"), isOn: binding(\.readReceipts))
                } footer: {
                    Text(String(localized: "settings.capture_reports.footer",
                                defaultValue: "Açıkken, aldığın ekran görüntüleri ve ekran kayıtları yerel olarak kaydedilir ve karşı tarafa şifreli olarak bildirilir."))
                }
                Section {
                    Toggle(isOn: Binding(
                        get: { model.settings.accessibilityHide },
                        set: { on in
                            if on { showingA11yWarning = true } else { set(\.accessibilityHide, false) }
                        })) {
                        Text(String(localized: "settings.a11y_hide", defaultValue: "Korumalı içeriği erişilebilirlikten gizle"))
                    }
                } footer: {
                    Text(String(localized: "settings.a11y_hide.footer",
                                defaultValue: "Varsayılan kapalı; VoiceOver'ı bozar ve bunu söyler."))
                }
                Section {
                    NavigationLink(String(localized: "experimental.title", defaultValue: "Deneysel")) {
                        ExperimentalView()
                    }
                    NavigationLink(String(localized: "diagnostics.title", defaultValue: "Tanılama")) {
                        DiagnosticsView()
                    }
                    NavigationLink(String(localized: "onboarding.card3.title", defaultValue: "Sınırlar")) {
                        ScrollView {
                            LimitsList().padding()
                        }
                        .navigationTitle(String(localized: "onboarding.card3.title", defaultValue: "Sınırlar"))
                    }
                }
                Section {
                    Button(role: .destructive) {
                        confirmingDelete = true
                    } label: {
                        Text(String(localized: "settings.delete_account", defaultValue: "Hesabı sil ve sıfırla"))
                    }
                    .disabled(deleting)
                } footer: {
                    Text(String(localized: "settings.delete_account.footer",
                                defaultValue: "Sunucudaki hesabı siler, kullanıcı adını serbest bırakır ve bu cihazdaki tüm mesajları, anahtarları ve ayarları yok eder."))
                }
            }
            .navigationTitle(String(localized: "settings.title", defaultValue: "Ayarlar"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button(String(localized: "common.ok", defaultValue: "Tamam")) { dismiss() }
                }
            }
            .confirmationDialog(String(localized: "settings.delete_account", defaultValue: "Hesabı sil ve sıfırla"),
                                isPresented: $confirmingDelete, titleVisibility: .visible) {
                Button(String(localized: "settings.delete_account.confirm", defaultValue: "Sil"), role: .destructive) {
                    deleting = true
                    Task {
                        await model.deleteAccountAndReset()
                        deleting = false
                        dismiss()
                    }
                }
                Button(String(localized: "common.cancel", defaultValue: "Vazgeç"), role: .cancel) {}
            }
            .sheet(isPresented: $showingA11yWarning) {
                AccessibilityHideWarningSheet(
                    onCancel: { showingA11yWarning = false },
                    onHide: {
                        showingA11yWarning = false
                        set(\.accessibilityHide, true)
                    })
            }
        }
    }

    // MARK: - Bindings into `Settings`

    private func binding<T: Equatable>(_ keyPath: WritableKeyPath<Settings, T>) -> Binding<T> {
        Binding(
            get: { model.settings[keyPath: keyPath] },
            set: { value in set(keyPath, value) })
    }

    private func set<T: Equatable>(_ keyPath: WritableKeyPath<Settings, T>, _ value: T) {
        var s: Settings = model.settings
        guard s[keyPath: keyPath] != value else { return }
        s[keyPath: keyPath] = value
        Task { await model.updateSettings(s) }
    }
}
