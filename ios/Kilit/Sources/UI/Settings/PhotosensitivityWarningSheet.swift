//  PhotosensitivityWarningSheet.swift
//  Kilit — UI/Settings (WP8), §5.10 / §10.5.
//
//  Presented EVERY time flicker is enabled: `interactiveDismissDisabled`,
//  "Kapalı bırak" is the cancel/default, "Aç" is destructive. Copy verbatim
//  from docs/COPY.md §10.5.

import SwiftUI

struct PhotosensitivityWarningSheet: View {
    let onKeepOff: () -> Void
    let onTurnOn: () -> Void

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    Label(String(localized: "photosensitivity.title", defaultValue: "Fotosensitivite uyarısı"),
                          systemImage: "exclamationmark.triangle.fill")
                        .font(.title2.bold())
                        .foregroundStyle(.red)
                    Text(String(localized: "photosensitivity.body",
                                defaultValue: "Titreşim Kalkanı mesaj içeriğinin üzerinde iki ince desen arasında saniyede 120 kez geçiş yapar (saniyede 60 tam döngü). Hızla yanıp sönen görüntüler fotosensitif epilepsisi olan kişilerde nöbeti tetikleyebilir; diğer kişilerde göz yorgunluğu, baş ağrısı, baş dönmesi veya bulantıya yol açabilir. Sizde ya da ekranınızı görebilecek birinde nöbet geçmişi varsa bu özelliği açmayın. Kendinizi kötü hissederseniz hemen kapatın. Bu deneysel bir caydırıcıdır; ekranınızın fotoğraflanmasını veya kaydedilmesini engellemez."))
                        .font(.body)
                    VStack(spacing: 12) {
                        Button {
                            onKeepOff()
                        } label: {
                            Text(String(localized: "photosensitivity.keep_off", defaultValue: "Kapalı bırak"))
                                .frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.borderedProminent)
                        .keyboardShortcut(.cancelAction)
                        Button(role: .destructive) {
                            onTurnOn()
                        } label: {
                            Text(String(localized: "photosensitivity.turn_on", defaultValue: "Aç"))
                                .frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.bordered)
                    }
                    .padding(.top, 8)
                }
                .padding(20)
            }
            .navigationTitle(String(localized: "experimental.title", defaultValue: "Deneysel"))
            .navigationBarTitleDisplayMode(.inline)
        }
        .interactiveDismissDisabled(true)
    }
}

/// §10.6: "Korumalı içeriği erişilebilirlikten gizle" warning.
struct AccessibilityHideWarningSheet: View {
    let onCancel: () -> Void
    let onHide: () -> Void

    var body: some View {
        NavigationStack {
            VStack(alignment: .leading, spacing: 16) {
                Text(String(localized: "a11y.hide.body",
                            defaultValue: "Bu ayar korumalı mesaj ve fotoğrafları VoiceOver, Ekranı Seslendir ve diğer yardımcı teknolojilerden gizler. VoiceOver kullanıyorsanız mesajları okuyamazsınız. Sesli okumanın bir mikrofonla kaydedilmesini zorlaştırır; başka bir koruma sağlamaz."))
                Button {
                    onCancel()
                } label: {
                    Text(String(localized: "a11y.hide.cancel", defaultValue: "Vazgeç"))
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                Button(role: .destructive) {
                    onHide()
                } label: {
                    Text(String(localized: "a11y.hide.confirm", defaultValue: "Gizle"))
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered)
                Spacer()
            }
            .padding(20)
            .navigationTitle(String(localized: "settings.a11y_hide", defaultValue: "Korumalı içeriği erişilebilirlikten gizle"))
            .navigationBarTitleDisplayMode(.inline)
        }
        .interactiveDismissDisabled(true)
    }
}
