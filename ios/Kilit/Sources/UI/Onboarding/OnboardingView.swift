//  OnboardingView.swift
//  Kilit — UI/Onboarding (WP8), §5.11 / §10.1 / §10.4.
//
//  Welcome → PasscodeGate (`canEvaluatePolicy`; `.passcodeNotSet` blocks;
//  skipped on Simulator) → username + server URL → challenge + register →
//  three explanation cards (copy verbatim from docs/COPY.md) → Done.
//  No notification permission is requested.

import SwiftUI

struct OnboardingView: View {
    @Environment(AppModel.self) private var model: AppModel

    enum Step: Int {
        case welcome, passcode, account, card1, card2, card3, done
    }

    @State private var step: Step = .welcome
    @State private var username: String = ""
    @State private var server: String = ""
    @State private var errorText: String? = nil
    @State private var working: Bool = false

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    stepContent
                }
                .padding(24)
            }
            footer
        }
        .background(KilitPalette.background)
    }

    @ViewBuilder
    private var stepContent: some View {
        switch step {
        case .welcome:
            Text("Kilit").font(.largeTitle.bold())
            Text(String(localized: "onboarding.welcome",
                        defaultValue: "Uçtan uca şifreli, ekran yakalamaya karşı sertleştirilmiş birebir mesajlaşma. Devam etmeden önce birkaç şeyi bilmen gerekir."))
        case .passcode:
            Text(String(localized: "onboarding.passcode.title", defaultValue: "Cihaz parolası gerekir"))
                .font(.title2.bold())
            Text(String(localized: "onboarding.passcode.body",
                        defaultValue: "Kilit, anahtarları ve mesajları cihaz parolasıyla korunan depoda tutar. Parolası olmayan cihazlarda anlamlı bir veri koruması yoktur; kayıt bu cihazlarda reddedilir. Ayarlar › Face ID ve Parola bölümünden bir parola belirle."))
            if AppModel.passcodeGate() == .passcodeNotSet {
                Label(String(localized: "onboarding.passcode.blocked", defaultValue: "Parola ayarlı değil"),
                      systemImage: "xmark.octagon.fill")
                    .foregroundStyle(.red)
            } else {
                Label(String(localized: "onboarding.passcode.ok", defaultValue: "Parola ayarlı"),
                      systemImage: "checkmark.circle.fill")
                    .foregroundStyle(.green)
            }
        case .account:
            Text(String(localized: "onboarding.account.title", defaultValue: "Hesap"))
                .font(.title2.bold())
            TextField(String(localized: "contacts.username", defaultValue: "kullanıcı adı"), text: $username)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled(true)
                .keyboardType(.asciiCapable)
                .textFieldStyle(.roundedBorder)
            TextField(String(localized: "onboarding.server", defaultValue: "https://sunucu.example.com"), text: $server)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled(true)
                .keyboardType(.URL)
                .textFieldStyle(.roundedBorder)
            Text(String(localized: "onboarding.account.footer",
                        defaultValue: "Sunucu adresi kayıttan sonra değiştirilemez (yalnızca \"Hesabı sil ve sıfırla\" ile). Kullanıcı adı: küçük harf, rakam, alt çizgi; 3–32 karakter. Anahtarları kaybolan bir kullanıcı adı sahibi tarafından geri alınamaz."))
                .font(.footnote)
                .foregroundStyle(.secondary)
            if let errorText {
                Text(errorText).foregroundStyle(.red).font(.footnote)
            }
        case .card1:
            Text(String(localized: "onboarding.card1.title", defaultValue: "Ne karartılır, ne algılanır"))
                .font(.title2.bold())
            Text(String(localized: "onboarding.card1.body",
                        defaultValue: "Mesajlar ve fotoğraflar, iOS'un ekran görüntüsünde, ekran kaydında ve AirPlay'de kararttığı özel bir katmanda gösterilir. Bu, iOS'un belgelenmemiş bir davranışına dayanır ve gelecekte çalışmayabilir; çalışmadığında üstteki rozet sarıya döner ve yalnızca algılama kalır. Ekran kaydı başladığında içerik gizlenir; ekran görüntüsü alındığında bu sonradan algılanır."))
        case .card2:
            Text(String(localized: "onboarding.card2.title", defaultValue: "Bildirimler iki yönlüdür"))
                .font(.title2.bold())
            Text(String(localized: "onboarding.card2.body",
                        defaultValue: "Sen ekran görüntüsü aldığında ya da ekranını kaydettiğinde karşı taraf bunu görür; karşı taraf yaptığında sen görürsün. Bu olaylar yalnızca şifreli kanaldan gider; sunucu bunları göremez. Bu kayıt tutma, uygulamayı kullanarak kabul ettiğin bir özelliktir ve Ayarlar'dan kapatılabilir."))
        case .card3:
            Text(String(localized: "onboarding.card3.title", defaultValue: "Sınırlar"))
                .font(.title2.bold())
            LimitsList()
        case .done:
            Text(String(localized: "onboarding.done.title", defaultValue: "Hazır"))
                .font(.title2.bold())
            Text(String(localized: "onboarding.done.body",
                        defaultValue: "Kişileri kullanıcı adıyla ekle ve güvenlik numaralarını karşılaştır."))
        }
    }

    private var footer: some View {
        HStack {
            if step != .welcome && step != .done && step.rawValue <= Step.account.rawValue {
                Button(String(localized: "common.back", defaultValue: "Geri")) {
                    if let previous = Step(rawValue: step.rawValue - 1) { step = previous }
                }
                .buttonStyle(.bordered)
            }
            Spacer()
            Button {
                advance()
            } label: {
                if working {
                    ProgressView()
                } else {
                    Text(nextTitle).frame(minWidth: 120)
                }
            }
            .buttonStyle(.borderedProminent)
            .disabled(!canAdvance || working)
        }
        .padding(16)
    }

    private var nextTitle: String {
        switch step {
        case .account: return String(localized: "onboarding.register", defaultValue: "Kaydol")
        case .done: return String(localized: "onboarding.finish", defaultValue: "Başla")
        case .welcome, .passcode, .card1, .card2, .card3:
            return String(localized: "common.next", defaultValue: "Devam")
        }
    }

    private var canAdvance: Bool {
        switch step {
        case .passcode: return AppModel.passcodeGate() != .passcodeNotSet
        case .account: return !username.isEmpty && !server.isEmpty
        case .welcome, .card1, .card2, .card3, .done: return true
        }
    }

    private func advance() {
        switch step {
        case .account:
            register()
        case .done:
            model.finishOnboarding()
        case .welcome, .passcode, .card1, .card2, .card3:
            if let next = Step(rawValue: step.rawValue + 1) { step = next }
        }
    }

    private func register() {
        working = true
        errorText = nil
        Task {
            do {
                try await model.register(username: username, server: server)
                step = .card1
            } catch let e as AppModel.RegistrationError {
                switch e {
                case .badUsername:
                    errorText = String(localized: "onboarding.bad_username", defaultValue: "Geçersiz kullanıcı adı")
                case .badServer:
                    errorText = String(localized: "onboarding.bad_server", defaultValue: "Geçersiz sunucu adresi")
                case .usernameTaken:
                    errorText = String(localized: "onboarding.taken", defaultValue: "Bu kullanıcı adı dolu")
                case .clockSkew:
                    errorText = String(localized: "clock.skew",
                                       defaultValue: "Cihaz saati yanlış. Tarih ve saati düzeltip tekrar deneyin.")
                case .staleKeys:
                    errorText = String(localized: "stale_spk",
                                       defaultValue: "Sunucu eski bir anahtar sunuyor; daha sonra tekrar deneyin")
                case .failed:
                    errorText = String(localized: "error.network", defaultValue: "Sunucuya ulaşılamadı")
                }
            } catch {
                errorText = String(localized: "error.network", defaultValue: "Sunucuya ulaşılamadı")
            }
            working = false
        }
    }
}

/// The ten limits of §10.4, verbatim (card 3, also linked from Settings).
struct LimitsList: View {
    static let items: [String] = [
        String(localized: "limits.1", defaultValue: "Ekrana tutulan ikinci bir kamera engellenemez. Filigran kimlik tespiti sağlar, titreşim caydırıcıdır, basılı tutarak gösterme açıkta kalan alanı küçültür. \"Kaydedilemez\" demiyoruz."),
        String(localized: "limits.2", defaultValue: "Ekran görüntüsü/kayıt karartması, iOS'un belgelenmemiş bir davranışına dayanır; bayrakla korunur, sürekli denetlenir ve gelecekte çalışmayabilir. Sonradan algılama garanti edilen taban çizgisidir. Yazdığın ama göndermediğin taslak karartılmaz."),
        String(localized: "limits.3", defaultValue: "Ekran görüntüsü bildirimi görüntü kaydedildikten sonra gelir; kayıt başladıktan sonraki ilk kareler yakalanabilir; macOS iPhone Yansıtma her iki mekanizmayı da atlayabilir."),
        String(localized: "limits.4", defaultValue: "Jailbreak'li ya da değiştirilmiş bir karşı taraf uygulaması süreleri yok sayabilir, bildirimleri bastırabilir ve içeriği saklayabilir. Ekranda \"bildirilmedi\" yazar, \"alınmadı\" değil."),
        String(localized: "limits.5", defaultValue: "Sunucu ve ağ, kimin kiminle ne zaman ve ne büyüklükte konuştuğunu, oturum kurulumlarını ve mesaj sayaçlarını görür."),
        String(localized: "limits.6", defaultValue: "Parolası olmayan cihazlarda anlamlı bir veri koruması yoktur; kayıt bu cihazlarda reddedilir."),
        String(localized: "limits.7", defaultValue: "Titreşim panel yenileme hızını aşamaz; 1/60 s ve üzeri pozlama, iki kareli seri çekim ya da video içeriği geri getirir; 60 Hz panellerde kapalıdır."),
        String(localized: "limits.8", defaultValue: "Birebir sohbette iki taraf da diğerinin filigran etiketini hesaplayabilir; filigran kanıt değil, ipucudur."),
        String(localized: "limits.9", defaultValue: "VoiceOver / Ekranı Seslendir içeriği sesli okur ve herhangi bir mikrofonla kaydedilebilir; isteğe bağlı bir ayar erişilebilirlik pahasına içeriği gizler."),
        String(localized: "limits.10", defaultValue: "Grup, ses, video, çoklu cihaz, hesap kurtarma (yeni telefon = yeni kimlik = \"güvenlik numarası değişti\"), bildirim içeriği yok. Mesajlar uygulama açıkken gelir."),
    ]

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            ForEach(Array(LimitsList.items.enumerated()), id: \.offset) { pair in
                HStack(alignment: .top, spacing: 8) {
                    Text(String(pair.offset + 1) + ".")
                        .font(.footnote.monospacedDigit())
                        .foregroundStyle(.secondary)
                    Text(pair.element)
                        .font(.footnote)
                }
            }
        }
    }
}
