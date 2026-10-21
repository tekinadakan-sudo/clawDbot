# Kilit — TestFlight'a yükleme (Mac mini)

Bu rehber, Kilit'i sahibin Mac mini'sinden TestFlight'a yükleyip iki iPhone'da denemek için gereken her adımı sırayla verir. Yerel bir Claude oturumu da bu dosyayı izleyebilir. **Kalın yazılı adımlar sahibin kararını ya da Apple hesabını gerektirir;** oturum bu adımlarda durup sorar.

Durum: `claude/anti-recording-ios-app` dalı GitHub Actions'ta (macOS, Xcode 16.4) derleniyor ve 158/158 birim testi geçiyor. Simge, `PrivacyInfo.xcprivacy` ve bundle ID (`com.carwan.kilit`) hazır.

## 0. Ön koşullar

- Xcode 16.x (16.4 önerilir) ve Xcode → Settings → Accounts'ta Apple Developer hesabı ekli.
- Ücretli Apple Developer Program üyeliği.
- Go 1.24+ (sunucu için): `brew install go`.
- HTTPS tüneli için `brew install cloudflared` **veya** Tailscale (aşağıda §1).
- Repo: `git clone https://github.com/tekinadakan-sudo/clawDbot && cd clawDbot && git checkout claude/anti-recording-ios-app`.

## 1. Sunucu (TestFlight derlemesi yalnızca HTTPS'e bağlanır)

TestFlight Release yapılandırmasıyla derlenir; Release'de ATS istisnası yoktur, yani `http://192.168…` çalışmaz. Sunucuya bir HTTPS adresi gerekir. Seçenekler:

| Seçenek | Adres | Artı | Eksi |
|---|---|---|---|
| A. Cloudflare hızlı tünel | `https://<rastgele>.trycloudflare.com` | 1 dakikada hazır, hesap gerekmez | Adres her başlatmada değişir. Kayıtlar adrese bağlı olduğu için hesaplar her seferinde yeniden açılır. Yalnızca ilk duman testi için uygun. |
| B. Tailscale Funnel | `https://<makine>.<tailnet>.ts.net` | Sabit adres, ücretsiz | Tailscale hesabı gerekir. |
| C. VPS + alan adı (`server/docker-compose.yml` + Caddy) | `https://kilit.<alan-adın>` | Kalıcı, gerçek kullanım için doğru yol | VPS ve DNS kaydı gerekir. |

**Sahip seçer.** Hızlı deneme için A ile başlayıp sonra B'ye ya da C'ye geçmek mantıklı.

Sunucuyu Mac mini'de derle ve çalıştır (A ya da B):

```sh
cd server
GOTOOLCHAIN=local CGO_ENABLED=0 go build -o kilitd ./cmd/kilitd
mkdir -p data
# A: önce tüneli başlat, verdiği https adresini kopyala
cloudflared tunnel --url http://localhost:8080
# B: tailscale funnel 8080   (adres: https://<makine>.<tailnet>.ts.net)

# Ayrı bir terminalde (ORIGIN = tünelin verdiği tam adres, sonda / olmadan):
./kilitd -db ./data/kilit.db -blobs ./data/blobs -addr 127.0.0.1:8080 \
         -public-origin "https://ORIGIN" -trusted-proxy 127.0.0.1/32,::1/128
curl -s https://ORIGIN/healthz      # {"ok":true,...} dönmeli
```

`-public-origin` ile telefonda girilen sunucu adresi **birebir aynı** olmalı; aksi halde kayıt imzası reddedilir. Tünel istekleri localhost'tan ilettiği için `-trusted-proxy 127.0.0.1/32,::1/128` gerekiyor; bu ayar istemci IP'sini doğru alır ve hız sınırlarını kişi başına tutar.

## 2. Apple tarafı (Chrome'da açık Apple Developer / App Store Connect)

1. **Bundle ID:** developer.apple.com → Certificates, IDs & Profiles → Identifiers → `+` → App IDs → App. Bundle ID: `com.carwan.kilit` (explicit). Capabilities: **Data Protection → Complete Protection**. Xcode'un otomatik imzalaması bunu kendisi de oluşturabilir; elle açmak daha öngörülebilir.
2. **Uygulama kaydı:** appstoreconnect.apple.com → Apps → `+` → New App. Platform: iOS. **Name:** App Store genelinde benzersiz olmalı; sahip "SAFE ZONE" adını seçti. Primary Language: Turkish. Bundle ID: `com.carwan.kilit`. SKU: `kilit-ios`. User Access: Full Access.
3. **Team ID:** CARWAN AI SOLUTIONS, `UG75Y7PKGC` (developer.apple.com → Membership). `ios/ExportOptions-TestFlight.plist` içinde zaten yazılı.

## 3. Derle, arşivle, yükle

```sh
cd ios
TEAM=UG75Y7PKGC   # §2.3

# Önce simülatör testleri (yerelde de yeşil olmalı)
xcodebuild -project Kilit.xcodeproj -scheme Kilit \
  -destination 'platform=iOS Simulator,name=iPhone 16' test | tail -5

# Arşiv (Release, gerçek cihaz)
xcodebuild -project Kilit.xcodeproj -scheme Kilit -configuration Release \
  -destination 'generic/platform=iOS' -archivePath ../build/Kilit.xcarchive \
  DEVELOPMENT_TEAM=$TEAM -allowProvisioningUpdates archive

# App Store Connect'e yükleme (TestFlight)
xcodebuild -exportArchive -archivePath ../build/Kilit.xcarchive \
  -exportOptionsPlist ExportOptions-TestFlight.plist -exportPath ../build/export \
  -allowProvisioningUpdates
```

Komut satırı yerine Xcode da kullanılabilir: Product → Archive → Organizer → Distribute App → TestFlight & App Store.

Bilinen hata kaynakları:
- *"No Accounts" / "No signing certificate"*: Xcode → Settings → Accounts'ta hesap ekli olmalı; `-allowProvisioningUpdates` Apple Distribution sertifikasını kendisi oluşturur.
- *"The bundle version must be higher"*: `manageAppVersionAndBuildNumber` derleme numarasını kendisi artırır. Hâlâ olursa `CURRENT_PROJECT_VERSION`'ı elle artır.
- *ITMS-91053 (privacy manifest)*: `ios/Kilit/Sources/PrivacyInfo.xcprivacy` mevcut; yeni bir "required reason" API eklenirse oraya da eklenmeli.

## 4. Export compliance (her derlemede App Store Connect sorar)

Yüklenen derleme App Store Connect → TestFlight'ta **"Missing Compliance"** olarak görünür; cevaplanmadan test edilemez. Uygulama uçtan uca şifreleme yapar (CryptoKit: X25519, Ed25519, ChaCha20-Poly1305), yani "uses encryption" sorusunun cevabı **evet**. Muafiyet ve bildirim soruları **hukuki bir karardır, sahip cevaplar** (`docs/APP_REVIEW_NOTES.md` §6). Karar verildikten sonra `INFOPLIST_KEY_ITSAppUsesNonExemptEncryption` proje ayarına eklenirse soru her derlemede tekrar sorulmaz.

## 5. TestFlight'ta dağıtım

- **Internal Testing** (önerilen ilk adım): TestFlight → Internal Testing → `+` grup → kendini ve ikinci telefonun Apple ID'sini ekle (App Store Connect kullanıcısı olmalılar). İnceleme gerektirmez; derleme işlendikten (5–30 dk) sonra kurulabilir.
- **External Testing**: Beta App Review gerektirir. Güvenli tuval tekniği yüzünden ret riski var; `docs/APP_REVIEW_NOTES.md`'deki açıklamaları inceleme notuna ekle. **Sahip onaylamadan dış test grubu açılmaz.**

## 6. İki telefonda deneme

1. İki iPhone'a da TestFlight uygulamasını kur, davet e-postasından Kilit'i yükle. Cihazlarda parola açık olmalı; parolasız cihazda kayıt reddedilir.
2. Onboarding → sunucu adresi: `https://ORIGIN` (§1, birebir aynı) → kullanıcı adları örn. `alice` ve `bob`.
3. Birbirinizi ekleyin, güvenlik numarasını karşılaştırın, mesajlaşın.
4. `docs/DEVICE_CHECKLIST.md` listesini uygulayın: ekran görüntüsü kararıyor mu, kayıt algılanıyor mu, basılı-tut, kaybolan mesaj, filigranın fotoğrafta görünmesi, 120 Hz (ProMotion cihazda).
5. Filigranı doğrulamak için: telefonun fotoğrafını çek, Diagnostics'teki `wm_secrets` hex değerini al, `server/` içinde `go run ./cmd/wmdecode -in foto.jpg -corners … -ws <hex> -usernames alice,bob`.
