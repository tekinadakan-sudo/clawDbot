# Kilit

**Kilit**, içeriğin alıcı cihazda yakalanmasını zorlaştıran, birebir uçtan uca şifreli bir iOS mesajlaşma uygulaması (Swift/SwiftUI, iOS 17+, yalnızca CryptoKit) ve kendi sunucunuzda çalıştırdığınız Go 1.24 "sakla ve ilet" sunucusundan (tek statik ikili, saf Go SQLite) oluşur. Faz 1 hedefi: sekiz özelliğin tamamıyla iki telefon arasında gösterilebilir bir sohbete giden en kısa yol.

*English summary at the end of this file.*

## Ne yapar

1. **Karartma:** Mesaj ve fotoğraf içeriği, iOS'un ekran görüntüsünde, ekran kaydında, AirPlay'de ve Uygulama Değiştirici'de kararttığı güvenli bir katmanda çizilir (elinden geleni yapar; `isSecureTextEntry`'nin belgelenmemiş bir yan etkisine dayanır ve sürekli denetlenir).
2. **Kayıt algılama:** Ekran kaydı/yansıtma `isSceneCaptured` ile algılanır ve sürdüğü sürece içerik gizlenir.
3. **Ekran görüntüsü algılama:** Sonradan algılanır, yerel olarak kaydedilir ve şifreli kanaldan karşı tarafa bildirilir (iki yönlü, Ayarlar'dan kapatılabilir).
4. **Basılı tutarak gösterme:** İçerik tutulduğu sürece görünür; kısmi gösterme fotoğraflarda bant bant.
5. **Kaybolan mesajlar:** Sohbet başına zamanlayıcı.
6. **Adli filigran:** Her çizilen kare, izleyene özgü bir desen taşır; çevrimdışı çözücü (`server/cmd/wmdecode`) faz 1'de gelir.
7. **Titreşim (deneysel, varsayılan kapalı):** 120 Hz panellerde, fotosensitivite uyarısıyla, kameranın tesadüfi çekimini bozmaya çalışır.
8. **Uçtan uca şifreleme:** X3DH + Double Ratchet (ChaCha20-Poly1305, HKDF-SHA256); güvenlik numaraları; sunucu asla düz metin, zamanlayıcı, yakalama olayı ya da ek anahtarı görmez.

## Ne yapmaz — sınırlar (uygulamadaki 3. kartla birebir aynı)

1. Ekrana tutulan ikinci bir kamera engellenemez. Filigran kimlik tespiti sağlar, titreşim caydırıcıdır, basılı tutarak gösterme açıkta kalan alanı küçültür. "Kaydedilemez" demiyoruz.
2. Ekran görüntüsü/kayıt karartması, iOS'un belgelenmemiş bir davranışına dayanır; bayrakla korunur, sürekli denetlenir ve gelecekte çalışmayabilir. Sonradan algılama garanti edilen taban çizgisidir. Yazdığın ama göndermediğin taslak karartılmaz.
3. Ekran görüntüsü bildirimi görüntü kaydedildikten sonra gelir; kayıt başladıktan sonraki ilk kareler yakalanabilir; macOS iPhone Yansıtma her iki mekanizmayı da atlayabilir.
4. Jailbreak'li ya da değiştirilmiş bir karşı taraf uygulaması süreleri yok sayabilir, bildirimleri bastırabilir ve içeriği saklayabilir. Ekranda "bildirilmedi" yazar, "alınmadı" değil.
5. Sunucu ve ağ, kimin kiminle ne zaman ve ne büyüklükte konuştuğunu, oturum kurulumlarını ve mesaj sayaçlarını görür.
6. Parolası olmayan cihazlarda anlamlı bir veri koruması yoktur; kayıt bu cihazlarda reddedilir.
7. Titreşim panel yenileme hızını aşamaz; 1/60 s ve üzeri pozlama, iki kareli seri çekim ya da video içeriği geri getirir; 60 Hz panellerde kapalıdır.
8. Birebir sohbette iki taraf da diğerinin filigran etiketini hesaplayabilir; filigran kanıt değil, ipucudur.
9. VoiceOver / Ekranı Seslendir içeriği sesli okur ve herhangi bir mikrofonla kaydedilebilir; isteğe bağlı bir ayar erişilebilirlik pahasına içeriği gizler.
10. Grup, ses, video, çoklu cihaz, hesap kurtarma (yeni telefon = yeni kimlik = "güvenlik numarası değişti"), bildirim içeriği yok. Mesajlar uygulama açıkken gelir.

**Kullanıcı adı kurtarılamaz (10. maddenin yanına):** kullanıcı adı sunucuda tekildir ve yalnızca eski kimlik anahtarıyla imzalanmış silme isteği onu serbest bırakır. Anahtarları kaybolan bir ad (telefon kaybı/değişimi, cihaz parolasının kaldırılması, sunucuya erişilemezken yeniden kurulum) sahibi tarafından geri alınamaz; kullanıcı yeni bir ad seçer, sunucu sahibi isterse `kilitd -delete-user <ad>` ile eskisini boşaltır. Normal yeniden kurulum ve "Hesabı sil ve sıfırla" önce sunucudaki hesabı sildiği için aynı ad yeni anahtarlarla yeniden alınabilir; karşı taraf anahtar değişikliği uyarısı görür.

Tehdit modelinin tamamı: [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

## Depo düzeni

```
docs/DESIGN.md            dondurulmuş tasarım (revizyon 5) — tek gerçek kaynak
docs/RESEARCH-NOTES.md    doğrulanmış iOS/Go API notları
docs/PROTOCOL.md          tel biçimi (X3DH, Double Ratchet, zarflar, ekler)
docs/VECTOR_SCHEMA.md     test vektörü şemaları; docs/vectors/*.json üretilen vektörler
docs/COPY.md              tüm kullanıcıya görünen metinler (TR + EN)
docs/THREAT_MODEL.md      tehdit modeli ve sınırlar
docs/DEVICE_CHECKLIST.md  iki telefonlu cihaz kontrol listesi
docs/APP_REVIEW_NOTES.md  App Review açıklamaları
server/                   Go 1.24 sunucu: cmd/kilitd, cmd/vectors, cmd/wmdecode, pkg/kilitcrypto, internal/*
                          Dockerfile, docker-compose.yml, Caddyfile, Makefile (hepsi server/ içinde)
ios/                      Xcode 16 projesi (elle yazılmış pbxproj), XcodeGen yedeği, Kilit/Sources, Kilit/Tests
.github/workflows/        server.yml (vet, test, race, vektör altın dosyası), ios-lint.yml (Linux doğrulayıcılar),
                          ios-build.yml (macOS + Xcode 16: derleme ve KilitTests, simülatörde)
```

## Sunucu — hızlı başlangıç (Linux)

```sh
cd server && GOTOOLCHAIN=local go mod download
go vet ./... && CGO_ENABLED=0 go test ./...          # CI ayrıca: CGO_ENABLED=1 go test -race ./...
go run ./cmd/vectors -out ../docs/vectors -swift ../ios/Kilit/Tests/Vectors   # çıktılar değişmemeli
CGO_ENABLED=0 go build -o kilitd ./cmd/kilitd
./kilitd -db ./dev.db -blobs ./blobs -addr :8080 -public-origin http://<lan-ip>:8080
```

`-public-origin`, telefonların girdiği sunucu adresiyle **aynı dize** olmalıdır (her kimlik doğrulama imzasına bağlanır).

**Üretim** (her şey `server/` içinden): alan adının A/AAAA kaydı sunucuya baksın, 80/443 açık olsun; `cd server && mkdir -p data && sudo chown 65532:65532 data`; `server/Caddyfile` içindeki alan adını ve `server/docker-compose.yml` içindeki `KILIT_PUBLIC_ORIGIN` değerini ayarlayın (`KILIT_TRUSTED_PROXY=172.28.0.0/16` kalsın); `docker compose up -d --build`. Ayrıntılar ve `wmdecode` kullanımı: [`server/README.md`](server/README.md).

## iOS — derleme (Mac, Xcode ≥ 16.0)

1. `open ios/Kilit.xcodeproj` (açılmazsa: `brew install xcodegen && cd ios && xcodegen generate` — elle yazılmış projeyi üzerine yazar).
2. Signing & Capabilities → Team seçin; Data Protection "Complete Protection" görünmeli.
3. `xcodebuild -project ios/Kilit.xcodeproj -scheme Kilit -destination 'platform=iOS Simulator,name=iPhone 16' test`
4. İki fiziksel iPhone'da çalıştırın (biri ProMotion) ve [`docs/DEVICE_CHECKLIST.md`](docs/DEVICE_CHECKLIST.md) listesini uygulayın.

İlk derleme sorunları için öncelikli bakılacak yerler, riskler ve `NSPinnedDomains` ekleme adımları: [`ios/README.md`](ios/README.md).

## Durum

- Faz 1, tasarım revizyon 5 (dondurulmuş). Go sunucu ve Swift istemci bu tasarımdan paralel iş paketleri halinde yazıldı.
- **Swift kodu henüz hiç derlenmedi:** bu depo Mac'siz bir ortamda üretildi; ilk derleme sahibinin Mac'inde olur. Linux'ta yalnızca yapısal doğrulayıcılar (pbxproj, plist, şema, YAML, dize kataloğu, grep kapıları) çalışır.
- Yalnızca cihazda doğrulanabilen açık riskler (güvenli tuval, `preventsCapture`, filigran bileşimi, 120 Hz) `ios/README.md` §5'te ve `docs/DESIGN.md` §9'da listelidir.
- Faz 2 adayları: başlık şifreleme (zarf `v:2`), Secure Enclave ile ana anahtar sarma, App Attest, anlık bildirim içeriği, çoklu cihaz.

---

## English summary

Kilit is a 1:1 end-to-end-encrypted iOS messenger (Swift/SwiftUI, iOS 17+, CryptoKit only) with a self-hosted Go 1.24 store-and-forward server (single static binary, pure-Go SQLite). Content is rendered inside a secure-canvas layer that iOS blanks in screenshots, recordings, AirPlay and the App Switcher (best effort); recording is detected via `isSceneCaptured` and content replaced while active; screenshots are detected after the fact and reported to the peer over the encrypted channel; content is hidden until held; messages disappear on a per-conversation timer; every frame carries a per-viewer forensic watermark with an offline decoder (`server/cmd/wmdecode`); and an opt-in, default-off, photosensitivity-gated 120 Hz flicker mode degrades casual camera snapshots. The server never sees plaintext, timers, capture events or attachment keys.

**Honest limits** (identical to onboarding card 3; DESIGN.md §1):

1. A second camera pointed at the screen cannot be prevented. The watermark gives attribution, the flicker is a deterrent, hold-to-reveal shrinks the exposed surface. Never say "cannot be recorded".
2. Screenshot/recording blanking relies on an undocumented UIKit rendering side effect of `isSecureTextEntry`; it uses only public calls, is feature-flagged, canary-checked, and may stop working on a future iOS. Detection after the fact is the guaranteed floor. Your own unsent draft in the composer is *not* blanked (deliberate trade-off, see §5.5); it is covered only by the App Switcher privacy cover.
3. `userDidTakeScreenshotNotification` posts after the PNG exists; the first frames after a recording starts may be captured before `isSceneCaptured` flips; macOS iPhone Mirroring (reported on iOS 26) bypasses both mechanisms.
4. A jailbroken or modified peer client can ignore timers, suppress capture reports and keep plaintext. UI wording is "no screenshot was *reported*", never "none was taken".
5. The server and network see metadata (who, when, sizes, session-establishment events and message counters).
6. Devices without a passcode have no meaningful at-rest protection; registration is refused on them.
7. Flicker cannot exceed the panel refresh rate; any exposure ≥ 1/60 s, a two-frame burst or video reconstructs the content; it is disabled on 60 Hz panels.
8. In a 1:1 chat either party can compute the other's watermark tag, so the mark is evidence, not proof.
9. VoiceOver / Speak Screen read protected content aloud and can be recorded with any microphone; an optional setting hides protected content from assistive technologies at the cost of accessibility.
10. No groups, audio, video, multi-device, account recovery (new phone = new identity = "safety number changed"), push content, or Notification Service Extension. APNs sending is a phase-2 hook; messages arrive when the app is foregrounded.

A username whose keys are lost is unrecoverable by its owner (the server owner can free it with `kilitd -delete-user <name>`); see `docs/THREAT_MODEL.md`.

**Server quick start:** `cd server && go vet ./... && CGO_ENABLED=0 go test ./... && CGO_ENABLED=0 go build -o kilitd ./cmd/kilitd && ./kilitd -db ./dev.db -blobs ./blobs -addr :8080 -public-origin http://<lan-ip>:8080`; production via `cd server && docker compose up -d --build` behind Caddy (`server/README.md`).

**iOS build:** `open ios/Kilit.xcodeproj` with Xcode ≥ 16.0, select a team, then `xcodebuild -project ios/Kilit.xcodeproj -scheme Kilit -destination 'platform=iOS Simulator,name=iPhone 16' test`; first-build triage, risks and CA pinning in `ios/README.md`; device checklist in `docs/DEVICE_CHECKLIST.md`.

**Status:** phase 1, design revision 5 (frozen). The Swift code has not yet been compiled — this repository was produced without a Mac; only Linux structural validators (`.github/workflows/ios-lint.yml`) and the Go test suite (`.github/workflows/server.yml`) have run.
