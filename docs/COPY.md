# Kilit — user-facing copy (verbatim from DESIGN.md §10)

## 10. User-facing copy (single source; `docs/COPY.md` is a verbatim copy)

### 10.1 Onboarding cards

**Card 1 — Ne karartılır, ne algılanır** / *What is blanked, what is detected*
TR: "Mesajlar ve fotoğraflar, iOS'un ekran görüntüsünde, ekran kaydında ve AirPlay'de kararttığı özel bir katmanda gösterilir. Bu, iOS'un belgelenmemiş bir davranışına dayanır ve gelecekte çalışmayabilir; çalışmadığında üstteki rozet sarıya döner ve yalnızca algılama kalır. Ekran kaydı başladığında içerik gizlenir; ekran görüntüsü alındığında bu sonradan algılanır."
EN: "Messages and photos are shown inside a special layer that iOS blanks in screenshots, screen recordings and AirPlay. This relies on an undocumented iOS behaviour and may stop working; when it does, the badge at the top turns amber and only detection remains. When a recording starts, content is hidden; a screenshot is detected after it is taken."

**Card 2 — Bildirimler iki yönlüdür** / *Reports go both ways*
TR: "Sen ekran görüntüsü aldığında ya da ekranını kaydettiğinde karşı taraf bunu görür; karşı taraf yaptığında sen görürsün. Bu olaylar yalnızca şifreli kanaldan gider; sunucu bunları göremez. Bu kayıt tutma, uygulamayı kullanarak kabul ettiğin bir özelliktir ve Ayarlar'dan kapatılabilir."
EN: "When you take a screenshot or record your screen, the other person sees it; when they do, you see it. These events travel only through the encrypted channel; the server cannot see them. This logging is a feature you accept by using the app and can be turned off in Settings."

**Card 3 — Sınırlar** / *Limits*: the limits list of §10.4, verbatim.

### 10.2 Badges (`ProtectionBadge`)
- green `badge.green`: TR "Karartma + algılama — ekran görüntüsü ve kayıt karartılır, ayrıca algılanır." EN "Blanking + detection — screenshots and recordings are blanked and also detected."
- amber `badge.amber`: TR "Yalnızca algılama — bu cihazda karartma kullanılamıyor; ekran görüntüleri sonradan algılanır ve bildirilir." EN "Detection only — blanking is unavailable on this device; screenshots are detected and reported after the fact."
- red `badge.red`: TR "Ekran paylaşılıyor — kayıt, AirPlay veya uzaktan kontrol etkin; içerik gizlendi." EN "Screen is being shared — recording, AirPlay or remote control is active; content is hidden."

### 10.3 Conversation rows and banners
- `capture.self.screenshot`: TR "Sen ekran görüntüsü aldın" / EN "You took a screenshot"
- `capture.self.recording_started`: TR "Ekran paylaşımını başlattın" / EN "You started screen sharing"
- `capture.self.recording_stopped`: TR "Ekran paylaşımını durdurdun" / EN "You stopped screen sharing"
- `capture.peer.screenshot`: TR "%@ ekran görüntüsü aldı (%lld)" / EN "%@ took a screenshot (%lld)" (integer placeholders in the catalog are `%lld`, §6)
- `capture.peer.recording_started` / `_stopped`: TR "%@ ekran paylaşımını başlattı" / "…durdurdu"; EN "%@ started screen sharing" / "…stopped screen sharing"
- `capture.peer.blanking_unavailable`: TR "%@'nin cihazı ekran görüntüsünü karartamıyor" / EN "%@'s device cannot blank screenshots"
- `capture.gap`: TR "Bildirilmeyen olay" / EN "Unreported event"
- `capture.none`: TR "Bildirilen ekran görüntüsü yok" / EN "No screenshot reported" (never "none taken")
- `undecryptable.row`: TR "Bu mesaj çözülemedi (%@)" / EN "This message could not be decrypted (%@)"
- `resync.row`: TR "Oturum yenilendi; son mesajlar yeniden gönderildi" / EN "Session re-established; recent messages were re-sent"
- `keychange.banner`: TR "Güvenlik numarası değişti. %@ yeni bir cihaz ya da kimlik kullanıyor olabilir. Göndermeden önce doğrulayın." / EN "Safety number changed. %@ may be using a new device or identity. Verify before sending." Buttons: `keychange.accept` TR "Yeni anahtarı kabul et" / EN "Accept new key"; `keychange.verify` TR "Güvenlik numarasını göster" / EN "Show safety number".
- `request.banner`: TR "Bilinmeyen gönderen" / EN "Unknown sender"; buttons `request.accept` TR "Kabul et" / EN "Accept", `request.block` TR "Engelle" / EN "Block".
- `attachment.expired`: TR "Ek süresi doldu" / EN "Attachment expired"
- `delete.me`: TR "Benim için sil" / EN "Delete for me"; `delete.both`: TR "Benim için ve karşı taraf için sil" / EN "Delete for me and the other side" (only on own messages; the only action that sends `ctrl.delete`, §3.4/§5.8)
- `stale_spk`: TR "Sunucu eski bir anahtar sunuyor; daha sonra tekrar deneyin" / EN "The server is serving an outdated key; try again later"
- `clock.skew`: TR "Cihaz saati yanlış. Tarih ve saati düzeltip tekrar deneyin." / EN "Your device clock is wrong. Fix the date and time and try again."
- `reveal.hint`: TR "görmek için basılı tut" / EN "hold to view"
- `lock.retry`: TR "Kilidi aç" / EN "Unlock"
- `capture.hidden`: TR "Ekran paylaşımı sırasında içerik gizli" / EN "Content hidden while the screen is shared"

### 10.4 Limits list (card 3, README, THREAT_MODEL)
TR:
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
EN: items 1–10 of §1 verbatim.

### 10.5 Photosensitivity warning sheet
Title TR "Fotosensitivite uyarısı" / EN "Photosensitivity warning".
TR: "Titreşim Kalkanı mesaj içeriğinin üzerinde iki ince desen arasında saniyede 120 kez geçiş yapar (saniyede 60 tam döngü). Hızla yanıp sönen görüntüler fotosensitif epilepsisi olan kişilerde nöbeti tetikleyebilir; diğer kişilerde göz yorgunluğu, baş ağrısı, baş dönmesi veya bulantıya yol açabilir. Sizde ya da ekranınızı görebilecek birinde nöbet geçmişi varsa bu özelliği açmayın. Kendinizi kötü hissederseniz hemen kapatın. Bu deneysel bir caydırıcıdır; ekranınızın fotoğraflanmasını veya kaydedilmesini engellemez."
EN: "Flicker Shield rapidly alternates between two fine patterns over message content (120 changes per second, 60 full cycles). Rapidly flashing or flickering images can trigger seizures in people with photosensitive epilepsy and can cause eye strain, headaches, dizziness or nausea in others. Do not turn this on if you, or anyone who may see your screen, has a history of seizures. Stop and turn it off immediately if you feel unwell. This is an experimental deterrent only; it does not prevent someone from photographing or recording your screen."
Buttons: cancel/default TR "Kapalı bırak" / EN "Keep off"; destructive TR "Aç" / EN "Turn on". Ineligibility reasons: TR "120 Hz ekran gerekir" / "Hareketi Azalt açık" / "Yanıp Sönen Işıkları Kıs açık" / "Düşük Güç Modu açık"; EN "Requires a 120 Hz display" / "Reduce Motion is on" / "Dim Flashing Lights is on" / "Low Power Mode is on". Status pill TR "Titreşim açık" / EN "Flicker on".

### 10.6 Accessibility-hide warning sheet
TR: "Bu ayar korumalı mesaj ve fotoğrafları VoiceOver, Ekranı Seslendir ve diğer yardımcı teknolojilerden gizler. VoiceOver kullanıyorsanız mesajları okuyamazsınız. Sesli okumanın bir mikrofonla kaydedilmesini zorlaştırır; başka bir koruma sağlamaz."
EN: "This setting hides protected messages and photos from VoiceOver, Speak Screen and other assistive technologies. If you use VoiceOver you will not be able to read messages. It makes recording spoken content with a microphone harder; it provides no other protection."
Buttons: TR "Vazgeç" / "Gizle"; EN "Cancel" / "Hide".

### 10.7 Settings disclosure (Guideline 2.5.14)
`settings.capture_reports.footer`: TR "Açıkken, aldığın ekran görüntüleri ve ekran kayıtları yerel olarak kaydedilir ve karşı tarafa şifreli olarak bildirilir." / EN "When on, screenshots and screen recordings you take are logged locally and reported to the other person over the encrypted channel."