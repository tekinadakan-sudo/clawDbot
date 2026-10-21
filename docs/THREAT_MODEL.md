# Kilit — Threat model (phase 1)

This document mirrors DESIGN.md §1 (overview and honest limits) and §2 (threat model table). The user-facing wording below is copied verbatim from `docs/COPY.md` §10.4; the app's onboarding card 3 and the READMEs show the same list. If the three ever disagree, DESIGN.md §10 wins.

## 1. What Kilit is

Kilit is a 1:1 end-to-end-encrypted iOS messenger (Swift/SwiftUI, iOS 17+, CryptoKit only) with a self-hosted Go 1.24 store-and-forward server. Its distinguishing property is that content is *hard to capture on the recipient's device*:

- message and photo content renders inside a secure-canvas layer that iOS blanks in screenshots, recordings, AirPlay and the App Switcher (best effort);
- recording/mirroring is detected via `isSceneCaptured` and content is replaced while it is active;
- screenshots are detected after the fact, logged and reported to the peer through the encrypted channel;
- content is hidden until held (hold-to-reveal, partial reveal);
- messages disappear on a per-conversation timer;
- every rendered frame carries a per-viewer forensic watermark, decodable offline with `server/cmd/wmdecode`;
- an opt-in, default-off, photosensitivity-gated 120 Hz flicker mode degrades casual camera snapshots.

The server never sees plaintext, timers, capture events or attachment keys.

### What the server does see

Every envelope body is integrity-protected (AEAD over `CONCAT(AD, sid, header)`), but the routing fields are plaintext to the server: `v`, `kind`, `sid`, the `x3dh` block (public identity/ephemeral keys, `spk_id`, `opk_id`) and `hdr` (ratchet public key, `pn`, `n`). Of these only `sid` and `hdr` are *authenticated* (inside the AAD); `v`, `kind` and the `x3dh` block are visible and unauthenticated. Tampering with them can make an envelope undecryptable, park it, or — only when the sender is already an accepted contact, and at most once per peer per 10 minutes — trigger one bundle fetch (costing one of the peer's one-time prekeys) and a fresh session whose first message is `ctrl.resync`. It can never produce plaintext or a forged message, and never alters what decrypts. The server therefore learns session-establishment events, per-direction message counters and DH-ratchet step timing in addition to who/when/sizes. Header encryption (envelope `v:2`) is a phase-2 item.

## 2. Adversaries, defenses, residual risk

| Adversary | Defense (phase 1) | Residual risk |
|---|---|---|
| Curious/compromised server | X3DH + Double Ratchet; envelope bodies and blobs opaque; routing fields visible — `sid` and `hdr` authenticated through the AAD, `v`/`kind`/`x3dh` unauthenticated, so tampering is limited to an undecryptable classification, parking, or (existing accepted contact, ≤ 1 per peer per 10 min) one bundle fetch plus a fresh `ctrl.resync` session; never plaintext or a forged message; timers, capture events, attachment keys inside ciphertext; plaintext padded to 256-byte buckets; delete on ack/TTL; `PRAGMA secure_delete=ON`; hashed tokens/nonces; IPs truncated to /24 (/48 v6); log retention bounded by Docker json-file rotation (3 × 10 MB); safety numbers; identity keys in every `prekey` envelope must equal the keys the client already holds for that username; receivers recompute `sid` from `ek` | Metadata/social graph incl. session events and counters; key substitution detectable only by comparing safety numbers; withheld OPKs force SPK-only sessions (replay excluded by `seen_ek`); a stale SPK can be served for up to 21 days; by rewriting `spk_id`/`opk_id` the server can burn at most one OPK of a peer per accepted contact per 10 min |
| Network attacker / malicious relay server | TLS 1.2+ (ATS); optional CA pin added by the owner (`ios/README.md`); signed single-use nonce auth with domain separation, timestamp and server origin bound into every signature, so a relayed challenge from another server is useless; E2EE underneath | Traffic analysis |
| Stolen 30-day bearer token (device not compromised) | 30-day expiry; `DELETE /v1/auth/session`; OPK batches signed with `IK_sig` (`opks_sig`) so a token thief cannot replace prekeys; account deletion requires `delete_sig`; E2EE unaffected | Silent deletion of queued ciphertext = DoS; consuming other users' OPKs under the victim's quota; reading envelope headers |
| Thief without passcode / forensic extraction | `NSFileProtectionComplete` on the data directory and via the `com.apple.developer.default-data-protection` entitlement; Keychain `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`; store closed on `protectedDataWillBecomeUnavailableNotification`; registration refused on `LAError.passcodeNotSet`; backup excluded | AFU memory extraction while unlocked |
| Thief with passcode | App lock = explicit `locked → authenticating → unlocked` state machine around `LAContext.evaluatePolicy(.deviceOwnerAuthentication)`; disappearing messages; panic wipe incl. server-side account deletion | Gate, not key wrap: data readable by a file dump. SE-wrapped master key is phase 2 |
| Peer: screen recording / AirPlay / QuickTime | Secure canvas blanks; `@Environment(\.isSceneCaptured)` replaces content; encrypted `ctrl.capture` to peer; local event log | First frames; iPhone Mirroring; jailbreak |
| Peer: screenshot | Secure canvas blanks (best effort); `userDidTakeScreenshotNotification` → log + encrypted report (0.5 s debounce, coalesced) | Detection-only if blanking fails |
| Peer: second camera | Hold-to-reveal (opaque placeholder), partial reveal, timers, no copy/share/save UI, forensic + visible watermark, opt-in flicker | Not preventable; watermark scrubbable |
| Peer: modified client | — (cooperative controls) | Timers/reports/forwarding unenforced on that side |
| Peer: jailbroken / instrumented device | None. No jailbreak heuristics (false positives, trivially bypassed, zero security value); App Attest gating is phase 2 | All client-side guarantees void on that device |
| Accessibility re-emission (VoiceOver, Speak Screen, Back Tap screenshot) | Setting "Korumalı içeriği erişilebilirlikten gizle" sets `accessibilityElementsHidden = true` on protected content (default off, degrades VoiceOver and says so); Back Tap screenshot = ordinary screenshot path | Audio recorded by a microphone |
| Local leftovers (caches, temp files, logs, crash dumps) | Ephemeral `URLSession`, no `URLCache`; decrypt only in memory via `CGImageSourceCreateWithData(…, kCGImageSourceShouldCache: false)`; best-effort zeroisation of the owned decrypt buffer and the display pixel buffer on viewer dismissal; decoded CGImage bitmaps are released, not scrubbed; `temporaryDirectory` cleared on launch and background; `Logger` with `privacy: .private` only, `print(` forbidden; no third-party crash/analytics SDKs (grep gate in CI) | OS-level crash logs of the process image; freed-but-unscrubbed decoded bitmaps |
| Backups / migration | `isExcludedFromBackup` re-applied every launch; ThisDeviceOnly Keychain; `kSecAttrSynchronizable = false` | New device = new identity |
| Push / lock screen | Phase 1 sends no pushes and requests no notification permission; the server keeps `push_tokens` and `PUT …/push-token` for phase 2; payload design = generic `loc-key` only | Generic text only (phase 2) |
| Clipboard / keyboard / Spotlight / App Switcher | No copy/drag/share actions; `UITextView` composer with autocorrection, spell check, smart quotes/dashes/insert and inline prediction off, `writingToolsBehavior = .none` (iOS 18 guarded); third-party keyboards blocked via `application(_:shouldAllowExtensionPointIdentifier:)`; no `NSUserActivity`/CoreSpotlight/Intents; opaque cover added synchronously in `sceneWillResignActive` | Keyboard learning not documented as disabled; composer draft visible in screenshots |
| Server abuse (flood, enumeration, OPK depletion, replay) | Per-IP and per-user token buckets (behind a trusted proxy, keyed by `X-Forwarded-For`); constant-shape challenge responses; identity lookup separated from OPK-claiming bundle fetch; per-(fetcher,target) and per-target OPK claim quotas that degrade to SPK-only instead of 429; single-use nonce consumed by `DELETE … RETURNING`; per-recipient (5000) and per-(sender,recipient) (500) queue caps; size caps; 128-bit random ids; `UNIQUE` identity keys | Distributed DoS |

## 3. Honest limits (verbatim; shown in onboarding card 3 and the READMEs)

### Türkçe (`docs/COPY.md` §10.4)

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

### English (DESIGN.md §1, items 1–10)

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

**Username recovery (belongs next to item 10; DESIGN.md §5.11):** a username is `UNIQUE` on the server and only a `delete_sig` from the old identity key frees it. A username whose keys are lost — lost or replaced phone, passcode removal (which deletes the ThisDeviceOnly Keychain items), a reinstall while the server was unreachable — is **unrecoverable by its owner**. The user picks a new name; the server owner may free the old one with `kilitd -delete-user <name>`. A normal reinstall or "Hesabı sil ve sıfırla" deletes the server account first, so the same name can be re-registered with fresh keys and the peer sees the key-change banner.

## 4. Assumptions

- Both participants run the unmodified app on a non-jailbroken iPhone with a passcode. Nothing in phase 1 verifies this (no jailbreak heuristics, no App Attest).
- The server operator is honest-but-curious at best; the design tolerates a malicious server for confidentiality and authenticity but not for availability or metadata.
- TLS is a second layer: it protects auth tokens and metadata from on-path observers, and the optional CA pin (`ios/README.md`) protects against a mis-issued certificate. E2EE does not depend on it.
- iOS behaviour is as documented in `docs/RESEARCH-NOTES.md` at the time of writing; the secure-canvas canary and the amber badge exist precisely because item 2 above may change under us.

## 5. Out of scope for phase 1

Header encryption, Secure Enclave key wrapping, App Attest, push notification content, multi-device, groups, sealed sender / metadata protection, post-quantum key agreement, and any defense against a cooperating malicious peer.
