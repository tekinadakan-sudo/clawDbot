# Kilit — Device checklist (DESIGN.md §7, step 5)

Run after `xcodebuild … test` is green on the Simulator (step 3 of `ios/README.md`). Needs two physical iPhones, at least one with a ProMotion (120 Hz) panel, both on the same server. Record the result of every row (pass / fail / observed behaviour) — several rows are *expected* to fail and exist so the behaviour is written down, not fixed.

## 0. Setup (§7 step 4)

- [ ] Server reachable: `https://kilit.example.com` or, in a Debug build, `http://<lan-ip>:8080`. The server's `-public-origin` must be the **same string** the phones enter (the origin is bound into every auth signature).
- [ ] Phone A registers `alice`, phone B registers `bob`; each adds the other by username.
- [ ] Compare safety numbers on both phones (digits and QR); mark "Doğrulandı".
- [ ] Have `bob` message first once, so the message-request path (accept before decrypt) is exercised on `alice`.

## 1. Capture blanking and reports

| # | Action | Expected | Result |
|---|---|---|---|
| 1.1 | Hardware screenshot (side + volume up) in an open conversation | Message region black in the PNG; both phones show "Sen ekran görüntüsü aldın" / "alice ekran görüntüsü aldı (1)" | |
| 1.2 | Two quick hardware screenshots within 2 s | Peer receives **one** coalesced report with `count: 2` (row shows "(2)") | |
| 1.3 | Control Center screen recording | Badge turns red, list replaced by "Ekran paylaşımı sırasında içerik gizli", peer gets `recording_started`; stopping sends `recording_stopped`; the recording shows no content | |
| 1.4 | AirPlay mirroring to a TV/Mac | Same as 1.3 | |
| 1.5 | QuickTime USB capture (Mac, File › New Movie Recording, iPhone as camera) | Same as 1.3; note whether the first frames before the badge flips contain content | |
| 1.6 | App Switcher (swipe up and hold) | Opaque privacy cover, no content in the snapshot | |
| 1.7 | macOS iPhone Mirroring | **Expected to fail** (content visible, no event). Record iOS/macOS versions and what was visible | |
| 1.8 | iOS 26 full-screen screenshot preview, on and off | Record whether the preview shows black and whether the event still fires | |
| 1.9 | Image viewer: band reveal open, hardware screenshot | Image region black (`preventsCapture`), watermark layers not captured; check whether system recording *fails to start* instead of showing black and word the UI accordingly | |
| 1.10 | Amber badge path: Diagnostics → secure canvas unavailable? | If the canary fails on this iOS, badge is amber, peer shows "…cihazı ekran görüntüsünü karartamıyor"; try the other `SecureLayerMode` in Diagnostics | |

## 2. Sessions, keys, accounts

| # | Action | Expected | Result |
|---|---|---|---|
| 2.1 | **Crossed initiation**: both phones tap send within one second of adding each other | Both converge on one session; nothing shows as undecryptable; Diagnostics lists one current session per peer | |
| 2.2 | On phone B: "Hesabı sil ve sıfırla" | Server account deleted, username freed; phone A keeps the conversation | |
| 2.3 | Delete the app on B, reinstall, re-register `bob` with fresh keys | Phone A shows the key-change banner; accept; messaging resumes | |
| 2.4 | Plain reinstall (no explicit delete) | Reinstall-wipe path deletes the account first (Keychain still present), then re-registration works | |
| 2.5 | Reinstall while the server is unreachable | Wipe proceeds after ≤ 60 s with "Eski hesap sunucudan silinemedi; bu kullanıcı adı dolu kalabilir"; name stays taken until `kilitd -delete-user bob` | |
| 2.6 | Remove the device passcode, reopen the app | Keychain items gone → forced re-registration (not a crash) | |
| 2.7 | Set the device clock wrong by > 5 min | "Cihaz saati yanlış" message, no re-onboarding | |

## 3. Reveal, composer, lock

| # | Action | Expected | Result |
|---|---|---|---|
| 3.1 | Hold a bubble | Content visible while held; hidden ≤ 1 frame after release; auto-ends at 20 s | |
| 3.2 | Start a scroll on a bubble | Reveal never starts from a scroll | |
| 3.3 | Tap the composer | Keyboard appears without the message list jumping | |
| 3.4 | Background → foreground with app lock on | Face ID prompt appears once per unlock; cancel shows "Kilidi aç" button, not a loop | |
| 3.5 | Set a disappearing timer, receive, reveal, wait | Message removed at the deadline; unrevealed bound honoured | |

## 4. Flicker (Deneysel)

| # | Action | Expected | Result |
|---|---|---|---|
| 4.1 | Diagnostics on the ProMotion phone | Panel Hz = 120, measured Hz ≈ 120 while flicker runs | |
| 4.2 | Low Power Mode on | Flicker ineligible ("Düşük Güç Modu açık"), stops within 1 s if running | |
| 4.3 | Settings › Accessibility › Motion › Limit Frame Rate on | Measured Hz drops; flicker stops/ineligible | |
| 4.4 | Toggle Dim Flashing Lights while flicker runs | Stops within 1 s | |
| 4.5 | 60 Hz phone | Toggle disabled with "120 Hz ekran gerekir" | |
| 4.6 | Photosensitivity sheet | Shown before the first enable, default button "Kapalı bırak" | |

## 5. Watermark

| # | Action | Expected | Result |
|---|---|---|---|
| 5.1 | Photograph the conversation with another phone | Faint texture (~5/255) visible over bubbles in the photo; **no flat haze** over a protected image. If either fails, switch rendering variant (SwiftUI overlay ↔ CALayer) in Diagnostics | |
| 5.2 | Photos at 25 / 40 / 70 cm, straight-on and at 30°, dark room and lit room; pass each through one social-media re-encode | Decode with `wmdecode -in photo.jpg -corners x1,y1,x2,y2,x3,y3,x4,y4 -ws <hex from Diagnostics> -usernames alice,bob` (corners read from the cursor position in Preview.app). Target ≥ 95 % correct decode at ≤ 40 cm straight-on | |
| 5.3 | Photos of other screens / other apps | Zero false decodes | |
| 5.4 | Tuning | If 5.2/5.3 miss, adjust amplitude (default 5) and cell size (default 28 pt) per DESIGN.md §5.9 and repeat | |

## 6. Hygiene

- [ ] Diagnostics shows the OPK count refilling after bundles are consumed.
- [ ] Console (Xcode › Devices) shows no plaintext in logs (`Logger` privacy `.private`).
- [ ] After force-quit, `tmp/` of the app container is empty (Xcode › Devices › Download Container).
- [ ] Settings › Diagnostics › undecryptable log is empty after all of the above.
