# Kilit — App Review notes (phase 1)

Disclosure prepared for the App Store Connect "Notes for review" field and for the owner before submission. Nothing here is a guarantee of approval; DESIGN.md §9 lists the accepted risk.

## 1. Screenshot / recording blanking (the main risk)

**What the app does.** Message and photo content is rendered inside the content view of a `UITextField` whose `isSecureTextEntry` is `true` (`Security/SecureHostField.swift`, `Security/SecureCanvasView.swift`). Apple documents that this trait "in some cases also disables the user's ability to record and broadcast the text in the view"; iOS therefore blanks that region in screenshots, screen recordings, AirPlay and the App Switcher snapshot.

**What it does not do.** Only public API is called. The field's private subview (`_UITextLayoutCanvasView`) is located by *class-name suffix* with `String(describing: type(of:))` and `UIView.subviews`; no private selector, header or `dlsym` is used. The alternative mode (`Security/CaptureShield.swift`) uses `setValue(_:forKey: "layer")`, i.e. Key-Value Coding on the public `UIView.layer` property. There is no swizzling and no use of `UIScreen.main` / `screenshotService` / KVC on `disableUpdateMask` (CI grep gate).

**Known position of Apple DTS.** DTS has said this is "not its intended purpose" and that there is no public API to block screenshots. The behaviour is therefore (a) feature-flagged (Settings › secure layer), (b) continuously canary-checked — when the canvas disappears the badge turns amber and the app degrades to detection only, and (c) disclosed to the user in onboarding card 1 and in every honest-limits list ("may stop working on a future iOS"). If review asks, the app functions fully with the flag off.

**Photo viewer.** Images render through `AVSampleBufferDisplayLayer` with the documented `preventsCapture = true` property — entirely public and intended.

## 2. Capture detection and reporting (Guideline 2.5.14 and 5.1.1)

The app observes `UIApplication.userDidTakeScreenshotNotification` and `UIScene.isSceneCaptured` (both public). When the user takes a screenshot or a recording starts, the event is logged locally and reported to the other participant **through the end-to-end-encrypted channel**; the server never sees it. This is disclosed:

- in onboarding card 2 ("Bildirimler iki yönlüdür" / "Reports go both ways"),
- in Settings with the footer `settings.capture_reports.footer`: "Açıkken, aldığın ekran görüntüleri ve ekran kayıtları yerel olarak kaydedilir ve karşı tarafa şifreli olarak bildirilir." / "When on, screenshots and screen recordings you take are logged locally and reported to the other person over the encrypted channel.",
- and the setting can be turned off.

No screen content is ever captured or transmitted by the app; only the fact and time of the event.

## 3. Flicker mode (photosensitivity)

"Titreşim Kalkanı" alternates two fine patterns at the display refresh rate. It is **off by default**, only available on 120 Hz panels, blocked when Reduce Motion, Dim Flashing Lights or Low Power Mode is on (the app observes `MADimFlashingLightsEnabled` and stops within one second), and gated behind the warning sheet of `docs/COPY.md` §10.5 whose default button is "Kapalı bırak" / "Keep off". `CADisableMinimumFrameDurationOnPhone` is set only so `CADisplayLink` can request 120 Hz for this feature.

## 4. Accessibility

Protected content is accessible to VoiceOver by default. An optional setting ("Korumalı içeriği erişilebilirlikten gizle") sets `accessibilityElementsHidden`; it is off by default and shows the warning of `docs/COPY.md` §10.6 explaining that VoiceOver users will no longer be able to read messages.

## 5. Privacy

- Account: a username chosen by the user and public keys. No phone number, email, contacts access, advertising identifier or analytics SDK (no third-party code at all; CI rejects non-Apple imports).
- Server data: ciphertext queues and metadata (sender, recipient, size, time) until acknowledged; attachments deleted after download or TTL. Logs keep IPs truncated to /24.
- Photos: `PhotosPicker` (no library permission needed) and the camera (`NSCameraUsageDescription`). Images are re-encoded without metadata and encrypted on-device before upload.
- Face ID: `NSFaceIDUsageDescription`, used only for the app lock via `LAContext`.
- Data Protection entitlement `com.apple.developer.default-data-protection = NSFileProtectionComplete`.
- Privacy nutrition label: "Data Linked to You: User ID (username)"; no tracking.
- **Privacy manifest:** if any file in `ios/Kilit/Sources` uses a required-reason API (`UserDefaults`, file timestamps, free disk space, system boot time), a `PrivacyInfo.xcprivacy` must be added under `ios/Kilit/Sources/` before upload. Check with `grep -rn "UserDefaults\|contentModificationDate\|systemUptime\|volumeAvailableCapacity" ios/Kilit/Sources` on the Mac.

## 6. Encryption export compliance

The app uses only Apple CryptoKit (X25519, Ed25519, ChaCha20-Poly1305, HKDF-SHA256) for end-to-end encryption of user messages. No `ITSAppUsesNonExemptEncryption` key is committed; the owner must answer the export-compliance questions in App Store Connect for each build (proprietary-protocol messaging with standard algorithms is typically *not* exempt from the self-classification report; a French import declaration may also apply). Set `ITSAppUsesNonExemptEncryption` via `INFOPLIST_KEY_ITSAppUsesNonExemptEncryption` in the project only after that decision.

## 7. Account deletion (Guideline 5.1.1(v))

Settings › "Hesabı sil ve sıfırla" deletes the server account (`DELETE /v1/users/me`, signed with the identity key), the session, and all local data. A reinstall also deletes the old account first.

## 8. Demo for review

Provide two test usernames on the owner's server, the server URL, and note that messages arrive only while the app is in the foreground (no push in phase 1). Mention that screenshots taken by the reviewer will appear black in the message area and will be reported to the other test account — this is the feature, not a bug.
