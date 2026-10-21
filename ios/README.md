# Kilit iOS app (`ios/`)

Swift 5 language mode, SwiftUI, iOS 17.0+, CryptoKit only, no packages. The project file is **hand-written** (DESIGN.md §6) and has never been opened by Xcode: every Swift file in this tree compiles for the first time on your Mac. Read the triage list in §4 before the first build.

## 1. Layout

```
ios/Kilit.xcodeproj/                 hand-written project (objectVersion 77, Xcode ≥ 16.0)
  project.pbxproj                    27 objects, ids 4B494C4954… (DESIGN.md §6 id table)
  project.xcworkspace/contents.xcworkspacedata
  xcshareddata/xcschemes/Kilit.xcscheme   shared scheme (needed for xcodebuild on a fresh clone)
ios/project.yml                      XcodeGen fallback — see §2, mutually exclusive with the .xcodeproj
ios/Kilit/Info-Debug.plist           file-only keys + scene manifest + NSAllowsLocalNetworking
ios/Kilit/Info-Release.plist         file-only keys + scene manifest
ios/Kilit/Kilit.entitlements         com.apple.developer.default-data-protection = NSFileProtectionComplete
ios/Kilit/Sources/                   synchronized folder → target Kilit   (App/, Crypto/, Store/, Net/, Security/, UI/, Resources/, Assets.xcassets)
ios/Kilit/Tests/                     synchronized folder → target KilitTests (XCTest, @testable import Kilit)
```

The two folders are Xcode 16 *synchronized root groups*: every file under them is a member of its target automatically, so adding a Swift file needs no project edit. **Anything placed under `Sources/` becomes a bundle resource or a compiled source** — keep READMEs, scripts and fixtures out of it. The plists and the entitlements file deliberately live *outside* both folders, so no membership-exception set is needed and they are never copied into the bundle.

Info.plist strategy: `GENERATE_INFOPLIST_FILE = YES` plus `INFOPLIST_FILE` (`Info-Debug.plist` in Debug, `Info-Release.plist` in Release). Keys with an `INFOPLIST_KEY_*` build setting (usage descriptions, launch screen, orientations) live only in the project; keys without one (`CADisableMinimumFrameDurationOnPhone`, the scene manifest, `NSAppTransportSecurity`) live only in the plist. Never put a key in both — Apple does not document the merge precedence. `INFOPLIST_KEY_UIApplicationSceneManifest_Generation` is intentionally **not** set (it would generate `UIApplicationSupportsMultipleScenes = YES` and duplicate the manifest).

## 2. Build and test on the Mac (DESIGN.md §7)

1. `git clone …` and `open ios/Kilit.xcodeproj` (Xcode ≥ 16.0; Xcode 15 refuses objectVersion 77).
   If the project will not open: `brew install xcodegen && cd ios && xcodegen generate`. **This overwrites `Kilit.xcodeproj` and the shared scheme with new object ids** — from then on edit `project.yml`, not the pbxproj, and do not mix the two workflows.
2. Signing & Capabilities → select your Team (the repo commits `DEVELOPMENT_TEAM = ""`); accept "Update to recommended settings" if prompted; verify Data Protection shows "Complete Protection".
3. `xcodebuild -project ios/Kilit.xcodeproj -scheme Kilit -destination 'platform=iOS Simulator,name=iPhone 16' test`
   Fix compile errors first (§4), then `SecureCanvasTests` (canary + environment propagation) and all vector tests must pass before any device work.
4. Run on two physical iPhones (one ProMotion). Enter the server URL in onboarding (`https://kilit.example.com`, or `http://<lan-ip>:8080` in Debug — the server's `-public-origin` must be the same string). Register `alice` and `bob`, add each other, compare safety numbers, have `bob` message first once.
5. Work through `docs/DEVICE_CHECKLIST.md`.

Debug builds may talk to a plain-HTTP LAN server because `Info-Debug.plist` sets `NSAllowsLocalNetworking`; Release builds are ATS-only (TLS 1.2+).

## 3. Linux lint (what CI checks)

`.github/workflows/ios-lint.yml` runs on every push/PR without a Mac: the pbxproj parses with the cordova `xcode` parser and the 27 ids of DESIGN.md §6 resolve; plists/entitlements parse and carry exactly the file-only keys; scheme and workspace XML parse; `project.yml` parses; `Localizable.xcstrings` parses with `sourceLanguage = tr`, every key has `tr` and `en`, and no `%d` placeholder exists (integers interpolated through `String(localized:defaultValue:)` are `%lld`); and the grep gates of §8 WP6/WP8 (no `print(`, no third-party imports, no copy/share/drag UI, no `UIScreen.main`, `setValue(_:forKey:)` only in `CaptureShield.swift` with `"layer"`, ≤ 500 lines per file). The workflow file contains the two validator scripts verbatim; to run them locally, copy them out of the YAML (or run the workflow with `act`).

## 4. First-build triage (DESIGN.md §9)

Nothing in this tree has been type-checked. The most likely first-build / first-run problems, in the order they tend to appear, and where to look:

| Symptom | Where | What to do |
|---|---|---|
| `sizeThatFits` ambiguity / returning `nil` not accepted | `Security/SecureContainer.swift` | The representable's `sizeThatFits(_:uiViewController:context:) -> CGSize?` must return `nil`; check the `@available` and the exact label set |
| `.environment(\.self, context.environment)` does not type-check with `AnyView` | `Security/SecureContainer.swift` | Apply `.environment(\.self, …)` to `content` first, then wrap in `AnyView` |
| `registerForTraitChanges` closure typing | `App/SceneDelegate.swift` | Closure is `(UITraitEnvironment, UITraitCollection) -> Void`; cast the first parameter |
| `MediaAccessibility` import / `kMADimFlashingLightsChangedNotification` bridge | `Security/FlickerMaskView.swift` | `Notification.Name(rawValue: kMADimFlashingLightsChangedNotification as String)`; observe on `NotificationCenter.default` |
| `CGBitmapInfo(rawValue:)` for tile images | `Security/WatermarkTile.swift` | Raw value = `CGImageAlphaInfo.noneSkipFirst.rawValue \| CGBitmapInfo.byteOrder32Little.rawValue` |
| `CMSampleBuffer` creation sequence | `Security/CaptureProtectedImageView.swift` | `CMVideoFormatDescriptionCreateForImageBuffer` → `CMSampleBufferCreateReadyWithImageBuffer` with `CMSampleTimingInfo`; check `OSStatus` handling |
| `@Observable` + actor isolation warnings/errors | `App/AppModel.swift`, `Net/MessageSync.swift` | UI mutations hop to `@MainActor`; do not add `Sendable` conformances blindly |
| `UIHostingController.safeAreaRegions` availability | `Security/SecureContainer.swift` | Needs `if #available(iOS 16.4, *)` (deployment target 17.0 already covers it; remove the guard if the compiler complains about it being redundant) |
| `UILongPressGestureRecognizer` target/selector plumbing | `Security/HoldToReveal.swift` | Target must be an `NSObject` subclass with an `@objc` method |
| `CGImage(width:…provider:…)` labels | `Security/WatermarkTile.swift` | 11 labelled arguments: `width:height:bitsPerComponent:bitsPerPixel:bytesPerRow:space:bitmapInfo:provider:decode:shouldInterpolate:intent:` |
| `UIColor(patternImage:)` scale | `Security/WatermarkLayers.swift` | Build the `UIImage` with `UIImage(cgImage:scale:orientation:)` using the screen scale |
| Raw string literal too large in the test target | `Tests/Vectors/KilitVectors+*.swift` | Each set must stay under 200 KB; split further if the compiler stalls |
| "Multiple commands produce Info.plist" | project | A plist was put inside `Sources/`; move it back to `ios/Kilit/` |
| Simulator Keychain errors (`errSecMissingEntitlement`/`-34018`) | `Store/Keychain.swift` | Simulator uses `WhenUnlockedThisDeviceOnly` (device: `WhenPasscodeSetThisDeviceOnly`); confirm the `#if targetEnvironment(simulator)` branch |

After compile errors: run `SecureCanvasTests` alone first. If the canary test fails on your iOS/Simulator version, open Diagnostics on a device and try the other `SecureLayerMode` (layer-swap) before changing code.

## 5. Open risks that only a device can settle (DESIGN.md §9)

- **Secure canvas** (`_UITextLayoutCanvasView`) may be absent, renamed, recreated at runtime, or not blank on your iOS. The canary re-evaluates on every layout; amber badge = detection only. App Review risk is accepted and written up in `docs/APP_REVIEW_NOTES.md`.
- **`preventsCapture`** may make system recording fail to start instead of showing black — test and word the UI.
- **Watermark compositing** (`plusLighter`/`plusDarker` in SwiftUI vs `compositingFilter` `"plusL"`/`"plusD"` on CALayer) over the secure canvas and the AV layer is unverifiable without a device; both variants ship and the checklist decides. Amplitude 5 / cell 28 pt are guesses until photographed; `server/cmd/wmdecode` exists so you can measure.
- **120 Hz delivery** depends on `CADisableMinimumFrameDurationOnPhone` being merged from the plist (both configs) and on the device; verify measured Hz in Diagnostics and every self-stop path (Low Power, Limit Frame Rate, Dim Flashing Lights, Reduce Motion).
- **CryptoKit/Go parity** is proven only when the vector tests run; likeliest divergences: CONCAT/header ordering, padding, attachment AAD framing, signed-message separators, `created_at` in the SPK bytes, `opks_sig` layout, base64url.
- **Keychain `WhenPasscodeSetThisDeviceOnly`**: passcode removal deletes keys → forced re-registration; the username is then unrecoverable by its owner (`kilitd -delete-user` on the server).
- **`URLSessionWebSocketTask` without an Origin header** against the Go server: expected fine; confirm on first device test.
- **iOS 26 full-screen screenshot preview** and **iPhone Mirroring**: document the observed behaviour; no mitigation planned.
- **Crossed initiation and reinstall/key-change** are exercised by scripted vectors; the real two-phone flows are on the checklist.

## 6. Adding a CA pin (`NSPinnedDomains`) to the Release build

Nothing is pinned in the repo (the example domain would break your deployment). To pin the Let's Encrypt chain of your server, pin the **CA's** SubjectPublicKeyInfo (root or intermediate), never the 90-day leaf.

1. Fetch the chain and keep the intermediate (second certificate) or use the ISRG Root X1 from letsencrypt.org:
   ```sh
   openssl s_client -connect kilit.example.com:443 -servername kilit.example.com -showcerts </dev/null 2>/dev/null \
     | awk '/BEGIN CERT/{n++} n==2' > intermediate.pem
   ```
2. Compute the SPKI SHA-256 in base64:
   ```sh
   openssl x509 -in intermediate.pem -pubkey -noout \
     | openssl pkey -pubin -outform der \
     | openssl dgst -sha256 -binary | base64
   ```
3. Add to `ios/Kilit/Info-Release.plist` (one or more hashes; include the root as a second entry to survive an intermediate rotation):
   ```xml
   <key>NSAppTransportSecurity</key>
   <dict>
   	<key>NSPinnedDomains</key>
   	<dict>
   		<key>kilit.example.com</key>
   		<dict>
   			<key>NSIncludesSubdomains</key>
   			<true/>
   			<key>NSPinnedCAIdentities</key>
   			<array>
   				<dict>
   					<key>SPKI-SHA256-BASE64</key>
   					<string>BASE64_SPKI_HASH_HERE</string>
   				</dict>
   			</array>
   		</dict>
   	</dict>
   </dict>
   ```
   Do not add it to `Info-Debug.plist` (that file already owns `NSAppTransportSecurity` for local networking; if you need both in Debug, put `NSPinnedDomains` inside the same dict).
4. The lint workflow fails on a committed `NSPinnedDomains` on purpose: keep the pinned plist in a local branch or patch it in your release script, and re-check it whenever Let's Encrypt rotates intermediates.

## 7. Conventions enforced by CI (so a PR is not bounced)

No `print(` (use `Logger` with `privacy: .private`); no imports outside the Apple frameworks listed in the lint script; no `.textSelection`, `contextMenu`, `onDrag`, `UIActivityViewController`, `QLPreviewController`, `UIImage(contentsOfFile:)`, `ImageAnalysisInteraction`, `CSSearchableIndex`, `NSUserActivity`, `UIScreen.main`, `onLongPressGesture` for reveal, KVC `disableUpdateMask`; `setValue(_:forKey:)` only in `Security/CaptureShield.swift` and only with `"layer"`; ≤ 500 lines per file; `%lld` for integers in the string catalog.
