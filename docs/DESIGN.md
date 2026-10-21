# Kilit — Phase 1 Design Document (final, revision 3)

## 1. Overview, goals, non-goals

Kilit is a 1:1 end-to-end-encrypted iOS messenger (Swift/SwiftUI, iOS 17+, CryptoKit only) with a self-hosted Go 1.24 store-and-forward server (single static binary, `modernc.org/sqlite`, no cgo). Its distinguishing property is that content is *hard to capture on the recipient's device*: message and photo content renders inside a secure-canvas layer that iOS blanks in screenshots, recordings, AirPlay and the App Switcher (best effort); recording/mirroring is detected via `isSceneCaptured` and content is replaced while it is active; screenshots are detected after the fact, logged and reported to the peer through the encrypted channel; content is hidden until held; messages disappear on a per-conversation timer; every rendered frame carries a per-viewer forensic watermark (with an offline decoder shipped in phase 1); and an opt-in, default-off, photosensitivity-gated 120 Hz flicker mode degrades casual camera snapshots. The server never sees plaintext, timers, capture events or attachment keys. **What the server does see:** every envelope is integrity-protected (AEAD over `CONCAT(AD, header)`), but its routing header is plaintext to the server — `kind`, `sid`, the `x3dh` block (public identity/ephemeral keys, `spk_id`, `opk_id`) and `hdr` (ratchet public key, `pn`, `n`). The server therefore learns session-establishment events, per-direction message counters and DH-ratchet step timing in addition to who/when/sizes. Header encryption (Double Ratchet §4 header keys, envelope `v:2`) is a phase-2 item. The phase-1 goal is the shortest path to a demonstrable two-phone conversation with all eight features, keeping the amount of Swift that must compile first-time on the owner's Mac as small as possible: encrypted JSON documents instead of a SQLite C-API layer, single-shot attachments, REST-only sending, an `LAContext` gate instead of a Secure Enclave key wrap.

**Phase-1 scope statement for feature 5 (watermark):** the pattern is rendered on every protected frame *and* decodable with `server/cmd/wmdecode` (Go, offline, phase 1). The per-pixel delta map is integer-exact and identical in Go and Swift (§5.9); calibration of amplitude and cell size against real photos happens on the owner's devices using the checklist in §7; the two knobs are documented in §5.9.

**Localisation decision:** phase 1 ships a **Turkish source language** app: `developmentRegion = tr`, `knownRegions = (tr, en, Base)`, `Localizable.xcstrings` with `sourceLanguage = "tr"` and a complete `en` translation (§6 gives the JSON shape). Devices set to English get English; every other device language gets Turkish (the development language). Keys are identifiers (`badge.green`), looked up with `String(localized: "badge.green", defaultValue: "Karartma + algılama")` (iOS 16+), so a missing catalog entry shows the Turkish default rather than the key. The single source for all user-facing safety text is **§10 of this document**; `docs/COPY.md` (owned by WP0) is a verbatim copy of §10, and WP8 and the READMEs copy from it verbatim.

**Non-goals / honest limits (verbatim in onboarding card 3, README, `docs/COPY.md` and `docs/THREAT_MODEL.md`; Turkish text in §10.4):**
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

## 2. Threat model summary

| Adversary | Defense (phase 1) | Residual risk |
|---|---|---|
| Curious/compromised server | X3DH + Double Ratchet; envelope bodies and blobs opaque, routing header visible but authenticated (§1); timers, capture events, attachment keys inside ciphertext; plaintext padded to 256-byte buckets; delete on ack/TTL (messages on ack, attachments on recipient `DELETE` after download, §3.5b); `PRAGMA secure_delete=ON`; hashed tokens/nonces; IPs truncated to /24 (/48 v6); log retention bounded by Docker json-file rotation (3 × 10 MB, §4.9); safety numbers; identity keys in every `prekey` envelope must equal the keys the client already holds/fetches for that username (§3.2); receivers recompute `sid` from `ek` and ignore the carried field on `prekey` envelopes | Metadata/social graph incl. session events and counters; key substitution detectable only by comparing safety numbers; withheld OPKs force SPK-only sessions (replay excluded by `seen_ek`, §3.2); a stale SPK can be served for up to 21 days (bounded by `created_at` in the SPK signature, §3.1) |
| Network attacker / malicious relay server | TLS 1.2+ (ATS); optional CA pin added by the owner (§6); signed single-use nonce auth with domain separation, timestamp **and server origin** bound into every signature (§3.1) so a relayed challenge from another server is useless; E2EE underneath | Traffic analysis |
| Stolen 30-day bearer token (device not compromised) | 30-day expiry; `DELETE /v1/auth/session`; OPK batches are signed with `IK_sig` (`opks_sig`, §3.1) so a token thief cannot replace prekeys; account deletion requires `delete_sig`; E2EE unaffected (DH1–DH3 need the victim's secrets) | Silent deletion of queued ciphertext (ack/`DELETE` of attachments) = DoS; consuming other users' OPKs under the victim's quota; reading envelope headers |
| Thief without passcode / forensic extraction | `NSFileProtectionComplete` on the data directory (children inherit) and via the `com.apple.developer.default-data-protection` entitlement; Keychain `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`; store closed on `protectedDataWillBecomeUnavailableNotification`; registration refused on `LAError.passcodeNotSet`; backup excluded | AFU memory extraction while unlocked |
| Thief with passcode | App lock = explicit `locked → authenticating → unlocked` state machine around `LAContext.evaluatePolicy(.deviceOwnerAuthentication)` (§5.11); disappearing messages; panic wipe incl. server-side account deletion | Gate, not key wrap: data readable by a file dump. SE-wrapped master key is phase 2 |
| Peer: screen recording / AirPlay / QuickTime | Secure canvas blanks; `@Environment(\.isSceneCaptured)` replaces content; encrypted `ctrl.capture` to peer; local event log | First frames; iPhone Mirroring; jailbreak |
| Peer: screenshot | Secure canvas blanks (best effort); `userDidTakeScreenshotNotification` → log + encrypted report (0.5 s debounce, coalesced) | Detection-only if blanking fails |
| Peer: second camera | Hold-to-reveal (opaque placeholder), partial reveal, timers, no copy/share/save UI, forensic + visible watermark, opt-in flicker | Not preventable; watermark scrubbable |
| Peer: modified client | — (cooperative controls) | Timers/reports/forwarding unenforced on that side |
| Peer: jailbroken / instrumented device | None. No jailbreak heuristics are used (false positives, trivially bypassed, zero security value); App Attest gating is phase 2 | All client-side guarantees void on that device |
| Accessibility re-emission (VoiceOver, Speak Screen, Back Tap screenshot) | Setting "Korumalı içeriği erişilebilirlikten gizle" sets `accessibilityElementsHidden = true` on protected content (default off, degrades VoiceOver and is said so); Back Tap screenshot = ordinary screenshot path | Audio recorded by a microphone |
| Local leftovers (caches, temp files, logs, crash dumps) | Ephemeral `URLSession`, no `URLCache`; decrypt only in memory via `CGImageSourceCreateWithData(…, kCGImageSourceShouldCache: false)`; **best-effort zeroisation of the owned decrypt buffer and of the display pixel buffer on viewer dismissal; decoded CGImage bitmaps are released, not scrubbed** (§3.5b); `temporaryDirectory` cleared on launch and background; `Logger` with `privacy: .private` only, `print(` forbidden; no third-party crash/analytics SDKs (grep gate §8) | OS-level crash logs of the process image; freed-but-unscrubbed decoded bitmaps |
| Backups / migration | `isExcludedFromBackup` re-applied every launch; ThisDeviceOnly Keychain; `kSecAttrSynchronizable = false` | New device = new identity |
| Push / lock screen | Phase 1 sends no pushes and does not request notification permission; the server keeps the `push_tokens` table and `PUT …/push-token` for phase 2; payload design = generic `loc-key` only, `hiddenPreviewsBodyPlaceholder` | Generic text only (phase 2) |
| Clipboard / keyboard / Spotlight / App Switcher | No copy/drag/share actions; `UITextView` composer with autocorrection, spell check, smart quotes/dashes/insert, `inlinePredictionType = .no`, `writingToolsBehavior = .none` (iOS 18 guarded); third-party keyboards blocked via `application(_:shouldAllowExtensionPointIdentifier:)`; no `NSUserActivity`/CoreSpotlight/Intents; opaque cover added synchronously in `sceneWillResignActive` | Keyboard learning not documented as disabled; composer draft visible in screenshots |
| Server abuse (flood, enumeration, OPK depletion, replay) | Per-IP and per-user token buckets (behind a trusted proxy, keyed by `X-Forwarded-For`, §4.6); constant-shape challenge responses; identity lookup separated from OPK-claiming bundle fetch; **per-(fetcher,target) and per-target OPK claim quotas that degrade to SPK-only instead of 429** (§4.6); single-use nonce consumed by `DELETE … RETURNING`; per-recipient (5000) and per-(sender,recipient) (500) queue caps; size caps; 128-bit random ids; `UNIQUE` identity keys | Distributed DoS |

## 3. Cryptographic protocol

Primitives: X25519 (`Curve25519.KeyAgreement` / `crypto/ecdh`), pure Ed25519 (`Curve25519.Signing` / `crypto/ed25519`; the 32-byte seed is the transport form, Go uses `NewKeyFromSeed`), SHA-256, HKDF-SHA256 (`HKDF<SHA256>.deriveKey` / `crypto/hkdf.Key`), HMAC-SHA256, ChaCha20-Poly1305 (`ChaChaPoly` / `golang.org/x/crypto/chacha20poly1305`). `Encode(PK)` = raw 32 bytes. All integers big-endian. `zeros` = 32 zero bytes (equal to empty salt per RFC 5869; a vector proves it). Every DH output is checked for all-zero with a constant-time OR-accumulate in Swift and rejected (`KilitCryptoError.lowOrderPoint`), matching Go's `crypto/ecdh` error; every received X25519/Ed25519 public key must be exactly 32 bytes (`KilitCryptoError.badKeyLength`) before use. Usernames are canonicalised to lowercase ASCII `^[a-z0-9_]{3,32}$` before signing, AD construction or hashing. `device_id` is a lowercase UUIDv4 string (36 ASCII chars, regex `^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`), validated by server and client. `server_origin` is the lowercase canonical origin the client talks to: `scheme://host[:port]`, no path, no trailing slash, default ports (80/443) omitted; the server rebuilds it from its `-public-origin` flag. No RawSpan-era CryptoKit overloads (iOS 26 only). Ed25519 signatures are never compared byte-for-byte across platforms (CryptoKit's are randomized); they are verified.

**Ed25519 strictness (protocol rule, identical in Go and Swift, unconditional):** both `crypto/ed25519` and CryptoKit accept small-order `A`, so a pre-check runs in *both* `pkg/kilitcrypto/sign.go` and `Crypto/Identity.swift` before the library verify: (1) signature length exactly 64; (2) `S = sig[32:64]` interpreted little-endian must be `< L` (compared bytewise against the constant `L = 2^252 + 27742317777372353535851937790883648493`); (3) `A` (the public key) and `R = sig[0:32]` must not be one of the 8 small-order encodings (table in `primitives.json`, key `ed25519_small_order_points`, with the non-canonical `+2^255` variants included — 14 encodings). Violations → `KilitCryptoError.badSignature` (a bad public key at import time → `KilitCryptoError.badPublicKey`). The negative vectors are generated from the Go wrapper, so the vector set is identical on both sides; the rule is recorded in `docs/PROTOCOL.md`.

JSON conventions (both sides, so logs and envelopes look alike even though no JSON is ever compared byte-for-byte): Swift `JSONEncoder` with `[.sortedKeys, .withoutEscapingSlashes]`; Go `json.Encoder` with `SetEscapeHTML(false)` and struct fields declared in alphabetical order. **Optional fields (`opk_id`, `att`, `ref`, `x3dh`, `opks_sig`, `created_at` where optional): receivers must treat an absent key and an explicit `null` identically; senders may emit either** (Swift's synthesized `Codable` omits, Go's `*T` emits `null`). `envelope.json` contains both spellings and the Go/Swift round-trip tests cover both. Base64url is the unpadded URL alphabet (RFC 4648 §5); Swift has no stock encoder, so `Bytes.swift` provides `base64url(_:)`/`Data(base64url:)` tested against `base64url.json` (inputs of length 0, 1, 2, 3 mod 3 and bytes ≥ 0x80).

### 3.1 Identity and prekeys

| Key | Type | Lifetime | Storage |
|---|---|---|---|
| `IK_sig` | Ed25519 seed (32 B) | permanent | Keychain `identity.ed25519.v1` |
| `IK_dh` | X25519 | permanent | Keychain `identity.x25519.v1` |
| `SPK` + `spk_id` (uint32, monotonic) + `created_at` | X25519 | rotate every 7 d; **previous SPK private keys kept 21 d after rotation** (a live `RatchetState.DHs` owns its own copy, so SPK deletion never breaks a session); a `prekey` envelope referencing an `spk_id` no longer stored → `spk_gone` (§3.2b) | `index.json` |
| `OPK_i` + `opk_id` (uint32) | X25519 | one use; 100 at registration; refill to 100 when server reports < 20 or sends `prekeys_low`; **private key deleted only (a) on first successful use in X3DH, or (b) 7 days after the id first appeared in `consumed_ids`, or (c) 30 days after upload** — `consumed_ids` is purely a refill signal; at most 500 stored | `index.json` |

> **Rationale (OPK deletion):** the server reports an id as consumed the instant a bundle fetch claims it, but the initiator's first message is sent later (unbounded gap: offline, backgrounded, attachment upload first). Deleting on the report alone would turn every such initiation into `opk_gone`; a malicious server could trigger it at will. With the grace window an `opk_gone` classification is impossible for an id inside it; `PrekeyLifecycleTests` (Swift) and `TestOPKClaimThenLateSend` (Go store) cover fetch → offline → send.

Signatures (all with `IK_sig`, `||` = concatenation, `0x00` = single separator byte, `nonce` = the 32-byte server challenge nonce, `ts` = client unix seconds corrected by the server offset learned from the challenge, `created_at` = unix seconds the SPK was generated):
- `ik_bind_sig = Sig("Kilit_IKBind_v1" || IK_dh_pub)`
- `spk.sig = Sig("Kilit_SPK_v1" || u32BE(spk_id) || u64BE(created_at) || SPK_pub)`
- `opks_sig = Sig("Kilit_OPKBatch_v1" || u32BE(count) || (u32BE(opk_id_1) || OPK_pub_1) || … || (u32BE(opk_id_count) || OPK_pub_count))` over the batch in request order; required whenever `opks` is non-empty (register and `PUT /v1/prekeys`)
- `register_proof = Sig("Kilit_Register_v1" || 0x00 || username || 0x00 || IK_dh_pub || 0x00 || device_id || 0x00 || nonce || 0x00 || u64BE(ts) || 0x00 || server_origin)`
- `login_sig = Sig("Kilit_Auth_v1" || 0x00 || username || 0x00 || nonce || 0x00 || u64BE(ts) || 0x00 || device_id || 0x00 || server_origin)`
- `delete_sig = Sig("Kilit_Delete_v1" || 0x00 || username || 0x00 || nonce || 0x00 || u64BE(ts) || 0x00 || server_origin)`

Published bundle: `{username, ik_sig, ik_dh, ik_bind_sig, spk:{id, pub, sig, created_at}, opk:{id,pub}|null}`. Server verifies `ik_bind_sig`, `spk.sig`, `opks_sig`, `register_proof` on upload; clients re-verify `ik_bind_sig` and `spk.sig` on fetch and in every `prekey` envelope (server untrusted). **SPK freshness:** an initiator rejects a bundle whose `spk.created_at` is older than 21 days (`KilitCryptoError.staleSPK`, UI "Sunucu eski bir anahtar sunuyor"); `GET /v1/users/{u}/prekeys` returns only the newest SPK row. Because the responder keeps a rotated SPK for 21 days after rotation and rotates every 7 days, any SPK an initiator accepts (≤ 21 d old) still has its private key on the responder.

**Identity uniqueness and proof of possession:** `register_proof` proves possession of `IK_sig`; possession of `IK_dh` is implicit — an initiation to the account can only be read by the holder of `IK_dh`, and the AD binds both keys and both usernames (§3.2), so a registration with someone else's `IK_dh` yields an account that can never read a message. `users.identity_sign_pub` and `users.identity_dh_pub` are `UNIQUE` (`409 key_in_use`), which together with the AD username binding is the defence against identity misbinding.

### 3.2 X3DH session setup (Alice → Bob)

```
EK_A = fresh X25519
DH1 = X25519(IK_dh_A, SPK_B)   DH2 = X25519(EK_A, IK_dh_B)
DH3 = X25519(EK_A, SPK_B)      DH4 = X25519(EK_A, OPK_B)        # only if OPK present
SK  = HKDF(ikm = 0xFF*32 || DH1 || DH2 || DH3 [|| DH4], salt = zeros,
           info = "Kilit_X3DH_v1_X25519_SHA256_ChaChaPoly", L = 32)
WS  = HKDF(ikm = SK, salt = zeros, info = "Kilit_WM_Secret_v1", L = 32)   # watermark secret
SID = SHA256("Kilit_SID_v1" || EK_A_pub)[0:8]                            # session routing hint
AD  = IK_sig_A || IK_dh_A || IK_sig_B || IK_dh_B
      || u16BE(len(uA)) || uA || u16BE(len(uB)) || uB            # initiator first
```
Alice deletes `EK_A` and the DH outputs, runs `RatchetInitAlice(SK, SPK_B)` and stores `{sid, ws, ad, identity keys of both parties, role = initiator, createdAt}` with the session. Every message Alice sends carries the `x3dh` block (`kind:"prekey"`) **until the first message from Bob decrypts on that session**, so a lost or delayed first message never strands the session.

**Responder rules (Bob), in order, for a `prekey` envelope from username `from`:**
1. *Identity binding (fixes the key-substitution bypass).* Verify `ik_bind_sig` and the 32-byte lengths; recompute `sid` from `ek` and ignore the carried `sid`. If a contact record for `from` exists, the envelope's `ik_sig`/`ik_dh` must be byte-equal to the record; otherwise this is a **key change**: no session is created, no OPK is consumed, the envelope is parked (reason `key_change`, §3.2b step 2), the blocking "Güvenlik numarası değişti" banner is shown, and X3DH runs only after the user taps "Yeni anahtarı kabul et" (which replaces the record, marks every session whose AD identity keys differ from the new record as *superseded* (`oldIdentity`), resets `wm_secrets`, and re-runs the inbound pipeline for the parked envelopes of that peer). If no record exists, Bob performs `GET /v1/users/{from}`: a `200` with byte-equal keys continues (trust-on-first-use); a `200` with different keys or a `404` is `KilitCryptoError.identityMismatch` (envelope classified undecryptable, nothing stored); **any transient failure (offline, 5xx, 429, timeout, `401 invalid_token` until re-login) parks the envelope with reason `lookup_deferred`** and retries at 10 s, 1 m, 10 m, 1 h, then hourly; after 24 h without a definitive answer it is classified `lookup_failed`. The Safety Number (§3.6) is defined over the identity keys in the *session AD*; code asserts they equal the contact record.
2. *Replay exclusion.* `sessions/<peer>.json` keeps `seen_ek`: the last 64 accepted `ek` values (30-day expiry). If `ek ∈ seen_ek` and a session with `sid(ek)` exists → decrypt with that session (normal "Alice has not heard back yet" case). If `ek ∈ seen_ek` and no such session exists → reject as `replay`, nothing changes. A `prekey` envelope matching an existing session's `ek` never re-runs X3DH.
3. *Fresh initiation.* `spk_id` not stored → `spk_gone`; `opk_id` present but not stored → `opk_gone`. Mirror the DHs with `(SPK_B, IK_dh_A)`, `(IK_dh_B, EK_A)`, `(SPK_B, EK_A)`, `(OPK_B, EK_A)`, run `RatchetInitBob(SK, SPK_B keypair)` (the state owns a copy of the SPK private key), decrypt on a candidate state, and only on success commit the session (with `sid`, `ws`, `ad`, `role = responder`, `createdAt`), add `ek` to `seen_ek`, delete `OPK_B`'s private key, **apply supersession rule S1 below**, and re-run the pipeline for envelopes parked under this `sid`. Inner message dedupe key is **`(author, id)`** per conversation (last 10 000 entries / 30 days); a duplicate is acked and dropped silently.
4. *Unknown sender (message request).* If `from` was not a contact, step 1 created the contact with `verified = false` and the conversation flagged "Bilinmeyen gönderen"; messages are stored but the first reveal is gated behind "Kabul et"; "Engelle" drops all future envelopes from that username locally (server-side block list is phase 2).

**Multiple sessions per peer, supersession and the sending-session rule.** Each `Session` carries `sid`, `role`, `createdAt`, `lastActivity?` (timestamp of the last successful decrypt of a *peer* message on it; own sends do not count) and `superseded: Bool` (sticky, never cleared). Every envelope carries `sid`; the receiver selects the session by `sid` — there is no trial decryption across sessions. **Supersession triggers:**
- **S1 (peer moved on):** when a new *responder* session is committed from a peer `prekey` envelope (step 3), every other session with that peer that already has `lastActivity` becomes superseded. Sessions without a decrypt are untouched (this preserves the crossed case). A peer initiates a fresh session only when it has no usable session, so a fresh initiation is proof that it has lost the old one.
- **S2 (key change):** on accepted key change, every session whose AD identity keys differ from the new contact record becomes superseded (`oldIdentity`).
- **S3 (local loss):** a session whose state fails the rollback check (§3.7) or cannot be parsed is **deleted** (not superseded) and its `sid` stays in `known_sids`; the client immediately fetches a bundle and initiates a new session whose first inner message is `ctrl.resync{lost_sid}` (§3.4).

Superseded sessions still decrypt (late messages), never send, never un-supersede, and are deleted 30 days after `lastActivity`; at most 4 sessions per peer (beyond that the oldest superseded one is deleted). **Sending-session rule (deterministic, clock-free, symmetric):** candidates = non-superseded sessions with this peer; if any candidate has `lastActivity`, the one with the lexicographically smallest `sid` is the sending session; otherwise the newest own-initiated candidate (by `createdAt`); if there is none, fetch a bundle and initiate. On a crossed initiation both sides converge after one round trip (each side first replies on the session it decrypted; neither crossed session had a decrypt when the other's initiation arrived, so S1 does not fire; the first message received on the other session gives both sessions a decrypt and the min-`sid` rule picks the same one on both devices). After a loss (S3) the other side's old session is superseded by S1 the moment the new initiation decrypts, so it stops sending into the void. SPK-only sessions are accepted and shown as "peer's one-time keys exhausted". `ratchet_conversation.json` scenarios `crossed`, `lost_session`, `reinit_after_rollback` and `key_change_then_send` assert the sending `sid` on both sides at every step.

> **Reviewer note (time-windowed tie-break).** The proposal to let a peer-initiated session become the sending session immediately and to apply the crossed tie-break only to initiations within 5 minutes is not adopted as written: a time window needs synchronised clocks and makes the vectors clock-dependent. Rule S1 gives the same outcome where it matters (an old session with a decrypt is superseded by a fresh initiation) and leaves the crossed case deterministic without a clock.

> **Reviewer note (replay fix, partial adoption).** Keeping a new responder session out of the sending role "until the peer's first DH-ratchet reply" is not adopted: in the normal case Bob's only session is a responder session on which only the initial message has decrypted, and Bob must reply on it. Replay is excluded structurally by `seen_ek`, dedupe prevents re-display, and the `lastActivity`/min-`sid` rule prevents a replay-created session from displacing a live one.

> **Reviewer note (trial-decryption order).** Superseded by the `sid` routing hint: selection is by `sid`, rollback-on-copy applies to the single selected session.

### 3.2b Inbound processing policy (identical in Go reference and Swift)

For every fetched envelope (WS live push or hello/poll drain; the client deduplicates on `msg_id` because both paths can deliver the same row):
0. **Outer dedupe before any KDF.** `conv/<peer>.json` keeps `processed_msg_ids` (outer `msg_id` of every envelope that reached step 3(a); last 10 000 / 30 days). A known `msg_id` → ack silently (`already_processed`, no system row). This is what makes crash redelivery deterministic: after a crash between 3(b) and 3(c) the ratchet has advanced and the inner JSON can never be recovered, so the outer id is the only usable key.
1. Parse outer JSON; `v != 1`, unknown `kind`, missing/odd-length `sid`, `hdr` not 41 bytes, `hdr[0] != 0x01` (`KilitCryptoError.badHeader`), `dh_pub` not 32 bytes → **undecryptable** (`bad_envelope`) before any KDF. For `prekey` envelopes `sid` is recomputed from `ek`.
2. Route by `sid`/`kind` as in §3.2. **Parking (never ack while parked):** an envelope that cannot be processed *yet* is stored in `conv/<peer>.json` → `parked[]` as `{msg_id, kind, sid, envelope, receivedAt, reason}`; bound 100 per peer (oldest dropped and acked as `parked_overflow`). Reasons and lifetimes: `key_change` (7 d, until acceptance), `unknown_sid` (24 h, re-run whenever a session with that `sid` is committed), `lookup_deferred` (24 h, retry schedule in §3.2 step 1). A `msg` whose `sid` is unknown is parked; **additionally, if that `sid` is in `known_sids` (every `sid` this device ever had with the peer, kept 90 days)** the device has lost that session (S3): it initiates a fresh session with `ctrl.resync{lost_sid}` at once. On expiry the envelope is classified undecryptable with its reason (`unknown_sid`, `lookup_failed`, `key_change_expired`) and acked. Then run `RatchetDecrypt` on a *copy* of the state.
3. On success, in this order: (a) append the plaintext message **and the outer `msg_id`** to `conv/<peer>.json` (atomic write); (b) commit the advanced ratchet state (and `seen_ek`) to `sessions/<peer>.json` (atomic write); (c) ack the `msg_id`. A crash between (a) and (b) leads to redelivery (no ack) that hits step 0 → `already_processed`, acked silently, and the ratchet state is re-derived on the next genuine message via `MKSKIPPED` (the message key for `n` was never committed as consumed, so `SkipMessageKeys` stores it and it is evicted later); a crash between (b) and (c) also hits step 0. Both cases are in the `replay` scenario of `ratchet_conversation.json`.
4. On any other failure the envelope is classified **undecryptable** with a reason code (`bad_envelope`, `unknown_sid`, `identity_mismatch`, `lookup_failed`, `key_change_expired`, `parked_overflow`, `replay`, `opk_gone`, `spk_gone`, `too_many_skipped`, `decrypt_failed`); a local system row "Bu mesaj çözülemedi (<reason>)" is inserted, the reason is logged in Diagnostics, and the envelope is acked. Decryption of a persisted failure is never retried.
5. Every fetched envelope is acked exactly once, after it is stored, parked-then-resolved, or classified. **Cursor** = max server `id` of envelopes that were stored, parked or classified (persisted in `index.json`, §5.3); parked envelopes advance the cursor because they are already on the device.

### 3.3 Double Ratchet (Signal §3, ChaChaPoly instantiation)

| Function | Definition |
|---|---|
| `KDF_RK(rk, dh)` | `HKDF(ikm = dh, salt = rk, info = "Kilit_DR_v1_RootChain", L = 64)` → `rk' = out[0:32]`, `ck = out[32:64]` |
| `KDF_CK(ck)` | `mk = HMAC-SHA256(ck, 0x01)`, `ck' = HMAC-SHA256(ck, 0x02)` |
| message keys | `HKDF(ikm = mk, salt = zeros, info = "Kilit_DR_v1_MessageKeys", L = 44)` → `key = out[0:32]`, `nonce = out[32:44]` |
| `ENCRYPT` | `ChaChaPoly.seal(pt, key, nonce, aad = CONCAT(AD, header))`; wire = `ciphertext || tag(16)`; nonce implicit |
| `HEADER` | 41 bytes: `0x01 || dh_pub(32) || u32BE(pn) || u32BE(n)`; `hdr[0] != 0x01` → `badHeader` before any KDF |
| `CONCAT(ad, h)` | `u16BE(len(ad)) || ad || h` |
| limits | `MAX_SKIP = 1000` per chain (`Nr + MAX_SKIP < until` → `tooManySkipped`); `MKSKIPPED` eviction below |

State `{DHs (own private key copy), DHr, RK, CKs, CKr, Ns, Nr, PN, MKSKIPPED}`; `RatchetEncrypt / RatchetDecrypt / TrySkippedMessageKeys / SkipMessageKeys / DHRatchet` follow the spec pseudocode verbatim (`Nr += 1` after deriving `mk`; `DHRatchet` resets `Ns/Nr`, two `KDF_RK` steps). `GENERATE_DH` goes through a `KeySource` protocol (`RandomKeySource` in the app, `ScriptedKeySource` in tests). **Private-key hygiene:** `DHs` is held in a `ZeroizingKey` wrapper (Swift: `SymmetricKey`-backed storage that is zeroised on deallocation, never plain `Data`; Go: `defer clear(buf)`); `DHRatchet` overwrites and zeroises the previous `DHs`; a responder session that has never sent keeps its SPK private-key copy only until its first send (first `DHRatchet`) or until it is superseded; the `basic` vector asserts that the state dump after B1 does not contain the SPK private key. **Invariants (ChaCha20-Poly1305 has no nonce-misuse resistance):** decrypt works on a copy of the state and commits only after `open` succeeds (§3.2b order); encrypt persists the advanced state atomically *before* ciphertext is handed to the network; a retry resends the cached envelope, never re-encrypts with the same `mk` (a `ctrl.resync` resend is a *new* encryption of old plaintext, not a reuse).

**MKSKIPPED eviction (exact, so both sides agree on the remaining key set):** an entry `(dh_pub, n) → (mk, insertedAt)` belongs to the chain identified by its `dh_pub`. On every insert: (1) drop entries older than 7 days; (2) while more than 5 distinct chains remain, drop every entry of the chain with the oldest newest-entry; (3) while more than 2000 entries remain, drop the oldest entry. An entry is deleted the moment it is used. `ratchet_conversation.json` contains one eviction scenario asserting the exact remaining key set.

Padding: inner JSON (UTF-8) → `json || 0x80 || 0x00*k` to the next multiple of 256 bytes (ISO/IEC 7816-4; at least one byte is always added); unpadding rejects a block whose length is not a multiple of 256, whose last non-zero byte is not `0x80`, or that is all zero (`KilitCryptoError.badPadding`). **Size budget:** inner JSON ≤ 40 960 bytes before padding (rejected before encryption), so padded ≤ 41 216 B, ciphertext ≤ 41 232 B, base64url ≤ 54 976 chars; with `hdr`, `sid`, the `x3dh` block (~300 chars) and framing the decoded envelope stays below the 65 536-byte envelope cap. The server decodes `envelope` and rejects `len(decoded) > maxEnvelope` with `413 envelope_too_large`; the HTTP body cap (128 KiB for `POST /v1/messages`) is enforced separately. `envelope.json` contains the maximum-size case and a `len % 256 != 0` negative.

### 3.4 Envelope formats

Server-visible `POST /v1/messages` body (the server treats `envelope` as opaque bytes and supplies `from` itself on delivery; there is no client-supplied `from`):
```json
{"to":"bob","msg_id":"9f1c…32hex","envelope":"<base64url(E2E bytes)>"}
```
E2E envelope bytes = UTF-8 JSON (`b64` = base64url, no padding; `sid` on every envelope; the server can read every field below except `ct`):
```json
{"v":1,"kind":"prekey","sid":"b64(8)",
 "x3dh":{"ik_sig":"b64","ik_dh":"b64","ik_bind_sig":"b64","ek":"b64","spk_id":7,"opk_id":1203},
 "hdr":"b64(41 bytes)","ct":"b64(ciphertext||tag)"}
```
`kind` is `"prekey"` (with `x3dh`; `opk_id` may be `null` or absent) or `"msg"` (no `x3dh`). Inner plaintext JSON (after unpadding); `ttl` is the conversation timer at send time in seconds (0 = off) and is present on every message so disappearing deadlines are reorder-safe:
```json
{"t":"text","id":"uuid","ts":1760000000,"ttl":86400,"text":"merhaba"}
{"t":"image","id":"uuid","ts":1760000000,"ttl":86400,
 "att":{"blob":"32hex","key":"b64(fileKey 32)","sha256":"b64(32)","mime":"image/jpeg","len":123456,"w":1200,"h":900}}
{"t":"ctrl.timer","id":"uuid","ts":…,"ttl":0,"timer":3600}
{"t":"ctrl.capture","id":"uuid","ts":…,"ttl":0,"seq_from":42,"seq_to":44,"count":3,
 "kind":"screenshot","ref":["uuid","uuid"]}        // kind: screenshot|recording_started|recording_stopped|blanking_unavailable
{"t":"ctrl.read","id":"uuid","ts":…,"ttl":0,"ref":["uuid"]}
{"t":"ctrl.delete","id":"uuid","ts":…,"ttl":0,"ref":["uuid"]}
{"t":"ctrl.resync","id":"uuid","ts":…,"ttl":0,"lost_sid":"b64(8)"}
```
Control-message semantics and budget (also in `docs/PROTOCOL.md`):
- **Dedupe and `ref` resolution.** The dedupe key is `(author, id)`. `ref` lists are resolved as `(expected author, id)`: for `ctrl.delete` the expected author is the control's sender; for `ctrl.read` the expected author is the receipt's recipient (i.e. the local user); for `ctrl.capture` the expected author is either party (`ref` is informational). An `id` that collides with a message of the other author is simply a different message. `ratchet_conversation.json` scenario `id_collision` covers it.
- `ctrl.capture`: events are **coalesced** client-side into one message per 2 s window per `kind`, carrying the **per-conversation** monotonic counter (owned by `CaptureGlue`, persisted in `index.json` as `captureSeq[peer]`) as the range `seq_from…seq_to` (gaps remain visible to the receiver), `count`, and the merged `ref` list of message ids visible during the window. Control messages are queued at lower priority than text/image messages and sent after them.
- `ctrl.read`: optional (Settings "Okundu bilgisi", default **off**). Sent at most once per 5 s per conversation, batching the ids first revealed in that window; only ids authored by the *recipient of the receipt* are honoured; renders a small "Görüldü" state on the sender.
- `ctrl.delete`: `ref` entries must identify messages **authored by the sender of the control message**; the receiver deletes those messages + blobs + keys locally; any other id is ignored and logged.
- `ctrl.resync`: sent as the first inner message of a fresh session created under S3 (or on `unknown_sid ∈ known_sids`). The receiver marks the session `lost_sid` superseded (S1 already did so), and **re-sends on the new session** its own messages that were sent on `lost_sid` within the last 7 days and are still stored locally (oldest first, at most 50), with their original `id`/`ts`/`ttl` so the peer's `(author, id)` dedupe drops any that had arrived. Each resend is a fresh ratchet encryption.
- `blanking_unavailable`: sent once per app launch per peer, the first time a conversation with that peer is opened while `SecureCanvasView.isProtected == false`.
- Every control message is a full ratchet message (advances the sending chain, 256-byte-padded envelope); the budget above keeps a screenshot burst, a 20 s reveal cycle or a 50-message resync inside the server's `Every(100ms)`/burst-50 send limit (the resync is paced at 10/s).

### 3.5 Attachments (single-shot, phase 1)

`blob_id` = 16 random bytes generated **by the client** (hex32 on the wire; the server rejects a duplicate id with `409 blob_exists`, on which the client generates a new `blob_id` and re-uploads, at most 3 attempts). `fileKey` = 32 random bytes = the `att.key` field. `HKDF(ikm = fileKey, salt = zeros, info = "Kilit_Attach_v1", L = 44)` → `key || nonce`. `AAD = "Kilit_Attach_v1" || version(1 byte, 0x01) || blob_id(16) || u16BE(len(mime)) || mime || u64BE(plaintext_len)`, where `plaintext_len` = `att.len` (the receiver must find exactly that many bytes after `open`). **The AAD deliberately omits sender and recipient:** the `fileKey` travels only inside the ratchet message, so binding to parties adds nothing and would complicate the vectors. Blob file = `"KATT" || 0x01 || ciphertext || tag(16)` (plaintext + 21 bytes); `att.sha256` = SHA-256 over the **entire blob file including the 5-byte header**. Version `0x02` is reserved for the chunked format (phase 1.5): `HKDF(ikm = fileKey, salt = zeros, info = "Kilit_Attach_v2", L = 36)` → `key(32) || prefix(4)`; 1 MiB chunks, nonce = `prefix(4) || u64BE(i)`, AAD = v1 AAD with `0x02` version byte `|| u32BE(i) || u8(is_last)`; v1 and v2 keys are therefore distinct.

**Send pipeline:** the picked `UIImage` is normalised by drawing it into `UIGraphicsImageRenderer(size: targetSize, format: {scale = 1, opaque = true})` with the long edge ≤ 2048 px and calling `jpegData(compressionQuality: 0.8)` on the result — this output is upright, carries no EXIF orientation tag and no GPS/maker metadata, and `att.w/h` equal the pixel dimensions. Plaintext cap 8 MiB. Upload precedes the message; the message carries `blob`, `key`, `sha256`, `len`, `mime`, `w`, `h`. **The sender never deletes the blob** (it cannot know whether delivery happened; its own local expiry may precede delivery); the server's blob TTL (§4.7) is the sender-side bound.

> **Reviewer note (sender-side blob deletion).** Having the sender call `DELETE /v1/attachments/{id}` when its own message expires is rejected: sender-side expiry is `sentAt + ttl` (e.g. 30 s) and happens before an offline recipient fetches the message, which would turn every short-timer attachment into "Ek süresi doldu". The recipient-side delete below plus the server TTL implements ack-based deletion.

**§3.5b Receive and display pipeline (feature 2):** `dataTask` on the ephemeral REST session (no `downloadTask`, so no temp file in `Caches/`) → verify `sha256` over the received bytes → write ciphertext with `[.atomic, .completeFileProtection]` to `blobs/<id>.bin` (a 404 shows "Ek süresi doldu" instead of an error) → **issue `DELETE /v1/attachments/{id}`** (fire-and-forget, retried from the outbox with the same 5 s–10 min backoff; a 404 counts as success). On open: read the file, allocate an owned `UnsafeMutableRawBufferPointer` of `att.len` bytes, `ChaChaPoly.open` with the AAD above and copy the result into that buffer (the transient `Data` returned by `open` is released immediately; it is the one copy that cannot be scrubbed), check `count == att.len`, wrap the buffer with `CFDataCreateWithBytesNoCopy(kCFAllocatorDefault, ptr, len, kCFAllocatorNull)`, `CGImageSourceCreateWithData(cfData, [kCGImageSourceShouldCache: false])`, then `CGImageSourceCreateThumbnailAtIndex(src, 0, [kCGImageSourceCreateThumbnailFromImageAlways: true, kCGImageSourceCreateThumbnailWithTransform: true, kCGImageSourceThumbnailMaxPixelSize: 2048, kCGImageSourceShouldCache: false])` (belt and braces for orientation; the sender already normalised), hand the `CGImage` to `CaptureProtectedImageView.display(_:)` (which converts it into a `CVPixelBuffer` it retains). **Dismissal order (best effort):** `displayLayer.sampleBufferRenderer.flush()` → release the `CMSampleBuffer`, the `CGImage` and the `CGImageSource` (set to nil) → `CVPixelBufferLockBaseAddress` + `memset_s` over the pixel buffer's base address for `bytesPerRow × height` → unlock and release → `memset_s` over the owned decrypt buffer → `deallocate()`. The decoded bitmap inside ImageIO and any intermediate copies are freed, not scrubbed; the threat table says so. Forbidden anywhere: `UIImage(contentsOfFile:)`, `UIImage(named:)` for protected content, `ImageAnalysisInteraction`, `QLPreviewController`, `UIDocumentInteractionController`, `PHPhotoLibrary` writes. `FileManager.default.temporaryDirectory` is emptied in `application(_:didFinishLaunchingWithOptions:)` and `sceneDidEnterBackground(_:)` (PhotosPicker spools land there).

### 3.6 Safety number

Per party: `h = SHA256("Kilit_SafetyNumber_v1" || IK_sig || IK_dh || username)`, then 5199 times `h = SHA256(h || IK_sig || IK_dh)`. Take `h[0:30]` as six 5-byte big-endian integers, each `mod 100000`, zero-padded to 5 digits → 30 digits. Safety number = 60 digits, lexicographically smaller 30-digit string first; shown in 12 groups of 5 and as QR `kilit-sn:v1:<60 digits>`. **The keys used are the identity keys bound in the active session's AD**, which the code asserts equal the contact record (`identityMismatch` otherwise). Any change of a contact's `IK_sig`/`IK_dh` — detected on fetch *or* in a `prekey` envelope (§3.2 step 1) — shows a blocking "Güvenlik numarası değişti" banner and disables sending until the user taps "Yeni anahtarı kabul et".

### 3.7 Local store wrapping

`masterKey = SymmetricKey(size: .bits256)` in Keychain. `storeKey = HKDF(ikm = masterKey, salt = zeros, info = "Kilit_LocalStore_v1", L = 32)`; per document `docKey = HKDF(ikm = storeKey, salt = zeros, info = "Kilit_LocalStoreDoc_v1" || relativePath, L = 32)`. Each store document = `ChaChaPoly.seal(JSON, docKey, nonce: random(4) || u64BE(generation), authenticating: AAD).combined` with `AAD = "Kilit_LocalStore_v1" || relativePath (UTF-8) || u64BE(generation)`, written `[.atomic, .completeFileProtection]`. `(docKey, nonce)` uniqueness is structural: distinct paths have distinct keys, and `generation` is strictly increasing per path (the 4 random bytes are a bonus, not a requirement). `generation` is a per-document counter incremented on every write; the counters for all documents live in `index.json`, and the generation of `index.json` itself lives in the Keychain item `store.generation`.

**Normative write order and load rule:** (1) child documents (`conv/*.json`, `sessions/*.json`, `blobs/*.bin`) first, each `[.atomic]`; (2) then `index.json`; (3) then the Keychain `store.generation`, updated on a serial background queue, coalesced to at most once per 2 s and flushed on `sceneDidEnterBackground`. On load a document is accepted when its `generation ≥` the recorded value (**never** equality); a higher value is adopted as the new record (a crash after step 1 or 2 is therefore harmless). A document whose generation is *below* the recorded value, or whose AAD does not match its path, fails closed (`LocalStoreError.rollback`): for a session file this deletes the session and triggers S3 (§3.2), for `index.json` a wipe prompt. A Keychain write that fails after a successful `index.json` write is tolerated (next load sees `≥`). This catches file swaps, restored-from-backup copies and accidental rollback (which would otherwise lead to message-key/nonce reuse on the next send). `SessionStoreAtomicityTests` injects a crash after each of the three writes and asserts no wipe prompt and no forced X3DH.

### 3.8 Test vectors

`go run ./cmd/vectors -out ../docs/vectors -swift ../ios/Kilit/Tests/Vectors` writes the JSON files and one Swift file per set: `KilitVectors.swift` (`enum KilitVectors {}`) plus `KilitVectors+Primitives.swift`, `+Base64url`, `+X3DH`, `+Ratchet`, `+Attachment`, `+Envelope`, `+Safety`, `+Watermark`, each `extension KilitVectors { static let <set>: String = #""" … """# }` (raw multi-line literal, so JSON backslashes are untouched). The generator uses `json.Encoder` with `SetEscapeHTML(false)` and `SetIndent`, and **fails** if any output contains the sequence `"""#` or exceeds 200 KB per file. All vectors are deterministic (fixed seeds, derived nonces). A golden test fails if regeneration drifts. **Vectors feed raw bytes:** every ratchet/X3DH step gives the *padded plaintext as hex* and expects `hdr`/`wire` byte-equal; JSON (de)serialisation of inner messages is tested separately by field-wise round-trip, never byte-for-byte. The file schemas are normative in §3.9 (copied to `docs/VECTOR_SCHEMA.md` by WP0).

**Set A — `x3dh_session.json`.** Inputs: Alice `ik_sig_seed = 00…01`, `ik_dh_priv = 00…02`, `ek_priv = 00…03`, first ratchet `dhs_priv = 00…04`; Bob `ik_sig_seed = 10…01`, `ik_dh_priv = 10…02`, `spk_priv = 10…03` (`spk_id 7`, `created_at = 1759900000`), `opk_priv = 10…04` (`opk_id 1203`), a second OPK `10…06` (`opk_id 1204`) for the batch signature; usernames `alice`, `bob`; `device_id = "6f1d2c3b-4a59-4e8f-9b0c-1d2e3f4a5b6c"`; `nonce = 0x20*32`; `ts = 1760000000`; `server_origin = "https://kilit.example.com"`. Outputs: all public keys; `ik_bind_sig`, `spk.sig`, `opks_sig`, `register_proof`, `login_sig`, `delete_sig` (Go deterministic; Swift verifies them and verifies its own fresh signatures) plus the exact signed message bytes (hex) for each; `dh1..dh4`, `sk`, `ws`, `sid`, `ad`, the full `prekey` envelope JSON for the first message (for parsing tests, not byte comparison), and a `no_opk` variant (`sk_no_opk`, `ad` unchanged). Negative cases: `ik_dh` swapped for another key → `identityMismatch`; `ik_bind_sig` over the wrong key → `badSignature`; `spk.created_at = ts − 22 d` → `staleSPK`.

**Set B — `ratchet_conversation.json`** (scenarios array). Inputs: Set A `sk`, `ad`, Bob's SPK keypair, scripted `KeySource` lists for both sides, an injected clock. `basic`: A1, A2, B1 (DH step; state dump must not contain the SPK private key), B2, A3 (DH step), B3, B4 delivered before B3 (skipped-key path), B3, A4, then a tampered copy of A4 (last tag byte flipped) and an `n` jump of 1001. `crossed`: both sides initiate (Bob's `ek_priv = 10…05`), exchange one message each on their own session, then one more each; expected `sid` values, the sending `sid` of each side at every step, and the final superseded flags. `replay`: Alice's first `prekey` envelope delivered twice, once before and once after a legitimate session exists; plus the crash-redelivery cases (redelivery of an envelope whose `msg_id` is in `processed_msg_ids`, with and without the committed ratchet state) → `already_processed`. `eviction`: 2100 skipped keys across 6 chains with injected timestamps; expected exact remaining `MKSKIPPED` key set. `lost_session`: converged session S; Bob deletes S; Alice sends on S → Bob parks (`unknown_sid ∈ known_sids`), initiates S2 with `ctrl.resync{S}`; Alice: S superseded by S1, resends; expected sending `sid` on both sides at every step and the final message sets. `reinit_after_rollback`: Bob's session file fails the generation check (S3) — same expectations plus `LocalStoreError.rollback`. `key_change_then_send`: Alice re-registers with new keys, Bob accepts the key change, both sides' sending `sid` is the new session and the old one is superseded (`oldIdentity`). `id_collision`: Bob sends a text whose `id` equals one of Alice's own ids; both are kept; a `ctrl.delete` from Bob with that id deletes only Bob's. `opk_grace`: Bob's OPK 1203 reported consumed at `t0`; Alice's initiation arrives at `t0 + 6 d` → decrypts; at `t0 + 8 d` → `opk_gone`. Per step: padded plaintext (hex), `hdr`, `aad`, `mk`, `key`, `nonce`, `wire`, and `RK, CKs, CKr, Ns, Nr, PN, MKSKIPPED keys` after the step. Expected errors: tamper → `authenticationFailure` with state unchanged; jump → `tooManySkipped`; `hdr[0] = 0x02` → `badHeader`; `dh_pub` of 31 bytes → `badKeyLength`.

Also `primitives.json` (RFC 7748 §6.1, RFC 8032 §7.1 test 1, RFC 5869 test 1, RFC 8439 §2.8.2, HKDF empty-vs-zero-salt equivalence, low-order point `00…00` → error, 31-byte key → `incorrectKeySize`, the malformed-Ed25519 negatives of §3 with the small-order table), `base64url.json`, `attachment.json` (blob file bytes for a 100-byte plaintext with `mime = "image/jpeg"`, `sha256`, AAD bytes, a wrong-`len` negative), `envelope.json` (padding cases incl. missing `0x80`, all-zero block, `len % 256 != 0`, the 40 960-byte maximum, a 40 961-byte rejection, outer-JSON negatives, absent-vs-`null` optional fields), `safety.json`, `watermark.json` (tag, CRC-4 with a worked bit-by-bit example, 16-bit payload, 36-cell layout for the Set A identities at `unix = 1760400000` (day number 20375, `day = 20375 mod 16 = 7`), the **integer delta map** at scale 1 (168×168 int8, hex) and SHA-256 of the maps at scales 2 and 3, and 16 sampled `(x, y, lighter, darker)` pixel values at scale 3).

> **Reviewer note (tolerance test for the tile).** A ±1 tolerance comparison is unnecessary: the map is produced by integer arithmetic identical in both languages (§5.9), so the test is exact. The only tolerance-based check is the device photo calibration (§7).

### 3.9 Vector file schemas (normative for WP1 and WP5)

Encodings: every byte string is **lowercase hex** unless the key name ends in `_b64` or the value is a copy of wire JSON (envelope objects use base64url exactly as on the wire). Integers are JSON numbers. Expected errors are strings equal to the Swift case name: `KilitCryptoError` cases `lowOrderPoint, badKeyLength, badPublicKey, badSignature, identityMismatch, replay, staleSPK, tooManySkipped, badHeader, badPadding, sizeLimit, unknownSession`; CryptoKit cases `authenticationFailure, incorrectKeySize, incorrectParameterSize`; store errors `rollback`. Classification strings are the reason codes of §3.2b.

```jsonc
// primitives.json
{"x25519":[{"name":"rfc7748","priv":"hex32","pub":"hex32","peer_pub":"hex32","shared":"hex32"}],
 "x25519_negative":[{"name":"low_order","priv":"hex32","peer_pub":"hex32","error":"lowOrderPoint"},
                    {"name":"short_key","priv":"hex32","peer_pub":"hex31","error":"badKeyLength"}],
 "ed25519":[{"name":"rfc8032_1","seed":"hex32","pub":"hex32","msg":"hex","go_sig":"hex64"}],
 "ed25519_negative":[{"name":"s_ge_l","pub":"hex32","msg":"hex","sig":"hex","error":"badSignature"}],
 "ed25519_small_order_points":["hex32", "…14 entries"],
 "hkdf":[{"name":"rfc5869_1","ikm":"hex","salt":"hex","info":"hex","len":42,"okm":"hex"},
         {"name":"empty_vs_zero_salt","ikm":"hex","salt_a":"","salt_b":"00…(32)","info":"hex","len":32,"okm":"hex"}],
 "hmac_kdf_ck":[{"ck":"hex32","mk":"hex32","ck_next":"hex32"}],
 "chachapoly":[{"name":"rfc8439","key":"hex32","nonce":"hex12","aad":"hex","pt":"hex","wire":"hex"}],
 "chachapoly_negative":[{"name":"short_key","key":"hex31","error":"incorrectKeySize"},
                        {"name":"bad_tag","key":"hex32","nonce":"hex12","aad":"hex","wire":"hex","error":"authenticationFailure"}]}

// base64url.json
{"cases":[{"bytes":"hex","text":"base64url"}]}

// x3dh_session.json
{"inputs":{"alice":{"username":"alice","ik_sig_seed":"hex32","ik_dh_priv":"hex32","ek_priv":"hex32","dhs_priv":"hex32"},
           "bob":{"username":"bob","ik_sig_seed":"hex32","ik_dh_priv":"hex32","spk_priv":"hex32","spk_id":7,"spk_created_at":1759900000,
                  "opks":[{"id":1203,"priv":"hex32"},{"id":1204,"priv":"hex32"}]},
           "device_id":"uuid","nonce":"hex32","ts":1760000000,"server_origin":"https://kilit.example.com"},
 "public":{"alice":{"ik_sig":"hex32","ik_dh":"hex32","ek":"hex32"},"bob":{"ik_sig":"hex32","ik_dh":"hex32","spk":"hex32","opks":[{"id":1203,"pub":"hex32"}]}},
 "signatures":{"ik_bind_sig":{"signer":"bob","msg":"hex","sig":"hex64"},"spk_sig":{...},"opks_sig":{...},
               "register_proof":{"signer":"alice","msg":"hex","sig":"hex64"},"login_sig":{...},"delete_sig":{...}},
 "x3dh":{"dh1":"hex32","dh2":"hex32","dh3":"hex32","dh4":"hex32","sk":"hex32","sk_no_opk":"hex32","ws":"hex32","sid":"hex8","ad":"hex"},
 "first_envelope":{ /* wire JSON object, base64url fields */ },
 "negative":[{"name":"ik_dh_swapped","error":"identityMismatch"},{"name":"bad_bind_sig","error":"badSignature"},{"name":"stale_spk","spk_created_at":1758000000,"error":"staleSPK"}]}

// ratchet_conversation.json
{"scenarios":[{"name":"basic","clock_start":1760000000,
  "key_sources":{"A":["hex32","…"],"B":["hex32","…"]},
  "steps":[
   {"op":"init_alice","side":"A","session":"S1","sk":"hex32","peer_pub":"hex32","ad":"hex","state_after":{STATE}},
   {"op":"init_bob","side":"B","session":"S1","sk":"hex32","dhs_priv":"hex32","ad":"hex","state_after":{STATE}},
   {"op":"encrypt","side":"A","session":"S1","label":"A1","pt_padded":"hex","hdr":"hex41","aad":"hex","mk":"hex32","key":"hex32","nonce":"hex12","wire":"hex","state_after":{STATE}},
   {"op":"decrypt","side":"B","session":"S1","label":"A1","hdr":"hex41","wire":"hex","pt_padded":"hex","state_after":{STATE}},
   {"op":"decrypt_expect_error","side":"B","session":"S1","hdr":"hex41","wire":"hex","error":"authenticationFailure","state_unchanged":true},
   {"op":"advance_clock","seconds":86400},
   {"op":"deliver_envelope","side":"B","from":"alice","msg_id":"hex16","envelope":{WIRE JSON},"expect":"stored|parked|classified","reason":"replay","expect_sending_sid":{"A":"hex8","B":"hex8"}},
   {"op":"delete_session","side":"B","session":"S1"},
   {"op":"accept_key_change","side":"B","peer":"alice"},
   {"op":"expect_mkskipped","side":"B","session":"S1","keys":[{"dh":"hex32","n":3}]},
   {"op":"expect_state_excludes","side":"B","session":"S1","bytes":"hex32"}]}]}
// STATE = {"rk":"hex32","cks":"hex32|null","ckr":"hex32|null","ns":0,"nr":0,"pn":0,"dhs_priv":"hex32","dhr":"hex32|null","mkskipped":[{"dh":"hex32","n":0,"mk":"hex32"}]}

// attachment.json
{"cases":[{"blob_id":"hex16","file_key":"hex32","mime":"image/jpeg","pt":"hex","key":"hex32","nonce":"hex12","aad":"hex","blob":"hex","sha256":"hex32"}],
 "negative":[{"name":"wrong_len","blob_id":"hex16","file_key":"hex32","mime":"image/jpeg","len":99,"blob":"hex","error":"authenticationFailure"}]}

// envelope.json
{"padding":[{"json":"hex","padded":"hex"}],
 "padding_negative":[{"padded":"hex","error":"badPadding"}],
 "size":{"max_ok_len":40960,"reject_len":40961,"error":"sizeLimit"},
 "outer":[{"name":"opk_null","json":"{…\"opk_id\":null…}","parses":true},{"name":"opk_absent","json":"{…}","parses":true},
          {"name":"v2","json":"…","parses":false,"reason":"bad_envelope"}],
 "inner_roundtrip":[{"json":"{…}"}]}

// safety.json
{"cases":[{"username":"alice","ik_sig":"hex32","ik_dh":"hex32","digits":"30 digits"}],"pairs":[{"a":"alice","b":"bob","number":"60 digits","qr":"kilit-sn:v1:…"}]}

// watermark.json
{"inputs":{"ws":"hex32","viewer":"alice","unix":1760400000},
 "tag":171,"day":7,"crc_steps":[{"bit":1,"fb":1,"crc":3}],"crc":9,"payload16":43897,
 "sync":"10110100011100101001","cells":[[true,false,…6],…6 rows],
 "delta":{"cell_pt":28,"k_per_scale":4,"amplitude":5,
          "scale1":{"w":168,"h":168,"int8":"hex (28224 bytes)"},
          "scale2_sha256":"hex32","scale3_sha256":"hex32",
          "samples_scale3":[{"x":10,"y":10,"delta":5,"lighter":5,"darker":255}]}}
```

## 4. Server design (Go 1.24)

### 4.1 Package layout (`server/`)

```
go.mod / go.sum            module github.com/tekinadakan-sudo/clawDbot/server; go 1.24.0  (WP0; read-only afterwards)
internal/pins/pins.go      blank imports of all four pinned modules so `go mod tidy` keeps the pins (WP0)
internal/ws/api.go         Delivery struct + Notifier interface (WP0, exact declarations below)
cmd/kilitd/main.go         flags/env, wiring (mux ← ws handler + notifier), signal.NotifyContext, graceful shutdown
cmd/vectors/main.go        writes docs/vectors/*.json + ios/Kilit/Tests/Vectors/KilitVectors*.swift
cmd/wmdecode/main.go       offline watermark decoder (photo + 4 corner points → {tag, day, confidence})
internal/config/config.go  Config struct, flag+env parsing
internal/store/            db.go (open, DSN pragmas, migrations via schema_version), schema.sql (go:embed),
                           users.go, prekeys.go, messages.go, attachments.go, sessions.go, nonces.go, sweeper.go
internal/auth/             challenge.go, login.go, message.go (canonical signed bytes), middleware.go (bearer)
internal/api/              mux.go (routes; takes ws http.Handler and ws.Notifier), middleware.go (recover, request-id,
                           slog, ratelimit, per-route body caps, proxy-IP warning), errors.go (code catalogue),
                           handlers_register.go, handlers_auth.go, handlers_users.go, handlers_prekeys.go,
                           handlers_messages.go (INSERT then notifier.Notify), handlers_attachments.go, handlers_devices.go
internal/ws/               api.go (WP0), hub.go (registry per user, fan-out, closeAll; implements http.Handler and Notifier),
                           conn.go (reader loop, writer with bounded queue, drain/live sequencing, ping 30 s), frames.go, handler.go
internal/blob/             store.go (os.Root), sweeper.go
internal/ratelimit/        keyed.go (x/time/rate + janitor), pair.go (two-key limiter for (fetcher,target))
internal/push/             pusher.go (Pusher interface), noop.go
pkg/kilitcrypto/           bytes.go, kdf.go, aead.go, sign.go (Ed25519 strict pre-checks), x3dh.go,
                           session.go (sid, seen_ek, supersession + selection rule, parking), inbound.go (§3.2b policy),
                           ratchet.go, keysource.go, envelope.go, attach.go, safety.go, watermark.go (payload + integer delta map),
                           wmdecode.go (decoder core, pure Go image ops), imgops.go (homography warp, bilinear, box blur, resize),
                           errors.go, *_test.go   (reference lib; server never imports it)
Dockerfile, docker-compose.yml, Caddyfile, Makefile, README.md
```
Pinned (newer releases require Go ≥ 1.26): `github.com/coder/websocket v1.8.15`, `golang.org/x/crypto v0.48.0`, `golang.org/x/time v0.14.0`, `golang.org/x/sync v0.19.0`, `modernc.org/sqlite v1.46.1`. `GOTOOLCHAIN=local` everywhere; never `go get -u`. `go.mod`/`go.sum` are committed once by WP0 with all pins and are read-only for WP1–WP4. **`golang.org/x/image` is not pinned:** `cmd/wmdecode` and its unit test implement homography warp, bilinear sampling, separable box blur and box/bilinear resize in pure Go on top of `image`, `image/draw`, `image/jpeg`, `image/png` only (`pkg/kilitcrypto/imgops.go`).

**Shared contracts (WP0, verbatim):**
```go
// internal/ws/api.go
package ws
// Delivery is one queued row handed to a live connection.
type Delivery struct { ID int64; MsgID string; From string; Envelope []byte; TS int64 }
// Notifier must never block the caller. The hub enqueues into a per-connection buffered channel of 256
// deliveries; on overflow the connection is closed with 1008 "slow_consumer" and the client re-syncs via hello.
type Notifier interface { Notify(userID int64, d Delivery) }

// internal/api/mux.go (WP3)
func New(cfg config.Config, st *store.Store, wsHandler http.Handler, n ws.Notifier) http.Handler

// internal/store (WP2) — minimal method list WP3/WP4 code against; all take ctx first
CreateUser(ctx, u NewUser) (userID int64, err error)            // ErrUsernameTaken, ErrKeyInUse
GetUserByName(ctx, username string) (*User, error)                 // ErrNotFound
DeleteUser(ctx, userID int64) error
PutSignedPrekey(ctx, userID int64, spk SignedPrekey) error          // ErrSPKNotMonotonic
PutOneTimePrekeys(ctx, userID int64, opks []OneTimePrekey) (count int, err error) // ErrOPKExists, ErrTooManyOPKs
FetchBundle(ctx, targetID int64, claimOPK bool) (*Bundle, error)
PrekeyCount(ctx, userID int64) (count int, spkID uint32, consumed []uint32, err error)
PutNonce(ctx, hash []byte, username string, expiresAt int64) error
ConsumeNonce(ctx, hash []byte, username string, now int64) (ok bool, err error)
CreateSession(ctx, tokenHash []byte, userID int64, deviceID string, expiresAt int64) error
LookupSession(ctx, tokenHash []byte, now int64) (*Session, error)
DeleteSession(ctx, tokenHash []byte) error
InsertMessage(ctx, m NewMessage) (id int64, existing bool, err error)   // ErrMsgIDConflict, ErrRecipientFull
ListMessages(ctx, recipientID, after int64, limit int) ([]Delivery, bool, error)
AckMessages(ctx, recipientID int64, msgIDs [][]byte) (deleted int, err error)
InsertAttachment(ctx, a NewAttachment) error; GetAttachment(ctx, id string) (*Attachment, error); DeleteAttachment(ctx, id string) error
PutPushToken(ctx, userID int64, deviceID, token, env string) error
Sweep(ctx, now int64) (SweepReport, error)
```

### 4.2 SQLite

DSN: `file:<path>?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)&_pragma=secure_delete(1)&_txlock=immediate`; `SetMaxOpenConns(4)`. Only the `_pragma=` form exists in v1.46.1.

```sql
CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL) STRICT;
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  identity_sign_pub BLOB NOT NULL UNIQUE CHECK(length(identity_sign_pub)=32),
  identity_dh_pub   BLOB NOT NULL UNIQUE CHECK(length(identity_dh_pub)=32),
  identity_bind_sig BLOB NOT NULL CHECK(length(identity_bind_sig)=64),
  created_at INTEGER NOT NULL) STRICT;
CREATE TABLE IF NOT EXISTS signed_prekeys (
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  key_id INTEGER NOT NULL, pub BLOB NOT NULL CHECK(length(pub)=32),
  sig BLOB NOT NULL CHECK(length(sig)=64), created_at INTEGER NOT NULL,
  PRIMARY KEY(user_id, key_id)) STRICT;
CREATE TABLE IF NOT EXISTS one_time_prekeys (
  id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  key_id INTEGER NOT NULL, pub BLOB NOT NULL CHECK(length(pub)=32), UNIQUE(user_id, key_id)) STRICT;
CREATE INDEX IF NOT EXISTS opk_user_id ON one_time_prekeys(user_id, id);
CREATE TABLE IF NOT EXISTS consumed_opks (
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, key_id INTEGER NOT NULL,
  claimed_at INTEGER NOT NULL, PRIMARY KEY(user_id, key_id)) STRICT;
CREATE TABLE IF NOT EXISTS auth_nonces (
  nonce_hash BLOB PRIMARY KEY, username TEXT NOT NULL COLLATE NOCASE,
  expires_at INTEGER NOT NULL) STRICT;
CREATE TABLE IF NOT EXISTS sessions (
  token_hash BLOB PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_id TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, last_seen INTEGER NOT NULL) STRICT;
CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id);
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT, msg_id BLOB NOT NULL UNIQUE,
  recipient_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  sender_id INTEGER NOT NULL, sender_username TEXT NOT NULL,
  envelope BLOB NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL) STRICT;
CREATE INDEX IF NOT EXISTS messages_recipient ON messages(recipient_id, id);
CREATE INDEX IF NOT EXISTS messages_sender_recipient ON messages(recipient_id, sender_id);
CREATE INDEX IF NOT EXISTS messages_expires ON messages(expires_at);
CREATE TABLE IF NOT EXISTS attachments (
  id TEXT PRIMARY KEY CHECK(length(id)=32), owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  recipient_id INTEGER NOT NULL, size INTEGER NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL) STRICT;
CREATE INDEX IF NOT EXISTS attachments_expires ON attachments(expires_at);
CREATE TABLE IF NOT EXISTS push_tokens (
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, device_id TEXT NOT NULL,
  token TEXT NOT NULL, env TEXT NOT NULL CHECK(env IN ('sandbox','production')), updated_at INTEGER NOT NULL,
  PRIMARY KEY(user_id, device_id)) STRICT;
```
`AUTOINCREMENT` on `users.id` and `messages.id` prevents rowid reuse after `DELETE /v1/users/me`; `sender_username` is denormalised at insert time so `from` on delivery is resolvable after the sender's account is gone (store test: delete user → re-register same name → old queued rows are delivered with the old `from` and are undecryptable by the new identity). Atomic OPK claim (inside the same immediate tx as the `consumed_opks` insert): `DELETE FROM one_time_prekeys WHERE id=(SELECT id FROM one_time_prekeys WHERE user_id=? ORDER BY id LIMIT 1) RETURNING key_id, pub`. Signed prekeys: bundle fetch returns `ORDER BY key_id DESC LIMIT 1` (incl. `created_at`); `PUT /v1/prekeys` with `spk` rejects `key_id <= current` (`400 spk_not_monotonic`), inserts, then deletes all but the two newest rows for that user. OPK upload is transactional: a duplicate `key_id` for the same user → `409 opk_exists` (whole request rejected); more than 500 stored OPKs after the insert → `400 too_many_opks`. `consumed_opks` rows are swept after 30 days. **Idempotent message insert (one immediate tx):** `SELECT id, sender_id, recipient_id FROM messages WHERE msg_id=?` → row with the same sender and recipient → `202` with that `id`; row with a different sender or recipient → `409 msg_id_conflict`; no row → check queue caps (`SELECT count(*) … WHERE recipient_id=?` and `… AND sender_id=?`) → `INSERT … RETURNING id`.

### 4.3 REST endpoints

#### 4.3.1 Conventions and error catalogue
- All timestamps (`ts`, `expires_at`, `created_at`, `server_time`) are unix seconds as JSON integers.
- Key bytes, `nonce`, `token`, `sig`, `envelope` are base64url unpadded strings; `msg_id` and `blob_id` are 32 lowercase hex chars; `device_id` is a lowercase UUIDv4; `username` is canonical (§3). Optional fields: absent and `null` are equivalent (§3).
- Errors are `{"error":"<code>","message":"<human text>"}` with the HTTP status in the table. Unknown users on `challenge` are indistinguishable from known ones (real nonce is always issued, bound to the username string).
- Body caps are per route (middleware): JSON routes 64 KiB, `POST /v1/messages` 128 KiB, `PUT /v1/prekeys` 256 KiB, attachment upload `-max-upload` (8 MiB + 21). `http.MaxBytesHandler` is **not** applied to the whole mux.

| Code | HTTP | Where |
|---|---|---|
| `bad_json`, `bad_username`, `bad_device_id`, `bad_key_length`, `bad_signature`, `spk_not_monotonic`, `too_many_opks`, `bad_msg_id`, `bad_blob_id`, `bad_ts` | 400 | validation |
| `invalid_token`, `nonce_invalid` (expired/unknown/replayed), `clock_skew` (`|now − ts| > 300`, body also carries `server_time`) | 401 | auth |
| `forbidden` (not owner/recipient) | 403 | attachments |
| `unknown_user`, `not_found` | 404 | lookups, messages, attachments |
| `username_taken`, `key_in_use`, `opk_exists`, `blob_exists`, `msg_id_conflict` (same `msg_id`, different sender or recipient) | 409 | register, prekeys, attachments, messages |
| `body_too_large`, `envelope_too_large` (decoded envelope > `-max-envelope`) | 413 | body caps |
| `rate_limited` (`Retry-After: 1`), `recipient_full` (client keeps the message in the outbox and retries with exponential backoff 5 s–10 min) | 429 | rate limits, queue caps |
| `internal` | 500 | recover middleware |

#### 4.3.2 Routes (B = `Authorization: Bearer`)

| Method/path | Auth | Request → Response |
|---|---|---|
| `POST /v1/auth/challenge` | – | `{username}` → `200 {nonce, expires_at, server_time}` (always 200; nonce bound to the username string, 60 s, single use; used for register, login and delete) |
| `POST /v1/register` | – | `{username, ik_sig, ik_dh, ik_bind_sig, register_proof, nonce, ts, spk:{id,pub,sig,created_at}, opks:[{id,pub}], opks_sig, device_id}` → `201 {user_id, token, expires_at}`; `409 username_taken` / `key_in_use`; `400 bad_signature`/`bad_username`/`bad_device_id`; `401 nonce_invalid`/`clock_skew`. **On `409 username_taken` the client re-challenges and reuses the already generated keys** (nothing was stored); the register limiter does not count 409 responses (§4.6) |
| `POST /v1/auth/login` | – | `{username, nonce, ts, device_id, sig}` → `200 {token, expires_at}`; `401` |
| `DELETE /v1/auth/session` | B | → `204` |
| `DELETE /v1/users/me` | B | `{nonce, ts, sig}` (`delete_sig`) → `204`; cascades users → prekeys, consumed_opks, sessions, messages as recipient, attachments as owner (files removed), push_tokens; messages *sent* by the user stay queued for their recipients with their stored `sender_username` |
| `GET /v1/users/{username}` | B | → `200 {username, ik_sig, ik_dh, ik_bind_sig}`; `404` (identity only; never claims an OPK; used for add-contact, TOFU on inbound `prekey`, safety-number refresh) |
| `GET /v1/users/{username}/prekeys` | B | → `200 {username, ik_sig, ik_dh, ik_bind_sig, spk:{id,pub,sig,created_at}, opk:{id,pub}|null}`; `404` (newest SPK only; claims one OPK unless a quota in §4.6 is exceeded, in which case `opk` is `null`) |
| `PUT /v1/prekeys` | B | `{spk:{id,pub,sig,created_at}|null, opks:[{id,pub}], opks_sig}` → `200 {opk_count, spk_id}`; `opks_sig` verified with the account's `identity_sign_pub` whenever `opks` is non-empty |
| `GET /v1/prekeys/count` | B | → `200 {opk_count, spk_id, consumed_ids:[…]}` (ids claimed in the last 30 days; a refill signal only) |
| `POST /v1/messages` | B | `{to, msg_id, envelope}` → `202 {id}`; duplicate `msg_id` with same sender and recipient → `202` same id; same `msg_id` from another sender or to another recipient → `409 msg_id_conflict`; `404 unknown_user`; `413 envelope_too_large`; `429 recipient_full` |
| `GET /v1/messages?after=<id>&limit=100` | B | → `200 {messages:[{id, msg_id, from, envelope, ts}], has_more}` |
| `POST /v1/messages/ack` | B | `{msg_ids:[…]}` → `200 {deleted}` (`WHERE recipient_id = me`) |
| `POST /v1/attachments/{id}` | B | header `X-Kilit-Recipient: bob`, body octet-stream ≤ 8 MiB + 21 → `201 {id, expires_at}`; `409 blob_exists`; `413 body_too_large`; `404 unknown_user` |
| `GET /v1/attachments/{id}` | B (owner or recipient) | → octet-stream, `Cache-Control: no-store` |
| `DELETE /v1/attachments/{id}` | B (owner or recipient) | → `204`; called by the recipient after a verified download (§3.5b) |
| `PUT /v1/devices/{device_id}/push-token` | B | `{token, env}` → `204` (phase-2 readiness; the phase-1 app never calls it) |
| `GET /v1/ws` | B header (`?token=` only when `KILIT_WS_QUERY_TOKEN=1`, off by default) | WebSocket upgrade |
| `GET /healthz` | – | `200 {"ok":true,"version":"<ldflags -X main.version>"}` |

Routing: Go 1.22 `ServeMux` method patterns; `TestRoutesRegister` catches conflicts; method mismatch yields the automatic 405. `/v1/ws` is registered with an `http.Handler` injected from `cmd/kilitd/main.go` (the `internal/ws.Hub`), and `handlers_messages.go` fans out after `INSERT` through the `ws.Notifier` interface from `internal/ws/api.go`. Listener is HTTP/1.1 only (`Server.Protocols.SetHTTP2(false)`) because `websocket.Accept` needs `http.Hijacker`; TLS terminates at Caddy. `ReadHeaderTimeout 10 s`, `IdleTimeout 120 s`.

### 4.4 WebSocket protocol (text frames, JSON, `SetReadLimit(128<<10)`, ≤ 3 connections/user)

Client → server: `{"t":"hello","after":4400}` (must be the first frame and arrive within 10 s of the upgrade, else close `1008` reason `no_hello`), `{"t":"ack","msg_ids":[…]}` (fire-and-forget, idempotent; REST ack also allowed), `{"t":"ping"}`.
Server → client: `{"t":"msg","id":4411,"msg_id":"…","from":"alice","envelope":"…","ts":1760000000}`, `{"t":"pong"}`, `{"t":"prekeys_low","opk_count":12,"consumed_ids":[…]}` (sent on connect and after every claim that drops the count below 20), `{"t":"error","code":"bad_frame"}`.
**Drain/live sequencing (per connection):** after `hello` the connection is in `draining`; `Notify` deliveries arriving during the drain are buffered (same 256-slot queue); the drain pages `id > after` in order; when the last page is sent, buffered deliveries with `id ≤ lastDrained` are dropped and the rest are flushed in `id` order; then the connection is `live`. A `ws` test inserts a row concurrently with the drain and asserts strictly increasing `id`s with no gap and no duplicate.
Limits: a 4th connection for a user closes the *oldest* with `1000` reason `superseded`; a frame over the read limit makes the library close the connection with `1009` automatically (the WS test asserts `CloseStatus == 1009`); an unparseable frame → error frame then close `1002`; a full per-connection queue → close `1008` reason `slow_consumer`. Sending is REST-only. Server pings every 30 s via `Conn.Ping(ctx, 10 s)`, closes after two failures. Handlers read with `context.Background()`; shutdown uses `RegisterOnShutdown(hub.closeAll)` → `Close(StatusGoingAway, "server shutting down")` → `WaitGroup`.

### 4.5 Auth flow

Challenge: 32 random bytes; store `SHA256(nonce)` bound to the canonical `username` string, `expires_at = now+60`; respond with `server_time` so the client computes `offset = server_time − localNow` and signs with `ts = localNow + offset`. Register/login/delete: `|now − ts| ≤ 300` (else `401 clock_skew` with `server_time`); consume with `DELETE FROM auth_nonces WHERE nonce_hash=? AND username=? AND expires_at>? RETURNING 1` (0 rows → `401 nonce_invalid`) *before* verifying; rebuild the signed message server-side from the fields plus `-public-origin`; `ed25519.Verify` after the strict pre-checks of §3. Register verifies `register_proof` with the submitted `ik_sig` and issues a token directly. Token: 32 random bytes, stored as SHA-256, 30-day expiry, `last_seen` updated at most once per minute. The client maps `401 invalid_token` → re-challenge/login once; `401 clock_skew` → explanation "Cihaz saati yanlış" (never re-onboarding); persistent `401 bad_signature`/`unknown_user` on login → `.onboarding` with explanation.

### 4.6 Rate limits (`internal/ratelimit.Keyed`, janitor evicts entries idle > 10 min)

| Route | Key | Limit |
|---|---|---|
| challenge | IP | `Every(2s)`, burst 10 |
| register | IP | `Every(20m)`, burst 3; implemented with `Reserve()` and the reservation is `Cancel()`ed on `409 username_taken` so picking taken names does not lock the user out |
| login | IP | `Every(2s)`, burst 10 |
| delete account | user | `Every(1h)`, burst 3 |
| user lookup | user + IP | `Every(1s)`, burst 20 |
| prekey fetch (request) | user + IP | `Every(1s)`, burst 20 |
| prekey fetch (**OPK claim**, per (fetcher, target)) | fetcher user → target user | `Every(20m)`, burst 3; beyond it the bundle is served **without** an OPK (no 429, so the fetcher cannot distinguish) |
| prekey fetch (**OPK claim**, per target, all fetchers) | target user | `Every(10s)`, burst 30; beyond it SPK-only; claim rate is logged per target and `prekeys_low` is pushed so the target refills |
| send message | user | `Every(100ms)`, burst 50; recipient queue cap 5000, per-(sender,recipient) cap 500 |
| upload | user | `Every(2s)`, burst 5 |
| other authed | user | `Every(200ms)`, burst 30 |

`429 rate_limited` with `Retry-After: 1`. **Client IP behind the proxy:** `X-Forwarded-For` (first untrusted hop) is honored only when `RemoteAddr` matches a `-trusted-proxy` CIDR; otherwise `RemoteAddr` is used. If a request carries `X-Forwarded-For` while no trusted proxy is configured, the middleware logs a warning (once per minute) "requests arrive via a proxy but -trusted-proxy is unset; per-IP limits are shared". `docker-compose.yml` configures the proxy CIDR (§4.9). API tests: with a trusted proxy configured, two `X-Forwarded-For` values get separate buckets; without, the header is ignored. Store test: 50 bundle fetches of one target by one account leave ≥ 90 of its 100 OPKs.

### 4.7 Attachment storage and sweepers

`os.OpenRoot(blobDir)` (Go 1.24 method set only: `OpenFile, Open, Mkdir, Remove, Stat`). Path `id[:2]/id`; `OpenFile(O_CREATE|O_EXCL|O_WRONLY, 0o600)` (`fs.ErrExist` → 409), `io.Copy` from `http.MaxBytesReader(w, r.Body, maxUpload)` applied only on this route (`*http.MaxBytesError` → 413), `Sync`, then insert row; failed insert removes the file. Serve with `http.ServeContent`, `application/octet-stream`, `Cache-Control: no-store`. Sweeper every 60 s: expired messages, nonces, sessions, `consumed_opks`; attachments `SELECT id … WHERE expires_at<? LIMIT 500` → `root.Remove` → delete row. **Blob TTL = message TTL + 24 h** (`-blob-ttl` defaults to `-msg-ttl + 24h`; startup refuses `blob-ttl < msg-ttl + 24h`), because a blob is always uploaded *before* the message that references it and the gap between upload and send is unbounded; a recipient that still hits a 404 shows "Ek süresi doldu". Startup `filepath.WalkDir` removes orphan files. API tests: an 8 MiB upload succeeds and a 8 MiB + 22 byte upload is 413; upload → download (recipient) → `DELETE` (recipient) → `GET` returns 404 and the file is gone.

### 4.8 Config (flags, env override `KILIT_*`)

`-addr :8080`, `-public-origin https://kilit.example.com` (required; used in signed messages), `-db /data/kilit.db`, `-blobs /data/blobs`, `-msg-ttl 168h`, `-blob-ttl 192h`, `-max-upload 8388629`, `-max-envelope 65536`, `-queue-cap 5000`, `-sender-queue-cap 500`, `-trusted-proxy` (CIDR list), `-ws-query-token false`, `-log-level info`. Logging `log/slog` JSON: no bodies, no tokens, IPs truncated, usernames never paired with IPs.

### 4.9 Dockerfile and deployment

```dockerfile
# syntax=docker/dockerfile:1
FROM golang:1.24-alpine AS build
WORKDIR /src
ARG VERSION=dev
ENV GOTOOLCHAIN=local CGO_ENABLED=0 GOFLAGS=-trimpath
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go build -ldflags="-s -w -X main.version=${VERSION}" -o /out/kilitd ./cmd/kilitd
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/kilitd /kilitd
VOLUME ["/data"]
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/kilitd","-db","/data/kilit.db","-blobs","/data/blobs","-addr",":8080"]
```
`Makefile`: `build` passes `VERSION=$(git describe --always --dirty)`. `Caddyfile`:
```
kilit.example.com {
    reverse_proxy kilitd:8080
}
```
`docker-compose.yml`: a named network `kilitnet` with a fixed subnet (`ipam: {config: [{subnet: 172.28.0.0/16}]}`); services `kilitd` (env `KILIT_PUBLIC_ORIGIN=https://kilit.example.com`, **`KILIT_TRUSTED_PROXY=172.28.0.0/16`**, volume `./data:/data`, `stop_grace_period: 15s`, `logging: {driver: json-file, options: {max-size: "10m", max-file: "3"}}`) and `caddy` (ports 80/443, volumes for `Caddyfile`, `caddy_data`, `caddy_config`). **Log retention is bounded by rotation (3 × 10 MB), not by time**; there is no separate log sweeper and the threat table says so. Prerequisites: DNS A/AAAA record for the domain pointing at the VPS; ports 80 and 443 open (ACME); `mkdir -p data && sudo chown 65532:65532 data` (distroless `nonroot` uid); `/data` on a local disk (WAL needs local file locking).

### 4.10 Test plan (Linux: `go vet ./...`, `CGO_ENABLED=0 go test ./...`; `-race` in CI with `CGO_ENABLED=1`)

- `pkg/kilitcrypto`: RFC vectors incl. the strict-Ed25519 negatives; X3DH symmetry with/without OPK; `identityMismatch` on key swap; `staleSPK`; `sid`/`seen_ek`/replay classification; supersession rules S1–S3 and the sending-session rule on `crossed`, `lost_session`, `reinit_after_rollback`, `key_change_then_send`; parking/unparking and `ctrl.resync` resend set; OPK grace timing; outer `msg_id` dedupe on crash redelivery; `(author, id)` collision; ratchet 200-message fuzz with reordering ≤ MAX_SKIP; skipped-key eviction exact set; tamper → error, state unchanged; MAX_SKIP violation; `badHeader`; **no-mk-reuse assertion** (set of `(key,nonce)` over a fuzz run has no duplicates); SPK private key absent from a responder state after its first send; attachment seal/open + AAD/len mismatch; watermark payload/CRC/delta map (golden) + decoder round-trip (synthetic tile → box blur radius cell/3 → JPEG Q75 → 0.4× bilinear resize → decode); golden-file test for `cmd/vectors`.
- `internal/store`: `t.TempDir()` DB per test; idempotent migrations; OPK claim atomic under 8 goroutines; claim → late send still finds the row intact server-side; SPK monotonic + prune to two; OPK duplicate 409 / cap 500; `UNIQUE` identity keys → `ErrKeyInUse`; `msg_id` idempotency (same pair → existing) and cross-sender/cross-recipient conflict; ack scoped to recipient; sweepers incl. blob TTL margin; `_txlock=immediate` concurrency (8 × 25 tx, zero `SQLITE_BUSY`); account delete cascade + re-register same name → old rows keep old `from`; `AUTOINCREMENT` no id reuse.
- `internal/auth`: nonce single-use, expiry, cross-username nonce rejected, clock skew returns `server_time`, origin mismatch rejected, canonical message bytes golden-tested against `x3dh_session.json`; `opks_sig` verified.
- `internal/api` (`httptest.NewServer`): challenge → register → lookup → prekeys → send → poll → ack → gone; replayed nonce 401; bad signature 400/401; 405; 429 after burst; register 409 does not consume the limiter; OPK quota degrades to SPK-only (50 fetches leave ≥ 90); 413 oversize body and oversize decoded envelope; 8 MiB upload OK; 409 duplicate blob; upload → download → delete → 404; `recipient_full`; `msg_id_conflict`; `key_in_use`; `DELETE /v1/users/me`; trusted-proxy bucket separation; route-conflict test.
- `internal/ws`: `websocket.Dial`; hello drains then live (through `Notifier`) with the concurrent-insert ordering test; no hello → 1008; 4th connection supersedes oldest; slow consumer → 1008; read limit → 1009; ack over WS; `prekeys_low`; graceful close returns 1001.

## 5. iOS app design (`ios/`)

### 5.1 File tree

```
ios/Kilit.xcodeproj/                              hand-written pbxproj (§6), workspace data, shared scheme
ios/project.yml                                   XcodeGen fallback
ios/Kilit/Info-Debug.plist                        file-only keys + scene manifest + NSAllowsLocalNetworking; OUTSIDE both synced folders
ios/Kilit/Info-Release.plist                      file-only keys + scene manifest; OUTSIDE both synced folders
ios/Kilit/Kilit.entitlements                      com.apple.developer.default-data-protection = NSFileProtectionComplete
ios/Kilit/Sources/                                synced folder → target Kilit
  App/KilitApp.swift                              @main, @UIApplicationDelegateAdaptor, RootView switch
  App/AppDelegate.swift                           configurationForConnecting → SceneDelegate; blocks .keyboard extension point; tmp cleanup
  App/SceneDelegate.swift                         PrivacyCover on sceneWillResignActive; protected-data notifications; tmp cleanup on background
  App/AppModel.swift                              @Observable root: phase, lockState, session, contacts, conversations, settings, diagnostics
  App/AppLock.swift                               locked → authenticating → unlocked state machine (§5.11)
  App/CaptureGlue.swift                           maps Security.CaptureEventKind → per-peer seq + Store.CaptureEvent + MessageSync.sendControl (coalescing)
  App/Diagnostics.swift                           secureCanvasAvailable + mode, panel Hz, measured Hz, capture state, OPK count, undecryptable log, wm_secrets hex
  Crypto/KilitCryptoError.swift                   lowOrderPoint, badKeyLength, badPublicKey, badSignature, identityMismatch, replay, staleSPK, tooManySkipped, badHeader, badPadding, sizeLimit, unknownSession
  Crypto/Bytes.swift                              Data(hex:), hex, base64url, u16/u32/u64 BE, constant-time zero check, ZeroizingKey
  Crypto/KDF.swift                                HKDF/HMAC wrappers; all info-string constants
  Crypto/AEAD.swift                               ChaChaPoly seal/open with implicit nonce; ISO 7816 padding
  Crypto/Identity.swift                           IdentityKeys, SignedPrekey (created_at), OneTimePrekey, strict Ed25519 pre-checks, signatures (§3.1)
  Crypto/KeySource.swift                          protocol KeySource { func x25519() -> PrivateKey }; Random/Scripted impls
  Crypto/X3DH.swift                               initiate(bundle:now:) / respond(x3dh:) → (sk, ws, sid, ad)
  Crypto/Session.swift                            Session {sid, role, createdAt, lastActivity, superseded, ws, ad, identities, state}; seen_ek; S1–S3; sending-session rule
  Crypto/Inbound.swift                            §3.2b policy as a pure function over (store snapshot, envelope) → actions; parking; known_sids
  Crypto/RatchetState.swift                       Codable state incl. own DHs (ZeroizingKey), MKSKIPPED entries with timestamps + eviction
  Crypto/DoubleRatchet.swift                      encrypt/decrypt with copy-commit; MessageHeader 41 B; CONCAT; DHs zeroise on DHRatchet
  Crypto/Envelope.swift                           outer envelope + inner message Codable (§3.4); JSONEncoder sortedKeys/withoutEscapingSlashes; absent==null
  Crypto/AttachmentCrypto.swift                   fileKey, seal/open into owned buffer, "KATT" header, AAD, sha256
  Crypto/SafetyNumber.swift                       60-digit fingerprint + QR string (from session AD keys)
  Crypto/WatermarkPayload.swift                   tag derivation, CRC-4, 16-bit payload, 36-cell layout, integer delta map (§5.9)
  Store/Keychain.swift                            SecItem wrappers (WhenPasscodeSetThisDeviceOnly; WhenUnlockedThisDeviceOnly on Simulator); serial queue
  Store/LocalStore.swift                          encrypted JSON documents with docKey + generation nonce/AAD, write order §3.7, Complete protection dir, backup exclusion, reinstall marker
  Store/Models.swift                              Contact (verified, wm_secrets), Conversation, Message (receivedAt, firstRevealedAt, expiresAt…), CaptureEvent, ParkedEnvelope, Settings
  Store/SessionStore.swift                        sessions/<peer>.json: Sessions (current + superseded), seen_ek, pending-send cache; write-before-send
  Store/PrekeyStore.swift                         SPK/OPK private keys with upload/consumed/used dates; deletion rules §3.1; refill trigger
  Store/BlobStore.swift                           blobs/<id>.bin ciphertext files
  Store/DisappearingScheduler.swift               deadlines (injected clock), purge on launch/foreground, unrevealed bound (ttl > 0 only)
  Net/APIClient.swift                             actor; two ephemeral URLSessions (REST / WS); REST calls (§4.3); clock offset; DTOs in Net/DTO.swift
  Net/DTO.swift                                   Codable request/response structs, field names exactly as §4.3
  Net/WebSocketClient.swift                       URLSessionWebSocketTask, hello/ack/ping, backoff 1–30 s, poll fallback
  Net/MessageSync.swift                           actor: inbound pipeline (§3.2b) incl. parking/retry, outbound encrypt→persist→send, resync resend, control coalescing, prekey refill, attachment DELETE
  Net/ImageNormalizer.swift                       UIGraphicsImageRenderer re-encode (≤ 2048 px, no metadata)
  Security/CaptureEventKind.swift                 enum screenshot|recordingStarted|recordingStopped|blankingUnavailable (no Store dependency)
  Security/SecureHostField.swift                  UITextField subclass; canvas lookup by class-name suffix
  Security/SecureCanvasView.swift                 contentView inside canvas; re-evaluated isProtected canary; recognizer disabling in the same pass
  Security/CaptureShield.swift                    alternative: Signal/Telegram layer-swap on a throwaway UITextField (flag-selected, same canary)
  Security/SecureContainer.swift                  UIViewControllerRepresentable + SecureHostingController<AnyView>; environment forwarded; sizing .fill
  Security/CaptureMonitor.swift                   isSceneCaptured bridge, screenshot debounce, onEvent(kind, timestamp)
  Security/CaptureProtectedImageView.swift        AVSampleBufferDisplayLayer.preventsCapture viewer + watermark CALayers above it + scrubbed teardown
  Security/PrivacyCover.swift                     opaque UIView cover + SwiftUI scenePhase redaction
  Security/WatermarkTile.swift                    delta map → two opaque BGRA CGImages (CGDataProvider), cached per (payload, scale)
  Security/WatermarkOverlay.swift                 SwiftUI: tiled Image + .plusLighter/.plusDarker inside hosted content; visible string
  Security/WatermarkLayers.swift                  CALayer pair with compositingFilter "plusL"/"plusD" and pattern background (viewer)
  Security/FlickerMaskView.swift                  CADisplayLink alternating masks + FlickerShield representable
  Security/HoldToReveal.swift                     PressHoldView (UILongPressGestureRecognizer, scroll guard) + RevealController (20 s auto-end, injected clock)
  Security/SecureComposer.swift                   UITextView representable with learning traits off
  Resources/Localizable.xcstrings                 sourceLanguage tr, full en (compiled by the synced folder)
  UI/Onboarding/OnboardingView.swift              Welcome → PasscodeGate → Username/server → 3 explanation cards → Done
  UI/Contacts/ContactsView.swift                  list, add by username (GET /v1/users), key-change state, message requests
  UI/Contacts/SafetyNumberView.swift              digits + QR + "Doğrulandı"
  UI/Chat/ConversationView.swift                  ProtectionBadge, CaptureBanner, SecureContainer{MessageList + WatermarkOverlay}, composer
  UI/Chat/MessageBubble.swift                     HoldToReveal, system rows (timer/capture/undecryptable/resync), image thumbnail placeholder
  UI/Chat/ComposerView.swift                      SecureComposer + PhotosPicker + camera
  UI/Chat/ProtectedImageViewer.swift              fullScreenCover: SecureContainer{CaptureProtectedImageView}, band-reveal overlay, flicker
  UI/Chat/ProtectionBadge.swift                   green/amber/red toolbar badge with one-sentence explanation
  UI/Settings/SettingsView.swift                  timer default, app lock, secure layer + mode, capture reports, read receipts, accessibility hide, server URL (read-only), wipe
  UI/Settings/ExperimentalView.swift              flicker toggle with eligibility reasons
  UI/Settings/PhotosensitivityWarningSheet.swift  EN/TR warning from docs/COPY.md, Keep off default, Turn on destructive
  UI/Settings/DiagnosticsView.swift               Diagnostics + capture log + undecryptable log + wm_secrets hex
  Assets.xcassets/                                AppIcon, AccentColor
ios/Kilit/Tests/                                  synced folder → target KilitTests
  Vectors/KilitVectors.swift, Vectors/KilitVectors+{Primitives,Base64url,X3DH,Ratchet,Attachment,Envelope,Safety,Watermark}.swift
  CryptoVectorTests.swift, Base64urlTests.swift, X3DHVectorTests.swift, SessionSelectionTests.swift, InboundPolicyTests.swift,
  RatchetVectorTests.swift, AttachmentTests.swift, EnvelopeTests.swift, SafetyNumberTests.swift, WatermarkTests.swift,
  SecureCanvasTests.swift, FlickerGateTests.swift, CaptureMonitorTests.swift, HoldToRevealTests.swift,
  DisappearingSchedulerTests.swift, LocalStoreTests.swift, SessionStoreAtomicityTests.swift, PrekeyLifecycleTests.swift,
  WebSocketClientTests.swift, AppLockTests.swift
```

### 5.2 View hierarchy and state

`KilitApp` → `RootView` switches on `AppModel.phase` (`.onboarding`, `.locked`, `.main`). `.main` = `NavigationStack { ContactsView }` → `ConversationView(conversation:)`; sheets: `SafetyNumberView`, `SettingsView`; `fullScreenCover`: `ProtectedImageViewer`. `ConversationView` body: `VStack { CaptureBanner; SecureContainer { ZStack { MessageList; WatermarkOverlay } }.frame(maxWidth: .infinity, maxHeight: .infinity); ComposerView }` with `ProtectionBadge` in the toolbar (green "Karartma + algılama", amber "Yalnızca algılama" when the canary failed, red "Ekran kaydediliyor"). State: one `@Observable final class AppModel` via `.environment(appModel)`; per-conversation `@Observable ConversationModel` holds decrypted messages in memory only while on screen; `MessageSync` and `APIClient` are actors, UI updates hop to `@MainActor`. **Environment across the UIKit boundary:** custom environment values and `@Observable` objects do not cross `UIViewControllerRepresentable` → `UIHostingController` on their own (only trait-backed values do), so `SecureContainer` re-applies the outer environment to the hosted root (§5.5); `NavigationStack`, sheets, `fullScreenCover` and `dismiss` live outside the containers and the hosted content only *reads* state and calls model methods. Swift language mode 5. No `@SceneStorage`, no state restoration. All user-visible strings go through `String(localized:defaultValue:)` keys in `Localizable.xcstrings`. **Conversation identity and ordering:** conversation id = canonical peer username (one conversation per contact, survives key change); the list is ordered by local `receivedAt`/`sentAt`; the sender's `ts` is shown only as metadata.

### 5.3 Persistence

| Data | Where | Protection |
|---|---|---|
| `IK_sig` seed, `IK_dh`, `masterKey`, bearer token, `device_id`, `store.generation` | Keychain generic passwords, service `com.kilit.keys`, `kSecUseDataProtectionKeychain = true`, `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` (`WhenUnlockedThisDeviceOnly` under `#if targetEnvironment(simulator)`); all `SecItem*` calls on one serial background queue | Never migrates; vanish on passcode removal → forced re-registration; reinstall detected by a missing `UserDefaults` `installMarker` → wipe |
| `index.json` (contacts with `verified`, `wm_secrets[]`; conversation metadata; settings; SPK/OPK privates with `uploadedAt`/`consumedReportedAt`; capture log; `captureSeq[peer]`; **`cursor`** (last processed server message id, §3.2b step 5, reset to 0 on wipe); per-document generations; server URL + clock offset) | `Application Support/Kilit/` (dir created with `.protectionKey: .complete`, `isExcludedFromBackup` re-applied each launch) | sealed per §3.7; `[.atomic, .completeFileProtection]` |
| `sessions/<peer>.json` (all `Session`s incl. `RatchetState` with own private keys, `sid`, `role`, `createdAt`, `lastActivity`, `superseded`, `ws`, `ad`; `seen_ek`; `known_sids`; pending-send cache) | same dir | same; written atomically before every send and after every successful decrypt (§3.2b order) |
| `conv/<peer>.json` (message log; `(author,id)` dedupe set; `processed_msg_ids`; `parked[]`) | same dir | same; separate from session state so a send never rewrites the history; written *before* the ratchet commit on receive |
| `blobs/<id>.bin` | same dir | same; deleted with the message |

`Message` model fields: `id, conversationID, author (.me/.peer), kind, ts (sender clock), sentAt?, receivedAt?, firstRevealedAt?, expiresAt?, ttl, text?, att?, sentOnSid?, state (.outbox/.sent/.received/.revealed/.undecryptable(reason))`. `LocalStore` closes and drops `storeKey` on `protectedDataWillBecomeUnavailableNotification` and reopens on `protectedDataDidBecomeAvailableNotification`. The per-conversation document rewrite is O(history) per message — acceptable for phase 1, noted as a known scaling cliff (migrate to per-message files in phase 2).

### 5.4 Networking

Two `URLSessionConfiguration.ephemeral` sessions, both with `urlCache = nil`, `requestCachePolicy = .reloadIgnoringLocalCacheData`: the **REST/upload session** with `waitsForConnectivity = true`, `timeoutIntervalForResource = 60`; the **WebSocket session** with `waitsForConnectivity = false`, `timeoutIntervalForResource = 15`, so a dead LAN/VPN fails the task fast and the backoff/poll state machine runs instead of waiting for the 7-day default. `APIClient` methods mirror §4.3: `challenge`, `register`, `login`, `logout`, `deleteAccount`, `lookup(username:)`, `fetchBundle(username:)`, `uploadPrekeys`, `prekeyCount`, `send`, `poll(after:)`, `ack`, `upload(blobID:recipient:data:)`, `download`, `deleteBlob`. Server URL is user-entered in onboarding, canonicalised to `server_origin` (§3), stored in `index.json`, and **read-only after registration** (changeable only through "Hesabı sil ve sıfırla", because `register_proof` is origin-bound). **ATS fact:** Apple documents that from iOS 17 ATS no longer allows connections to IP-address hosts by default and that `NSAllowsLocalNetworking = YES` re-enables them; the **Debug** build's `Info-Debug.plist` therefore carries `NSAppTransportSecurity → NSAllowsLocalNetworking = true` (no `NSAllowsArbitraryLoads`) so `http://<lan-ip>:8080` / `ws://` work for the two-phone LAN test. The Release build has no ATS exceptions and no pin; §6 documents how the owner adds `NSPinnedDomains` once the production domain's CA SPKI hash is known. `WebSocketClient` creates `URLSessionWebSocketTask` from a `URLRequest` with the bearer header, sends `hello` with `index.json`'s `cursor`, exponential backoff 1–30 s, polls every 20 s while down (`WebSocketClientTests` uses a stubbed failing task and asserts the backoff/poll fallback starts); inbound rows are deduplicated by `msg_id` across the WS and poll paths before entering the §3.2b pipeline. Outbound: encrypt → persist state + cached envelope → `POST`; on `429 recipient_full` the message stays in the outbox with backoff; control messages are coalesced and queued behind content messages (§3.4); attachment `DELETE`s share the outbox.

### 5.5 SecureContentView (secure layer)

`SecureHostField: UITextField`: `isSecureTextEntry = true`, `borderStyle = .none`, `textColor/tintColor/backgroundColor = .clear` (never `alpha`), `isAccessibilityElement = false`, `autocorrectionType = .no`, `textContentType = nil`; overrides `canBecomeFirstResponder → false`, `textRect/editingRect/placeholderRect(forBounds:) → bounds`, `gestureRecognizerShouldBegin(_:) → false`, `hitTest(_:with:)` forwarded to `hostedContent`, `layoutSubviews()` sets `secureCanvas.frame = bounds` where `secureCanvas = subviews.first { String(describing: type(of: $0)).hasSuffix("CanvasView") }` (`_UITextLayoutCanvasView` on iOS 15–26; never by layer index).

`SecureCanvasView: UIView` adds the field edge-to-edge and calls `field.layoutIfNeeded()` in `didMoveToWindow()` (lazy canvas). **The canary is re-evaluated on every `layoutSubviews()` and `didMoveToWindow()`, not once:** `let canvas = field.secureCanvas; let ok = canvas != nil && contentView.superview === canvas && canvas?.superview === field; if !ok { attachContent() }`, and `isProtected`/`onProtectionChange` fire on every transition in either direction (UITextField may discard and recreate its private canvas on text, trait or window changes; a stale canvas would otherwise make the content vanish while the badge stays green). **In the same re-evaluation pass**, every recognizer in `(field.gestureRecognizers ?? []) + (canvas?.gestureRecognizers ?? [])` gets `isEnabled = false` (public API) — UITextInteraction installs recognizers lazily, so a one-time pass is not enough. `SecureCanvasTests` includes "set `field.text`, layout again → content still inside the *current* canvas, `isProtected == true`, and every recognizer on field and current canvas is disabled".

**Alternative blanking mode (flag `Settings.secureLayerMode = .canvas | .layerSwap`, default `.canvas`):** `CaptureShield.setHidden(_:layerOf:)` is the Signal/Telegram variant — a throwaway `UITextField`, find its `TextLayoutCanvasView` subview, `canvas.setValue(view.layer, forKey: "layer")`, toggle `isSecureTextEntry` off→on, restore the original layer — applied to `SecureHostingController.view.layer` (re-applied in `updateUIViewController` and on `didMoveToWindow`). Its canary is "canvas view found" (`isProtected` has the same meaning: the flag could be stamped). The owner can switch modes in Settings › Diagnostics after the first device test without re-architecting. Grep gate: `setValue(_:forKey: "layer")` on a `UIView` is permitted **only** in `Security/CaptureShield.swift`; `disableUpdateMask` is forbidden everywhere.

`SecureContainer<Content: View>: UIViewControllerRepresentable` hosts a `UIHostingController<AnyView>` in `SecureHostingController` with `hosting.safeAreaRegions = .container` (iOS 16.4+) so only the outer SwiftUI hierarchy performs keyboard avoidance. **Environment forwarding:** `makeUIViewController` and `updateUIViewController` build the root as `AnyView(content.environment(\.self, context.environment))` (`UIViewControllerRepresentableContext.environment` is public, iOS 13+), so every environment value and `@Observable` object set by the outer hierarchy — `AppModel`, `ConversationModel`, `RevealController`, custom keys — is re-applied inside; `SecureCanvasTests.testEnvironmentPropagates` hosts a view that reads a custom `@Observable` from the environment and asserts it renders (via `hosting.view.layoutIfNeeded()` and a `Text` snapshot of `accessibilityLabel`). **Sizing: one mode, `.fill`:** `hosting.sizingOptions = []` and `sizeThatFits(_:uiViewController:context:)` returns `nil`, so the representable adopts whatever SwiftUI proposes (the caller gives it `.frame(maxWidth: .infinity, maxHeight: .infinity)`); this avoids the infinite/zero sizes that `.zero`/`.infinity` probing produced. The image viewer is full-screen by construction and uses the same mode; `CaptureProtectedImageView` is given an explicit `.aspectRatio(CGFloat(att.w)/CGFloat(att.h), contentMode: .fit).frame(maxWidth: .infinity, maxHeight: .infinity)` inside the content. Exactly two containers exist: the message list and the image viewer. The image additionally renders through `CaptureProtectedImageView` (`AVSampleBufferDisplayLayer.preventsCapture = true`, `CVPixelBufferCreate` BGRA, `CMSampleBufferCreateReadyWithImageBuffer`, `displayLayer.sampleBufferRenderer.enqueue(_:)`). **The composer sits outside both containers** (deliberate: keyboard handling and text input inside a secure canvas are unverified territory); the draft is therefore visible in screenshots/recordings and this is stated in limits item 2. When `isProtected == false`: `Diagnostics.secureCanvasAvailable = false`, badge turns amber, `blanking_unavailable` is emitted per §3.4 ("Ayşe'nin cihazı ekran görüntüsünü karartamıyor" on the peer). Flag `Settings.secureLayerEnabled` (default on). Forbidden: whole-window layer reparenting, KVC `disableUpdateMask`, `UIScreen.main`, `UIWindowScene.screenshotService`.

### 5.6 Capture detection flow

`CaptureMonitor` (`@MainActor @Observable`, in `Security/`, depends on nothing outside UIKit/SwiftUI): a `CaptureEnvironmentReader` view reads `@Environment(\.isSceneCaptured)` and calls `monitor.update(captured:)`; `SceneDelegate` additionally uses `registerForTraitChanges([UITraitSceneCaptureState.self])` on the window scene (`sceneCaptureState == .active`) for the cover. `UIApplication.userDidTakeScreenshotNotification` is observed with a 0.5 s debounce (UIKit can post twice). The monitor exposes `var onEvent: ((CaptureEventKind, _ timestamp: Date) -> Void)?` and owns **no counter**; `App/CaptureGlue.swift` (WP8) keeps the **per-conversation** `captureSeq[peer]` (persisted in `index.json`), increments it for the conversation on screen, appends `CaptureEvent{peer, seq, kind, ts, ref}` to the local log, inserts a system row ("Sen ekran görüntüsü aldın"), and feeds `MessageSync.sendControl`, which coalesces into `ctrl.capture{seq_from, seq_to, count, kind, ref}` per §3.4; the receiver renders "Ayşe ekran görüntüsü aldı (3)" and dims the referenced bubbles, and a gap in the per-peer sequence renders "Bildirilmeyen olay" (so a screenshot in another chat never looks like a suppressed event). While captured: `MessageList` is replaced by an opaque `Rectangle().fill(.background)` with `Label("Ekran paylaşımı sırasında içerik gizli", systemImage: "eye.slash")`, the viewer calls `clear()` and dismisses, flicker stops, badge turns red. Wording is neutral (recording, AirPlay and remote control are indistinguishable). Disclosed in onboarding card 2 and Settings (Guideline 2.5.14). `CaptureMonitorTests` covers the debounce (two notifications within 0.5 s → one event); the per-peer `seq` monotonicity and the 2 s coalescing window are covered in `CaptureGlue` tests with an injected clock (`CaptureMonitorTests` file, WP8 section).

### 5.7 Hold-to-reveal and partial reveal

`HoldToReveal` renders an opaque pre-rendered placeholder: **a constant 56 pt tall bubble** for text (never sized by content, which would leak length) and a constant **200×150 pt** panel for images, each with a "görmek için basılı tut" glyph; the real `Text`/image is not in the view tree, so nothing to deblur, nothing for VoiceOver or snapshots. On reveal the bubble expands to its real height with animations disabled (`withTransaction(Transaction(animation: nil))`), rows below shift and the revealed bubble keeps its top edge where it was; on release it collapses back to 56 pt. **Gesture = UIKit, not SwiftUI's `onLongPressGesture`** (SwiftUI's `LongPressGesture` *succeeds and ends* when `minimumDuration` elapses, so `onPressingChanged(false)` fires in the same frame as `perform`): `PressHoldView: UIViewRepresentable` installs

```swift
let lp = UILongPressGestureRecognizer(target: context.coordinator, action: #selector(Coordinator.handle(_:)))
lp.minimumPressDuration = 0.3
lp.allowableMovement = 8
lp.cancelsTouchesInView = false
lp.delaysTouchesBegan = false
view.addGestureRecognizer(lp)
```
`.began → onChange(true)` **unless the enclosing scroll view (walk `superview`s for the first `UIScrollView`) `isDragging || isDecelerating`**, in which case the recognizer is reset (`isEnabled = false; isEnabled = true`) and nothing is revealed; `.ended / .cancelled / .failed → onChange(false)`. `allowableMovement = 8` stays below `UIScrollView`'s pan-start distance so a drag that pauses never reveals. The content lives inside `SecureCanvasView`, whose `hitTest` forwarding delivers the touch. `RevealController` (`@Observable`, injected clock) allows one revealed bubble at a time (`revealedID`), auto-ends after 20 s, plays haptic `.soft`; `HoldToRevealTests` covers the single-reveal invariant, the 20 s auto-end, and the scroll guard with a stubbed `isDragging` provider. Images: in `ProtectedImageViewer` the display layer is never masked — an opaque mid-tone panel (`#3A3A3E`) is drawn *on top of* the viewer as a SwiftUI overlay with a rectangular cut-out of `max(120pt, height/4)` centred on the finger (`DragGesture(minimumDistance: 0)`), implemented as `ZStack { Rectangle().fill(panel); Rectangle().frame(band).blendMode(.destinationOut) }.compositingGroup()` so the capture-protected layer is untouched. First reveal starts the disappearing timer and (if enabled) queues `ctrl.read`.

### 5.8 Disappearing messages

Per-conversation timer (off, 30 s, 5 m, 1 h, 24 h, 7 d; **default off**) set by either party via `ctrl.timer`, shown as a system row; every message carries its own `ttl`. **With `ttl = 0` a message never expires.** With `ttl > 0`: receiver `expiresAt = firstRevealedAt + ttl` once revealed, and unrevealed messages expire at `receivedAt + max(ttl, 24 h) + 7 d`; sender `expiresAt = sentAt + ttl` regardless of whether the receiver ever revealed it (sender-side expiry deletes locally only; the server row was acked at delivery). `DisappearingScheduler` (injected clock; `DisappearingSchedulerTests` cover all three deadline formulas, the `ttl = 0` never-expires case and purge ordering) keeps one `Timer` for the earliest deadline while foregrounded, purges on launch and `scenePhase == .active`, deletes message + blob + key, and the *author* sends `ctrl.delete` for its own messages (cooperative; the receiver honours it only for messages authored by the sender, §3.4).

### 5.9 Watermark overlay

Payload 16 bits = `tag(8) || day(4) || crc4(4)`: `tag = HKDF(ikm = WS, salt = zeros, info = "Kilit_WM_v1" || viewerUsername, L = 1)[0]`, `day = (unixSeconds / 86400) mod 16`. **CRC-4:** polynomial `x⁴ + x + 1` (`0x3`), non-reflected, MSB-first, init `0x0`, no final XOR, no augmentation, over the 12 bits `tag(8) || day(4)` fed MSB-first:
```
crc = 0
for bit in bits:                      # 12 bits, MSB first
    fb  = ((crc >> 3) & 1) ^ bit
    crc = ((crc << 1) & 0xF) ^ (0x3 if fb else 0)
```
A bit-by-bit worked example is in `watermark.json`. **WS used for the mark:** the contact record stores `wm_secrets[]`, the WS of every session ever established with that peer in order; the mark uses the *first* entry; it is carried forward across re-initiations and reset only on an accepted identity-key change. Diagnostics shows the current `wm_secrets` in hex so the owner can feed them to the decoder. The decoder accepts a list of candidate WS values and tries all.

Layout: tile 6×6 cells, cell 28 pt (168 pt tile); the 20 border cells carry the fixed sync sequence `0b10110100011100101001` clockwise from top-left; the inner 4×4 carries the 16 bits row-major. Manchester-within-cell: bit 1 = left half brighter, right half darker; bit 0 reversed.

**Integer delta map (identical code in Go `watermark.go` and Swift `WatermarkPayload.swift`, no Core Graphics drawing, no filter API):** for scale `s ∈ {1,2,3}`, `W = H = 168·s`, `cell = 28·s`, `half = 14·s`, `k = 4·s` (box width, even). Base pattern `P[y][x] ∈ {−5, +5}`: cell `(r, c) = (y / cell, x / cell)`, bit `b` from the matrix, `left = (x mod cell) < half`, `P = +5` if `b == left` else `−5`. Softening = separable box filter with periodic wrap (so tiles are seamless): `Hs[y][x] = Σ_{i=−k/2}^{k/2−1} P[y][(x+i) mod W]`, `V[y][x] = Σ_{j=−k/2}^{k/2−1} Hs[(y+j) mod H][x]`, `Δ[y][x] = V / (k·k)` using **integer division truncating toward zero** (Swift `Int./` and Go `int /` agree). The map is `int8` with values in `[−5, 5]`. Two **opaque** BGRA images are derived per pixel: lighter `L = max(0, Δ)` in all three colour channels, alpha 255; darker `D = 255 − max(0, −Δ)`, alpha 255. With opaque sources `plusLighter` gives `R = min(1, dst + L/255)` and `plusDarker` gives `R = max(0, dst + D/255 − 1) = dst − max(0,−Δ)/255` exactly, with no premultiplication or alpha ramp involved. `WatermarkTile.swift` builds the `CGImage`s with `CGDataProvider(data:)` + `CGImage(width:height:bitsPerComponent: 8, bitsPerPixel: 32, bytesPerRow: 4·W, space: CGColorSpaceCreateDeviceRGB(), bitmapInfo: [.byteOrder32Little, CGImageAlphaInfo.premultipliedFirst], provider:decode: nil, shouldInterpolate: false, intent: .defaultIntent)`, cached per `(payload, displayScale)`. `watermark.json` carries the full scale-1 map, SHA-256 of scales 2 and 3, and sampled pixels; `WatermarkTests` and the Go golden test compare **exactly**.

**Placement:** (1) message list — `WatermarkOverlay` is the **last child of the `ZStack` inside the hosted content** (not an `.overlay` on the representable), so it composites against ordinary SwiftUI layers inside the same `UIHostingController`: `Image(decorative: lighter, scale: displayScale).resizable(resizingMode: .tile).blendMode(.plusLighter)` and the same for `darker` with `.plusDarker`, both `.offset(phase)` by a per-viewing-session random phase in `[0,168)²`, `.allowsHitTesting(false)`, `.accessibilityHidden(true)`. (2) image viewer — `CaptureProtectedImageView` adds two `CALayer`s above its display layer (`WatermarkLayers.swift`): `backgroundColor = UIColor(patternImage: UIImage(cgImage: tile, scale: displayScale, orientation: .up)).cgColor`, `compositingFilter = "plusL"` / `"plusD"` (the Core Animation filter names SwiftUI's `.plusLighter`/`.plusDarker` map to), same phase offset via `contentsCenter`-free `bounds.origin`; SwiftUI blend modes are not used over the AV layer. **Whether the render server honours these composites over the secure canvas and over a `preventsCapture` layer cannot be sampled in-app** (snapshot APIs do not reflect render-server compositing), so it is a device-checklist item (§7: "watermark visible at ~5/255 over bubbles in a photo; no flat haze over the protected image") and a §9 risk; the fallback if either fails is the other variant (SwiftUI blend ↔ CALayer compositingFilter), both of which exist. Surfaces are mid-tone by design (bubbles `#4A4A4F` on `#2C2C30`, viewer letterbox `#3A3A3E`, never pure black). A visible diagonal "@ayse · 21 Eki" at 9 % alpha complements it. `WatermarkOverlay` takes the 6×6 `Bool` matrix and the visible string as inputs (no dependency on `Crypto/` or `Store/`).

> **Reviewer note (pixel-sampling self-check).** A Diagnostics self-check that samples a live pixel is rejected: nothing an app can call reads the render server's composite of a secure canvas or a `preventsCapture` layer. Diagnostics instead verifies the delta-map → `CGImage` path offscreen (renders the two tiles over a `#4A4A4F` field with `UIGraphicsImageRenderer` and asserts the expected ±5 at sampled pixels), and the live composite is verified by the device photo checklist.

**Decoder (`server/cmd/wmdecode`, phase 1, core in `pkg/kilitcrypto/wmdecode.go`, pure Go):** inputs a JPEG/PNG and four screen-corner coordinates, perspective-warps (homography, bilinear sampling) to a canonical 1179×2556 grid, converts to luma, high-pass filters (subtract a separable box blur of radius one cell), integrates left/right half-cell means, searches tile phase (and ±5 % scale, ±3° rotation) by correlating the 20-cell sync sequence, rejects cells whose variance exceeds a threshold (text ink), majority-votes each data bit across tiles, checks CRC-4, and prints `{tag, day, confidence, matches:[username…]}` given `-ws` candidates and `-usernames`. Usage: `wmdecode -in photo.jpg -corners x1,y1,x2,y2,x3,y3,x4,y4 -ws <hex from Diagnostics>[,<hex>…] -usernames alice,bob` (corners clockwise from the screen's top-left as read from the cursor position in Preview.app). Go unit test: render the tile over a `#4A4A4F` field with sample text, box blur radius cell/3, JPEG Q75, resize 0.4× bilinear, decode → correct payload. Calibration knobs (only two): amplitude (3–6) and cell size (24–32 pt); device acceptance criteria are in §7.

### 5.10 Experimental flicker

`FlickerMaskView` as researched: dedicated sublayer with `actions = ["contents": NSNull(), …]`, two complementary device-pixel checkerboard `CGImage`s (cell 3 pt, mask colour = bubble background), `CADisplayLink(target: weakProxy, selector:)`, `preferredFrameRateRange = CAFrameRateRange(minimum: 120, maximum: 120, preferred: 120)`, `add(to: .main, forMode: .common)`, measured rate `1/(targetTimestamp − timestamp)` EMA, self-stop below 100 Hz for 30 frames, hard blocks: `window?.windowScene?.screen.maximumFramesPerSecond < 120`, `UIAccessibility.isReduceMotionEnabled`, `MADimFlashingLightsEnabled()`, Low Power Mode, thermal `.serious/.critical`, `willResignActive`, captured. **Dim Flashing Lights changes are observed exactly as Apple's sample "Responding to changes in the flashing lights setting" does:** `NotificationCenter.default.addObserver(self, selector: #selector(environmentChanged(_:)), name: kMADimFlashingLightsChangedNotification as NSNotification.Name, object: nil)` (cited in the file header); `blockingCondition()` is additionally re-run on `UIApplication.didBecomeActiveNotification` as belt and braces; there is no per-tick polling. `FlickerShield: UIViewRepresentable` overlays only the currently revealed text bubble during the hold, never photos or full screen. Settings › Deneysel: toggle disabled with reason on ineligible devices; enabling presents `PhotosensitivityWarningSheet` every time (`interactiveDismissDisabled`, "Kapalı bırak" cancel default, "Aç" destructive; TR/EN copy in §10.5); persistent "Titreşim açık" pill; stop reasons surface as a toast. Requires `CADisableMinimumFrameDurationOnPhone = true` (in both plists).

### 5.11 Settings, app lock and onboarding

**App lock state machine** (`App/AppLock.swift`, `AppLockTests` with an injected authenticator): states `locked → authenticating → unlocked`. Authentication (`LAContext.evaluatePolicy(.deviceOwnerAuthentication, localizedReason:)`) starts only on launch and on a `.background → .active` scene-phase transition; `.inactive ↔ .active` flips while `authenticating` are ignored. Success → `unlocked`; cancel or failure → `locked` with an explicit "Kilidi aç" retry button. `PrivacyCover` is only the snapshot cover for `sceneWillResignActive`, never the lock UI.

Onboarding: Welcome → PasscodeGate (`LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error:)`; `.passcodeNotSet` blocks with explanation; skipped on Simulator) → username + server URL (canonicalised to `server_origin`; availability learned from register's 409, on which the client re-challenges and reuses its keys) → `POST /v1/auth/challenge` → keys generated, `POST /v1/register` with `register_proof` and `opks_sig` (token returned) → three cards (§10.1) → Done. No notification permission is requested in phase 1. **Settings and defaults:** default timer (**off**); app lock (**on**); secure layer (**on**, mode `.canvas`); capture reports to peer (**on**, disclosed); "Okundu bilgisi" (**off**); "Korumalı içeriği erişilebilirlikten gizle" (**off**, warning sheet §10.6); Deneysel (flicker **off**); Diagnostics; server URL (read-only after registration); "Hesabı sil ve sıfırla" = `challenge` → `DELETE /v1/users/me` with `delete_sig` → `DELETE /v1/auth/session` → wipe store + Keychain + `installMarker` + `cursor = 0`.

### 5.12 XCTest plan

| Test file | Consumes | Checks | Simulator |
|---|---|---|---|
| `CryptoVectorTests` | `primitives` | X25519/HKDF/HMAC/ChaChaPoly bytes; Ed25519 verify Go sig + own sig; strict pre-check negatives and small-order table; salt equivalence; low-order/size negatives | yes |
| `Base64urlTests` | `base64url` | encode/decode incl. length mod 3 cases | yes |
| `X3DHVectorTests` | `x3dh_session` | SK/WS/SID/AD bytes both sides, with/without OPK; all six signatures verified; exact signed-message bytes; `identityMismatch`, `badSignature`, `staleSPK` negatives | yes |
| `SessionSelectionTests` | `ratchet_conversation` (`crossed`, `lost_session`, `reinit_after_rollback`, `key_change_then_send`) | S1–S3, sending `sid` per step both sides, superseded flags, `ctrl.resync` resend set | yes |
| `InboundPolicyTests` | `ratchet_conversation` (`replay`, `id_collision`, `opk_grace`) | step 0 outer dedupe, parking reasons/expiry, `known_sids` trigger, classification strings | yes |
| `RatchetVectorTests` | `ratchet_conversation` (`basic`, `eviction`) | every `hdr`/`wire` byte-equal via `ScriptedKeySource`; MKSKIPPED path and exact eviction set; tamper → `authenticationFailure`, state unchanged; `tooManySkipped`; `badHeader`; `badKeyLength`; SPK private absent after B1 | yes |
| `AttachmentTests` | `attachment` | blob bytes, sha256 over whole file, AAD/len mismatch rejected, owned-buffer decrypt | yes |
| `EnvelopeTests` | `envelope` | padding/unpadding incl. missing `0x80`, all-zero, `len % 256`; 40 960 OK / 40 961 rejected; outer-JSON negatives; absent-vs-`null`; Codable field-wise round-trip | yes |
| `SafetyNumberTests`, `WatermarkTests` | `safety`, `watermark` | digits; tag/CRC worked example/layout; scale-1 delta map byte-equal, scale-2/3 hashes, sampled pixels of derived images | yes |
| `SecureCanvasTests` | – | canary `isProtected`; hit-test reaches content; `field.text` change → content in current canvas + recognizers disabled; environment propagation of a custom `@Observable`; `CaptureShield` canary (window via `UIWindow(windowScene:)` from `connectedScenes`, torn down in `tearDown`) | yes (blanking: device only) |
| `FlickerGateTests` | – | `blockingCondition()` with injected flags | yes |
| `CaptureMonitorTests` | – | 0.5 s debounce; `CaptureGlue` per-peer `seq` monotonicity and coalescing window | yes |
| `HoldToRevealTests` | – | single reveal; 20 s auto-end; no reveal while stubbed scroll view is dragging/decelerating | yes |
| `DisappearingSchedulerTests` | – | receiver/sender/unrevealed deadlines; `ttl = 0` never expires; purge order | yes |
| `LocalStoreTests` | – | seal/open round-trip; docKey/generation nonce + AAD; `≥` acceptance and adoption of a higher generation; rollback refused; `.complete` attribute (`XCTSkip` on Simulator) | partial |
| `SessionStoreAtomicityTests` | – | state on disk advanced before the send callback; inbound order plaintext → ratchet → ack with an injected failing writer; crash injected after each of the three §3.7 writes → no wipe, no forced X3DH | yes |
| `PrekeyLifecycleTests` | – | OPK deleted on use / 7 d after consumed report / 30 d after upload, never on report alone; SPK retention 21 d; refill trigger | yes |
| `WebSocketClientTests` | – | stubbed failing task → backoff and 20 s poll fallback start; `msg_id` dedupe across paths | yes |
| `AppLockTests` | – | state machine transitions, no re-prompt on `.inactive ↔ .active` while authenticating | yes |

## 6. Xcode project plan

Hand-written `ios/Kilit.xcodeproj/project.pbxproj`: `objectVersion = 77`, `preferredProjectObjectVersion = 77`, `minimizedProjectReferenceProxies = 1`, `developmentRegion = tr`, `knownRegions = (tr, en, Base)`, ids in the `4B494C4954…` series. **Id table (27 ids, the acceptance criterion):** `…01` project, `…02` mainGroup, `…03` Products, `…04` Kilit.app ref, `…05` KilitTests.xctest ref, `…06` Sources synced root, `…07` Tests synced root, `…09` `Kilit` PBXGroup, `…10` app target, `…11/12/13` its phases, `…14` its config list, `…15/16` its Debug/Release, `…20` test target, `…21/22/23` phases, `…24` config list, `…25/26` Debug/Release, `…27` container proxy, `…28` target dependency, `…30` project config list, `…31/32` project Debug/Release. (No `…08`: because the plists and entitlements live in `ios/Kilit/` outside both synced folders, no exception set exists.) **Group structure:** mainGroup children = `Kilit` (`path = Kilit; sourceTree = "<group>"`) and `Products`; the `Kilit` group's children are the two `PBXFileSystemSynchronizedRootGroup`s with single-segment paths `path = Sources;` (→ target Kilit) and `path = Tests;` (→ target KilitTests). Empty build-phase `files`, `PBXTargetDependency` + `PBXContainerItemProxy`, `TestTargetID`. `project.xcworkspace/contents.xcworkspacedata` and shared `xcshareddata/xcschemes/Kilit.xcscheme` (BlueprintIdentifiers = target ids, `shouldAutocreateTestPlan = "YES"`) are committed. Validation on Linux: cordova `xcode` parser, id cross-reference (27 ids), plist/XML/YAML/xcstrings-JSON parse — run by `.github/workflows/ios-lint.yml`.

App target: `IPHONEOS_DEPLOYMENT_TARGET = 17.0`, `SWIFT_VERSION = 5.0`, `TARGETED_DEVICE_FAMILY = 1`, `GENERATE_INFOPLIST_FILE = YES`, **`INFOPLIST_FILE = Kilit/Info-Debug.plist` in Debug and `Kilit/Info-Release.plist` in Release**, `CODE_SIGN_ENTITLEMENTS = Kilit/Kilit.entitlements` (both configs), `INFOPLIST_KEY_NSCameraUsageDescription`, `INFOPLIST_KEY_NSPhotoLibraryUsageDescription`, `INFOPLIST_KEY_NSFaceIDUsageDescription`, `INFOPLIST_KEY_UILaunchScreen_Generation = YES`, `INFOPLIST_KEY_UISupportedInterfaceOrientations_iPhone = UIInterfaceOrientationPortrait`, `ENABLE_PREVIEWS = YES`, `CODE_SIGN_STYLE = Automatic`, `DEVELOPMENT_TEAM = ""`, `PRODUCT_BUNDLE_IDENTIFIER = com.example.Kilit`, `ENABLE_TESTABILITY = YES` (project Debug). **`INFOPLIST_KEY_UIApplicationSceneManifest_Generation` is not set** (it would generate `UIApplicationSupportsMultipleScenes = YES` and duplicate a key). Test target: `com.apple.product-type.bundle.unit-test`, `TEST_HOST = "$(BUILT_PRODUCTS_DIR)/Kilit.app/$(BUNDLE_EXECUTABLE_FOLDER_PATH)/Kilit"`, `BUNDLE_LOADER = "$(TEST_HOST)"`.

Plists contain **only** keys with no `INFOPLIST_KEY_` equivalent, each key in exactly one place. Both plists: `CADisableMinimumFrameDurationOnPhone = true` and the full scene manifest
```xml
<key>UIApplicationSceneManifest</key>
<dict>
	<key>UIApplicationSupportsMultipleScenes</key><false/>
	<key>UISceneConfigurations</key><dict/>
</dict>
```
(`SceneDelegate` is attached in `AppDelegate.application(_:configurationForConnecting:options:)` returning `UISceneConfiguration(name: nil, sessionRole: connectingSceneSession.role)` with `delegateClass = SceneDelegate.self`). `Info-Debug.plist` additionally: `NSAppTransportSecurity → NSAllowsLocalNetworking = true`. **No `NSPinnedDomains` is committed**; `ios/README.md` shows the owner how to add it with the ISRG/intermediate SPKI hash to `Info-Release.plist`. `Kilit.entitlements` contains `com.apple.developer.default-data-protection = NSFileProtectionComplete`. Push Notifications is **not** added in phase 1. No `ITSAppUsesNonExemptEncryption` key.

**String catalog shape** (`Resources/Localizable.xcstrings`, hand-written JSON):
```json
{"sourceLanguage":"tr","version":"1.0","strings":{
 "badge.green":{"extractionState":"manual","localizations":{
   "tr":{"stringUnit":{"state":"translated","value":"Karartma + algılama"}},
   "en":{"stringUnit":{"state":"translated","value":"Blanking + detection"}}}}}}
```
Every key has both `tr` and `en` units; the ios-lint workflow checks the file parses and that every key has both.

XcodeGen fallback `ios/project.yml` (XcodeGen ≥ 2.45.4, `projectFormat: xcode16_0`, `options.developmentLanguage: tr`): sources `- {path: Kilit/Sources, type: syncedFolder}` and `- {path: Kilit/Tests, type: syncedFolder}`; app settings use `configs: {Debug: {INFOPLIST_FILE: Kilit/Info-Debug.plist}, Release: {INFOPLIST_FILE: Kilit/Info-Release.plist}}` plus a `base:` map for the shared settings (never mix a flat map with `base:`/`configs:`); `CODE_SIGN_ENTITLEMENTS: Kilit/Kilit.entitlements`; `bundle.unit-test` depending on Kilit; `scheme.testTargets: [KilitTests]`. `xcodegen generate` overwrites the hand-written project and scheme — mutually exclusive workflows.

## 7. Build and run

**Server (Linux):**
1. `cd server && GOTOOLCHAIN=local go mod download`
2. `go vet ./... && CGO_ENABLED=0 go test ./...` (CI additionally `CGO_ENABLED=1 go test -race ./...`)
3. `go run ./cmd/vectors -out ../docs/vectors -swift ../ios/Kilit/Tests/Vectors` (committed outputs must be unchanged)
4. `CGO_ENABLED=0 go build -o kilitd ./cmd/kilitd && ./kilitd -db ./dev.db -blobs ./blobs -addr :8080 -public-origin http://<lan-ip>:8080`
5. Production: DNS A/AAAA → VPS, ports 80/443 open, `mkdir -p data && sudo chown 65532:65532 data`, set the domain in `Caddyfile` and `KILIT_PUBLIC_ORIGIN` in `docker-compose.yml` (keep `KILIT_TRUSTED_PROXY=172.28.0.0/16`), `docker compose up -d --build`.

**iOS (owner's Mac, Xcode ≥ 16.0):**
1. `git clone` and `open ios/Kilit.xcodeproj` (if it will not open: `brew install xcodegen && cd ios && xcodegen generate`).
2. Signing & Capabilities → select Team; accept "Update to recommended settings" if prompted; verify Data Protection shows "Complete Protection".
3. `xcodebuild -project ios/Kilit.xcodeproj -scheme Kilit -destination 'platform=iOS Simulator,name=iPhone 16' test` — fix compile errors first, then `SecureCanvasTests` (canary + environment propagation) and all vector tests must pass before any device work.
4. Run on two physical iPhones (one ProMotion); enter the server URL in onboarding (`https://kilit.example.com`, or `http://<lan-ip>:8080` in Debug — the server's `-public-origin` must be the same string); register `alice` and `bob`; add each other; compare safety numbers; have `bob` message first once to exercise the message-request path.
5. Device checklist (`docs/DEVICE_CHECKLIST.md`): hardware screenshot (region black, both sides see the event, two quick screenshots arrive as one coalesced report with `count: 2`), Control Center recording, AirPlay, QuickTime USB capture, App Switcher, iPhone Mirroring (expected to fail — record it), iOS 26 full-screen screenshot preview on/off; **crossed initiation: both phones tap send within one second of adding each other; verify both converge on one session and nothing is undecryptable**; delete and reinstall the app on one phone (keeping the username by re-registering) → the other side shows the key-change banner, accepts, and messaging resumes; hold-to-reveal persists while held and hides ≤ 1 frame after release, reveal never starts from a scroll; image band reveal + hardware screenshot still black; keyboard appears without the message list jumping; Face ID lock prompt appears once per unlock, cancel shows "Kilidi aç"; Diagnostics measured Hz on ProMotion with Low Power Mode and Limit Frame Rate toggled; toggling Dim Flashing Lights while flicker runs stops it within 1 s; **watermark visible as faint texture (~5/255) over bubbles in a device photo, and no flat haze over the protected image** (if either fails, switch to the other rendering variant in Diagnostics); watermark photos at 25/40/70 cm, straight and 30°, dark and lit room, each passed through one social-media re-encode and decoded with `wmdecode -in photo.jpg -corners x1,y1,x2,y2,x3,y3,x4,y4 -ws <hex from Diagnostics> -usernames alice,bob` (corners read from the cursor position in Preview.app; target ≥ 95 % correct decode at ≤ 40 cm straight-on, zero false decodes on photos of other screens; tune amplitude and cell size from the results); passcode removal → forced re-registration; wrong device clock → "Cihaz saati yanlış" instead of re-onboarding.

## 8. Implementation work breakdown (disjoint file sets)

| # | Package | Owns | Depends on | Acceptance |
|---|---|---|---|---|
| WP0 | Go module skeleton + shared interfaces + copy + vector schema | `server/go.mod`, `server/go.sum`, `server/internal/pins/pins.go`, `server/internal/ws/api.go`, `docs/COPY.md` (verbatim §10), `docs/VECTOR_SCHEMA.md` (verbatim §3.9) | nothing (executed first, ~1 h) | all five pins present with `go 1.24.0`; `go mod tidy` is a no-op; `Notifier`/`Delivery` compile exactly as §4.1; `COPY.md` and `VECTOR_SCHEMA.md` match the doc; `go.mod`/`go.sum` read-only afterwards |
| WP1 | Go crypto reference + vectors + decoder | `server/pkg/kilitcrypto/**`, `server/cmd/vectors/**`, `server/cmd/wmdecode/**`, `docs/vectors/*.json`, `ios/Kilit/Tests/Vectors/*.swift`, `docs/PROTOCOL.md` | WP0; §3, §3.9 | RFC vectors incl. strict-Ed25519 negatives; X3DH symmetry ± OPK; identity mismatch; staleSPK; supersession/selection/parking scenarios; OPK grace; outer-dedupe; ratchet fuzz, skip, exact eviction, rollback, no-mk-reuse; attachment; watermark delta map golden + decode round-trip in pure Go; golden file; raw Swift literals ≤ 200 KB, no `"""#` |
| WP2 | Server store + config | `server/internal/store/**`, `server/internal/config/**` | WP0; §4.1 method list, §4.2, §4.8 | temp-DB tests; idempotent migrations; atomic OPK claim + consumed_opks; SPK monotonic/prune with created_at; OPK dup/cap; UNIQUE identity keys; msg_id idempotency/conflict SQL; cascade delete + AUTOINCREMENT + sender_username; concurrency zero BUSY; sweepers with blob margin |
| WP3 | Server auth + API + ratelimit + push | `server/internal/{auth,api,ratelimit,push}/**` | WP0 (`ws.Notifier`, `New` signature), WP2 store method list, §4.3–4.6 | full httptest flow incl. challenge-before-register, origin binding, clock skew, `opks_sig`, account delete, OPK quota → SPK-only, msg_id conflict, key_in_use, register-409 limiter exemption, trusted-proxy buckets + warning, per-route body caps, attachment delete flow, 405/413/429/409; route-conflict test; truncated-IP logging |
| WP4 | Server WS + blob + main + Docker + server CI | `server/internal/ws/{hub,conn,frames,handler}.go`, `server/internal/blob/**`, `server/cmd/kilitd/**`, `server/Dockerfile`, `docker-compose.yml`, `Caddyfile`, `Makefile`, `server/README.md`, `.github/workflows/server.yml` | WP0, WP2 (drain queries), WP3 (`api.New`) | hello/no-hello/drain-live ordering/ack/`prekeys_low`/supersede/slow_consumer; close codes 1001/1008/1009/1002; static `CGO_ENABLED=0` binary with version; nonroot image; compose with fixed subnet + trusted proxy; CI runs vet, test, race, vectors golden; README has the `wmdecode` usage |
| WP5 | Swift crypto | `ios/Kilit/Sources/Crypto/**`, `ios/Kilit/Tests/{CryptoVector,Base64url,X3DHVector,SessionSelection,InboundPolicy,RatchetVector,Attachment,Envelope,SafetyNumber,Watermark}Tests.swift` | §3, §3.9 (schema is in the doc, so WP5 starts after WP0 and consumes WP1's files when they land) | every vector has a consuming test; `KeySource` injection; strict Ed25519 pre-checks; no RawSpan APIs; errors map to `KilitCryptoError`/`CryptoKitError`; JSONEncoder sortedKeys/withoutEscapingSlashes; absent==null; integer delta map |
| WP6 | Swift security views | `ios/Kilit/Sources/Security/**`, `ios/Kilit/Tests/{SecureCanvas,FlickerGate,CaptureMonitor,HoldToReveal}Tests.swift` | §5.5–5.10 only (no `Crypto/`, `Store/`, `Net/` imports) | canary re-evaluation + recognizer disabling + hit-test + text-change + environment-propagation tests; `CaptureShield` behind flag; `.fill` sizing returns nil; flicker gate tests with Apple-style notification observer; debounce tests; reveal tests incl. scroll guard; `WatermarkTile` from raw bytes; grep gate (no `setValue(_:forKey:` outside `CaptureShield.swift` and only with `"layer"`, no `disableUpdateMask`, `UIScreen.main`, `onLongPressGesture` for reveal, no `Canvas` blur APIs) |
| WP7 | Swift store + networking + sync | `ios/Kilit/Sources/{Store,Net}/**`, `ios/Kilit/Tests/{LocalStore,SessionStoreAtomicity,DisappearingScheduler,PrekeyLifecycle,WebSocketClient}Tests.swift` | WP5 public types; §3.2b; §3.7 write order; §4.3/§4.4 JSON; §5.3–5.4 | DTO field names identical to server; write order + `≥` acceptance tests with injected crashes; write-before-send and plaintext-before-ratchet-before-ack; parking/retry; OPK lifecycle; two URLSessions and fallback test; reinstall wipe; msg_id dedupe; control coalescing; attachment DELETE after store |
| WP8 | SwiftUI UI + app shell + glue | `ios/Kilit/Sources/{App,UI,Resources}/**`, `ios/Kilit/Sources/Assets.xcassets/**`, `ios/Kilit/Tests/AppLockTests.swift` | WP5–WP7 public APIs; `docs/COPY.md` (WP0) | all eight features reachable; message-request, key-change, resync flows; per-peer capture seq in `CaptureGlue`; app-lock state machine; strings from `Localizable.xcstrings` (tr source + en), copy verbatim from `docs/COPY.md`; watermark as last ZStack child inside the container; grep gate (no `.textSelection`, `contextMenu` copy, `onDrag`, `UIActivityViewController`, `QLPreviewController`, `UIImage(contentsOfFile:`, `ImageAnalysisInteraction`, `CSSearchableIndex`, `NSUserActivity`, `print(`, third-party `import`s) |
| WP9 | Xcode project + docs + repo hygiene | `ios/Kilit.xcodeproj/**`, `ios/project.yml`, `ios/Kilit/Info-Debug.plist`, `ios/Kilit/Info-Release.plist`, `ios/Kilit/Kilit.entitlements`, `ios/README.md`, `README.md`, `.gitignore`, `.github/workflows/ios-lint.yml`, `docs/THREAT_MODEL.md`, `docs/DEVICE_CHECKLIST.md`, `docs/APP_REVIEW_NOTES.md` | §5.1 tree, §6, `docs/COPY.md` | pbxproj parses (cordova `xcode`), the 27 ids of §6 resolve, nested `Kilit` group with single-segment synced paths, `developmentRegion = tr`; plists carry the scene manifest; plists/yml/xml/xcstrings valid; `.gitignore` = `xcuserdata/`, `DerivedData/`, `*.xcuserstate`, `server/kilitd`, `server/dev.db*`, `server/blobs/`, `data/`; ios-lint CI runs the Linux validators; docs mirror §1–§2 and copy from `COPY.md` |

Single-implementer order: WP0 → WP1 → WP2 → WP3 → WP4 → WP5 → WP7 → WP6 → WP8 → WP9. After WP0, the packages WP1, WP2, WP5, WP6 and WP9 have no inter-dependencies and can start in parallel (WP5 codes against §3.9 and plugs in WP1's generated files when they exist); WP3 needs WP2's method list (fixed in §4.1); WP4 needs WP2 and WP3's `api.New`; WP7 needs WP5; WP8 needs WP5–WP7 and `docs/COPY.md` (WP0).

## 9. Open risks and Mac-only verification

- **No Swift compiler on Linux**: every Swift file compiles for the first time on the Mac. Mitigations: only APIs checked against developer.apple.com, Swift 5 mode, no iOS 26-era overloads, smallest possible surface. Most likely first-build/first-run issues: `sizeThatFits` returning `nil`, `.environment(\.self, context.environment)` with `AnyView`, `registerForTraitChanges` closure typing, `MediaAccessibility` import and the `as NSNotification.Name` cast, `@Observable` + actor isolation warnings, `UIHostingController.safeAreaRegions` availability annotation, `UILongPressGestureRecognizer` target/selector plumbing, `CGImage(width:…provider:…)` argument labels, `UIColor(patternImage:)` scale handling, raw string literal size in the test target (split per set keeps each under 200 KB).
- **Secure canvas** (`_UITextLayoutCanvasView`): may be absent, renamed, recreated at runtime, or not blank on the owner's iOS; the continuously re-evaluated canary and amber badge make it visible; the `CaptureShield` layer-swap is the flag-selectable alternative; Apple DTS calls it "not its intended purpose" — App Review risk accepted and disclosed in `docs/APP_REVIEW_NOTES.md`.
- **`preventsCapture`** may make system recording fail to start instead of showing black; test and word the UI.
- **Watermark compositing**: whether `plusLighter`/`plusDarker` (SwiftUI, inside the hosted content) and `compositingFilter` `"plusL"`/`"plusD"` (CALayer, above the AV layer) survive render-server compositing over the secure canvas and a `preventsCapture` layer is unverifiable on Linux and unsampleable in-app; both variants exist and the device checklist decides. Display colour management on P3 panels may alter the ±5 code values by ±1 — irrelevant to the decoder, excluded from the exact test (which checks the delta map, not the panel).
- **CryptoKit/Go parity** is proven only when XCTest runs sets A and B; the likeliest divergences are CONCAT/header ordering, padding, AAD framing for attachments, the signed-message separators, `created_at` in the SPK bytes, the `opks_sig` batch layout, and base64url — each has a dedicated raw-byte vector.
- **120 Hz delivery** depends on the plist key being merged (both plists) and on the device; verify measured Hz in Diagnostics and every self-stop path.
- **Keychain `WhenPasscodeSetThisDeviceOnly`**: passcode removal deletes keys (forced re-registration); reinstall persistence; both device-only.
- **Watermark calibration** (amplitude 5, cell 28 pt) is a guess until photographed; the decoder exists in phase 1 so the owner can measure and tune.
- **Spec text** for X3DH/Double Ratchet was reconstructed from libsignal source and knowledge (signal.org unreachable from the build network); the owner should skim X3DH §2–4 and Double Ratchet §3/§5.2/§6 once before freezing the wire format.
- **Dependency pinning**: `x/crypto v0.48.0` is the last Go-1.24-compatible release; later fixes require raising the toolchain or switching the AEAD to stdlib AES-256-GCM (same `nonce||ct||tag` layout, version bump).
- **`URLSessionWebSocketTask` without an Origin header** against coder/websocket: expected fine; confirm on first device test.
- **iOS 26 full-screen screenshot preview** and **iPhone Mirroring**: document observed behaviour; no mitigation planned.
- **Multi-session convergence, supersession and `ctrl.resync`** are exercised by scripted vectors; the real crossed initiation and the reinstall/key-change flow on two phones are on the device checklist (§7 step 5).

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
- `capture.peer.screenshot`: TR "%@ ekran görüntüsü aldı (%d)" / EN "%@ took a screenshot (%d)"
- `capture.peer.recording_started` / `_stopped`: TR "%@ ekran paylaşımını başlattı" / "…durdurdu"; EN "%@ started screen sharing" / "…stopped screen sharing"
- `capture.peer.blanking_unavailable`: TR "%@'nin cihazı ekran görüntüsünü karartamıyor" / EN "%@'s device cannot blank screenshots"
- `capture.gap`: TR "Bildirilmeyen olay" / EN "Unreported event"
- `capture.none`: TR "Bildirilen ekran görüntüsü yok" / EN "No screenshot reported" (never "none taken")
- `undecryptable.row`: TR "Bu mesaj çözülemedi (%@)" / EN "This message could not be decrypted (%@)"
- `resync.row`: TR "Oturum yenilendi; son mesajlar yeniden gönderildi" / EN "Session re-established; recent messages were re-sent"
- `keychange.banner`: TR "Güvenlik numarası değişti. %@ yeni bir cihaz ya da kimlik kullanıyor olabilir. Göndermeden önce doğrulayın." / EN "Safety number changed. %@ may be using a new device or identity. Verify before sending." Buttons: `keychange.accept` TR "Yeni anahtarı kabul et" / EN "Accept new key"; `keychange.verify` TR "Güvenlik numarasını göster" / EN "Show safety number".
- `request.banner`: TR "Bilinmeyen gönderen" / EN "Unknown sender"; buttons `request.accept` TR "Kabul et" / EN "Accept", `request.block` TR "Engelle" / EN "Block".
- `attachment.expired`: TR "Ek süresi doldu" / EN "Attachment expired"
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
TR: "Titreşim Kalkanı mesaj içeriğinin üzerinde ince bir deseni saniyede 60 kez değiştirir. Hızla yanıp sönen görüntüler fotosensitif epilepsisi olan kişilerde nöbeti tetikleyebilir; diğer kişilerde göz yorgunluğu, baş ağrısı, baş dönmesi veya bulantıya yol açabilir. Sizde ya da ekranınızı görebilecek birinde nöbet geçmişi varsa bu özelliği açmayın. Kendinizi kötü hissederseniz hemen kapatın. Bu deneysel bir caydırıcıdır; ekranınızın fotoğraflanmasını veya kaydedilmesini engellemez."
EN: "Flicker Shield rapidly alternates a fine pattern over message content (60 times per second). Rapidly flashing or flickering images can trigger seizures in people with photosensitive epilepsy and can cause eye strain, headaches, dizziness or nausea in others. Do not turn this on if you, or anyone who may see your screen, has a history of seizures. Stop and turn it off immediately if you feel unwell. This is an experimental deterrent only; it does not prevent someone from photographing or recording your screen."
Buttons: cancel/default TR "Kapalı bırak" / EN "Keep off"; destructive TR "Aç" / EN "Turn on". Ineligibility reasons: TR "120 Hz ekran gerekir" / "Hareketi Azalt açık" / "Yanıp Sönen Işıkları Kıs açık" / "Düşük Güç Modu açık"; EN "Requires a 120 Hz display" / "Reduce Motion is on" / "Dim Flashing Lights is on" / "Low Power Mode is on". Status pill TR "Titreşim açık" / EN "Flicker on".

### 10.6 Accessibility-hide warning sheet
TR: "Bu ayar korumalı mesaj ve fotoğrafları VoiceOver, Ekranı Seslendir ve diğer yardımcı teknolojilerden gizler. VoiceOver kullanıyorsanız mesajları okuyamazsınız. Sesli okumanın bir mikrofonla kaydedilmesini zorlaştırır; başka bir koruma sağlamaz."
EN: "This setting hides protected messages and photos from VoiceOver, Speak Screen and other assistive technologies. If you use VoiceOver you will not be able to read messages. It makes recording spoken content with a microphone harder; it provides no other protection."
Buttons: TR "Vazgeç" / "Gizle"; EN "Cancel" / "Hide".

### 10.7 Settings disclosure (Guideline 2.5.14)
`settings.capture_reports.footer`: TR "Açıkken, aldığın ekran görüntüleri ve ekran kayıtları yerel olarak kaydedilir ve karşı tarafa şifreli olarak bildirilir." / EN "When on, screenshots and screen recordings you take are logged locally and reported to the other person over the encrypted channel."