# kilitd — Kilit relay server

The Go 1.24 relay behind the Kilit iOS app: a store-and-forward queue for end-to-end
encrypted envelopes, a prekey directory (X3DH bundles), single-shot attachment blobs and a
WebSocket delivery channel. It never sees plaintext; the full design is `docs/DESIGN.md` §4
(this directory is the Go module `github.com/tekinadakan-sudo/clawDbot/server`).

## Build and test (Linux, Go 1.24.x)

```sh
cd server
export GOTOOLCHAIN=local          # never download a newer toolchain; the deps are pinned
go mod download
go vet ./... && CGO_ENABLED=0 go test ./...
CGO_ENABLED=1 go test -race ./... # CI also runs this (needs gcc)
go run ./cmd/vectors -out ../docs/vectors -swift ../ios/Kilit/Tests/Vectors   # committed outputs must be unchanged
CGO_ENABLED=0 go build -o kilitd ./cmd/kilitd                                 # or: make build (bakes in git describe)
```

Pinned dependencies (newer releases require Go ≥ 1.26, so never `go get -u`):
`github.com/coder/websocket v1.8.15`, `golang.org/x/crypto v0.48.0`, `golang.org/x/time v0.14.0`,
`golang.org/x/sync v0.19.0`, `modernc.org/sqlite v1.46.1` (pure Go; the binary is static).

## Run locally

```sh
./kilitd -db ./dev.db -blobs ./blobs -addr :8080 -public-origin http://<lan-ip>:8080
curl -s http://<lan-ip>:8080/healthz      # {"ok":true,"version":"..."}
```

`-public-origin` is bound into every signed registration/login/delete message, so the string the
phones enter in onboarding must be exactly this value (`http://<lan-ip>:8080` in Debug on the LAN,
`https://kilit.example.com` in production). The blob directory is created if missing; the SQLite
file (WAL mode) must live on a local disk.

## Configuration

Every flag can be given as an environment variable `KILIT_<FLAG>` (dashes → underscores);
flags win over the environment. Boolean values accept `1/true/yes` and `0/false/no`.

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `-addr` | `KILIT_ADDR` | `:8080` | listen address (HTTP/1.1 only; TLS terminates at Caddy) |
| `-public-origin` | `KILIT_PUBLIC_ORIGIN` | *(required)* | `scheme://host[:port]`, no path; part of the signed messages |
| `-db` | `KILIT_DB` | `/data/kilit.db` | SQLite database path |
| `-blobs` | `KILIT_BLOBS` | `/data/blobs` | attachment directory (`id[:2]/id`, 0600) |
| `-msg-ttl` | `KILIT_MSG_TTL` | `168h` | queued message lifetime |
| `-blob-ttl` | `KILIT_BLOB_TTL` | `msg-ttl + 24h` | attachment lifetime; startup refuses anything lower |
| `-max-upload` | `KILIT_MAX_UPLOAD` | `8388629` | attachment cap in bytes (8 MiB + 21) |
| `-max-envelope` | `KILIT_MAX_ENVELOPE` | `65536` | decoded envelope cap in bytes |
| `-queue-cap` | `KILIT_QUEUE_CAP` | `5000` | queued messages per recipient |
| `-sender-queue-cap` | `KILIT_SENDER_QUEUE_CAP` | `500` | queued messages per (sender, recipient) |
| `-trusted-proxy` | `KILIT_TRUSTED_PROXY` | *(none)* | CIDR list whose `X-Forwarded-For` is honoured for per-IP limits |
| `-ws-query-token` | `KILIT_WS_QUERY_TOKEN` | `false` | also accept `?token=` on `GET /v1/ws` |
| `-log-level` | `KILIT_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` (JSON logs on stderr) |
| `-delete-user <name>` | — | — | admin subcommand, see below |

Logs never contain bodies, tokens or usernames paired with IPs; client IPs are truncated to
`/24` (IPv4) or `/48` (IPv6).

## Admin: `kilitd -delete-user <name>`

A username can only be freed by its own keys (`DELETE /v1/users/me`, which the app calls from
"Hesabı sil ve sıfırla" and from the reinstall wipe). **If the keys are lost — phone lost, passcode
removed, app reinstalled while the server was unreachable — the account cannot be recovered and the
name stays taken** (there is no account recovery by design: new phone = new identity = "güvenlik
numarası değişti"). The operator frees the name with:

```sh
./kilitd -db /data/kilit.db -blobs /data/blobs -delete-user alice
# in production:
cd server && docker compose run --rm --entrypoint /kilitd kilitd -db /data/kilit.db -blobs /data/blobs -delete-user alice
```

It removes the owner's attachment files first, then the user row (sessions, prekeys, queued
messages and attachment rows cascade). `-public-origin` is not needed for this subcommand.

## Production deployment (everything from `server/`)

1. DNS A/AAAA record for the domain pointing at the VPS; ports 80 and 443 open (ACME).
2. `cd server && mkdir -p data && sudo chown 65532:65532 data` — the image runs as the distroless
   `nonroot` user (uid 65532) and `./data` is mounted at `/data` (database, WAL/SHM, blobs).
   `/data` must be on a local disk (WAL needs local file locking).
3. Put the domain in `Caddyfile` and `KILIT_PUBLIC_ORIGIN` in `docker-compose.yml`; keep
   `KILIT_TRUSTED_PROXY=172.28.0.0/16` (the compose network `kilitnet` has that fixed subnet, so
   Caddy's `X-Forwarded-For` is trusted and per-IP limits apply to real clients).
4. `docker compose up -d --build` (or `make up`, which passes `VERSION=$(git describe --always --dirty)`
   into the image; `/healthz` reports it). The build context is this directory; `.dockerignore`
   keeps `dev.db*`, `blobs/`, `data/`, a stale `kilitd` and tests out of it.
5. `docker compose logs -f kilitd`. Log retention is bounded by rotation (3 × 10 MB), not time.
   `stop_grace_period: 15s` covers the 10 s graceful shutdown (open WebSockets get close `1001`).

The container speaks plain HTTP/1.1 on `kilitd:8080`; Caddy terminates TLS (WebSocket upgrades need
HTTP/1.1, so HTTP/2 is disabled on the Go listener as well).

## Protocol summary

REST (`/v1/...`, JSON, bearer tokens): `POST /v1/auth/challenge`, `POST /v1/register`,
`POST /v1/auth/login`, `DELETE /v1/auth/session`, `DELETE /v1/users/me`, `GET /v1/users/{username}`,
`GET /v1/users/{username}/prekeys`, `PUT /v1/prekeys`, `GET /v1/prekeys/count`, `POST /v1/messages`,
`GET /v1/messages?after=&limit=`, `POST /v1/messages/ack`, `POST|GET|DELETE /v1/attachments/{id}`,
`PUT /v1/devices/{device_id}/push-token`, `GET /healthz`. Error bodies are `{"error":"<code>",...}`;
rate limits answer `429` with `Retry-After: 1`. Details and the code catalogue: `docs/DESIGN.md` §4.3.

WebSocket `GET /v1/ws` (same bearer; text frames, JSON, ≤ 128 KiB, ≤ 3 connections per user):

| Direction | Frame |
|---|---|
| client → server | `{"t":"hello","after":<last id>}` — must be the first frame, within 10 s (else close `1008 no_hello`) |
| client → server | `{"t":"ack","msg_ids":[...]}` (≤ 500), `{"t":"ping"}` — together limited to 30 burst / 5 per s per **user** (else `1008 rate_limited`) |
| server → client | `{"t":"msg","id":…,"msg_id":"…","from":"…","envelope":"<base64url>","ts":…}` |
| server → client | `{"t":"pong"}`, `{"t":"prekeys_low","opk_count":…,"consumed_ids":[…]}`, `{"t":"error","code":"bad_frame\|rate_limited"}` |

After `hello` the queue `id > after` is drained in pages, then the connection is live; rows that
arrive during the drain are delivered exactly once, in `id` order. Close codes: `1000 superseded`
(4th connection replaces the oldest), `1001` shutdown, `1002 bad_frame`, `1008 slow_consumer`
(256 undelivered frames), `1009` oversize frame. Sending is REST-only. The server pings every 30 s.

## Watermark decoder (`cmd/wmdecode`)

The app overlays a faint per-viewer forensic watermark; a photo of a screen can be decoded offline:

```sh
go run ./cmd/wmdecode -in photo.jpg -corners x1,y1,x2,y2,x3,y3,x4,y4 -ws <hex from Diagnostics>[,<hex>…] -usernames alice,bob
```

Corners are the four screen corners clockwise from the top-left as read from the cursor position in
Preview.app; `-ws` takes the watermark secrets shown in the app's Diagnostics screen (smallest `sid`
first) and the output is `{tag, day, confidence, matches:[username…]}`. It is a hint, not proof:
both parties of a chat can compute the other's tag (`docs/THREAT_MODEL.md`).

## Limits worth knowing

- No account recovery and no multi-device: a lost key means a new identity, and a username whose
  keys are gone can only be freed with `-delete-user` (above).
- The server sees who talks to whom, when, how much, session setups and message counters; it
  never sees content, and messages are deleted on ack or after `-msg-ttl`.
- Messages are delivered while the app is open (no push content in phase 1); the queue holds
  5000 per recipient / 500 per sender.
