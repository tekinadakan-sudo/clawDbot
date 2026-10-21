import Foundation
import CryptoKit

// MARK: - Transport (injected so tests run without a network)

protocol HTTPTransport: AnyObject {
    func perform(_ request: URLRequest) async throws -> (Data, HTTPURLResponse)
}

final class URLSessionTransport: HTTPTransport {
    let session: URLSession

    init(session: URLSession) {
        self.session = session
    }

    func perform(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else { throw APIError.badResponse }
        return (data, http)
    }
}

enum APIError: Error, Equatable {
    /// Non-2xx with the server's `{"error": code}` when it parsed, plus `server_time` on `clock_skew` and the
    /// delta-seconds `Retry-After` header when present (`429 rate_limited` / `attachment_quota`).
    case http(status: Int, code: String?, serverTime: UInt64?, retryAfter: UInt64?)
    case transport(String)
    case badResponse
    case notLoggedIn

    var status: Int? {
        if case .http(let s, _, _, _) = self { return s }
        return nil
    }

    var code: String? {
        if case .http(_, let c, _, _) = self { return c }
        return nil
    }

    var retryAfter: UInt64? {
        if case .http(_, _, _, let r) = self { return r }
        return nil
    }

    /// `401 unknown_user` / `bad_signature` on `POST /v1/auth/login`: the server does not know this account or
    /// these keys (§4.5). Never retried in a loop; when it persists the client returns to onboarding.
    var isLoginRejection: Bool {
        status == 401 && (code == "unknown_user" || code == "bad_signature")
    }

    /// Offline, 5xx, 429 (incl. `attachment_quota`), `408 request_timeout`, `401 invalid_token` (until re-login):
    /// park / retry, never a verdict (§3.2 step 1).
    var isTransient: Bool {
        switch self {
        case .transport, .badResponse, .notLoggedIn:
            return true
        case .http(let s, let c, _, _):
            return s >= 500 || s == 429 || s == 408 || (s == 401 && c == "invalid_token")
        }
    }
}

// MARK: - APIClient (§4.3, §5.4)

actor APIClient {
    static let requestTimeout: TimeInterval = 60

    nonisolated let origin: String
    private let transport: HTTPTransport
    private(set) var token: String?
    /// `server_time − localNow` learned from the last challenge.
    private(set) var clockOffset: Int64

    init(origin: String, transport: HTTPTransport, token: String? = nil, clockOffset: Int64 = 0) {
        self.origin = origin
        self.transport = transport
        self.token = token
        self.clockOffset = clockOffset
    }

    /// REST/upload session: ephemeral, no cache, waits for connectivity, 60 s request / 600 s resource.
    static func restSession() -> URLSession {
        let c: URLSessionConfiguration = URLSessionConfiguration.ephemeral
        c.urlCache = nil
        c.requestCachePolicy = .reloadIgnoringLocalCacheData
        c.waitsForConnectivity = true
        c.timeoutIntervalForRequest = 60
        c.timeoutIntervalForResource = 600
        return URLSession(configuration: c)
    }

    /// WebSocket session: ephemeral, no cache, no waiting for connectivity, request and resource timeouts left at
    /// their defaults (a short resource timeout would tear down every healthy socket; the connect phase is bounded
    /// by `WebSocketClient`'s watchdog instead).
    static func webSocketSession() -> URLSession {
        let c: URLSessionConfiguration = URLSessionConfiguration.ephemeral
        c.urlCache = nil
        c.requestCachePolicy = .reloadIgnoringLocalCacheData
        c.waitsForConnectivity = false
        return URLSession(configuration: c)
    }

    /// `scheme://host[:port]`, lowercase, no path, default ports omitted (§3 `server_origin`).
    static func canonicalOrigin(_ raw: String) -> String? {
        var text: String = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if !text.contains("://") { text = "https://" + text }
        guard let comps = URLComponents(string: text), let scheme = comps.scheme?.lowercased(),
              let host = comps.host?.lowercased(), !host.isEmpty else { return nil }
        guard scheme == "http" || scheme == "https" else { return nil }
        var out: String = "\(scheme)://\(host)"
        if let port = comps.port {
            let isDefault: Bool = (scheme == "http" && port == 80) || (scheme == "https" && port == 443)
            if !isDefault { out += ":\(port)" }
        }
        return out
    }

    func setToken(_ value: String?) {
        token = value
    }

    func setClockOffset(_ value: Int64) {
        clockOffset = value
    }

    /// `ts = localNow + offset` for signed requests.
    func correctedTime(localNow: UInt64) -> UInt64 {
        let v: Int64 = Int64(localNow) + clockOffset
        return v > 0 ? UInt64(v) : 0
    }

    // MARK: request plumbing

    private func makeRequest(_ method: String, _ path: String, body: Data? = nil, contentType: String? = "application/json",
                             auth: Bool, timeout: TimeInterval? = APIClient.requestTimeout,
                             headers: [String: String] = [:]) throws -> URLRequest {
        guard let url = URL(string: origin + path) else { throw APIError.badResponse }
        var req: URLRequest = URLRequest(url: url)
        req.httpMethod = method
        if let t = timeout { req.timeoutInterval = t }
        if let ct = contentType { req.setValue(ct, forHTTPHeaderField: "Content-Type") }
        req.setValue("application/json", forHTTPHeaderField: "Accept")
        if auth {
            guard let tok = token else { throw APIError.notLoggedIn }
            req.setValue("Bearer \(tok)", forHTTPHeaderField: "Authorization")
        }
        for (k, v) in headers {
            req.setValue(v, forHTTPHeaderField: k)
        }
        req.httpBody = body
        return req
    }

    private func encode<T: Encodable>(_ value: T) throws -> Data {
        try KilitJSON.encoder().encode(value)
    }

    /// Performs the request and maps every non-2xx status to `APIError.http`.
    private func perform(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        let data: Data
        let response: HTTPURLResponse
        do {
            (data, response) = try await transport.perform(request)
        } catch let e as APIError {
            throw e
        } catch {
            throw APIError.transport(String(describing: error))
        }
        guard (200...299).contains(response.statusCode) else {
            let parsed: ErrorResponse? = try? KilitJSON.decoder().decode(ErrorResponse.self, from: data)
            let retry: String? = response.value(forHTTPHeaderField: "Retry-After")
            let retryAfter: UInt64? = retry.flatMap { UInt64($0.trimmingCharacters(in: .whitespaces)) }
            throw APIError.http(status: response.statusCode, code: parsed?.error, serverTime: parsed?.serverTime,
                                retryAfter: retryAfter)
        }
        return (data, response)
    }

    private func call<T: Decodable>(_ type: T.Type, _ request: URLRequest) async throws -> T {
        let (data, _) = try await perform(request)
        do {
            return try KilitJSON.decoder().decode(T.self, from: data)
        } catch {
            throw APIError.badResponse
        }
    }

    private func callNoContent(_ request: URLRequest) async throws {
        _ = try await perform(request)
    }

    // MARK: §4.3.2 routes

    /// Also learns the clock offset (`server_time − localNow`).
    func challenge(username: String, localNow: UInt64) async throws -> ChallengeResponse {
        let req: URLRequest = try makeRequest("POST", "/v1/auth/challenge", body: try encode(ChallengeRequest(username: username)), auth: false)
        let resp: ChallengeResponse = try await call(ChallengeResponse.self, req)
        clockOffset = Int64(resp.serverTime) - Int64(localNow)
        return resp
    }

    func register(_ body: RegisterRequest) async throws -> RegisterResponse {
        let req: URLRequest = try makeRequest("POST", "/v1/register", body: try encode(body), auth: false)
        let resp: RegisterResponse = try await call(RegisterResponse.self, req)
        token = resp.token
        return resp
    }

    func login(_ body: LoginRequest) async throws -> LoginResponse {
        let req: URLRequest = try makeRequest("POST", "/v1/auth/login", body: try encode(body), auth: false)
        let resp: LoginResponse = try await call(LoginResponse.self, req)
        token = resp.token
        return resp
    }

    func logout() async throws {
        try await callNoContent(try makeRequest("DELETE", "/v1/auth/session", contentType: nil, auth: true))
        token = nil
    }

    func deleteAccount(_ body: DeleteAccountRequest) async throws {
        try await callNoContent(try makeRequest("DELETE", "/v1/users/me", body: try encode(body), auth: true))
    }

    func lookup(username: String) async throws -> UserResponse {
        try await call(UserResponse.self, try makeRequest("GET", "/v1/users/\(username)", contentType: nil, auth: true))
    }

    func fetchBundle(username: String) async throws -> BundleResponse {
        try await call(BundleResponse.self, try makeRequest("GET", "/v1/users/\(username)/prekeys", contentType: nil, auth: true))
    }

    func uploadPrekeys(_ body: PrekeysPutRequest) async throws -> PrekeysPutResponse {
        try await call(PrekeysPutResponse.self, try makeRequest("PUT", "/v1/prekeys", body: try encode(body), auth: true))
    }

    func prekeyCount() async throws -> PrekeyCountResponse {
        try await call(PrekeyCountResponse.self, try makeRequest("GET", "/v1/prekeys/count", contentType: nil, auth: true))
    }

    func send(_ body: SendRequest) async throws -> SendResponse {
        try await call(SendResponse.self, try makeRequest("POST", "/v1/messages", body: try encode(body), auth: true))
    }

    func poll(after: Int64, limit: Int = 100) async throws -> MessagesResponse {
        try await call(MessagesResponse.self, try makeRequest("GET", "/v1/messages?after=\(after)&limit=\(limit)", contentType: nil, auth: true))
    }

    func ack(msgIds: [String]) async throws -> AckResponse {
        try await call(AckResponse.self, try makeRequest("POST", "/v1/messages/ack", body: try encode(AckRequest(msgIds: msgIds)), auth: true))
    }

    /// Leaves the request timeout at the session default (600 s resource cap, §5.4).
    func upload(blobID: String, recipient: String, data: Data) async throws -> AttachmentUploadResponse {
        let req: URLRequest = try makeRequest("POST", "/v1/attachments/\(blobID)", body: data, contentType: "application/octet-stream",
                                              auth: true, timeout: nil, headers: ["X-Kilit-Recipient": recipient])
        return try await call(AttachmentUploadResponse.self, req)
    }

    /// `dataTask` only (no `downloadTask`, so no temp file in `Caches/`).
    func download(blobID: String) async throws -> Data {
        let req: URLRequest = try makeRequest("GET", "/v1/attachments/\(blobID)", contentType: nil, auth: true, timeout: nil)
        let (data, _) = try await perform(req)
        return data
    }

    /// `204`; a `404` counts as success (§3.5b).
    func deleteBlob(blobID: String) async throws {
        do {
            try await callNoContent(try makeRequest("DELETE", "/v1/attachments/\(blobID)", contentType: nil, auth: true))
        } catch APIError.http(let status, _, _, _) where status == 404 {
            return
        }
    }

    func registerPushToken(deviceId: String, token value: String, env: String) async throws {
        try await callNoContent(try makeRequest("PUT", "/v1/devices/\(deviceId)/push-token",
                                                body: try encode(PushTokenRequest(token: value, env: env)), auth: true))
    }

    /// `GET /v1/ws` with the bearer header (`ws`/`wss` scheme); nil without a token.
    func webSocketRequest() -> URLRequest? {
        guard let tok = token else { return nil }
        var text: String = origin
        if text.hasPrefix("https://") {
            text = "wss://" + String(text.dropFirst("https://".count))
        } else if text.hasPrefix("http://") {
            text = "ws://" + String(text.dropFirst("http://".count))
        }
        guard let url = URL(string: text + "/v1/ws") else { return nil }
        var req: URLRequest = URLRequest(url: url)
        req.setValue("Bearer \(tok)", forHTTPHeaderField: "Authorization")
        return req
    }
}

// MARK: - Signed auth bodies (§3.1)

enum AuthRequests {
    static func register(username: String, local: IdentityKeys, deviceId: String, nonce: Data, ts: UInt64, origin: String,
                         spk: SignedPrekey, opks: [OneTimePrekey]) throws -> RegisterRequest {
        let ids: IdentityPublicKeys = local.publicKeys
        let proof: Data = try local.sign(SignedMessages.registerProof(username: username, ikDh: ids.ikDh, deviceId: deviceId,
                                                                      nonce: nonce, ts: ts, serverOrigin: origin))
        return RegisterRequest(username: username, ikSig: ids.ikSig, ikDh: ids.ikDh, ikBindSig: try local.ikBindSig(),
                               registerProof: proof, nonce: nonce, ts: ts, spk: try PrekeyUpload.spkDTO(spk, local: local),
                               opks: opks.map { OPKDTO(id: $0.id, pub: $0.publicKey) },
                               opksSig: try PrekeyUpload.opksSig(opks, local: local), deviceId: deviceId)
    }

    static func login(username: String, local: IdentityKeys, deviceId: String, nonce: Data, ts: UInt64, origin: String) throws -> LoginRequest {
        let sig: Data = try local.sign(SignedMessages.login(username: username, nonce: nonce, ts: ts, deviceId: deviceId, serverOrigin: origin))
        return LoginRequest(username: username, nonce: nonce, ts: ts, deviceId: deviceId, sig: sig)
    }

    static func deleteAccount(username: String, local: IdentityKeys, nonce: Data, ts: UInt64, origin: String) throws -> DeleteAccountRequest {
        let sig: Data = try local.sign(SignedMessages.delete(username: username, nonce: nonce, ts: ts, serverOrigin: origin))
        return DeleteAccountRequest(nonce: nonce, ts: ts, sig: sig)
    }
}

// MARK: - Attachment upload (§3.5: fresh blob_id AND fileKey on 409 / 408, ≤ 3 attempts)

enum AttachmentUploadError: Error, Equatable {
    case exhausted
    /// `429 attachment_quota`: the owner's or the recipient's blob quota is full. Temporary, never a verdict: the
    /// user (whose send is pending) is told to retry after `retryAfter` seconds (`Retry-After`, 60 s default).
    case quotaExceeded(retryAfter: UInt64)
}

enum AttachmentUploader {
    static let maxAttempts: Int = 3
    static let defaultQuotaRetryAfter: UInt64 = 60

    /// Seals (drawing `blob_id` and `fileKey` from `keySource`) and uploads; on `409 blob_exists` and on a transient
    /// `408 request_timeout` (the server already removed the partial file) the plaintext is re-sealed under a new
    /// `blob_id` and a new `fileKey` (the last attempt's 408 propagates). `429 attachment_quota` becomes
    /// `.quotaExceeded`. Any other error propagates.
    static func upload(plaintext: Data, mime: String, recipient: String, api: APIClient, keySource: KeySource) async throws -> SealedAttachment {
        var attempt: Int = 0
        while attempt < maxAttempts {
            attempt += 1
            let sealed: SealedAttachment = try AttachmentCrypto.seal(plaintext: plaintext, mime: mime, keySource: keySource)
            do {
                _ = try await api.upload(blobID: sealed.blobIdHex, recipient: recipient, data: sealed.blob)
                return sealed
            } catch APIError.http(let status, let code, _, _) where status == 409 && code == "blob_exists" {
                continue
            } catch APIError.http(let status, _, _, _) where status == 408 && attempt < maxAttempts {
                continue
            } catch APIError.http(let status, let code, _, let retryAfter) where status == 429 && code == "attachment_quota" {
                throw AttachmentUploadError.quotaExceeded(retryAfter: retryAfter ?? defaultQuotaRetryAfter)
            }
        }
        throw AttachmentUploadError.exhausted
    }
}
