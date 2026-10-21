import XCTest
import CryptoKit
@testable import Kilit

/// §3.5: on `409 blob_exists` the upload is re-sealed under a fresh `blob_id` AND a fresh `fileKey`
/// (so `att.key` and `att.sha256` change too); at most 3 attempts; other errors propagate.
final class AttachmentUploadTests: XCTestCase {
    private final class UploadLog {
        private(set) var paths: [String] = []
        private(set) var bodies: [Data] = []
        private(set) var recipients: [String?] = []
        private let lock: NSLock = NSLock()

        func record(_ request: URLRequest) -> Int {
            lock.lock()
            defer { lock.unlock() }
            paths.append(request.url?.path ?? "")
            bodies.append(request.httpBody ?? Data())
            recipients.append(request.value(forHTTPHeaderField: "X-Kilit-Recipient"))
            return paths.count
        }
    }

    private func api(_ transport: StubTransport) -> APIClient {
        APIClient(origin: "https://kilit.test", transport: transport, token: "t")
    }

    func testRetryOn409UsesFreshBlobIdAndFileKey() async throws {
        let blob1: Data = Bytes.random(16)
        let key1: Data = Bytes.random(32)
        let blob2: Data = Bytes.random(16)
        let key2: Data = Bytes.random(32)
        let source: ScriptedKeySource = ScriptedKeySource(keys: [], bytes: [blob1, key1, blob2, key2])
        let log: UploadLog = UploadLog()
        let transport: StubTransport = StubTransport { request in
            let n: Int = log.record(request)
            if n == 1 { return try StubTransport.json(409, request, ["error": "blob_exists", "message": "duplicate"]) }
            let id: String = String((request.url?.path ?? "").split(separator: "/").last ?? "")
            return try StubTransport.json(201, request, ["id": id, "expires_at": 1_760_100_000])
        }
        let plaintext: Data = Data("hello, attachment".utf8)
        let sealed: SealedAttachment = try await AttachmentUploader.upload(plaintext: plaintext, mime: "image/jpeg", recipient: "bob",
                                                                           api: api(transport), keySource: source)
        XCTAssertEqual(log.paths.count, 2)
        XCTAssertEqual(log.paths[0], "/v1/attachments/\(blob1.hex)")
        XCTAssertEqual(log.paths[1], "/v1/attachments/\(blob2.hex)")
        XCTAssertEqual(log.recipients, ["bob", "bob"])
        XCTAssertEqual(sealed.blobId, blob2)
        XCTAssertEqual(sealed.blobIdHex, blob2.hex)
        XCTAssertEqual(sealed.fileKey, key2)
        XCTAssertNotEqual(sealed.fileKey, key1)
        XCTAssertNotEqual(log.bodies[0], log.bodies[1])
        XCTAssertEqual(log.bodies[1], sealed.blob)
        // att.sha256 covers the whole blob file and differs between the two attempts.
        XCTAssertEqual(KDF.sha256(log.bodies[1]), sealed.sha256)
        XCTAssertNotEqual(KDF.sha256(log.bodies[0]), sealed.sha256)
        XCTAssertTrue(AttachmentCrypto.verifyDigest(blob: log.bodies[1], expected: sealed.sha256))
        // Distinct fileKeys → distinct (key, nonce): no Poly1305 key reuse across the two bodies.
        let first: (key: Data, nonce: Data) = AttachmentCrypto.deriveKeys(fileKey: key1)
        let second: (key: Data, nonce: Data) = AttachmentCrypto.deriveKeys(fileKey: key2)
        XCTAssertNotEqual(first.key, second.key)
        XCTAssertNotEqual(first.nonce, second.nonce)
        XCTAssertEqual(source.bytesDrawn, 4)
        XCTAssertEqual(source.overdrawnBytes, 0)
        XCTAssertEqual(sealed.len, UInt64(plaintext.count))
        XCTAssertEqual(sealed.mime, "image/jpeg")
        // The final blob opens with the final key.
        let opened: OwnedPlaintextBuffer = try AttachmentCrypto.open(blob: sealed.blob, fileKey: sealed.fileKey, blobId: sealed.blobId,
                                                                     mime: sealed.mime, len: sealed.len)
        XCTAssertEqual(opened.count, plaintext.count)
        opened.clear()
    }

    func testGivesUpAfterThreeAttempts() async throws {
        let log: UploadLog = UploadLog()
        let transport: StubTransport = StubTransport { request in
            _ = log.record(request)
            return try StubTransport.json(409, request, ["error": "blob_exists"])
        }
        do {
            _ = try await AttachmentUploader.upload(plaintext: Data([7, 7, 7]), mime: "image/jpeg", recipient: "bob",
                                                    api: api(transport), keySource: RandomKeySource())
            XCTFail("expected exhaustion")
        } catch let e as AttachmentUploadError {
            XCTAssertEqual(e, .exhausted)
        }
        XCTAssertEqual(log.paths.count, AttachmentUploader.maxAttempts)
        XCTAssertEqual(log.paths.count, 3)
        XCTAssertEqual(Set(log.paths).count, 3)
        XCTAssertEqual(Set(log.bodies).count, 3)
    }

    func testOtherErrorsPropagateWithoutRetry() async throws {
        let log: UploadLog = UploadLog()
        let transport: StubTransport = StubTransport { request in
            _ = log.record(request)
            return try StubTransport.json(413, request, ["error": "body_too_large"])
        }
        do {
            _ = try await AttachmentUploader.upload(plaintext: Data([1]), mime: "image/jpeg", recipient: "bob",
                                                    api: api(transport), keySource: RandomKeySource())
            XCTFail("expected an HTTP error")
        } catch let e as APIError {
            XCTAssertEqual(e.status, 413)
            XCTAssertEqual(e.code, "body_too_large")
        }
        XCTAssertEqual(log.paths.count, 1)
    }

    /// End to end: `sendImage` uploads, keeps the sender's ciphertext locally and sends an `image` message whose
    /// `att` matches the upload; the receiver's download path issues `DELETE` after a verified download.
    func testSendImageAndReceiverDownloadDelete() async throws {
        let alice: SyncHarness = try SyncHarness(username: "alice")
        let bob: TestPeer = TestPeer(username: "bob", now: SyncHarness.now0)
        alice.peers["bob"] = bob
        let uploads: UploadLog = UploadLog()
        var sentEnvelope: Data? = nil
        alice.override = { request in
            let path: String = request.url?.path ?? ""
            if request.httpMethod == "POST", path.hasPrefix("/v1/attachments/") {
                _ = uploads.record(request)
                let id: String = String(path.split(separator: "/").last ?? "")
                return try StubTransport.json(201, request, ["id": id, "expires_at": 1_760_100_000])
            }
            if request.httpMethod == "POST", path == "/v1/messages" {
                let body: SendRequest = try KilitJSON.decoder().decode(SendRequest.self, from: request.httpBody ?? Data())
                sentEnvelope = body.envelope
                return try StubTransport.json(202, request, ["id": 1])
            }
            return nil
        }
        let image: NormalizedImage = NormalizedImage(data: Data(repeating: 0xAB, count: 4096), width: 64, height: 48)
        _ = try await alice.sync.sendImage(to: "bob", image: image)
        XCTAssertEqual(uploads.paths.count, 1)
        let conv: ConversationDocument = try XCTUnwrap(try alice.conversation("bob"))
        let message: Message = try XCTUnwrap(conv.messages.first)
        XCTAssertEqual(message.kind, .image)
        XCTAssertEqual(message.state, .sent)
        let att: InnerAttachment = try XCTUnwrap(message.att)
        XCTAssertEqual("/v1/attachments/\(att.blob)", uploads.paths[0])
        XCTAssertEqual(att.w, 64)
        XCTAssertEqual(att.h, 48)
        XCTAssertEqual(att.len, 4096)
        XCTAssertEqual(att.mime, "image/jpeg")
        XCTAssertTrue(alice.blobs.exists(id: att.blob))
        XCTAssertTrue(message.blobDownloaded)
        XCTAssertNotNil(sentEnvelope)
        // The sender never queues a DELETE for its own blob.
        XCTAssertTrue(alice.store.index.outbox.isEmpty)

        // Receiver side: download → verify sha256 → write blobs/<id>.bin → DELETE from the outbox.
        let blobBytes: Data = uploads.bodies[0]
        let receiver: BlobStore = BlobStore(directory: URL(fileURLWithPath: "/kilit-tests/recv", isDirectory: true), writer: MemoryFileWriter())
        let download: StubTransport = StubTransport { request in
            try StubTransport.data(200, request, blobBytes)
        }
        let ok: Bool = try await AttachmentDownloader.download(att: att, api: api(download), blobs: receiver)
        XCTAssertTrue(ok)
        XCTAssertTrue(receiver.exists(id: att.blob))
        let opened: OwnedPlaintextBuffer = try AttachmentDownloader.open(att: att, blobs: receiver)
        XCTAssertEqual(opened.count, 4096)
        opened.clear()
        // A corrupted body fails the digest and is not stored; a 404 means "Ek süresi doldu".
        let corrupt: StubTransport = StubTransport { request in
            try StubTransport.data(200, request, blobBytes + Data([0]))
        }
        let other: BlobStore = BlobStore(directory: URL(fileURLWithPath: "/kilit-tests/recv2", isDirectory: true), writer: MemoryFileWriter())
        do {
            _ = try await AttachmentDownloader.download(att: att, api: api(corrupt), blobs: other)
            XCTFail("expected digest failure")
        } catch let e as AttachmentError {
            XCTAssertEqual(e, .expired)
        }
        XCTAssertFalse(other.exists(id: att.blob))
        let gone: StubTransport = StubTransport { request in
            try StubTransport.json(404, request, ["error": "not_found"])
        }
        let expired: Bool = try await AttachmentDownloader.download(att: att, api: api(gone), blobs: other)
        XCTAssertFalse(expired)
    }
}
