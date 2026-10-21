import Foundation
import CryptoKit

// MARK: - blobs/<id>.bin (§3.7: not a store document)

/// Attachment ciphertext exactly as downloaded, `[.atomic, .completeFileProtection]`, no generation, no docKey;
/// integrity is `att.sha256`, verified on download and again on open.
final class BlobStore {
    let directory: URL
    private let writer: FileWriter

    init(directory: URL, writer: FileWriter = DiskFileWriter()) {
        self.directory = directory
        self.writer = writer
    }

    static func isValidId(_ id: String) -> Bool {
        let bytes: [UInt8] = Array(id.utf8)
        guard bytes.count == 32 else { return false }
        for b in bytes {
            let ok: Bool = (b >= 0x30 && b <= 0x39) || (b >= 0x61 && b <= 0x66)
            if !ok { return false }
        }
        return true
    }

    func url(id: String) -> URL {
        directory.appendingPathComponent("\(id).bin")
    }

    func write(id: String, ciphertext: Data) throws {
        try writer.write(ciphertext, to: url(id: id))
    }

    func read(id: String) throws -> Data? {
        try writer.read(url(id: id))
    }

    func exists(id: String) -> Bool {
        ((try? writer.read(url(id: id))) ?? nil) != nil
    }

    func delete(id: String) {
        try? writer.remove(url(id: id))
    }

    func deleteAll() throws {
        try writer.remove(directory)
    }
}

// MARK: - Receive pipeline (§3.5b)

enum AttachmentError: Error, Equatable {
    /// `404 not_found` or a digest mismatch ("Ek süresi doldu").
    case expired
    case notDownloaded
    case badId
}

enum AttachmentDownloader {
    /// `dataTask` on the ephemeral REST session → verify `sha256` → write `blobs/<id>.bin`. Returns false when
    /// the server answered 404 (the message shows "Ek süresi doldu"); the caller queues `DELETE` on true.
    static func download(att: InnerAttachment, api: APIClient, blobs: BlobStore) async throws -> Bool {
        guard BlobStore.isValidId(att.blob) else { throw AttachmentError.badId }
        let bytes: Data
        do {
            bytes = try await api.download(blobID: att.blob)
        } catch APIError.http(let status, _, _) where status == 404 {
            return false
        }
        guard AttachmentCrypto.verifyDigest(blob: bytes, expected: att.sha256) else {
            throw AttachmentError.expired
        }
        try blobs.write(id: att.blob, ciphertext: bytes)
        return true
    }

    /// Reads the file, re-verifies the digest (a mismatch deletes the file) and opens it into an owned buffer.
    static func open(att: InnerAttachment, blobs: BlobStore) throws -> OwnedPlaintextBuffer {
        guard let bytes = try blobs.read(id: att.blob) else { throw AttachmentError.notDownloaded }
        guard AttachmentCrypto.verifyDigest(blob: bytes, expected: att.sha256), let blobId = Data(hex: att.blob) else {
            blobs.delete(id: att.blob)
            throw AttachmentError.expired
        }
        return try AttachmentCrypto.open(blob: bytes, fileKey: att.key, blobId: blobId, mime: att.mime, len: att.len)
    }
}
