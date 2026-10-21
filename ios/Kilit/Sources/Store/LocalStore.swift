import Foundation
import CryptoKit
import UIKit

// MARK: - File writer (injected so tests can fail or record writes)

protocol FileWriter: AnyObject {
    /// `[.atomic, .completeFileProtection]`; creates intermediate directories.
    func write(_ data: Data, to url: URL) throws
    /// nil when the file does not exist.
    func read(_ url: URL) throws -> Data?
    /// Files or directories; a missing item is not an error.
    func remove(_ url: URL) throws
    func contents(of directory: URL) throws -> [URL]
    func createDirectory(_ url: URL) throws
}

final class DiskFileWriter: FileWriter {
    private let fm: FileManager = FileManager.default

    init() {}

    func write(_ data: Data, to url: URL) throws {
        try createDirectory(url.deletingLastPathComponent())
        try data.write(to: url, options: [.atomic, .completeFileProtection])
    }

    func read(_ url: URL) throws -> Data? {
        guard fm.fileExists(atPath: url.path) else { return nil }
        return try Data(contentsOf: url)
    }

    func remove(_ url: URL) throws {
        guard fm.fileExists(atPath: url.path) else { return }
        try fm.removeItem(at: url)
    }

    func contents(of directory: URL) throws -> [URL] {
        guard fm.fileExists(atPath: directory.path) else { return [] }
        return try fm.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil, options: [.skipsHiddenFiles])
    }

    func createDirectory(_ url: URL) throws {
        try fm.createDirectory(at: url, withIntermediateDirectories: true,
                               attributes: [.protectionKey: FileProtectionType.complete])
    }
}

/// Dictionary-backed writer for tests and previews; records every written path in order.
final class MemoryFileWriter: FileWriter {
    private(set) var files: [String: Data] = [:]
    private(set) var writtenPaths: [String] = []

    init() {}

    func write(_ data: Data, to url: URL) throws {
        files[url.path] = data
        writtenPaths.append(url.lastPathComponent)
    }

    func read(_ url: URL) throws -> Data? {
        files[url.path]
    }

    func remove(_ url: URL) throws {
        let prefix: String = url.path
        for key in files.keys where key == prefix || key.hasPrefix(prefix + "/") {
            files.removeValue(forKey: key)
        }
    }

    func contents(of directory: URL) throws -> [URL] {
        let prefix: String = directory.path + "/"
        return files.keys.filter { $0.hasPrefix(prefix) }.sorted().map { URL(fileURLWithPath: $0) }
    }

    func createDirectory(_ url: URL) throws {}
}

// MARK: - Errors and writes

enum LocalStoreError: Error, Equatable {
    case closed
    /// Generation below the recorded value, or AAD/path mismatch (§3.7 fail-closed).
    case rollback(path: String)
    /// Opened fine but the JSON does not decode.
    case corrupt(path: String)
}

struct DocumentWrite {
    let path: String
    let json: Data

    init(path: String, json: Data) {
        self.path = path
        self.json = json
    }

    init<T: Encodable>(path: String, value: T) throws {
        self.path = path
        self.json = try KilitJSON.encoder().encode(value)
    }
}

enum LoadResult<T> {
    case missing
    case ok(T)
    /// The document decrypted but its generation is below the record; the stale content is handed back so the
    /// caller can record what it lost (session sids → `known_sids`).
    case rollback(T?)
    case corrupt
}

// MARK: - LocalStore (§3.7, §5.3)

/// Sealed JSON documents under `Application Support/Kilit/`: `index.json` plus `sessions/*.json` and
/// `conv/*.json`. Not thread-safe by itself: `MessageSync` is its single caller in the app.
final class LocalStore {
    static let indexPath: String = "index.json"
    static let installMarkerKey: String = "installMarker"
    static let noncePrefixLength: Int = 4

    let directory: URL
    private let keychain: KeychainStore
    private let writer: FileWriter
    private let defaults: UserDefaults
    private var storeKey: Data?
    private(set) var index: StoreIndex
    private(set) var indexGeneration: UInt64

    private let generationQueue: DispatchQueue = DispatchQueue(label: "com.kilit.store.generation", qos: .utility)
    private let generationLock: NSLock = NSLock()
    private var pendingGeneration: UInt64?
    private var flushScheduled: Bool = false
    /// Keychain `store.generation` writes are coalesced to at most one per this interval (§3.7 step 3).
    var generationCoalesceInterval: TimeInterval = 2

    init(directory: URL, keychain: KeychainStore, writer: FileWriter = DiskFileWriter(),
         defaults: UserDefaults = UserDefaults.standard) {
        self.directory = directory
        self.keychain = keychain
        self.writer = writer
        self.defaults = defaults
        self.storeKey = nil
        self.index = StoreIndex()
        self.indexGeneration = 0
    }

    static func defaultDirectory() -> URL {
        let base: URL = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        return base.appendingPathComponent("Kilit", isDirectory: true)
    }

    var isOpen: Bool { storeKey != nil }

    func fileURL(_ path: String) -> URL {
        directory.appendingPathComponent(path)
    }

    static func sessionPath(_ peer: String) -> String { "sessions/\(peer).json" }
    static func conversationPath(_ peer: String) -> String { "conv/\(peer).json" }

    // MARK: key derivation and sealing (static so tests can check bytes)

    static func storeKey(masterKey: Data) -> Data {
        KDF.hkdf(ikm: masterKey, salt: KDF.zeros32, info: KilitInfo.localStore, length: 32)
    }

    static func docKey(storeKey: Data, path: String) -> Data {
        KDF.hkdf(ikm: storeKey, salt: KDF.zeros32, info: Bytes.utf8(KilitInfo.localStoreDoc) + Bytes.utf8(path), length: 32)
    }

    static func aad(path: String, generation: UInt64) -> Data {
        Bytes.utf8(KilitInfo.localStore) + Bytes.utf8(path) + BE.u64(generation)
    }

    /// `ChaChaPoly.seal(json, docKey, nonce: random(4) || u64BE(generation), authenticating: AAD).combined`.
    static func seal(json: Data, storeKey: Data, path: String, generation: UInt64,
                     randomPrefix: Data = Bytes.random(LocalStore.noncePrefixLength)) throws -> Data {
        guard randomPrefix.count == LocalStore.noncePrefixLength else { throw CryptoKitError.incorrectParameterSize }
        let nonceBytes: Data = randomPrefix + BE.u64(generation)
        let nonce: ChaChaPoly.Nonce = try ChaChaPoly.Nonce(data: nonceBytes)
        let key: SymmetricKey = SymmetricKey(data: docKey(storeKey: storeKey, path: path))
        let box: ChaChaPoly.SealedBox = try ChaChaPoly.seal(json, using: key, nonce: nonce,
                                                            authenticating: aad(path: path, generation: generation))
        return box.combined
    }

    /// Reads the generation from the nonce and opens with the matching AAD; any failure is `rollback(path)`.
    static func open(sealed: Data, storeKey: Data, path: String) throws -> (json: Data, generation: UInt64) {
        guard sealed.count >= 12 + AEAD.tagLength else { throw LocalStoreError.rollback(path: path) }
        let nonceBytes: Data = Bytes.copy(sealed.prefix(12))
        var generation: UInt64 = 0
        for b in nonceBytes.suffix(8) {
            generation = generation << 8 | UInt64(b)
        }
        do {
            let box: ChaChaPoly.SealedBox = try ChaChaPoly.SealedBox(combined: sealed)
            let key: SymmetricKey = SymmetricKey(data: docKey(storeKey: storeKey, path: path))
            let json: Data = try ChaChaPoly.open(box, using: key, authenticating: aad(path: path, generation: generation))
            return (json, generation)
        } catch {
            throw LocalStoreError.rollback(path: path)
        }
    }

    // MARK: open / close

    /// Creates the directory (Complete protection, backup exclusion), loads or creates `masterKey`, and loads
    /// `index.json` under the `≥` rule against the Keychain `store.generation`.
    func open() throws {
        if isOpen { return }
        try prepareDirectory()
        let master: Data = try loadOrCreateMasterKey()
        let sk: Data = LocalStore.storeKey(masterKey: master)
        let recorded: UInt64 = try keychain.readStoreGeneration()
        if let bytes = try writer.read(fileURL(LocalStore.indexPath)) {
            let opened: (json: Data, generation: UInt64) = try LocalStore.open(sealed: bytes, storeKey: sk, path: LocalStore.indexPath)
            guard opened.generation >= recorded else { throw LocalStoreError.rollback(path: LocalStore.indexPath) }
            guard let loaded = try? KilitJSON.decoder().decode(StoreIndex.self, from: opened.json) else {
                throw LocalStoreError.corrupt(path: LocalStore.indexPath)
            }
            index = loaded
            indexGeneration = opened.generation
            if opened.generation > recorded { scheduleGenerationWrite(opened.generation) }
        } else {
            guard recorded == 0 else { throw LocalStoreError.rollback(path: LocalStore.indexPath) }
            index = StoreIndex()
            indexGeneration = 0
        }
        storeKey = sk
    }

    /// Drops `storeKey` and the in-memory index (called on `protectedDataWillBecomeUnavailable`).
    func close() {
        flushGeneration()
        storeKey = nil
        index = StoreIndex()
        indexGeneration = 0
    }

    /// Directory with `.complete` protection and `isExcludedFromBackup`, re-applied on every launch.
    func prepareDirectory() throws {
        try writer.createDirectory(directory)
        try? FileManager.default.setAttributes([.protectionKey: FileProtectionType.complete], ofItemAtPath: directory.path)
        var url: URL = directory
        var values: URLResourceValues = URLResourceValues()
        values.isExcludedFromBackup = true
        try? url.setResourceValues(values)
    }

    private func loadOrCreateMasterKey() throws -> Data {
        if let existing = try keychain.read(KeychainAccount.masterKey), existing.count == 32 {
            return existing
        }
        let fresh: Data = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
        try keychain.write(KeychainAccount.masterKey, fresh)
        return fresh
    }

    // MARK: documents

    func loadDetailed<T: Decodable>(_ type: T.Type, at path: String) throws -> LoadResult<T> {
        guard let sk = storeKey else { throw LocalStoreError.closed }
        guard let bytes = try writer.read(fileURL(path)) else { return .missing }
        let opened: (json: Data, generation: UInt64)
        do {
            opened = try LocalStore.open(sealed: bytes, storeKey: sk, path: path)
        } catch {
            return .rollback(nil)
        }
        let decoded: T? = try? KilitJSON.decoder().decode(T.self, from: opened.json)
        let recorded: UInt64 = index.generations[path] ?? 0
        if opened.generation < recorded { return .rollback(decoded) }
        guard let value = decoded else { return .corrupt }
        if opened.generation > recorded { index.generations[path] = opened.generation }
        return .ok(value)
    }

    /// nil when missing; throws `rollback`/`corrupt`. A higher generation than recorded is adopted.
    func load<T: Decodable>(_ type: T.Type, at path: String) throws -> T? {
        switch try loadDetailed(type, at: path) {
        case .missing: return nil
        case .ok(let v): return v
        case .rollback: throw LocalStoreError.rollback(path: path)
        case .corrupt: throw LocalStoreError.corrupt(path: path)
        }
    }

    /// Normative write order (§3.7): child documents first (each atomic, generation incremented), then
    /// `index.json` (which records the new child generations and the mutation), then the Keychain generation
    /// on the serial background queue (coalesced). After a child write succeeds its generation is recorded in
    /// memory even if a later write throws, so a retry never reuses a generation.
    func commit(_ writes: [DocumentWrite], mutateIndex: ((inout StoreIndex) -> Void)? = nil) throws {
        guard let sk = storeKey else { throw LocalStoreError.closed }
        for w in writes {
            let generation: UInt64 = (index.generations[w.path] ?? 0) + 1
            let sealed: Data = try LocalStore.seal(json: w.json, storeKey: sk, path: w.path, generation: generation)
            try writer.write(sealed, to: fileURL(w.path))
            index.generations[w.path] = generation
        }
        var next: StoreIndex = index
        if let m = mutateIndex { m(&next) }
        let generation: UInt64 = indexGeneration + 1
        let json: Data = try KilitJSON.encoder().encode(next)
        let sealed: Data = try LocalStore.seal(json: json, storeKey: sk, path: LocalStore.indexPath, generation: generation)
        try writer.write(sealed, to: fileURL(LocalStore.indexPath))
        index = next
        indexGeneration = generation
        scheduleGenerationWrite(generation)
    }

    func commitIndex(_ mutate: @escaping (inout StoreIndex) -> Void) throws {
        try commit([], mutateIndex: mutate)
    }

    func removeDocument(at path: String) throws {
        try writer.remove(fileURL(path))
    }

    // MARK: Keychain generation (step 3)

    private func scheduleGenerationWrite(_ generation: UInt64) {
        generationLock.lock()
        pendingGeneration = generation
        let schedule: Bool = !flushScheduled
        flushScheduled = true
        generationLock.unlock()
        if schedule {
            generationQueue.asyncAfter(deadline: .now() + generationCoalesceInterval) { [weak self] in
                self?.flushPendingGeneration()
            }
        }
    }

    private func flushPendingGeneration() {
        generationLock.lock()
        let pending: UInt64? = pendingGeneration
        pendingGeneration = nil
        flushScheduled = false
        generationLock.unlock()
        if let g = pending {
            // A Keychain write that fails after a successful index.json write is tolerated (§3.7).
            try? keychain.writeStoreGeneration(g)
        }
    }

    /// Synchronous flush (sceneDidEnterBackground, tests).
    func flushGeneration() {
        generationQueue.sync { [weak self] in
            self?.flushPendingGeneration()
        }
    }

    // MARK: reinstall marker and wipe (§5.3, §5.11)

    /// `installMarker` missing while Keychain identity items are present.
    func reinstallDetected() -> Bool {
        guard defaults.object(forKey: LocalStore.installMarkerKey) == nil else { return false }
        let identity: Data? = (try? keychain.read(KeychainAccount.identitySig)) ?? nil
        return identity != nil
    }

    func markInstalled() {
        defaults.set(true, forKey: LocalStore.installMarkerKey)
    }

    /// Removes every file, every Keychain item and the install marker; `cursor` resets with the index.
    func wipe() throws {
        close()
        try writer.remove(directory)
        try keychain.deleteAll()
        defaults.removeObject(forKey: LocalStore.installMarkerKey)
        generationLock.lock()
        pendingGeneration = nil
        generationLock.unlock()
    }

    // MARK: protected-data notifications (§5.3)

    /// Forwards `protectedDataWillBecomeUnavailable` (false) / `protectedDataDidBecomeAvailable` (true);
    /// the owner (`MessageSync`) calls `close()` / `open()` on its own executor.
    static func observeProtectedData(center: NotificationCenter = NotificationCenter.default,
                                     onChange: @escaping (Bool) -> Void) -> [NSObjectProtocol] {
        let gone: NSObjectProtocol = center.addObserver(forName: UIApplication.protectedDataWillBecomeUnavailableNotification,
                                                        object: nil, queue: nil) { _ in onChange(false) }
        let back: NSObjectProtocol = center.addObserver(forName: UIApplication.protectedDataDidBecomeAvailableNotification,
                                                        object: nil, queue: nil) { _ in onChange(true) }
        return [gone, back]
    }
}
