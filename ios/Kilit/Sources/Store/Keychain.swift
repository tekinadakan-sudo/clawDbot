import Foundation
import Security

// MARK: - Keychain accounts (§5.3)

/// Generic-password accounts under service `com.kilit.keys`.
enum KeychainAccount {
    static let service: String = "com.kilit.keys"
    static let identitySig: String = "identity.ed25519.v1"
    static let identityDh: String = "identity.x25519.v1"
    static let masterKey: String = "store.master.v1"
    static let token: String = "auth.token.v1"
    static let deviceId: String = "device.id.v1"
    static let storeGeneration: String = "store.generation"
    static let all: [String] = [identitySig, identityDh, masterKey, token, deviceId, storeGeneration]
}

enum KeychainError: Error, Equatable {
    case status(OSStatus)
}

/// The subset of SecItem the store needs; `Keychain` is the device implementation, `InMemoryKeychain` the
/// test double (no entitlement, no passcode requirement).
protocol KeychainStore: AnyObject {
    /// nil when the item does not exist.
    func read(_ account: String) throws -> Data?
    /// Adds or replaces.
    func write(_ account: String, _ data: Data) throws
    /// Missing items are not an error.
    func delete(_ account: String) throws
    func deleteAll() throws
}

// MARK: - Device keychain

/// `kSecClassGenericPassword` items with `kSecUseDataProtectionKeychain = true`,
/// `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` (`WhenUnlockedThisDeviceOnly` on the Simulator), every
/// SecItem call on one serial background queue (they block the calling thread).
final class Keychain: KeychainStore {
    private let service: String
    private let queue: DispatchQueue

    init(service: String = KeychainAccount.service) {
        self.service = service
        self.queue = DispatchQueue(label: "com.kilit.keychain", qos: .userInitiated)
    }

    private static var accessible: CFString {
        #if targetEnvironment(simulator)
        return kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        #else
        return kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
        #endif
    }

    private func baseQuery(_ account: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecUseDataProtectionKeychain as String: true,
        ]
    }

    func read(_ account: String) throws -> Data? {
        try queue.sync { () throws -> Data? in
            var query: [String: Any] = baseQuery(account)
            query[kSecMatchLimit as String] = kSecMatchLimitOne
            query[kSecReturnData as String] = true
            var item: CFTypeRef?
            let status: OSStatus = SecItemCopyMatching(query as CFDictionary, &item)
            switch status {
            case errSecSuccess:
                return item as? Data
            case errSecItemNotFound:
                return nil
            default:
                throw KeychainError.status(status)
            }
        }
    }

    func write(_ account: String, _ data: Data) throws {
        try queue.sync { () throws -> Void in
            var add: [String: Any] = baseQuery(account)
            add[kSecAttrAccessible as String] = Keychain.accessible
            add[kSecValueData as String] = data
            var status: OSStatus = SecItemAdd(add as CFDictionary, nil)
            if status == errSecDuplicateItem {
                let update: [String: Any] = [kSecValueData as String: data]
                status = SecItemUpdate(baseQuery(account) as CFDictionary, update as CFDictionary)
            }
            guard status == errSecSuccess else { throw KeychainError.status(status) }
        }
    }

    func delete(_ account: String) throws {
        try queue.sync { () throws -> Void in
            let status: OSStatus = SecItemDelete(baseQuery(account) as CFDictionary)
            guard status == errSecSuccess || status == errSecItemNotFound else { throw KeychainError.status(status) }
        }
    }

    func deleteAll() throws {
        for account in KeychainAccount.all {
            try delete(account)
        }
    }
}

// MARK: - Test double

final class InMemoryKeychain: KeychainStore {
    private var items: [String: Data] = [:]
    private let lock: NSLock = NSLock()
    /// When set, every write throws (simulates a failing Keychain after a successful `index.json` write).
    var failWrites: Bool = false
    private(set) var writeCount: Int = 0

    init() {}

    func read(_ account: String) throws -> Data? {
        lock.lock()
        defer { lock.unlock() }
        return items[account]
    }

    func write(_ account: String, _ data: Data) throws {
        lock.lock()
        defer { lock.unlock() }
        if failWrites { throw KeychainError.status(errSecInteractionNotAllowed) }
        writeCount += 1
        items[account] = data
    }

    func delete(_ account: String) throws {
        lock.lock()
        defer { lock.unlock() }
        items.removeValue(forKey: account)
    }

    func deleteAll() throws {
        lock.lock()
        defer { lock.unlock() }
        items.removeAll()
    }
}

// MARK: - Typed helpers

extension KeychainStore {
    /// `store.generation`: the generation of `index.json` as 8 big-endian bytes (0 when absent).
    func readStoreGeneration() throws -> UInt64 {
        guard let d = try read(KeychainAccount.storeGeneration), d.count == 8 else { return 0 }
        var v: UInt64 = 0
        for b in d {
            v = v << 8 | UInt64(b)
        }
        return v
    }

    func writeStoreGeneration(_ generation: UInt64) throws {
        try write(KeychainAccount.storeGeneration, BE.u64(generation))
    }

    func readString(_ account: String) throws -> String? {
        guard let d = try read(account) else { return nil }
        return String(decoding: d, as: UTF8.self)
    }

    func writeString(_ account: String, _ value: String) throws {
        try write(account, Data(value.utf8))
    }

    /// The identity keys stored under `identity.ed25519.v1` / `identity.x25519.v1`, nil when either is absent.
    func readIdentity() throws -> IdentityKeys? {
        guard let seed = try read(KeychainAccount.identitySig), let dh = try read(KeychainAccount.identityDh) else {
            return nil
        }
        return try IdentityKeys(sigSeed: seed, dhPriv: dh)
    }

    func writeIdentity(_ keys: IdentityKeys) throws {
        try write(KeychainAccount.identitySig, keys.sigSeed)
        try write(KeychainAccount.identityDh, keys.dhPriv)
    }
}
