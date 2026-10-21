import Foundation
import CryptoKit

/// Protocol-level errors (DESIGN.md §3.9 lists the case names; the vector files use them verbatim).
enum KilitCryptoError: Error, Equatable {
    /// A DH output was all zero (low-order peer point).
    case lowOrderPoint
    /// A key or ratchet public key is not exactly 32 bytes.
    case badKeyLength
    /// An Ed25519 public key failed import or is a small-order encoding.
    case badPublicKey
    /// A signature failed the strict pre-checks or the library verify.
    case badSignature
    /// Identity keys differ from the contact record / lookup result.
    case identityMismatch
    /// `ek` already seen and no session with `sid(ek)` exists.
    case replay
    /// Bundle SPK older than 21 days.
    case staleSPK
    /// `Nr + MAX_SKIP < until`.
    case tooManySkipped
    /// Header not 41 bytes or version byte != 0x01.
    case badHeader
    /// ISO/IEC 7816-4 unpadding failed.
    case badPadding
    /// Inner JSON larger than 40 960 bytes before padding.
    case sizeLimit
    /// No session with the given sid.
    case unknownSession

    /// The vector-file spelling of the case.
    var vectorName: String {
        switch self {
        case .lowOrderPoint: return "lowOrderPoint"
        case .badKeyLength: return "badKeyLength"
        case .badPublicKey: return "badPublicKey"
        case .badSignature: return "badSignature"
        case .identityMismatch: return "identityMismatch"
        case .replay: return "replay"
        case .staleSPK: return "staleSPK"
        case .tooManySkipped: return "tooManySkipped"
        case .badHeader: return "badHeader"
        case .badPadding: return "badPadding"
        case .sizeLimit: return "sizeLimit"
        case .unknownSession: return "unknownSession"
        }
    }
}

/// Maps any error thrown by this module to the string spelling used by the vector files
/// (`KilitCryptoError` cases, CryptoKit cases `authenticationFailure`, `incorrectKeySize`,
/// `incorrectParameterSize`, and `rollback` for the store error).
enum KilitErrorName {
    static func of(_ error: Error) -> String {
        if let e = error as? KilitCryptoError {
            return e.vectorName
        }
        if let e = error as? CryptoKitError {
            switch e {
            case .authenticationFailure: return "authenticationFailure"
            case .incorrectKeySize: return "incorrectKeySize"
            case .incorrectParameterSize: return "incorrectParameterSize"
            default: return "cryptoKit"
            }
        }
        if let e = error as? EnvelopeError {
            switch e {
            case .badEnvelope: return "bad_envelope"
            }
        }
        return "unknown"
    }
}
