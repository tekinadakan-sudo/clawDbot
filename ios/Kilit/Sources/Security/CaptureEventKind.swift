//  CaptureEventKind.swift
//  Kilit — Security/ (WP6). Self-contained: no Crypto/, Store/ or Net/ dependency.
//
//  The raw values are exactly the §3.4 wire spellings carried as a plain `String`
//  by `Crypto/Envelope.swift` and `Store/Models.swift`; `App/CaptureGlue.swift`
//  is the only place that converts with `rawValue` / `init(rawValue:)`.

import Foundation

enum CaptureEventKind: String, Codable, CaseIterable, Equatable {
    case screenshot = "screenshot"
    case recordingStarted = "recording_started"
    case recordingStopped = "recording_stopped"
    case blankingUnavailable = "blanking_unavailable"

    /// `blanking_unavailable` carries no per-conversation counter (§3.4); the other
    /// three events each consume one `seq` in `CaptureGlue`.
    var consumesSequenceNumber: Bool {
        switch self {
        case .screenshot, .recordingStarted, .recordingStopped:
            return true
        case .blankingUnavailable:
            return false
        }
    }
}
