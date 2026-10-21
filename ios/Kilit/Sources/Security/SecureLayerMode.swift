//  SecureLayerMode.swift
//  Kilit — Security/ (WP6). `Settings` (Store/) persists `rawValue`; WP8 passes the
//  enum into `SecureContainer(mode:enabled:…)`, so Security/ never imports Store/.

import Foundation

enum SecureLayerMode: String, Codable, CaseIterable, Equatable {
    /// Hosted content is placed inside the UITextField secure canvas (§5.5, default).
    case canvas
    /// Signal/Telegram layer swap on a throwaway UITextField (`CaptureShield`, §5.5).
    case layerSwap
}
