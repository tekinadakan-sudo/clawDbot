//  ProtectionBadge.swift
//  Kilit — UI/Chat (WP8), §5.2 / §10.2.
//
//  Toolbar badge: green "Karartma + algılama", amber "Yalnızca algılama" (the
//  canary failed or the secure layer is off), red "Ekran kaydediliyor"
//  (isSceneCaptured). Tapping shows the one-sentence explanation. Also the
//  capture banner and the opaque replacement shown while the screen is shared.

import SwiftUI

enum ProtectionState: Equatable {
    case green
    case amber
    case red

    static func current(isCaptured: Bool, isProtected: Bool) -> ProtectionState {
        if isCaptured { return .red }
        return isProtected ? .green : .amber
    }

    var color: Color {
        switch self {
        case .green: return .green
        case .amber: return .orange
        case .red: return .red
        }
    }

    var symbol: String {
        switch self {
        case .green: return "checkmark.shield.fill"
        case .amber: return "exclamationmark.shield.fill"
        case .red: return "record.circle.fill"
        }
    }

    var title: String {
        switch self {
        case .green:
            return String(localized: "badge.green.title", defaultValue: "Karartma + algılama")
        case .amber:
            return String(localized: "badge.amber.title", defaultValue: "Yalnızca algılama")
        case .red:
            return String(localized: "badge.red.title", defaultValue: "Ekran kaydediliyor")
        }
    }

    var explanation: String {
        switch self {
        case .green:
            return String(localized: "badge.green",
                          defaultValue: "Karartma + algılama — ekran görüntüsü ve kayıt karartılır, ayrıca algılanır.")
        case .amber:
            return String(localized: "badge.amber",
                          defaultValue: "Yalnızca algılama — bu cihazda karartma kullanılamıyor; ekran görüntüleri sonradan algılanır ve bildirilir.")
        case .red:
            return String(localized: "badge.red",
                          defaultValue: "Ekran paylaşılıyor — kayıt, AirPlay veya uzaktan kontrol etkin; içerik gizlendi.")
        }
    }
}

struct ProtectionBadge: View {
    let state: ProtectionState
    @State private var showingExplanation: Bool = false

    var body: some View {
        Button {
            showingExplanation = true
        } label: {
            Label(state.title, systemImage: state.symbol)
                .labelStyle(.iconOnly)
                .foregroundStyle(state.color)
        }
        .accessibilityLabel(state.title)
        .alert(state.title, isPresented: $showingExplanation) {
            Button(String(localized: "common.ok", defaultValue: "Tamam"), role: .cancel) {}
        } message: {
            Text(state.explanation)
        }
    }
}

/// Thin banner under the navigation bar while the badge is amber or red.
struct CaptureBanner: View {
    let state: ProtectionState

    var body: some View {
        if state != .green {
            HStack(spacing: 8) {
                Image(systemName: state.symbol)
                Text(state.explanation)
                    .font(.footnote)
            }
            .foregroundStyle(.primary)
            .padding(.horizontal, 12)
            .padding(.vertical, 6)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(state.color.opacity(0.18))
        }
    }
}

/// Opaque replacement for the message list while the scene is captured (§5.6).
struct CaptureHiddenView: View {
    var body: some View {
        ZStack {
            Rectangle().fill(.background)
            Label(String(localized: "capture.hidden", defaultValue: "Ekran paylaşımı sırasında içerik gizli"),
                  systemImage: "eye.slash")
                .font(.headline)
                .foregroundStyle(.secondary)
                .padding()
        }
    }
}

/// Mid-tone palette (§5.9): never pure black so the watermark has headroom.
enum KilitPalette {
    static let bubble: Color = Color(red: 0x4A / 255.0, green: 0x4A / 255.0, blue: 0x4F / 255.0)
    static let bubbleUI: UIColor = UIColor(red: 0x4A / 255.0, green: 0x4A / 255.0, blue: 0x4F / 255.0, alpha: 1)
    static let background: Color = Color(red: 0x2C / 255.0, green: 0x2C / 255.0, blue: 0x30 / 255.0)
    static let ownBubble: Color = Color(red: 0x3F / 255.0, green: 0x55 / 255.0, blue: 0x6E / 255.0)
}
