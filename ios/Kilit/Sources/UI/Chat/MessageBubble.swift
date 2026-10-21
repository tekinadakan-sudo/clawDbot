//  MessageBubble.swift
//  Kilit — UI/Chat (WP8), §5.7 / §5.6 / §10.3.
//
//  Content rows render an opaque pre-rendered placeholder (56 pt text bubble,
//  200×150 pt image panel, never sized by content) with the "görmek için
//  basılı tut" glyph; the real text is NOT in the view tree until the UIKit
//  press-hold reveals it (expansion without animation). System rows: timer,
//  capture (self / peer / gap), undecryptable, resync, key change. Own messages
//  use the same placeholder and gesture. No copy / share / drag / selection.

import SwiftUI

enum TimerOptions {
    /// off, 30 s, 5 m, 1 h, 24 h, 7 d (§5.8).
    static let all: [UInt32] = [0, 30, 300, 3600, 86_400, 604_800]

    static func label(_ seconds: UInt32) -> String {
        switch seconds {
        case 0: return String(localized: "timer.off", defaultValue: "Kapalı")
        case 30: return String(localized: "timer.30s", defaultValue: "30 saniye")
        case 300: return String(localized: "timer.5m", defaultValue: "5 dakika")
        case 3600: return String(localized: "timer.1h", defaultValue: "1 saat")
        case 86_400: return String(localized: "timer.24h", defaultValue: "24 saat")
        case 604_800: return String(localized: "timer.7d", defaultValue: "7 gün")
        default:
            let value: Int = Int(seconds)
            return String(localized: "timer.seconds", defaultValue: "\(value) saniye")
        }
    }
}

struct MessageRowView: View {
    let message: Message
    let peer: String
    let isGap: Bool
    let isDimmed: Bool
    let flickerEnabled: Bool
    let onOpenImage: (Message) -> Void
    let onDeleteForMe: (Message) -> Void
    let onDeleteForBoth: (Message) -> Void

    @Environment(RevealController.self) private var reveal: RevealController
    @Environment(AppModel.self) private var model: AppModel

    var body: some View {
        Group {
            switch message.kind {
            case .text, .image:
                contentRow
            case .timer:
                systemRow(timerText)
            case .capture:
                captureRow
            case .undecryptable:
                systemRow(String(localized: "undecryptable.row",
                                 defaultValue: "Bu mesaj çözülemedi (\(undecryptableReason))"))
            case .resync:
                systemRow(String(localized: "resync.row",
                                 defaultValue: "Oturum yenilendi; son mesajlar yeniden gönderildi"))
            case .keyChange:
                systemRow(String(localized: "keychange.row", defaultValue: "Güvenlik numarası değişti"))
            }
        }
        .listRowBackground(Color.clear)
        .listRowSeparator(.hidden)
    }

    // MARK: - Content

    private var isRevealed: Bool { reveal.isRevealed(message.id) }

    private var contentRow: some View {
        HStack {
            if message.author == .me { Spacer(minLength: 48) }
            VStack(alignment: message.author == .me ? .trailing : .leading, spacing: 4) {
                bubble
                metadata
            }
            if message.author == .peer { Spacer(minLength: 48) }
        }
        .opacity(isDimmed ? 0.45 : 1)
        .swipeActions(edge: .trailing, allowsFullSwipe: false) {
            Button(role: .destructive) {
                onDeleteForMe(message)
            } label: {
                Label(String(localized: "delete.me", defaultValue: "Benim için sil"), systemImage: "trash")
            }
            if message.author == .me {
                Button(role: .destructive) {
                    onDeleteForBoth(message)
                } label: {
                    Label(String(localized: "delete.both", defaultValue: "Benim için ve karşı taraf için sil"),
                          systemImage: "trash.slash")
                }
            }
        }
    }

    @ViewBuilder
    private var bubble: some View {
        let fill: Color = message.author == .me ? KilitPalette.ownBubble : KilitPalette.bubble
        if message.kind == .image && message.blobExpired {
            Text(String(localized: "attachment.expired", defaultValue: "Ek süresi doldu"))
                .font(.footnote)
                .foregroundStyle(.secondary)
                .frame(width: RevealMetrics.imagePlaceholderSize.width,
                       height: RevealMetrics.imagePlaceholderSize.height)
                .background(fill, in: RoundedRectangle(cornerRadius: 14))
        } else if message.kind == .image && !message.blobDownloaded {
            ProgressView()
                .frame(width: RevealMetrics.imagePlaceholderSize.width,
                       height: RevealMetrics.imagePlaceholderSize.height)
                .background(fill, in: RoundedRectangle(cornerRadius: 14))
        } else if isRevealed && message.kind == .text {
            Text(message.text ?? "")
                .padding(.horizontal, 12)
                .padding(.vertical, 8)
                .frame(minHeight: RevealMetrics.textPlaceholderHeight, alignment: .leading)
                .background(fill, in: RoundedRectangle(cornerRadius: 14))
                .overlay {
                    if flickerEnabled {
                        FlickerShield(enabled: true, maskColor: KilitPalette.bubbleUI) { reason in
                            model.flickerStopped(reason)
                        }
                        .allowsHitTesting(false)
                        .clipShape(RoundedRectangle(cornerRadius: 14))
                    }
                }
                .pressHold { handlePress($0) }
        } else {
            placeholder(fill: fill)
                .pressHold { handlePress($0) }
        }
    }

    private func placeholder(fill: Color) -> some View {
        let size: CGSize = message.kind == .image
            ? RevealMetrics.imagePlaceholderSize
            : CGSize(width: 180, height: RevealMetrics.textPlaceholderHeight)
        return HStack(spacing: 6) {
            Image(systemName: message.kind == .image ? "photo" : "hand.tap")
            Text(String(localized: "reveal.hint", defaultValue: "görmek için basılı tut"))
                .font(.caption)
        }
        .foregroundStyle(.secondary)
        .frame(width: size.width, height: size.height)
        .background(fill, in: RoundedRectangle(cornerRadius: 14))
        .accessibilityLabel(String(localized: "reveal.hint", defaultValue: "görmek için basılı tut"))
    }

    private func handlePress(_ pressing: Bool) {
        withTransaction(Transaction(animation: nil)) {
            if pressing {
                reveal.begin(id: message.id)
                if message.kind == .image { onOpenImage(message) }
            } else {
                reveal.end(id: message.id)
            }
        }
    }

    private var metadata: some View {
        HStack(spacing: 6) {
            Text(MessageRowView.time(message.ts))
            if message.author == .me {
                switch message.state {
                case .outbox:
                    Image(systemName: "clock")
                case .sent, .revealed, .received, .undecryptable:
                    if message.readByPeer {
                        Text(String(localized: "message.seen", defaultValue: "Görüldü"))
                    } else {
                        Image(systemName: "checkmark")
                    }
                }
            }
            if message.ttl > 0 {
                Image(systemName: "timer")
            }
        }
        .font(.caption2)
        .foregroundStyle(.secondary)
    }

    // MARK: - System rows

    private func systemRow(_ text: String) -> some View {
        Text(text)
            .font(.footnote)
            .foregroundStyle(.secondary)
            .multilineTextAlignment(.center)
            .frame(maxWidth: .infinity)
            .padding(.vertical, 4)
    }

    private var timerText: String {
        let seconds: UInt32 = message.timer ?? 0
        let who: String = message.author == .me
            ? String(localized: "timer.who.me", defaultValue: "Sen")
            : peer
        if seconds == 0 {
            return String(localized: "timer.row.off", defaultValue: "\(who) kaybolan mesajları kapattı")
        }
        let label: String = TimerOptions.label(seconds)
        return String(localized: "timer.row.set", defaultValue: "\(who) kaybolan mesaj süresini \(label) olarak ayarladı")
    }

    private var undecryptableReason: String {
        if case .undecryptable(let reason) = message.state { return reason }
        return "?"
    }

    @ViewBuilder
    private var captureRow: some View {
        if let event = message.capture {
            if let kind = CaptureGlue.wireKind(event.kind) {
                VStack(spacing: 2) {
                    if isGap {
                        systemRow(String(localized: "capture.gap", defaultValue: "Bildirilmeyen olay"))
                    }
                    systemRow(captureText(kind: kind, event: event))
                }
            } else {
                Color.clear
                    .frame(height: 0)
                    .onAppear { model.diagnostics.noteUnknownCaptureKind(event.kind) }
            }
        } else {
            EmptyView()
        }
    }

    private func captureText(kind: CaptureEventKind, event: CaptureEvent) -> String {
        let count: Int = Int(event.count ?? 1)
        if message.author == .me {
            switch kind {
            case .screenshot:
                return String(localized: "capture.self.screenshot", defaultValue: "Sen ekran görüntüsü aldın")
            case .recordingStarted:
                return String(localized: "capture.self.recording_started", defaultValue: "Ekran paylaşımını başlattın")
            case .recordingStopped:
                return String(localized: "capture.self.recording_stopped", defaultValue: "Ekran paylaşımını durdurdun")
            case .blankingUnavailable:
                return String(localized: "capture.self.blanking_unavailable",
                              defaultValue: "Bu cihaz ekran görüntüsünü karartamıyor")
            }
        }
        switch kind {
        case .screenshot:
            return String(localized: "capture.peer.screenshot", defaultValue: "\(peer) ekran görüntüsü aldı (\(count))")
        case .recordingStarted:
            return String(localized: "capture.peer.recording_started", defaultValue: "\(peer) ekran paylaşımını başlattı")
        case .recordingStopped:
            return String(localized: "capture.peer.recording_stopped", defaultValue: "\(peer) ekran paylaşımını durdurdu")
        case .blankingUnavailable:
            return String(localized: "capture.peer.blanking_unavailable",
                          defaultValue: "\(peer)'nin cihazı ekran görüntüsünü karartamıyor")
        }
    }

    static func time(_ unix: UInt64) -> String {
        let formatter: DateFormatter = DateFormatter()
        formatter.timeStyle = .short
        formatter.dateStyle = .none
        return formatter.string(from: Date(timeIntervalSince1970: TimeInterval(unix)))
    }
}
