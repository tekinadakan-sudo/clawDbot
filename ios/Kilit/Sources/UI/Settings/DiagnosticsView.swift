//  DiagnosticsView.swift
//  Kilit — UI/Settings (WP8), §5.1 / §5.9.
//
//  Secure canvas availability + mode, panel Hz, measured Hz, capture state,
//  connection, OPK count, the offline tile self-check, the capture log, the
//  undecryptable log and every `wm_secret` in hex (smallest `sid` first) for
//  `wmdecode -ws`. Nothing here is copyable through a share sheet; values are
//  plain text for the owner to read off the screen.

import SwiftUI

struct DiagnosticsView: View {
    @Environment(AppModel.self) private var model: AppModel

    private var d: Diagnostics { model.diagnostics }

    var body: some View {
        List {
            Section(String(localized: "diagnostics.state", defaultValue: "Durum")) {
                LabeledContent(String(localized: "diagnostics.canvas", defaultValue: "Güvenli tuval"),
                               value: d.secureCanvasAvailable ? "✓" : "✗")
                LabeledContent(String(localized: "settings.secure_mode", defaultValue: "Karartma yöntemi"),
                               value: d.secureLayerMode.rawValue + (d.secureLayerEnabled ? "" : " (off)"))
                LabeledContent(String(localized: "diagnostics.panel_hz", defaultValue: "Panel Hz"), value: String(d.panelHz))
                LabeledContent(String(localized: "diagnostics.measured_hz", defaultValue: "Ölçülen Hz"),
                               value: String(Int(d.measuredHz.rounded())))
                if let reason = d.flickerStopReason {
                    LabeledContent(String(localized: "diagnostics.flicker_stop", defaultValue: "Titreşim durma nedeni"), value: reason)
                }
                LabeledContent(String(localized: "diagnostics.captured", defaultValue: "Ekran yakalanıyor"),
                               value: d.isCaptured ? "✓" : "✗")
                LabeledContent(String(localized: "diagnostics.connection", defaultValue: "Bağlantı"), value: connectionText)
                LabeledContent(String(localized: "diagnostics.opk", defaultValue: "Sunucudaki OPK sayısı"),
                               value: d.opkCount.map { String($0) } ?? "–")
                if !d.unknownCaptureKinds.isEmpty {
                    LabeledContent(String(localized: "diagnostics.unknown_kinds", defaultValue: "Bilinmeyen olay türleri"),
                                   value: d.unknownCaptureKinds.joined(separator: ", "))
                }
            }
            Section(String(localized: "diagnostics.watermark", defaultValue: "Filigran")) {
                Button(String(localized: "diagnostics.tile_check", defaultValue: "Desen öz denetimini çalıştır")) {
                    d.tileSelfCheckPassed = Diagnostics.tileSelfCheck(cache: model.tileCache)
                }
                if let passed = d.tileSelfCheckPassed {
                    LabeledContent(String(localized: "diagnostics.tile_result", defaultValue: "Öz denetim"),
                                   value: passed ? "✓" : "✗")
                }
                if d.wmSecrets.isEmpty {
                    Text(String(localized: "diagnostics.no_secrets", defaultValue: "Henüz oturum yok"))
                        .foregroundStyle(.secondary)
                }
                ForEach(d.wmSecrets) { row in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(row.peer).font(.footnote.bold())
                        Text("sid " + row.sidHex).font(.system(.caption2, design: .monospaced))
                        Text("ws " + row.wsHex).font(.system(.caption2, design: .monospaced))
                    }
                }
            }
            Section(String(localized: "diagnostics.capture_log", defaultValue: "Yakalama günlüğü")) {
                if d.captureLog.isEmpty {
                    Text(String(localized: "capture.none", defaultValue: "Bildirilen ekran görüntüsü yok"))
                        .foregroundStyle(.secondary)
                }
                ForEach(Array(d.captureLog.enumerated()), id: \.offset) { pair in
                    let e: CaptureEvent = pair.element
                    HStack {
                        Text(e.peer).font(.footnote)
                        Spacer()
                        Text(e.kind + (e.seq.map { " #\($0)" } ?? ""))
                            .font(.system(.caption, design: .monospaced))
                        Text(DiagnosticsView.time(e.ts)).font(.caption).foregroundStyle(.secondary)
                    }
                }
            }
            Section(String(localized: "diagnostics.undecryptable_log", defaultValue: "Çözülemeyen mesajlar")) {
                if d.undecryptableLog.isEmpty {
                    Text(String(localized: "diagnostics.none", defaultValue: "Yok")).foregroundStyle(.secondary)
                }
                ForEach(Array(d.undecryptableLog.enumerated()), id: \.offset) { pair in
                    let e: UndecryptableEntry = pair.element
                    VStack(alignment: .leading, spacing: 2) {
                        HStack {
                            Text(e.peer).font(.footnote)
                            Spacer()
                            Text(e.reason).font(.system(.caption, design: .monospaced))
                            Text(DiagnosticsView.time(e.at)).font(.caption).foregroundStyle(.secondary)
                        }
                        Text(e.msgId).font(.system(.caption2, design: .monospaced)).foregroundStyle(.secondary)
                    }
                }
            }
        }
        .navigationTitle(String(localized: "diagnostics.title", defaultValue: "Tanılama"))
        .task {
            await model.refresh()
        }
    }

    private var connectionText: String {
        switch d.connection {
        case .stopped: return String(localized: "connection.stopped", defaultValue: "Durduruldu")
        case .connecting: return String(localized: "connection.connecting", defaultValue: "Bağlanıyor")
        case .live: return String(localized: "connection.live", defaultValue: "Bağlı")
        case .down(let attempt):
            return String(localized: "connection.down.attempt", defaultValue: "Bağlantı yok (deneme \(attempt))")
        }
    }

    static func time(_ unix: UInt64) -> String {
        let formatter: DateFormatter = DateFormatter()
        formatter.dateStyle = .short
        formatter.timeStyle = .short
        return formatter.string(from: Date(timeIntervalSince1970: TimeInterval(unix)))
    }
}
