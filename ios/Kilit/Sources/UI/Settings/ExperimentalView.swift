//  ExperimentalView.swift
//  Kilit — UI/Settings (WP8), §5.10 / §10.5.
//
//  Settings › Deneysel: the flicker toggle, disabled with a reason on
//  ineligible devices; enabling presents `PhotosensitivityWarningSheet` every
//  time; a persistent "Titreşim açık" pill while on; stop reasons surface as a
//  toast through `AppModel.flickerStopped`.

import MediaAccessibility
import SwiftUI
import UIKit

enum FlickerReasons {
    static let needs120: String = String(localized: "flicker.reason.120hz", defaultValue: "120 Hz ekran gerekir")
    static let reduceMotion: String = String(localized: "flicker.reason.reduce_motion", defaultValue: "Hareketi Azalt açık")
    static let dimFlashing: String = String(localized: "flicker.reason.dim_flashing", defaultValue: "Yanıp Sönen Işıkları Kıs açık")
    static let lowPower: String = String(localized: "flicker.reason.low_power", defaultValue: "Düşük Güç Modu açık")
    static let pill: String = String(localized: "flicker.pill", defaultValue: "Titreşim açık")

    /// The first ineligibility reason for this device/settings state, or nil.
    @MainActor
    static func ineligibility(panelHz: Int) -> String? {
        if panelHz < 120 { return needs120 }
        if UIAccessibility.isReduceMotionEnabled { return reduceMotion }
        if MADimFlashingLightsEnabled() { return dimFlashing }
        if ProcessInfo.processInfo.isLowPowerModeEnabled { return lowPower }
        return nil
    }

    /// Toast text for a stop reason; nil when nothing should be shown.
    @MainActor
    static func text(_ reason: FlickerMaskView.StopReason) -> String? {
        switch reason {
        case .rateTooLow(let hz):
            let value: Int = Int(hz.rounded())
            return String(localized: "flicker.stop.rate", defaultValue: "Titreşim durdu: ölçülen hız \(value) Hz")
        case .accessibilitySetting:
            return UIAccessibility.isReduceMotionEnabled ? reduceMotion : dimFlashing
        case .lowPowerMode:
            return lowPower
        case .thermal:
            return String(localized: "flicker.stop.thermal", defaultValue: "Titreşim durdu: cihaz ısındı")
        case .captured:
            return String(localized: "flicker.stop.captured", defaultValue: "Titreşim durdu: ekran paylaşılıyor")
        case .notActive, .hostRequest:
            return nil
        }
    }
}

struct ExperimentalView: View {
    @Environment(AppModel.self) private var model: AppModel
    @State private var showingWarning: Bool = false

    private var ineligible: String? {
        FlickerReasons.ineligibility(panelHz: model.diagnostics.panelHz)
    }

    var body: some View {
        List {
            Section {
                Toggle(isOn: Binding(
                    get: { model.settings.flicker },
                    set: { on in
                        if on {
                            showingWarning = true
                        } else {
                            apply(false)
                        }
                    })) {
                    VStack(alignment: .leading, spacing: 4) {
                        Text(String(localized: "experimental.flicker", defaultValue: "Titreşim Kalkanı"))
                        if let reason = ineligible {
                            Text(reason)
                                .font(.footnote)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
                .disabled(ineligible != nil && !model.settings.flicker)
                if model.settings.flicker {
                    FlickerPill()
                }
            } footer: {
                Text(String(localized: "experimental.footer",
                            defaultValue: "Yalnızca basılı tutarak gösterilen metin balonunun üzerinde çalışır; fotoğraflarda ve tam ekranda asla. Her açışta fotosensitivite uyarısı gösterilir."))
            }
        }
        .navigationTitle(String(localized: "experimental.title", defaultValue: "Deneysel"))
        .sheet(isPresented: $showingWarning) {
            PhotosensitivityWarningSheet(
                onKeepOff: { showingWarning = false },
                onTurnOn: {
                    showingWarning = false
                    apply(true)
                })
        }
    }

    private func apply(_ on: Bool) {
        var s: Settings = model.settings
        s.flicker = on
        Task { await model.updateSettings(s) }
    }
}

/// Persistent status pill while flicker is enabled.
struct FlickerPill: View {
    var body: some View {
        Label(FlickerReasons.pill, systemImage: "bolt.fill")
            .font(.caption.bold())
            .padding(.horizontal, 10)
            .padding(.vertical, 4)
            .background(Color.orange.opacity(0.25), in: Capsule())
    }
}
