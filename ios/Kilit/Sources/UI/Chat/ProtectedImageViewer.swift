//  ProtectedImageViewer.swift
//  Kilit — UI/Chat (WP8), §3.5b / §5.5 / §5.7 / §5.9.
//
//  fullScreenCover: the second (and last) `SecureContainer` hosts a
//  `CaptureProtectedImageView` (AVSampleBufferDisplayLayer.preventsCapture) with
//  the two watermark CALayers above it. The display layer is never masked: an
//  opaque mid-tone panel (`#3A3A3E`) is drawn ON TOP as a SwiftUI overlay with a
//  rectangular cut-out of `max(120 pt, height / 4)` centred on the finger,
//  `ZStack { panel; band.blendMode(.destinationOut) }.compositingGroup()`.
//  When `isSceneCaptured` flips true the view is cleared and the cover dismissed.
//  Decrypt path: owned buffer → CFData (no copy) → CGImageSource (no cache) →
//  thumbnail CGImage → the buffer is scrubbed immediately after decoding.

import CoreGraphics
import ImageIO
import SwiftUI
import UIKit

struct ProtectedImageViewer: View {
    let message: Message
    let peer: String

    @Environment(AppModel.self) private var model: AppModel
    @Environment(\.dismiss) private var dismiss: DismissAction
    @Environment(\.isSceneCaptured) private var isSceneCaptured: Bool
    @Environment(\.displayScale) private var displayScale: CGFloat

    @State private var image: CGImage? = nil
    @State private var failure: String? = nil
    /// Finger position (band centre) while dragging; nil = fully covered.
    @State private var fingerY: CGFloat? = nil

    private var aspect: CGFloat {
        guard let att = message.att, att.w > 0, att.h > 0 else { return 4.0 / 3.0 }
        return CGFloat(att.w) / CGFloat(att.h)
    }

    var body: some View {
        ZStack {
            Color(uiColor: CaptureProtectedImageView.letterbox).ignoresSafeArea()
            SecureContainer(mode: model.secureLayerMode,
                            enabled: model.settings.secureLayer,
                            hidesFromAssistiveTechnologies: model.settings.accessibilityHide) {
                GeometryReader { proxy in
                    ZStack {
                        ProtectedImageHost(image: image,
                                           tiles: model.watermarkTiles(peer: peer, displayScale: displayScale),
                                           phase: model.watermarkPhase)
                            .aspectRatio(aspect, contentMode: .fit)
                            .frame(maxWidth: .infinity, maxHeight: .infinity)
                        bandPanel(height: proxy.size.height)
                    }
                    .frame(width: proxy.size.width, height: proxy.size.height)
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .ignoresSafeArea()
            VStack {
                HStack {
                    Spacer()
                    Button {
                        close()
                    } label: {
                        Image(systemName: "xmark.circle.fill")
                            .font(.title)
                            .foregroundStyle(.white.opacity(0.8))
                            .padding()
                    }
                    .accessibilityLabel(String(localized: "common.close", defaultValue: "Kapat"))
                }
                Spacer()
                if let failure {
                    Text(failure)
                        .font(.footnote)
                        .foregroundStyle(.white)
                        .padding()
                } else {
                    Text(String(localized: "viewer.hint", defaultValue: "görmek için parmağını ekranda gezdir"))
                        .font(.footnote)
                        .foregroundStyle(.white.opacity(0.7))
                        .padding()
                }
            }
        }
        .task {
            await load()
        }
        .onChange(of: isSceneCaptured) { _, captured in
            if captured { close() }
        }
        .onDisappear {
            image = nil
            model.reveal.end(id: message.id)
        }
    }

    // MARK: - Band reveal (§5.7)

    private func bandPanel(height: CGFloat) -> some View {
        let band: CGFloat = RevealMetrics.revealBandHeight(forViewerHeight: height)
        return ZStack(alignment: .top) {
            Rectangle().fill(Color(uiColor: CaptureProtectedImageView.letterbox))
            if let y = fingerY {
                Rectangle()
                    .frame(height: band)
                    .offset(y: y - band / 2)
                    .blendMode(.destinationOut)
            }
        }
        .compositingGroup()
        .contentShape(Rectangle())
        .gesture(
            DragGesture(minimumDistance: 0)
                .onChanged { value in fingerY = value.location.y }
                .onEnded { _ in fingerY = nil }
        )
        .accessibilityHidden(true)
    }

    // MARK: - Loading

    private func load() async {
        guard let sync = model.sync else { return }
        do {
            let buffer: OwnedPlaintextBuffer = try await sync.openAttachment(peer: peer, messageId: message.id)
            let decoded: CGImage? = ProtectedImageViewer.decode(buffer)
            buffer.clear()
            guard let decoded else {
                failure = String(localized: "attachment.expired", defaultValue: "Ek süresi doldu")
                return
            }
            image = decoded
        } catch {
            failure = String(localized: "attachment.expired", defaultValue: "Ek süresi doldu")
        }
    }

    /// §3.5b: no-copy CFData → CGImageSource (no cache) → thumbnail (≤ 2048 px, transform applied).
    static func decode(_ buffer: OwnedPlaintextBuffer) -> CGImage? {
        buffer.withBytes { (raw: UnsafeRawBufferPointer) -> CGImage? in
            guard let base = raw.baseAddress, raw.count > 0 else { return nil }
            let pointer: UnsafePointer<UInt8> = base.assumingMemoryBound(to: UInt8.self)
            guard let data = CFDataCreateWithBytesNoCopy(kCFAllocatorDefault, pointer, raw.count, kCFAllocatorNull) else {
                return nil
            }
            let sourceOptions: [CFString: Any] = [kCGImageSourceShouldCache: false]
            guard let source = CGImageSourceCreateWithData(data, sourceOptions as CFDictionary) else { return nil }
            let thumbOptions: [CFString: Any] = [
                kCGImageSourceCreateThumbnailFromImageAlways: true,
                kCGImageSourceCreateThumbnailWithTransform: true,
                kCGImageSourceThumbnailMaxPixelSize: 2048,
                kCGImageSourceShouldCache: false,
            ]
            return CGImageSourceCreateThumbnailAtIndex(source, 0, thumbOptions as CFDictionary)
        }
    }

    private func close() {
        image = nil
        dismiss()
    }
}

/// Hosts `CaptureProtectedImageView`; `clear()` runs on a nil image and on dismantle.
struct ProtectedImageHost: UIViewRepresentable {
    let image: CGImage?
    let tiles: (lighter: CGImage, darker: CGImage)?
    let phase: CGPoint

    func makeUIView(context: Context) -> CaptureProtectedImageView {
        let view: CaptureProtectedImageView = CaptureProtectedImageView(frame: .zero)
        if let tiles {
            view.setWatermark(WatermarkLayers(lighter: tiles.lighter, darker: tiles.darker, phase: phase))
        }
        return view
    }

    func updateUIView(_ uiView: CaptureProtectedImageView, context: Context) {
        if let image {
            if context.coordinator.displayed !== image {
                context.coordinator.displayed = image
                do {
                    try uiView.display(image)
                } catch {
                    uiView.clear()
                }
            }
        } else if context.coordinator.displayed != nil {
            context.coordinator.displayed = nil
            uiView.clear()
        }
    }

    static func dismantleUIView(_ uiView: CaptureProtectedImageView, coordinator: Coordinator) {
        uiView.clear()
    }

    func makeCoordinator() -> Coordinator {
        Coordinator()
    }

    final class Coordinator {
        var displayed: CGImage? = nil
        init() {}
    }
}
