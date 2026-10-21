//  CaptureProtectedImageView.swift
//  Kilit — Security/ (WP6), §3.5b / §5.5.
//
//  Shows a decrypted CGImage through an `AVSampleBufferDisplayLayer` with
//  `preventsCapture = true` (public API). `display(_:)` is exactly the §3.5b
//  sequence: CVPixelBufferCreate (BGRA) → CMVideoFormatDescriptionCreateForImageBuffer
//  → CMSampleTimingInfo → CMSampleBufferCreateReadyWithImageBuffer →
//  kCMSampleAttachmentKey_DisplayImmediately → renderer.flush() → renderer.enqueue().
//  `clear()` is the §3.5b dismissal order with a `memset_s` scrub of the pixel
//  buffer and of the owned decrypt buffer handed over by the caller.
//  Two watermark CALayers (`WatermarkLayers`) sit above the display layer.

import AVFoundation
import CoreGraphics
import CoreMedia
import CoreVideo
import ImageIO
import UIKit

final class CaptureProtectedImageView: UIView {

    enum DisplayError: Error, Equatable {
        case pixelBuffer
        case context
        case formatDescription
        case sampleBuffer
    }

    /// Viewer letterbox colour (§5.9: mid-tone `#3A3A3E`, never pure black).
    static let letterbox: UIColor = UIColor(red: 0x3A / 255.0, green: 0x3A / 255.0,
                                            blue: 0x3E / 255.0, alpha: 1)

    override class var layerClass: AnyClass { AVSampleBufferDisplayLayer.self }

    // The backing layer is created from `layerClass`, so this cast cannot fail.
    private var displayLayer: AVSampleBufferDisplayLayer { layer as! AVSampleBufferDisplayLayer }

    private var pixelBuffer: CVPixelBuffer?
    private var sampleBuffer: CMSampleBuffer?
    private var image: CGImage?
    private var imageSource: CGImageSource?
    private var decryptBuffer: UnsafeMutableRawBufferPointer?
    private var watermark: WatermarkLayers?

    override init(frame: CGRect) {
        super.init(frame: frame)
        displayLayer.preventsCapture = true
        displayLayer.videoGravity = .resizeAspect
        displayLayer.masksToBounds = true
        backgroundColor = CaptureProtectedImageView.letterbox
        isOpaque = true
        isAccessibilityElement = false
        accessibilityElementsHidden = true
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        return nil
    }

    deinit {
        // Belt and braces when the owner forgot `clear()`; only stored properties
        // and a nonisolated helper are touched here.
        CaptureProtectedImageView.scrub(pixelBuffer: pixelBuffer, decryptBuffer: decryptBuffer)
    }

    // MARK: - Display

    /// Enqueues `image` as one display-immediately frame. The optional `source`
    /// and `decryptBuffer` are retained until `clear()`, which releases the source
    /// and scrubs + deallocates the buffer (§3.5b dismissal order).
    func display(_ image: CGImage,
                 source: CGImageSource? = nil,
                 decryptBuffer: UnsafeMutableRawBufferPointer? = nil) throws {
        clear()
        self.image = image
        self.imageSource = source
        self.decryptBuffer = decryptBuffer

        // (1) BGRA pixel buffer with the CGImage drawn into it.
        let pb: CVPixelBuffer = try CaptureProtectedImageView.makePixelBuffer(from: image)

        // (2) Format description for the image buffer.
        var fd: CMVideoFormatDescription?
        let fdStatus: OSStatus = CMVideoFormatDescriptionCreateForImageBuffer(
            allocator: kCFAllocatorDefault,
            imageBuffer: pb,
            formatDescriptionOut: &fd)
        guard fdStatus == noErr, let formatDescription = fd else {
            throw DisplayError.formatDescription
        }

        // (3) Ready sample buffer with a zero presentation time.
        var timing: CMSampleTimingInfo = CMSampleTimingInfo(
            duration: .invalid, presentationTimeStamp: .zero, decodeTimeStamp: .invalid)
        var sb: CMSampleBuffer?
        let sbStatus: OSStatus = CMSampleBufferCreateReadyWithImageBuffer(
            allocator: kCFAllocatorDefault,
            imageBuffer: pb,
            formatDescription: formatDescription,
            sampleTiming: &timing,
            sampleBufferOut: &sb)
        guard sbStatus == noErr, let sample = sb else {
            throw DisplayError.sampleBuffer
        }

        // (4) Display immediately: without a control timebase the layer interprets
        //     presentation timestamps against the host clock.
        if let attachments = CMSampleBufferGetSampleAttachmentsArray(sample, createIfNecessary: true),
           CFArrayGetCount(attachments) > 0 {
            let first: CFMutableDictionary = unsafeBitCast(
                CFArrayGetValueAtIndex(attachments, 0), to: CFMutableDictionary.self)
            CFDictionarySetValue(
                first,
                Unmanaged.passUnretained(kCMSampleAttachmentKey_DisplayImmediately).toOpaque(),
                Unmanaged.passUnretained(kCFBooleanTrue).toOpaque())
        }

        // (5) Flush, then enqueue through the iOS 17 renderer.
        let renderer: AVSampleBufferVideoRenderer = displayLayer.sampleBufferRenderer
        renderer.flush()
        renderer.enqueue(sample)

        pixelBuffer = pb
        sampleBuffer = sample
    }

    /// §3.5b dismissal order: flush → release sample buffer, image and source →
    /// scrub the pixel buffer → scrub + deallocate the owned decrypt buffer.
    func clear() {
        displayLayer.sampleBufferRenderer.flush()
        sampleBuffer = nil
        image = nil
        imageSource = nil
        scrubBuffers()
    }

    // MARK: - Watermark

    /// Installs (or removes, with nil) the two watermark layers above the display layer.
    func setWatermark(_ layers: WatermarkLayers?) {
        watermark?.removeFromSuperlayer()
        watermark = layers
        if let layers {
            layers.install(in: displayLayer, displayScale: currentDisplayScale)
            layers.layout(contentBounds: bounds)
        }
    }

    override func layoutSubviews() {
        super.layoutSubviews()
        watermark?.layout(contentBounds: bounds)
    }

    override func didMoveToWindow() {
        super.didMoveToWindow()
        if window != nil, let watermark {
            watermark.updateDisplayScale(currentDisplayScale)
        }
    }

    private var currentDisplayScale: CGFloat {
        window?.windowScene?.screen.scale ?? traitCollection.displayScale
    }

    // MARK: - Buffers

    private func scrubBuffers() {
        CaptureProtectedImageView.scrub(pixelBuffer: pixelBuffer, decryptBuffer: decryptBuffer)
        pixelBuffer = nil
        decryptBuffer = nil
    }

    /// Zeroes the pixel buffer's rows and the owned decrypt buffer, then frees
    /// the latter. Best effort (§2): ImageIO's decoded bitmap is freed, not scrubbed.
    nonisolated static func scrub(pixelBuffer: CVPixelBuffer?,
                                  decryptBuffer: UnsafeMutableRawBufferPointer?) {
        if let pb = pixelBuffer {
            CVPixelBufferLockBaseAddress(pb, [])
            if let base = CVPixelBufferGetBaseAddress(pb) {
                let length: Int = CVPixelBufferGetBytesPerRow(pb) * CVPixelBufferGetHeight(pb)
                _ = memset_s(base, length, 0, length)
            }
            CVPixelBufferUnlockBaseAddress(pb, [])
        }
        if let owned = decryptBuffer {
            if let base = owned.baseAddress, owned.count > 0 {
                _ = memset_s(base, owned.count, 0, owned.count)
            }
            owned.deallocate()
        }
    }

    static func makePixelBuffer(from image: CGImage) throws -> CVPixelBuffer {
        let attrs: [CFString: Any] = [
            kCVPixelBufferCGImageCompatibilityKey: true,
            kCVPixelBufferCGBitmapContextCompatibilityKey: true,
            kCVPixelBufferIOSurfacePropertiesKey: [:] as CFDictionary,
        ]
        var buffer: CVPixelBuffer?
        let status: CVReturn = CVPixelBufferCreate(
            kCFAllocatorDefault, image.width, image.height,
            kCVPixelFormatType_32BGRA, attrs as CFDictionary, &buffer)
        guard status == kCVReturnSuccess, let pb = buffer else {
            throw DisplayError.pixelBuffer
        }
        CVPixelBufferLockBaseAddress(pb, [])
        defer { CVPixelBufferUnlockBaseAddress(pb, []) }
        guard let context = CGContext(
            data: CVPixelBufferGetBaseAddress(pb),
            width: image.width,
            height: image.height,
            bitsPerComponent: 8,
            bytesPerRow: CVPixelBufferGetBytesPerRow(pb),
            space: CGColorSpaceCreateDeviceRGB(),
            bitmapInfo: CGBitmapInfo.byteOrder32Little.rawValue | CGImageAlphaInfo.premultipliedFirst.rawValue
        ) else {
            throw DisplayError.context
        }
        context.draw(image, in: CGRect(x: 0, y: 0, width: image.width, height: image.height))
        return pb
    }
}
