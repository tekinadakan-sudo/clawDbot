import Foundation
import UIKit

/// Normalised JPEG ready for `AttachmentCrypto.seal`: upright, no EXIF orientation, no GPS/maker metadata,
/// `width`/`height` equal to the pixel dimensions (= `att.w/h`).
struct NormalizedImage: Equatable {
    let data: Data
    let width: Int
    let height: Int
    static let mime: String = "image/jpeg"
}

enum ImageNormalizerError: Error, Equatable {
    case undecodable
    case tooLarge
}

/// §3.5 send pipeline: draw the picked image into a `UIGraphicsImageRenderer` (scale 1, opaque) with the long
/// edge ≤ 2048 px and re-encode with `jpegData(compressionQuality: 0.8)`.
enum ImageNormalizer {
    static let maxLongEdge: CGFloat = 2048
    static let quality: CGFloat = 0.8

    static func targetSize(for size: CGSize) -> CGSize {
        let w: CGFloat = max(1, size.width.rounded(.down))
        let h: CGFloat = max(1, size.height.rounded(.down))
        let longEdge: CGFloat = max(w, h)
        guard longEdge > maxLongEdge else { return CGSize(width: w, height: h) }
        let scale: CGFloat = maxLongEdge / longEdge
        return CGSize(width: max(1, (w * scale).rounded(.down)), height: max(1, (h * scale).rounded(.down)))
    }

    /// Decodes the picked bytes in memory (never through a file) and normalises them.
    static func normalize(pickedData: Data) throws -> NormalizedImage {
        guard let image = UIImage(data: pickedData) else { throw ImageNormalizerError.undecodable }
        return try normalize(image)
    }

    static func normalize(_ image: UIImage) throws -> NormalizedImage {
        // `size` already accounts for `imageOrientation`; drawing applies the orientation, so the output is upright.
        let target: CGSize = targetSize(for: image.size)
        let format: UIGraphicsImageRendererFormat = UIGraphicsImageRendererFormat()
        format.scale = 1
        format.opaque = true
        let renderer: UIGraphicsImageRenderer = UIGraphicsImageRenderer(size: target, format: format)
        let rendered: UIImage = renderer.image { _ in
            image.draw(in: CGRect(origin: .zero, size: target))
        }
        guard let jpeg = rendered.jpegData(compressionQuality: quality) else { throw ImageNormalizerError.undecodable }
        guard jpeg.count <= AttachmentCrypto.maxPlaintext else { throw ImageNormalizerError.tooLarge }
        return NormalizedImage(data: jpeg, width: Int(target.width), height: Int(target.height))
    }
}
