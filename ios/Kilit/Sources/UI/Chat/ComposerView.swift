//  ComposerView.swift
//  Kilit — UI/Chat (WP8), §5.5.
//
//  `SecureComposer` (UITextView with every learning trait off) + `PhotosPicker`
//  + camera. The composer sits OUTSIDE both secure containers (deliberate,
//  limits item 2): the unsent draft is visible in screenshots.

import PhotosUI
import SwiftUI
import UIKit

struct ComposerView: View {
    @Binding var text: String
    let isEnabled: Bool
    let onSend: () -> Void
    /// Picked image bytes (decoded in memory by `ImageNormalizer`, never through a file).
    let onImage: (Data) -> Void

    @State private var pickerItem: PhotosPickerItem? = nil
    @State private var showingCamera: Bool = false

    private var canSend: Bool {
        isEnabled && !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    private var cameraAvailable: Bool {
        UIImagePickerController.isSourceTypeAvailable(.camera)
            && Bundle.main.object(forInfoDictionaryKey: "NSCameraUsageDescription") != nil
    }

    var body: some View {
        HStack(alignment: .bottom, spacing: 8) {
            PhotosPicker(selection: $pickerItem, matching: .images, photoLibrary: .shared()) {
                Image(systemName: "photo")
                    .font(.title2)
                    .frame(width: 36, height: 36)
            }
            .disabled(!isEnabled)
            .accessibilityLabel(String(localized: "composer.photo", defaultValue: "Fotoğraf seç"))
            if cameraAvailable {
                Button {
                    showingCamera = true
                } label: {
                    Image(systemName: "camera")
                        .font(.title2)
                        .frame(width: 36, height: 36)
                }
                .disabled(!isEnabled)
                .accessibilityLabel(String(localized: "composer.camera", defaultValue: "Fotoğraf çek"))
            }
            SecureComposer(text: $text, isEditable: isEnabled)
                .background(Color(uiColor: .secondarySystemBackground), in: RoundedRectangle(cornerRadius: 12))
            Button {
                onSend()
            } label: {
                Image(systemName: "arrow.up.circle.fill")
                    .font(.title)
                    .frame(width: 36, height: 36)
            }
            .disabled(!canSend)
            .accessibilityLabel(String(localized: "composer.send", defaultValue: "Gönder"))
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 6)
        .onChange(of: pickerItem) { _, item in
            guard let item else { return }
            Task {
                if let data = try? await item.loadTransferable(type: Data.self) {
                    onImage(data)
                }
                pickerItem = nil
            }
        }
        .fullScreenCover(isPresented: $showingCamera) {
            CameraPicker { data in
                showingCamera = false
                if let data { onImage(data) }
            }
            .ignoresSafeArea()
        }
    }
}

/// `UIImagePickerController` with the camera source; the shot is re-encoded in
/// memory and never saved to the photo library.
struct CameraPicker: UIViewControllerRepresentable {
    let completion: (Data?) -> Void

    final class Coordinator: NSObject, UIImagePickerControllerDelegate, UINavigationControllerDelegate {
        let completion: (Data?) -> Void

        init(completion: @escaping (Data?) -> Void) {
            self.completion = completion
        }

        func imagePickerController(_ picker: UIImagePickerController,
                                   didFinishPickingMediaWithInfo info: [UIImagePickerController.InfoKey: Any]) {
            let image: UIImage? = info[.originalImage] as? UIImage
            let data: Data? = image?.jpegData(compressionQuality: 0.9)
            completion(data)
        }

        func imagePickerControllerDidCancel(_ picker: UIImagePickerController) {
            completion(nil)
        }
    }

    func makeCoordinator() -> Coordinator {
        Coordinator(completion: completion)
    }

    func makeUIViewController(context: Context) -> UIImagePickerController {
        let picker: UIImagePickerController = UIImagePickerController()
        picker.sourceType = .camera
        picker.allowsEditing = false
        picker.delegate = context.coordinator
        return picker
    }

    func updateUIViewController(_ uiViewController: UIImagePickerController, context: Context) {}
}
