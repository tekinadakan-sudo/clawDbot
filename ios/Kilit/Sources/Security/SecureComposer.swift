//  SecureComposer.swift
//  Kilit — Security/ (WP6), §2 clipboard/keyboard row.
//
//  UITextView composer with every learning / rewriting trait off: autocorrection,
//  spell check, smart quotes / dashes / insert-delete, `inlinePredictionType = .no`
//  (iOS 17) and `writingToolsBehavior = .none` (iOS 18, availability-guarded).
//  The composer sits OUTSIDE the secure containers (§5.5): the draft is visible
//  in screenshots, which limits item 2 states. Third-party keyboards are blocked
//  app-wide by `AppDelegate` (`shouldAllowExtensionPointIdentifier`).

import SwiftUI
import UIKit

final class SecureTextView: UITextView {
    override init(frame: CGRect, textContainer: NSTextContainer?) {
        super.init(frame: frame, textContainer: textContainer)
        autocorrectionType = .no
        spellCheckingType = .no
        smartQuotesType = .no
        smartDashesType = .no
        smartInsertDeleteType = .no
        inlinePredictionType = .no
        if #available(iOS 18.0, *) {
            writingToolsBehavior = .none
        }
        textContentType = nil
        keyboardType = .default
        returnKeyType = .default
        enablesReturnKeyAutomatically = false
        dataDetectorTypes = []
        textDragInteraction?.isEnabled = false
        backgroundColor = .clear
        font = UIFont.preferredFont(forTextStyle: .body)
        adjustsFontForContentSizeCategory = true
        textContainerInset = UIEdgeInsets(top: 8, left: 4, bottom: 8, right: 4)
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        return nil
    }
}

struct SecureComposer: UIViewRepresentable {

    @Binding var text: String
    var minHeight: CGFloat = 36
    var maxHeight: CGFloat = 120
    var isEditable: Bool = true

    init(text: Binding<String>, minHeight: CGFloat = 36, maxHeight: CGFloat = 120, isEditable: Bool = true) {
        self._text = text
        self.minHeight = minHeight
        self.maxHeight = maxHeight
        self.isEditable = isEditable
    }

    @MainActor
    final class Coordinator: NSObject, UITextViewDelegate {
        var text: Binding<String>

        init(text: Binding<String>) {
            self.text = text
        }

        func textViewDidChange(_ textView: UITextView) {
            if text.wrappedValue != textView.text {
                text.wrappedValue = textView.text
            }
        }
    }

    func makeCoordinator() -> Coordinator {
        Coordinator(text: $text)
    }

    func makeUIView(context: Context) -> SecureTextView {
        let view: SecureTextView = SecureTextView(frame: .zero, textContainer: nil)
        view.delegate = context.coordinator
        view.isEditable = isEditable
        view.isScrollEnabled = true
        view.text = text
        return view
    }

    func updateUIView(_ uiView: SecureTextView, context: Context) {
        context.coordinator.text = $text
        uiView.isEditable = isEditable
        if uiView.text != text {
            uiView.text = text
        }
    }

    func sizeThatFits(_ proposal: ProposedViewSize, uiView: SecureTextView, context: Context) -> CGSize? {
        guard let width = proposal.width, width > 0 else { return nil }
        let fitting: CGSize = uiView.sizeThatFits(CGSize(width: width, height: CGFloat.greatestFiniteMagnitude))
        let height: CGFloat = min(max(fitting.height, minHeight), maxHeight)
        return CGSize(width: width, height: height)
    }
}
