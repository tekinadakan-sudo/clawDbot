//  KilitApp.swift
//  Kilit — App/ (WP8), §5.2.
//
//  `@main` entry: `@UIApplicationDelegateAdaptor` (keyboard extension block,
//  tmp cleanup, SceneDelegate attachment) and `RootView`, which switches on
//  `AppModel.phase`. `NavigationStack`, sheets and `fullScreenCover` live out
//  here, outside the two secure containers. No `@SceneStorage`, no restoration.

import SwiftUI

@main
struct KilitApp: App {
    @UIApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate: AppDelegate
    @State private var model: AppModel

    @MainActor
    init() {
        _model = State(initialValue: AppModel.shared)
    }

    var body: some Scene {
        WindowGroup {
            RootView()
                .environment(model)
        }
    }
}

struct RootView: View {
    @Environment(AppModel.self) private var model: AppModel
    @Environment(\.scenePhase) private var scenePhase: ScenePhase

    var body: some View {
        ZStack {
            content
            CaptureEnvironmentReader(monitor: model.captureMonitor)
            if let toast = model.toast {
                ToastView(text: toast)
            }
        }
        .preferredColorScheme(.dark)
        .task {
            await model.bootstrap()
        }
        .onChange(of: scenePhase) { _, phase in
            model.scenePhaseChanged(phase)
        }
        .onChange(of: model.lock.state) { _, _ in
            model.lockStateChanged()
        }
    }

    @ViewBuilder
    private var content: some View {
        switch model.phase {
        case .loading:
            Color(uiColor: PrivacyCoverView.background).ignoresSafeArea()
        case .onboarding:
            OnboardingView()
        case .locked:
            LockedView()
        case .main:
            NavigationStack {
                ContactsView()
            }
        case .wipeRequired:
            WipeRequiredView()
        }
    }
}

/// The lock UI (§5.11): never the privacy cover.
struct LockedView: View {
    @Environment(AppModel.self) private var model: AppModel

    var body: some View {
        ZStack {
            Color(uiColor: PrivacyCoverView.background).ignoresSafeArea()
            VStack(spacing: 24) {
                Image(systemName: "lock.fill")
                    .font(.system(size: 48))
                    .foregroundStyle(.secondary)
                Text("Kilit")
                    .font(.largeTitle.bold())
                if model.lock.state == .authenticating {
                    ProgressView()
                } else {
                    Button {
                        model.lock.retry()
                    } label: {
                        Text(String(localized: "lock.retry", defaultValue: "Kilidi aç"))
                            .frame(minWidth: 160)
                    }
                    .buttonStyle(.borderedProminent)
                }
            }
        }
    }
}

/// Rolled-back `index.json`: the store fails closed and the user must wipe (§3.7).
struct WipeRequiredView: View {
    @Environment(AppModel.self) private var model: AppModel
    @State private var working: Bool = false

    var body: some View {
        VStack(spacing: 20) {
            Image(systemName: "exclamationmark.triangle")
                .font(.system(size: 40))
                .foregroundStyle(.yellow)
            Text(String(localized: "wipe.required.title", defaultValue: "Yerel veri bütünlüğü bozuldu"))
                .font(.title2.bold())
                .multilineTextAlignment(.center)
            Text(String(localized: "wipe.required.body",
                        defaultValue: "Yerel depo daha eski bir sürüme geri döndürülmüş görünüyor. Güvenlik için mesajlar ve anahtarlar silinip uygulama sıfırlanmalı."))
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)
            Button(role: .destructive) {
                working = true
                Task {
                    await model.wipeLocal()
                    working = false
                }
            } label: {
                Text(String(localized: "wipe.required.action", defaultValue: "Sil ve sıfırla"))
                    .frame(minWidth: 200)
            }
            .buttonStyle(.borderedProminent)
            .disabled(working)
        }
        .padding(24)
    }
}

/// Bottom toast for stop reasons and errors (§5.10).
struct ToastView: View {
    let text: String

    var body: some View {
        VStack {
            Spacer()
            Text(text)
                .font(.footnote)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 16)
                .padding(.vertical, 10)
                .background(.ultraThinMaterial, in: Capsule())
                .padding(.bottom, 24)
        }
        .allowsHitTesting(false)
        .transition(.opacity)
    }
}
