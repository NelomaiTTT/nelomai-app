# Nelomai App

Native Nelomai client for Android, Windows, macOS, and Linux.

The repository contains the shared application core, versioned panel
contracts, platform tunnel adapters, privileged desktop services, and the
signed update boundary. The UI remains a temporary diagnostic surface and is
not the product design.

## Current architecture

- Tauri 2 with Svelte and TypeScript for the shared application shell.
- Rust for shared native logic and desktop integration.
- Android plugin backed by the official
  `com.wireguard.android:tunnel` library.
- Privileged WireGuard and AmneziaWG 3 tunnel services for Windows, macOS, and
  Linux.
- Signed automatic updates for desktop platforms; Android installation stays a
  separate native boundary.

Actual measurements, limitations, and the platform decision are recorded in
[`docs/adr/0001-platform-feasibility.md`](docs/adr/0001-platform-feasibility.md).
The panel boundary is documented in
[`docs/panel_contract.md`](docs/panel_contract.md).
The Windows service boundary and the deferred runtime smoke are documented in
[`docs/windows-tunnel-service.md`](docs/windows-tunnel-service.md).
The Unix service boundary is documented in
[`docs/unix-tunnel-helper.md`](docs/unix-tunnel-helper.md).
Application update policy and release gates are documented in
[`docs/application-updates.md`](docs/application-updates.md).
Split-tunnel behavior, privacy boundaries, synchronization, and platform
fallbacks are documented in
[`docs/split-tunnel.md`](docs/split-tunnel.md).
The synchronized inbox and Android push setup are documented in
[`docs/notifications.md`](docs/notifications.md).

## Release history («Что нового»)

Opening the dialog fetches public release notes from the panel's
`GET /api/client/v1/releases/changelog` endpoint. The response uses
`{"api_version":"1","entries":[{"version":"…","notes":"…"}]}`.
The last valid history is cached locally; bundled notes are an offline fallback
until the first successful fetch. Panel edits replace the cached history without
an application rebuild. Notes are plain text, never executable HTML.

This request is independent of login, runtime admission and VPN operations, runs
only when the dialog opens, and is bounded to eight seconds and 4 MiB.
An unavailable or older panel does not block the application. Deploy panel
support (including migration `20260912_0059`) before releasing this client.

## Local checks

Rust installed by Homebrew `rustup` may require this path in a fresh shell:

```bash
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"
export JAVA_HOME="/opt/homebrew/opt/openjdk@17"
export PATH="$JAVA_HOME/bin:$PATH"
```

Run the shared checks:

```bash
npm install
npm test
npm run check
npm run build
cargo test --manifest-path src-tauri/Cargo.toml
cargo test --manifest-path plugins/tunnel-android/Cargo.toml
cargo test --manifest-path spikes/desktop-helper/Cargo.toml
python3 contracts/python/validate_fixtures.py
```

The Android SDK is installed at
`/opt/homebrew/share/android-commandlinetools`. Android builds also require
Java 17 and the configured Android NDK.

Pinned development versions are recorded in `.nvmrc`, `rust-toolchain.toml`,
`.java-version`, and `.android-toolchain`.
