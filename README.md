# Nelomai App

Native Nelomai client for Android, Windows, macOS, and Linux.

Task 0 proved the platform approach. Task 1 establishes the versioned shared
contracts. The UI remains a temporary diagnostic surface and is not the
product design.

## Current spike

- Tauri 2 with Svelte and TypeScript for the shared application shell.
- Rust for shared native logic and desktop integration.
- Android plugin backed by the official
  `com.wireguard.android:tunnel` library.
- Unix privileged-helper prototype with kernel-authenticated peer UID.

Actual measurements, limitations, and the platform decision are recorded in
[`docs/adr/0001-platform-feasibility.md`](docs/adr/0001-platform-feasibility.md).
The panel boundary is documented in
[`docs/panel_contract.md`](docs/panel_contract.md).
The Windows service boundary and the deferred runtime smoke are documented in
[`docs/windows-tunnel-service.md`](docs/windows-tunnel-service.md).

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
