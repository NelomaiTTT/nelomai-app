# Application updates

## Shared behavior

`nelomai-client-updater` owns update policy and state. Automatic updates are
enabled by default and the preference is written atomically to a private JSON
file. A user who disables automatic installation still sees the available
version and can start it manually.

The coordinator serializes installation attempts. Repeated button presses or
simultaneous background/manual starts share one backend operation. Observable
states are idle, available, downloading, ready to restart, and failed.
Critical compatibility remains controlled by the bootstrap `required` flag;
the existing client core refuses new connections while it is set.

## Desktop

Windows, macOS, and Linux use the official Tauri updater. Release builds create
updater artifacts, and the updater validates their signatures before invoking
the platform installer. The build must receive the public key in
`NELOMAI_UPDATER_PUBLIC_KEY`. Signing automation must keep the private key
outside the repository.

The app sends its bearer token only to the panel manifest and artifact
endpoints. A manifest that announces another origin or another panel path is
rejected before download.

## Android boundary

The Tauri updater does not support Android. Android installation therefore
stays a separate native adapter with the same `UpdateBackend` contract:

1. Download the APK from the authenticated panel endpoint into app-private
   cache.
2. Compare the announced version with the bootstrap offer.
3. Hand the APK to Android `PackageInstaller`.
4. Let Android verify that the APK is signed by the same application
   certificate and request confirmation from the user.
5. Delete the cached APK after success, rejection, or failure.

The Android adapter must not use shared external storage, request silent
installation privileges, or accept an APK signed with another certificate.
Its implementation and device smoke test remain a separate platform task
because the package signing certificate has not been provisioned yet.

## Release gates

- Generate and securely store the Tauri signing private key in
  `TAURI_SIGNING_PRIVATE_KEY` and its password secret.
- Embed the matching public key through `NELOMAI_UPDATER_PUBLIC_KEY`.
- Store a separate raw 32-byte Ed25519 seed in
  `NELOMAI_RELEASE_MANIFEST_PRIVATE_KEY_B64`; configure the matching public key
  on the panel as `CLIENT_RELEASE_MANIFEST_PUBLIC_KEY_B64`.
- The `release` GitHub Actions workflow builds Linux x86_64, Windows x86_64,
  macOS x86_64, and macOS aarch64 updater artifacts for a stable `v*` tag or a
  manual version. It publishes only after every matrix job succeeds.
- The workflow publishes a deterministic JSON manifest, its detached Ed25519
  signature, and Tauri-signed packages. Draft and prerelease GitHub releases
  are not consumed by the panel.
- The panel verifies the manifest signature, artifact size, and SHA-256 before
  atomically publishing the release. It retains current and previous versions.
- Exercise a signed update on Windows, macOS, and Linux.
- Provision the Android package signing certificate before implementing the
  native APK installer.
