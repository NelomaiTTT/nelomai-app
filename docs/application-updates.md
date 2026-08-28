# Application updates

## Shared behavior

`nelomai-client-updater` owns update policy and state. Automatic updates are
enabled by default and the preference is written atomically to a private JSON
file. A user who disables automatic installation still sees the available
version and can start it manually.

The coordinator serializes installation attempts. Repeated button presses or
simultaneous background/manual starts share one backend operation. Observable
states are idle, available, downloading, ready to restart, awaiting Android
installation, and failed.
Critical compatibility remains controlled by the bootstrap `required` flag;
the existing client core refuses new connections while it is set.

When an authenticated process returns to the foreground, it requests only the
current `Bootstrap.update` state through the native application layer. This
does not run core bootstrap, change the current screen, stop a tunnel, or
replace connection and binding state. Concurrent foreground events share one
refresh. A temporary request failure preserves the last visible update status.
If automatic updates are enabled, the refreshed offer enters the same
serialized installation flow as login/bootstrap; otherwise it remains
available for manual installation.

## Desktop

Windows, macOS, and Linux use the official Tauri updater. Release builds create
updater artifacts, and the updater validates their signatures before invoking
the platform installer. The build must receive the public key in
`NELOMAI_UPDATER_PUBLIC_KEY`. Signing automation must keep the private key
outside the repository.

The app sends its bearer token only to the panel manifest and artifact
endpoints. A manifest that announces another origin or another panel path is
rejected before download.

Every successful login and bootstrap observes the panel offer in the native
update coordinator. Automatic installation starts in the background by
default. The webview can read only the safe phase, version, release notes, and
byte progress; it never receives the bearer token, manifest signature, or
artifact URL. Manual and automatic attempts share one serialized native
operation. Once the signed package is installed, the UI asks the user to
restart the application.

The bootstrap request sends `X-Nelomai-App-Version` so the panel records the
version that is actually running after a self-update. Older clients omit the
header and remain compatible.

## Android boundary

The Tauri updater does not support Android. Android installation therefore
stays a separate native adapter with the same `UpdateBackend` contract:

1. Download the APK from the authenticated panel endpoint into app-private
   cache.
2. Compare the announced version with the bootstrap offer.
3. Verify SHA-256, package name, version, the release signer fingerprint, and
   equality with the certificate of the installed application.
4. Share only the private `cache/updates` file through `FileProvider` and open
   the system package installer.
5. Ask the user for Android's per-application install permission and final
   installation confirmation when required.
6. Reuse the verified cached APK after a cancelled prompt and remove stale APKs
   before downloading another release.

The Android adapter must not use shared external storage, request silent
installation privileges, or accept an APK signed with another certificate.
The package signing certificate is provisioned in GitHub Secrets. Its SHA-256
fingerprint is authenticated by the signed release manifest; it is not trusted
from the APK alone.

## Release gates

- Version `0.1.4` is the one-time updater bridge and must be installed manually
  over older builds. It must not be marked critical or minimum-supported.
  Desktop releases after `0.1.4` can be delivered through the panel.
- Generate and securely store the Tauri signing private key in
  `TAURI_SIGNING_PRIVATE_KEY` and its password secret.
- Embed the matching public key through `NELOMAI_UPDATER_PUBLIC_KEY`.
- Store a separate raw 32-byte Ed25519 seed in
  `NELOMAI_RELEASE_MANIFEST_PRIVATE_KEY_B64`; configure the matching public key
  on the panel as `CLIENT_RELEASE_MANIFEST_PUBLIC_KEY_B64`.
- The `release` GitHub Actions workflow is started only through guarded manual
  dispatch. It builds Linux x86_64, Windows x86_64, and macOS aarch64 updater
  artifacts, plus a signed Android aarch64 APK. Intel macOS builds are not
  published. It publishes only after every build job succeeds.
- The workflow publishes a deterministic JSON manifest, its detached Ed25519
  signature, and Tauri-signed packages. Draft and prerelease GitHub releases
  are not consumed by the panel.
- The Android APK and its signing-certificate fingerprint are included in the
  signed release manifest. The panel stores the APK privately and serves it
  only to authenticated application sessions.
- The panel verifies the manifest signature, artifact size, and SHA-256 before
  atomically publishing the release. It retains current and previous versions.
- Exercise a signed update on Windows, macOS, Linux, and a physical Android
  device. Android must show its system confirmation UI; silent installation is
  neither requested nor supported.

## Panel-first release order

The panel release sync, not GitHub publication by itself, is the source of the
`app_release_available` notification. Release notification production and the
new `AppRelease` are committed atomically after the panel verifies and stores
all signed artifacts.

For every application release:

1. Deploy the compatible panel change through the guarded panel updater.
2. Verify panel health and release-sync readiness without running production
   preflight against the working database.
3. Start the manual `release` workflow with
   `panel_notification_ready=true`. The acknowledgement confirms that the
   notification producer is already deployed; it is not a remote capability
   probe.
4. Let the guarded workflow create the version tag and GitHub release.
5. Wait for normal panel release sync and verify the notification audit event.

A pushed `v*` tag no longer starts release publication. This closes the path
that could publish an application before the panel notification producer was
ready.

There is no automatic notification backfill for a version that the panel
already published. The first release containing foreground refresh remains
compatible with older clients, but an older warm process can show the inbox
message without refreshing its update offer until the next cold bootstrap.
After that release is installed, subsequent foreground resumes refresh the
offer without disturbing an active tunnel. A required offer is displayed on
warm refresh, while the core `UpdateRequired` gate is still applied only by a
cold bootstrap.
