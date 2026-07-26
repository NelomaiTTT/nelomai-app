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

- Generate and securely store the Tauri signing private key.
- Embed the matching public key through `NELOMAI_UPDATER_PUBLIC_KEY`.
- Implement the two authenticated panel update endpoints.
- Exercise a signed update on Windows, macOS, and Linux.
- Provision the Android package signing certificate before implementing the
  native APK installer.
