# Desktop runtime packaging (0.2.16)

The installed `nelomai-app` is the common broker. Do not distribute the raw
`nelomai-runtime` next to it: only the signed slot under `runtime/engines/latest/0.2.16`
is admitted. There is no stable slot in this release.

Use a clean source checkout and the existing platform engine preparation scripts.
Desktop AmneziaWG Go uses clean pinned commit `08d68cdae27762c3e07f36bbb12d2bad32f81926`,
not the Android working-tree overrides. Never reset a developer's vendor tree;
build an archive of that commit in a private temporary directory when necessary.
macOS WireGuard Go remains pinned to `ecfc5a8d54462e18e13c72173e2623d16d8e25a0`.

1. Build the UI with `npm run build` and the native service for the target.
2. Set the explicit public `NELOMAI_RELEASE_MANIFEST_PUBLIC_KEY_B64` build input.
   Build the product with `cargo build --release -p nelomai-app --features desktop-runtime --bin nelomai-runtime`.
   This feature embeds the UI; a raw Cargo release without `custom-protocol`
   still uses the development URL. Build common with
   `cargo build --release -p nelomai-app --features custom-protocol --bin nelomai-app`.
   Add the same explicit `--target` to both when cross-compiling.
3. Assemble a fresh payload directory containing the flat runtime and service
   binaries, existing platform engine binaries/libraries, `webview/` copied from
   `build/`, and `licenses/`. The packager validates the exact required license
   names and platform executable formats. Copy Tauri MIT/Apache licenses from
   the resolved Tauri source. Linux includes the existing `resolvconf` script.
4. Run `package-runtime-artifact.py --payload PAYLOAD --output ARTIFACT
   --platform macos|linux|windows --architecture aarch64|x86_64 --version 0.2.16
   --source-commit CLEAN_SOURCE_SHA --signing-key EXPLICIT_RAW_ED25519_KEY`.
   The output is immutable. On macOS the packager signs copied executables
   ad-hoc, without timestamps, before hashing them. Never substitute input bytes
   for the resulting ZIP or re-sign an already published stable payload.
5. Run `stage-desktop-runtime.py --artifact ARTIFACT
   --output src-tauri/platform-runtime/desktop-bundle --signing-key EXPLICIT_RAW_ED25519_KEY`.
   Output must be absent; retain/move earlier local output if rebuilding.
   This verifies and extracts the final ZIP and signs the latest-only container
   manifest. Dispatcher gets the exact signed service bytes.
6. Bundle with the corresponding `bundle.PLATFORM.conf.json`. Do **not** pass
   `desktop-runtime` to `tauri bundle`: its required-feature declaration excludes
   an unversioned duplicate from common. Keep this separate from the child build.
   Local macOS smoke uses `--bundles app --no-sign --ci` and overrides only
   `bundle.createUpdaterArtifacts=false`; no production updater key is needed.
7. Finalize the outer macOS `.app` using ad-hoc `codesign --force --sign -
   --timestamp=none APP` without `--deep`. Then run `codesign --verify --strict APP`
   and `APP/Contents/MacOS/nelomai-app --verify-runtime-layout
   APP/Contents/Resources/runtime`. The latter only verifies files, never opens
   auth or invokes an installer. Record the final archive/container hashes.

Keep `runtime.zip`, its manifest and signature as the same-source stable artifact
for future embedding. A supplied source SHA is not proof of a clean build: record
the source checkout, build inputs and final digests separately. Local test keys
and synthetic-source smoke artifacts are not release artifacts.

Installed Unix launches require the protected common layout before auth. macOS
uses `/Library/Application Support/Nelomai/common/Nelomai.app`; Linux retains both
the whole AppImage and extracted AppDir under `/usr/local/libexec/nelomai/common`.
The pre-auth handoff copies the whole package and then executes as the user.
Do not run the application as root, weaken ancestors, or execute installers as
part of packaging tests. Windows keeps the existing per-machine NSIS installation.
