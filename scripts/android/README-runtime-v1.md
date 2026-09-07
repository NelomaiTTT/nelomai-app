# Android runtime-v1 build inputs

`0.2.16` ships only `latest`. The stable AAR/native payload is built from the
same revision for future embedding, not linked into this APK. Its immutable
identities are `ru.nelomai.runtime.stable`, `stable_runtime_`,
`libnelomai_runtime_stable.so` / `nelomai_runtime_v1`, and
`libstable_runtime_wg_go.so`.

The common ABI library is `plugins/runtime-android-common/android`. It is a
container dependency, not part of either runtime payload. The generated
GoBackend delegates Android VPN primitives to the single common service;
all recovery/executor/lease implementation remains in the versioned adapter.

## Build sequence

Use the locked Cargo graph and existing SDK/NDK/JDK17/Go caches. Do not edit
vendor or Cargo registry inputs. The source generators create disposable build
trees. A future container must consume a published stable artifact unchanged.

1. `python3 scripts/android/generate-build-inputs.py --root "$TASK_ROOT"`
2. In `src-tauri/gen/android`, run
   `./gradlew :app:testArm64DebugUnitTest :tauri-plugin-tunnel-android:testDebugUnitTest :stable-runtime-android:assembleDebug --offline`.
3. Build `nelomai-android-container` and `nelomai-app --lib` for
   `aarch64-linux-android`, with the NDK's `aarch64-linux-android24-clang` /
   `llvm-ar` and explicit ELF SONAME linker flags. Set
   `WRY_ANDROID_PACKAGE=ru.nelomai.client`,
   `WRY_ANDROID_LIBRARY=nelomai_app_lib`, and `WRY_ANDROID_KOTLIN_FILES_OUT_DIR`
   to the app's ignored generated Kotlin directory for the latest build.
4. `prepare-stable-rust.py --root ... --output <fresh directory>` makes the
   stable source variant, including namespaced Tauri/keyring/opener JNI.
   Build it with `WRY_ANDROID_PACKAGE=ru.nelomai.runtime.stable`,
   `WRY_ANDROID_LIBRARY=nelomai_runtime_stable`, its own generated Kotlin output
   directory, and `-C link-arg=-Wl,-soname,libnelomai_runtime_stable.so`.
5. `build-tunnel-runtime.py --root ... --output <fresh directory> --ndk ...
   --go-archive <cached Go 1.25 archive> --slot latest|stable` builds each Go/JNI
   library from clean pinned vendor archives plus tracked parent patches. The
   cached toolchain is unpacked locally; only the generated copy is patched.
6. `stage-runtime-build.py --root ... --output <fresh directory> --native <so>
   --tunnel <so> --readelf <NDK llvm-readelf> --slot latest|stable
   --source-commit <full commit>` stages real classes, WebView assets, stripped
   native libraries and licenses. Its collision ZIP is an inspection input,
   not a release APK.
7. `check-runtime-collisions.py --latest <latest collision-input.zip>
   --stable <stable collision-input.zip> --readelf <NDK llvm-readelf>` must
   report no conflicts before combining slots. No intersection allowlist is
   used.
8. `build-runtime-artifact.py --payload <stable payload> --output <new output>
   --version 0.2.16 --source-commit <full commit> --signing-key <explicit raw
   Ed25519 key> --readelf <NDK llvm-readelf>` validates actual class/JNI/ABI/ELF
   identities and licenses, then writes immutable ZIP + canonical signed
   manifest. Production signing is a separate release-authorized action.

## Local APK verification (no installation)

The staging script's explicit `--local-test-container --host <common host so>`
option generates a new disposable test trust key, a latest-only signed
container manifest, and `apk/assets` / `apk/jniLibs`. It never discovers a
release key. Rebuild the common host with the generated `test-public-key.b64`
as `NELOMAI_RELEASE_MANIFEST_PUBLIC_KEY_B64`, and replace only the staged common
host ELF with that build. Never publish these local test inputs.

Build with `./gradlew :app:assembleArm64Debug --offline
-PnelomaiRuntimeInputs=<absolute staging apk directory>
-x :app:rustBuildArm64Debug`. The skip is appropriate only because real native
libraries have already been built and staged. Without staged signed inputs,
APK assembly fails closed; ordinary JVM checks do not need signing inputs.

`check-container-apk.py --apk ... --apkanalyzer <SDK apkanalyzer> --public-key
<pinned raw or base64 Ed25519 public key>` verifies the signature and inspects the
actual APK's decoded manifest and DEX, checks exactly one non-exported VPN
service, and verifies every indexed payload hash and the installed ELF bytes.
The debug APK is not installed or release-signed by this workflow.

Hardware gates remain separate: VPN permission, foreground-service startup,
live tunnel/lease cleanup, tile idle retry, UI process death, Binder admission,
Keystore migration/crash replay, unknown-source permission and APK installer.
