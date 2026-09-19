# Immutable 0.2.16 runtime artifacts

This maintenance line ships **latest-only 0.2.16**. The separate synthetic
two-slot packages are test inputs, not public installers. Packaging, native
re-extraction, limited Linux execution and full candidate acceptance are
different gates; none implies the others.

The synthetic latest identity is plain `0.2.17`, distinct from immutable stable
`0.2.16` and accepted by both Rust semver and the panel's PEP 440 parser/current
contract bounds. It changes only the separate acceptance container/Android
build identity, not the normal shipping version or final stable payload bytes.

## Source and final bytes

Dispatch `release.yml` with a full lowercase 40-character `source_sha`. Every
checkout uses that SHA, fetches history/submodules and checks `HEAD`, clean
tracked content, the reviewed maintenance ancestor and absence of intervening
merge commits. The dispatch ref's head must equal `source_sha`. Version is
checked as `0.2.16`; the workflow never rewrites source versions. Existing local
or remote `v0.2.16` must peel to the same SHA; publication never retags.

The workflow is already registered on the default branch. A separately
authorized future push/dispatch may use the maintenance ref; merging this
workflow into main is not an extra prerequisite merely to select `--ref`.
This work itself does not push or dispatch anything.

Each native platform produces exactly:

```text
nelomai-runtime-0.2.16-PLATFORM-ARCHITECTURE.zip
nelomai-runtime-0.2.16-PLATFORM-ARCHITECTURE.manifest.json
nelomai-runtime-0.2.16-PLATFORM-ARCHITECTURE.manifest.sig
```

Targets are Linux/x86_64, Windows/x86_64, macOS/aarch64 and Android/aarch64.
All four are required by `build-runtime-release-set.py`. The root files are
`nelomai-runtime-0.2.16-release-set.manifest.json` and `.manifest.sig`.
`stable_manifest_sha256` is the SHA-256 of the **root manifest bytes**, never
one platform's manifest. Its entries bind final ZIP, platform manifest and
signature names/digests. Android retains its compiled AAR/SO/resource/license
checks through the existing shared validator; macOS retains final ad-hoc native
signatures before hashing. Nothing signs or rewrites stable payloads afterward.

Shared Rust contracts authenticate runtime, root and container documents via
`verify-runtime-manifest`. Python consumers reuse that adapter and the existing
native packagers; they do not implement a second runtime trust parser.

Signature formats stay distinct:

- Raw 32-byte Ed25519 public/private keys for runtime/root/container documents.
  Their domains remain `nelomai-runtime-manifest-v1\0`,
  `nelomai-runtime-release-set-v1\0` and `nelomai-container-manifest-v1\0`.
  These detached signatures are raw 64-byte signatures.
- Existing `nelomai-release-manifest.json` signs its exact bytes with Ed25519,
  without adding a domain; its `.sig` remains base64.
- Desktop updater signatures and `NELOMAI_UPDATER_PUBLIC_KEY` retain Tauri's
  base64-wrapped minisign format. `verify-updater-signature` uses the same
  minisign verifier/decode sequence as Tauri, not the runtime Ed25519 parser.
- Android installation uses its APK keystore certificate; the expected
  `ANDROID_SIGNER_SHA256` is separate from both public-key formats above.

## Current release pipeline (2026-09-09)

The build graph is `verify → native_drafts → sign → native_packages → finalize`.
Publication remains a separate dispatch; building never publishes.

- `build_only` is the default. It uses deliberately public TEST trust derived
  per source/run and cannot be promoted. The shared signing/finalization jobs
  receive no production signing secrets in this mode.
- `sign_candidate` runs the same graph with release trust. Four native jobs
  build the runtime payloads; `sign` signs the runtime/root/container documents.
  Native packaging consumes those unchanged bytes and emits **only shipping
  installers**. Desktop common wrappers reuse the signed latest WebView;
  neither packaging Python nor Tauri's before-build hook rebuilds the UI.
  `finalize` signs desktop updater packages and the APK, verifies the final
  signatures and writes the release manifest plus shipping inventory.
- `publish_approved_candidate` selects retained bytes from a successful
  `sign_candidate` run. Supply the source SHA, version, `candidate_run_id`,
  release notes and `panel_notification_ready=true`. Artifact ID and inventory
  digest are resolved automatically. Publication checks source/run identity,
  retention, the exact shipping allowlist and each downloaded file hash. It
  does not compile, sign, replace existing assets or move a tag.

Native packaging still checks extracted runtime bytes. APK checking retains
versionCode/versionName, DEX/ABI/JNI and native payload checks. Signature
production and runtime/updater verification remain; the removed manual
approvals and full acceptance publication gate are **not** reintroduced.
A passing build is not proof of installation or tunnel behavior on a device.

The signing job provisions Python/Rust only. Finalization provisions the
signing CLIs and Android build-tools, not Go, NDK or native GTK dependencies.
Native build/packaging jobs retain the dependencies they consume.

## Signing configuration

Keep `release-candidate-signing`, `release-candidate-finalization` and
`release-publication` as credential/configuration boundaries. Read-only GitHub
inspection on 2026-09-09 found no approval protection rules on them.
The unused `release-candidate-acceptance` environment is not part of this graph.
No environment configuration is changed by the workflow simplification.

Configure raw Ed25519 public pin `NELOMAI_RELEASE_MANIFEST_PUBLIC_KEY_B64`
and APK certificate pin `ANDROID_SIGNER_SHA256` as repository variables.
The separate Tauri public pin `NELOMAI_UPDATER_PUBLIC_KEY` and existing Firebase
values remain repository Secrets. Private runtime-signing material belongs to
signing/finalization; Tauri and Android private signing material belongs to
finalization. Private keys never enter uploaded artifacts or job outputs.

## Retention and reruns

Artifacts are retained for 14 days. `candidate-0.2.16` contains the exact
22-file shipping allowlist plus `candidate-inventory.json`: four installers,
twelve runtime files, two root files, two release-manifest files and two
licensed-source archive/checksum files. Publication uses that explicit list.

Use **Re-run failed jobs** for a failed attempt of unchanged source. Uploads
replace same-named build artifacts within that run, and source/root/package
identity checks prevent mixing different inputs. The selected completed run
may have any attempt number. A missing, expired, ambiguous, wrong-source or
unsuccessful build is rejected; changed source requires a new build.
Artifact selection was checked read-only against a retained GitHub build.

Acceptance packager/test helpers remain available for explicit local testing,
but ordinary releases no longer build, finalize or upload acceptance installers.
The separate Linux diagnostic workflow opts into both packages with
`package-release-platform.py --include-acceptance`; this flag is absent from
the ordinary release workflow.

## Actual command boundaries

The Ubuntu verifier provisions JDK 17 and NDK `28.2.13676358` before mandatory
compiled Java/ELF fixture discovery (`android-fixtures: true` on the native host
action). Local fixture runs must likewise supply `JAVA_HOME` and
`ANDROID_NDK_HOME` (or `NDK_HOME`); tools resolve the actual Linux/Darwin host
subdirectory. Missing or nonexecutable tools fail the tests, never skip their
compiled-byte coverage. `ANDROID_HOME` also identifies the SDK for opt-in actual
APK packaging tests. These tests do not establish device acceptance.

The workflow supplies explicit paths/pins to these consumers. The last command\n(`verify-release-platform.py`) is an optional legacy two-package test, not a workflow job:

```text
build-release-platform.py --mode MODE --source-sha SHA --platform P --architecture A --public-key RAW --output DRAFT --work TEMP [--ndk NDK --go-archive ARCHIVE]
sign-runtime-candidate.py --mode MODE --source-sha SHA --drafts FOUR_DRAFTS --output SIGNED --signing-key RAW_PRIVATE --public-key RAW_PUBLIC
package-release-platform.py --mode MODE --source-sha SHA --release-set-sha256 ROOT_SHA --platform P --architecture A --signed SIGNED --draft PLATFORM_DRAFT --public-key RAW --output PACKAGES [--ndk NDK]
finalize-release-candidate.py --mode MODE --source-sha SHA --release-set-sha256 ROOT_SHA --packages FOUR_PACKAGES --signed SIGNED --output FINAL --private-key RAW_PRIVATE --public-key RAW_PUBLIC --work TEMP --sdk SDK
verify-release-platform.py --source-sha SHA --release-set-sha256 ROOT_SHA --inventory-sha256 INV_SHA --acceptance-inventory-sha256 TEST_INV_SHA --platform P --architecture A --signed SIGNED --candidate CANDIDATE --acceptance ACCEPTANCE --public-key RAW --output EVIDENCE [--ndk NDK] [--linux-execution]
```

`build-runtime-acceptance-container.py` also exposes the local explicit TEST-key
stage/package CLI (`--help` lists inputs). Its keyless `stage_signed` function
consumes final signatures in the workflow; it never needs a release private key.
Android `check-container-apk.py --acceptance` additionally requires exact root
and platform manifest digests. Ordinary checker invocation still rejects stable
DEX and stable slots. The Gradle `-PnelomaiAcceptance=true` path must link the
exact final stable AAR; it cannot silently enable stable in a shipping APK.

## Optional acceptance tooling and hardware limits

The Linux executable exercises actual `CommonHost`, `VerifiedRuntime`, inherited
broker/native channels, the unchanged stable executable, real WebView controls
through AT-SPI and actual Unix `TunnelRequestHandler` framing. Only external
native effects use an explicitly labelled test adapter; starting a physical
tunnel returns UNRUN. A separate ordinary startup check executes the actual
packaged common/latest runtime/dispatcher/engine from a root-owned disposable
Linux layout. Docker execution disables external networking, uses a fresh
unprivileged application user, and never invokes a host installer or product
panel. The source-fixed `PANEL_BASE` and TLS trust remain unchanged.

Task12 fixes signed slot selection before immutable publication: engine startup
resolves its kernel executable against authenticated slot bytes, the dispatcher
selects an exact signed identity only while idle, and CommonHost binds all native
transport clones once to its installed target. Pending preference cannot retarget
a running incarnation; stale Stop/private commands remain fenced. Installation
readiness checks the authenticated container layout separately from active slot.
Source tests execute Stable through the actual Unix socket and dispatcher, with
an external native-effects child. Shipping remains latest-only. New candidate
bytes still require fresh signing and exact-candidate tests.

`scripts/run-real-panel-acceptance.py` is the local real-broker/panel/PostgreSQL
fault producer. It requires an explicitly isolated migrated database and a
recorded panel archive on loopback. It runs real HTTP, protected-file persistence,
actual process exits and independent DB observations. Only external native/agent
effects are adapted; actual cleanup jobs and leases are completed by the existing
panel recovery worker. The macOS phase fault hook is a disposable rename
interposer, not a product hook or journal rewrite. Results record tested source
diff/driver hashes; the supplied panel SHA is an archive provenance claim, not
argument-based verification. This is not a packaged-candidate approval issuer.

The legacy full producer interface, not invoked by the release workflow, is:

```text
python scripts/require-candidate-acceptance.py --source-sha SHA40 --release-set-sha256 SHA64 --inventory-sha256 SHA64 --candidate-directory PATH
```

This legacy command must not be treated as a successful device check or a
publication approval issuer. Current publication does not call it.
Physical Windows/macOS/Android update, retained login and tunnel checks still
need the actual corrected installers on those devices; Linux execution tests
with native-effects adapters are not a physical VPN test.
