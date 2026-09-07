# Immutable 0.2.16 runtime artifacts

This maintenance line ships **latest-only 0.2.16**. The separate synthetic
two-slot packages are test inputs, not public installers. Packaging, native
re-extraction, limited Linux execution and full candidate acceptance are
different gates; none implies the others.

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

## Three modes and two signing phases

`build_only` is the default. It is read-only, nonpublishing and uses deliberately
public TEST trust derived per source/run. All runtime/common/dispatcher native
builds receive the same compile-time TEST runtime pin through the existing
`NELOMAI_RELEASE_MANIFEST_PUBLIC_KEY_B64` interface. Native output directories
are isolated; no release/test Cargo output artifact is reused across jobs.
Private TEST material is regenerated in phase-local temporary paths, not
uploaded. This is useful preliminary packaging/native/Linux coverage, not a
release-trust, updater-installation or hardware approval. Its inventory remains
permanently nonpublishable even if someone later approves an environment.

`sign_candidate` follows this order:

1. Four keyless native jobs compile final payloads under the explicit release
   public pin, inspect them natively and upload draft ZIPs signed with ephemeral
   TEST keys. No release private key is available to those jobs.
2. Protected `release-candidate-signing` verifies all unchanged drafts, creates
   final runtime signatures/root and signs ordinary latest-only and separate
   two-slot container documents. It does not run foreign native packagers.
3. Four keyless native jobs extract final signed payloads and build ordinary
   installers plus separate synthetic acceptance installers. macOS applies
   only the outer ad-hoc app seal, without `--deep`; final inner bytes and modes
   must survive native packaging/re-extraction unchanged. Candidate APKs are
   packaged unsigned for the next phase.
4. Distinct protected `release-candidate-finalization` signs the final desktop
   installer bytes with Tauri and the final APKs with their keystore, then
   creates the existing signed release manifest and exact inventories. It
   checks that APK signing did not alter DEX/resources/native entries. The
   matching updater public pin verifies each final desktop signature.
5. Four native jobs re-extract/recheck those final installers, including real
   Android APK/DEX/ABI/JNI/symbol checks and the ordinary shipping gate. The
   Linux job additionally runs the separately scoped disposable adapter.
6. Protected `release-candidate-acceptance` requires actual approval **and** the
   authoritative full real-client/platform acceptance producer. That producer
   is currently missing: the explicit Task12 boundary below returns nonzero.

`publish_approved_candidate` never builds, signs, repackages, installs or accepts
a replacement candidate. A read-only preflight compiles trusted verification
adapters from the pinned source. The separate contents:write job under
`release-publication` verifies those same-run adapters' digests, the original
retained candidate ZIP, original run/source/protection/approval provenance,
root, every installer digest and both signature formats again immediately
before creating the release with `--target "$SOURCE_SHA"`.

## Configuration and approval prerequisites

At this work's read-only repository preflight, the public repository had **no
environments configured**. No environment/configuration was created by this
task. YAML labels alone do not authorize release signing or publication.
An authorized administrator must separately configure all four environments:

- `release-candidate-signing`
- `release-candidate-finalization`
- `release-candidate-acceptance`
- `release-publication`

Each requires actual required reviewers and `prevent_self_review=true`.
GET checks bind current positive environment IDs to exactly one approved review
per required identity in the current run. Rejected, duplicate, missing, stale,
recreated or ambiguous review history fails closed. Only integer run attempt 1
is eligible. Failed/rejected runs and GitHub reruns require a **new run and new
approvals**, not approval reuse or timestamp/order inference. The two signing
waves deliberately use different environment identities and approvals.

Configure the raw Ed25519 public pin as repository variable
`NELOMAI_RELEASE_MANIFEST_PUBLIC_KEY_B64`, the separate Tauri public pin as
`NELOMAI_UPDATER_PUBLIC_KEY`, the expected APK certificate as
`ANDROID_SIGNER_SHA256`, and the existing public Firebase application/API/project
values as repository variables. Provision matching private Ed25519 material only
in the signing/finalization environments. Tauri signing key/password and Android
keystore/base64/alias/password secrets belong only to finalization. No private
key is an artifact or job output. The panel's manifest public key must match the
existing release-envelope signer independently of its deployment readiness.

## Retention and promotion identity

Artifacts are retained for 14 days. `candidate-0.2.16` contains only the exact
22-file ordinary shipping allowlist plus `candidate-inventory.json`: four
installers, twelve runtime files, two root files, two existing release-manifest
files and two licensed-source archive/checksum files. Promotion passes the
explicit allowlist to GitHub; it does not use a publication glob.

`acceptance-only-0.2.16` and its `acceptance-inventory.json` are separate. Their
final installer hashes bind synthetic tests to exact candidate/root bytes, but
they are never ordinary shipping assets. Size reports remain in native draft
and package indexes; final signed release metadata also records installer sizes.

Promotion requires `candidate_run_id`, `candidate_artifact_id`,
`release_set_sha256` and `inventory_sha256`. The original run must be a successful
completed first-attempt `workflow_dispatch` of this release workflow at the
exact source SHA/repository. GET artifact metadata must identify that same run,
repository/head repository, artifact ID/name and nonexpired retention. Its
authoritative ZIP digest/size and every extracted file are checked, then checked
again after candidate verification. Caller JSON and a GitHub artifact name do
not replace this provenance. Expired/missing bytes or changed digests require a
new build and acceptance; rebuilding under an old approval is forbidden.

## Actual command boundaries

The workflow supplies explicit paths/pins and runs these existing CLI consumers:

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

## Unclosed acceptance boundary

The Linux executable exercises actual `CommonHost`, `VerifiedRuntime`, inherited
broker/native channels, the unchanged stable executable, real WebView controls
through AT-SPI and actual Unix `TunnelRequestHandler` framing. Only external
native effects use an explicitly labelled test adapter; starting a physical
tunnel returns UNRUN. A separate ordinary startup check executes the actual
packaged common/latest runtime/dispatcher/engine from a root-owned disposable
Linux layout. Docker execution disables external networking, uses a fresh
unprivileged application user, and never invokes a host installer or product
panel. The source-fixed `PANEL_BASE` and TLS trust remain unchanged.

The real production dispatcher is latest-only. More importantly, the immutable
0.2.16 Unix and Windows engines also load Latest and require their own executable
to equal the latest engine path. A future dispatcher alone cannot make these
stable engine bytes work. This is a **known missing implementation requiring a
prepublication Task12 fix**, not a hardware-only UNRUN or future-only deferral.
The supplemental adapter does not claim stable→production dispatcher/engine
acceptance. Any resulting new candidate bytes require fresh signing and tests.

The mandatory full producer interface is:

```text
python scripts/require-candidate-acceptance.py --source-sha SHA40 --release-set-sha256 SHA64 --inventory-sha256 SHA64 --candidate-directory PATH
```

Until Task12 implements and executes authoritative real-client/panel/platform
checks, this command explicitly reports UNRUN and exits nonzero. It accepts no
successful receipt/override. Packaging and Linux supplemental evidence cannot
close it. Full UI→production business HTTP/tunnel flow, actual-release trust,
physical Apple/Windows/Android checks and platform updater installation remain
unrun without the respective environments and authorization. Local macOS app
and Android APK builds are TEST-trust packaging checks only. Task11 candidate
acceptance and publication remain closed despite passing preliminary gates.
