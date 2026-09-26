# Stable macOS common identity

The common host owns file-based Keychain access. Its release signature now uses
one persistent self-signed certificate, not a per-build ad-hoc cdhash identity.
Developer ID is not required for this Keychain mechanism. This does **not**
provide notarization or bypass Gatekeeper, admin authorization, locked keychains,
or approval to access records created by previous ad-hoc releases.

## One-time provisioning (separate authorized operation)

In GitHub environment `release-candidate-finalization`, configure:

- Secret `NELOMAI_MACOS_SIGNING_P12_BASE64`: base64 PKCS#12 containing the
  persistent code-signing certificate and its private key.
- Secret `NELOMAI_MACOS_SIGNING_P12_PASSWORD`: nonempty password for that P12.
- Variable `NELOMAI_MACOS_SIGNER_SHA1`: the certificate's 40 hexadecimal SHA1
  fingerprint, without colons (not the P12 file digest). This is the certificate
  identity syntax used by macOS designated requirements, not an archive hash.

Use a certificate with digitalSignature/codeSigning usage and a planned lifetime.
Keep a protected offline backup of both identity and password. Do not regenerate
the certificate per release, use the disposable test identity, or upload its key
to source control. Certificate replacement changes the designated requirement and
needs a separate migration plan. No certificate is installed as a system trust root.

Until provisioned, `sign_candidate` and `build_and_publish` fail closed at common
signing. `build_only` still works without these credentials. Setting the secrets
or generating a production key is **not** part of the local code change.

## Release path

1. Existing native packaging compiles without private signing credentials and
   verifies the exact embedded runtime and dispatcher payloads.
2. Protected `macos_common_sign` downloads `packages-macos`, checks its source,
   release-set and archive digest, and signs a copy of **only** the outer common
   app. Identifier is `ru.nelomai.client`; its designated requirement pins this
   identifier and the leaf certificate fingerprint. No `--deep` signing.
3. Strict signature/requirement checks and comparisons before/after signing and
   re-extraction enforce unchanged nested payloads. The final package/index is
   uploaded as `signed-common-macos`; the original artifact is not overwritten.
4. Linux finalization consumes this artifact, checks its pinned signing metadata
   and archive digest, then generates the existing updater signature and shipping
   inventory. There are still 22 shipping assets. Metadata records the native
   phase's verification; it is not a substitute for native codesign validation.

The P12 is imported into a private temporary keychain, with codesign access only
for that keychain. The original keychain search list is restored and the temporary
keychain/P12 removed in cleanup. Default/login keychains and real application
records are not changed. Forced runner termination cannot guarantee Python cleanup;
this job must use the disposable GitHub-hosted macOS runner, not a user's workstation
or persistent shared signing runner.

Retained candidates use their existing artifacts and publication checks. They are
not re-signed by promotion. A new source change requires a new candidate as usual.

## Validation and limits

Run `python -m unittest scripts.tests.test_macos_common_signing
scripts.tests.test_macos_signing_finalization scripts.tests.test_release_workflow`.
On a test Mac, `NELOMAI_TEST_NATIVE_SIGNING=1 python -m unittest
scripts.tests.test_macos_common_signing` also signs two synthetic bundles with a
disposable certificate and checks cleanup; it does not install Nelomai.

Stable identity can avoid repeated Keychain prompts for newly created records
while the keychain is unlocked. Migrating old ad-hoc item permissions remains
separate. No full-install dialog count or silent first-upgrade migration is claimed.
