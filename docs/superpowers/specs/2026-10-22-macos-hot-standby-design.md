# macOS hot standby 0.4.0: CI foundation

Date: 2026-10-22. Branch: `Future/macos-hot-standby-0.4.0`.
Starting source: `12d6f73` (`fix(ui): reconcile recovered connection after Start error`).

## Existing production architecture

Keep the current root `launchd` service and versioned engine. The system daemon
`ru.nelomai.tunnel` is installed under `/Library/PrivilegedHelperTools`; its
dispatcher starts the selected engine. `crates/unix-service/src/main.rs` holds
the existing `engine-owner.lock` and composes `PlatformBackend` with
`member_network::runtime::NativePairFactory` through `CompositeBackend`.

On macOS, `NativePairFactory` opens `factory::MacPair`, using the existing
`wireguard-go` and `amneziawg-go` backends for slots A and B. The backend starts
native `utun` interfaces and records member ownership and native identity.
`SessionNetwork` owns shared routing/DNS changes; the shared tunnel session and
role coordinator retain the session, lease and generation rules. Reuse this
path rather than adding another forwarding runtime.

`crates/client-tunnel/src/redundancy/probe_socket.rs` binds each IPv4 DNS probe to
the member's source address and interface index using `IP_BOUND_IF`. Binding
failure aborts before connect/send. The macOS network adapter implements member
routes with `/sbin/route ... -ifscope <interface>`; this system command performs
native routing-socket operations. Its command abstraction also provides route
readback and DNS management through `netstat` and `networksetup`. Existing unit
tests supply command fixtures and do not mutate host routes or DNS. Keep the
current privileged helper architecture; NetworkExtension and a new paid Apple
signing dependency are not prerequisites for this development foundation.

## Hosted CI boundary

`.github/workflows/macos-development.yml` accepts pushes only to this branch and
manual dispatches on this branch in `NelomaiTTT/nelomai-app`. A manual run must
provide the exact full current source SHA. The guard requires the event SHA,
requested SHA, checkout and fetched branch HEAD to agree; a mismatch fails
explicitly. Checkout credentials are not persisted and repository permissions
are read-only.

The single dedicated local macOS VM job (`nelomai-040-macos-vm`, ARM64) uses
Rust `1.88.0`, rustfmt,
clippy and target `aarch64-apple-darwin`. It checks formatting, checks/clippies
Unix service and real desktop application targets, builds the locked frontend,
and compiles/links all service and app binaries including the feature-gated
`nelomai-runtime`. Cargo dependency resolution stays locked. Existing Unix
service, contracts, tunnel, client-core coordinator and client-application tests
run as the ordinary runner user. No ignored privileged native tests are enabled.
Independent validation steps keep failures visible while collecting compile
diagnostics even if formatting fails.

This workflow has no installer, service execution, signing, Keychain, secrets,
release, candidate or publication step, and builds no Linux, Windows or Android
target. Local inspection and edits do not authorize local builds, tests,
dependency installation or network changes on the user's Mac. The first hosted
run may expose baseline macOS defects; its concrete diagnostics must guide fixes.

## Evidence and remaining acceptance

Compile/unit CI is not native hardware acceptance. Successful CI would establish
that the exact source compiles and links for macOS arm64 and passes the selected
existing nonprivileged regressions. It cannot establish real utun ownership,
per-member probe isolation, primary/standby promotion, routing/DNS restoration,
sleep/wake, network changes, stop/recovery or installed-service behavior.
Those require a separately authorized Mac hardware session with real peers and
before/after OS evidence. No macOS hardware acceptance has run yet.

The signed UI recovery check is PASS at the starting source. The earlier Linux
`E0384` exact trigger remains unresolved; neither this macOS foundation nor the
UI result closes it. The PC is now shut down, so no further PC verification is
claimed. Existing platform workflows and all product versions remain unchanged.

## Authorization acceptance (22 October)

VM acceptance must count administrator authorization, Keychain access and
Gatekeeper/background approval separately, alongside hot standby and primary
ready timings. Cover fresh install, new-path signed update, old-updater migration,
Start/Stop, IPC outage, automatic recovery and cancellation.

Target: one administrator authorization for a new-path install/update, no
installer elevation from runtime Start/Stop/recovery, no re-prompt after cancel
within one startup/install operation. The original user UID crosses elevation
explicitly; common and helper installation share the authorization and preserve
rollback. Original Linux preparation behavior remains unchanged.

Initial common application startup retains one bounded repair/migration attempt
after read-only readiness checks. This is deliberately different from runtime
Prepare: the old updater replaces the common broker before updating the helper,
and the old helper rejects that broker before answering Version. Thus this first
legacy migration can require an additional authorization. An unavailable service
at a fresh application startup can also invoke that one repair; runtime polling
and automatic reconnect cannot. Cancellation exits the startup instead of looping.
Do not claim one dialog for legacy migration or zero dialogs under every fault.

Keychain stays with the existing common process and pinned certificate identity;
no relaxed ACL, new credential daemon or Developer ID dependency. Continuity and
actual dialog counts require VM evidence. Hosted CI executes shell fixture and
Rust regressions without touching the user's Mac install or Keychain.

## 0.4.x certificate incident acceptance (23 October)

Before the next signed 0.4.x candidate, audit build and runtime TLS trust for the
eMudhra/emSign incident. Source: https://discuss.python.org/t/109576
User reference: https://x.com/L4UR3N7/status/2113291274664976774
This is a required verification item, not a claim of remediation or compromise.

- Python tooling minimums from the advisory: pip 26.2.2, certifi 2026.10.19;
  uv >=0.13.4 and sigstore >=4.5.1 if used. Bootstrap pip using the advisory's
  exact wheel SHA256, not an unverified upgrade through the affected trust store.
- Check existing venvs, self-hosted runners and container CA bundles separately;
  updating system roots alone does not remove pip's vendored roots.
- client-api uses reqwest rustls-tls. Audit/update resolved webpki-roots and
  rustls-webpki against upstream advisories, including updater TLS dependencies;
  an OS certificate update alone is not proof the shipped binary is remediated.
- Retain signed manifests, artifact hashes, updater signature checks and pinned
  macOS common identity. Never disable TLS verification or trust arbitrary CAs.
- Apply and verify changes within 0.4.x branches only; do not alter 0.3.x, HA,
  production panel or host-wide trust stores as part of this recorded requirement.
