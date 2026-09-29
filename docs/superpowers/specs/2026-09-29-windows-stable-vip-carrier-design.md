# Windows hot standby: stable VIP carrier

Status: proposed architecture, awaiting user review. No product implementation
or additional hardware acceptance is implied by this document.

## Intent and scope

The user approved developing Windows hot standby with one stable local VPN-IP
owner and two addressless native transports. The server-side algorithm must
remain identical for Android, Windows, macOS and Linux: one redundancy session,
one virtual address, independent primary/reserve peers, existing membership and
role generations. Do not add Windows-specific peer allocation, API fields,
server mutations or configuration formats.

Success is two simultaneously usable independent Windows transports, genuine
reserve traffic, safe selection and complete owned cleanup. Preserving the
client IP is necessary but does not itself prove TCP continuity across different
public egress/NAT states. Report failover traffic recovery and existing-connection
continuity separately, without promising lossless switching.

Only Windows pair code changes. Ordinary single-tunnel behavior, Android,
macOS/Linux, authentication, IPC authorization and production panel/agents stay
unchanged. Use the existing main checkout; no branch, release, deployment,
gate bypass or vendor modifications. Windows stays ON; heartbeat stays PAUSED.

## Baseline and evidence

Baseline app source is b0d796a0c5b6a07d0476627ae82c605ccdf50857; successful
CI36555104166 / candidate36555129204 is installed. Do not rebuild, redownload or
reinstall that unchanged candidate. Ordinary Tic/Tak and Stray hardware tests
passed; the complete pair/failover matrix has NOT passed.

Windows refused the same VIP on both native member interfaces. The current
`MemberParameters` requires Address; `open_base` checks that source on the member
interface; `member_guard` combines the member index with its own LUID. That
model cannot represent a source owned by a third interface.

Native experiments in WINDOWS-SHARED-VIP-RESEARCH-2026-09-29.md established:

- Outbound transport observes egress index B and source-holder LUID C.
- Outbound packet observes egress index B and egress LUID B.
- Local weak-host IPFORWARD observes destination index/LUID B, source index/LUID
  C and OUTBOUND_PASS_THRU (0x40000).
- Exact three-layer DNS exceptions delivered real WG replies (3/5, two timeouts)
  and real AWG replies (5/5). Missing exceptions blocked their corresponding
  layer. Raw endpoints/fragments require explicit exclusion from probe permits.
- These experiments used an existing addressed source interface, not a new
  durable carrier; they used one dynamic WFP session, not the product's static
  base/dynamic permit lifetimes. They do not prove two-peer failover or recovery.

## Architecture and alternatives

Choose one session-owned address-only carrier C and addressless native members
A/B. Keep WG through the installed WireGuardNT path and AWG through the installed
AWG service/DLL path. Do not substitute one backend API for the other.

Rejected alternatives: assigning the VIP twice reproduces the native failure;
moving the VIP between A/B destroys source stability; replacing all desktop
engines with Android's userspace dispatcher unnecessarily changes other
platforms and protocol backends. None requires a new server allocation model.

### Carrier C

Use the already installed, trusted Wintun DLL to create a dedicated carrier
with a retained adapter/session handle. Require an already running Wintun driver;
do not silently install, replace or remove a driver. A missing supported driver
is a capability failure, not permission for a new installer action.

Carrier names/GUIDs derive from the authenticated local runtime and full session
scope in a new carrier domain, disjoint from member A/B names and GUIDs. Require
fresh absence before create; never adopt a same-name existing adapter. After
create, capture GUID, LUID, index and adapter type, retain the handle, and verify
the actual identity before and after each native effect.

Assign the validated session addresses exactly once, to C. Require exactly one
canonical IPv4 /32 matching the logical configuration and identical address sets
across members. Any IPv6 address must also remain on C and match both members;
do not silently drop IPv6 or change DNS/split semantics. Unsupported families
must reject pair preparation before effects, not advertise incomplete support.

Retain a bounded, cancellable Wintun session to maintain carrier liveness. It is
not another encryption engine or userspace packet bridge. Traffic accidentally
routed into the carrier must not be forwarded to physical networking. Hardware
proof must establish carrier readiness, source selection, reply delivery and
finite shutdown before this implementation is selected by the factory.

No data default or probe destination route points to C. Owned weak-host changes
are applied only to C and A/B, with full row baseline/readback and exact CAS
restoration. Never enable physical-interface or global forwarding/weak-host
settings. True injected transit must remain blocked despite local pass-through.

### Logical versus native member configuration

Continue accepting the existing server configurations with Address and DNS.
Parse and validate them before producing a separate, zeroizing native rendering
for the Windows pair. Extract addresses/DNS into the pair-owned carrier/network
intent; remove Address/DNS from the native member rendering, force Table=off,
and retain the existing hook rejection and endpoint normalization rules.

Preserve peer keys, preshared keys, AllowedIPs, keepalive and AWG parameters.
Private owner-file hashes describe the exact native rendering, never the logical
input. Logical address validation and native ownership remain separate checks.
Do not weaken ordinary `slot_configuration` or teach the server to emit a
special Windows profile. AWG's own ALE permits must be audited/observed with the
new guard; they must not be treated as proof of standby authorization.

### Routes, DNS and probe sockets

Keep the existing pair route/DNS owner and physical endpoint bypass checks.
Data routes select A or B. Bind every health socket exclusively to the VIP on C
and the explicitly selected egress member; separately attest C's address/DAD
state and the member's GUID/LUID/index/native process/configuration.

Preserve the bounded five-second Tentative-to-Preferred readiness wait and
reattest ownership on every read. Other address states, mismatched identities
and API errors fail immediately. No unbound or physical-network fallback.

DNS belongs to the logical pair and is applied to verified carrier C, not A/B.
This choice requires actual Windows resolver tests with addressless A/B;
if it fails, stop factory enablement and revise this design rather than silently
restoring competing per-member DNS. A successful API write is not DNS acceptance.
Record its exact baseline/current/pending states independently of selected slot.

## WFP authorization

Model carrier identity and each egress identity separately. Preserve index,
LUID, GUID, session/generation checks; do not fix classification by removing a
guard. Add outbound packet layers and forward source/destination identity and
flag conditions to the typed, exactly comparable policy model.

The intended fail-closed lifetime is static, nonpersistent base blocks for the
owned member egresses plus dynamic active-data/probe permits. Active data permits
are restricted to the verified carrier source addresses and selected member,
with the existing routing/split contract. Inactive members receive only the
exact DNS probe exceptions; outer VPN transport retains its verified physical
endpoint bypass and existing service identity checks.

Standby exceptions are a conjunction:

1. Transport: member egress index, carrier LUID, exact source/target, exclusive
   held local port, remote port53, UDP17, NONE_SET IS_RAW_ENDPOINT (0x10).
2. Packet: member index/LUID and exact source/target address family.
3. Forward: destination member index/LUID, source carrier index/LUID, exact
   source/target, ALL_SET OUTBOUND_PASS_THRU (0x40000).

The packet/forward exceptions do not establish socket ownership or encode the
UDP port by themselves. The transport exception supplies that restriction;
all required bases remain installed. Raw, fragmented and foreign/transit
packets must not become a shortcut around a missing transport exception.

Use a new version/domain of deterministic object keys for this layout. Persist
full expected snapshots and transitions. Static bases and dynamic permits have
separate commits; no cross-engine atomicity claim. Withdraw/read back old active
data permits before route selection, install/read back new permits only after
identity/route/DNS verification. Do not publish active/healthy early.

Prove the static-sublayer/dynamic-filter reference and lifetime design natively
before enabling it. On helper exit, dynamic permits must disappear while static
bases continue blocking any surviving member. Static nonpersistent objects do
not survive BFE/OS restart: epoch loss is fail-stop/recovery, never a silent
resume. Do not claim uninterrupted BFE-restart protection without independent
packet evidence. No BFE/global firewall restart is authorized by this spec.

Withdraw permits and prove absence BEFORE releasing their exclusively held
ports. If removal cannot be proved, retain ports until process exit and keep
cleanup pending; never return the port while an allow may remain.

## Durable ownership and lifecycle

Extend the existing protected record/CAS boundary with a typed carrier record.
It includes runtime/boot/scope, generation, prepared/created/configured/closing/
stopped phase, exact native identity, intended addresses and exact owned row
baselines/current/pending mutations. Never store keys or packet contents there.

Journal intended creation before effects, captured identity before address
publication, and each mutation before its native CAS/readback. An ambiguous
creation ACK grants no identity adoption or deletion authority. A fresh claim
must prove carrier absence as well as both member slots and the guard universe.

Old protected pair records remain readable through an explicit cleanup-only
legacy decoder. Recover/retire old resources with their old exact key model;
do not migrate a live old pair into C/A/B or invent a carrier from a missing
field. Unknown versions/foreign identities are rejected without file deletion.
Completed markers and protected anti-replay checks include carrier completion.

Start: durable claim -> prepare carrier -> verify its address/readiness ->
prepare addressless primary -> install/read back bases -> owned routes/DNS ->
dynamic active permits -> verified primary traffic. Reserve acquisition remains
background primary-first; attaching/replacing B never recreates C or changes IP.

Switch: verify generations/carrier/target health -> persist intent -> withdraw
old active data permits -> exact owned route/DNS transition -> verify endpoint
bypasses and identities -> install target permits -> verify data -> publish
local role -> existing idempotent server ACK. Preserve the server-owned
virtual address and retain C through all successful member changes.

Stop: persist closing -> withdraw/prove permit absence -> close probes ->
restore owned routes/DNS -> restore exact owned weak-host rows while all bases
still block -> stop exact members -> remove exact carrier address rows -> end
carrier session/close created handle -> prove native absence -> remove
exact own bases -> complete protected tombstone -> existing panel Stop worker.
WARM is the existing server lease policy; it does not keep local C/A/B alive
after Stop. Stop must not race speculative authentication requests.

Any partial operation leaves a durable cleanup obligation. Recovery never
resumes traffic from journals alone. Index reuse, GUID/LUID mismatch, stale boot,
foreign processes/row changes or unknown guard snapshots stop native mutation.
No journal/auth-file deletion, broad adapter deletion, service-name adoption or
whole-table firewall reset is a recovery strategy.

## Code boundaries

- New portable `member_carrier` ownership/state model and tests in
  crates/windows-service/src; new Windows `windows/member_carrier` native adapter.
- `redundancy.rs`: separate validated addressless pair rendering; ordinary path
  unchanged. Native owner records hash that exact rendering.
- `member_pair.rs` and `windows/member_pair.rs`: compose C/A/B, distinct source
  readiness and egress proofs; extend DNS/cleanup/rebind/completion ordering.
- `member_guard.rs` and `windows/member_guard.rs`: typed three-layer policy,
  distinct identities, versioned key domain and static/dynamic lifetime tests.
- `windows/member_session.rs` and protected file types: carrier storage,
  cleanup-only legacy recovery and completion/empty-claim checks.
- Existing route/probe/owner interfaces get the smallest explicit changes needed
  for carrier identity; no server contract or unrelated platform refactoring.

## Verification and acceptance gates

Before native factory enablement, finish the missing bounded native proofs:
wrong destination/protocol, genuine injected transit with a positive control,
new address-only carrier and reply delivery, and static-base/dynamic-permit
withdrawal/own-process-exit behavior. Use only owned test adapters/services,
30-second diagnostic routes and a retained-handle watchdog of at most60seconds.
Keep LAN/SSH, no physical/global settings, and independent cleanup evidence.

Use RED-to-GREEN tests for logical/native rendering, mismatched addresses,
carrier/member separation, exact WFP conditions, stale generations, foreign
identity/index reuse, each partial Start/Switch/Stop commit, lost ACKs, dynamic
rundown, probe port release ordering and cleanup-only legacy journals. Exercise
real coordinator/record validation paths, not only a new isolated model.

Run Windows-service tests, relevant core/application regressions, full Rust
workspace, strict Clippy/fmt and native Windows CI. Mac cross compilation is not
a substitute for native CI. No unrelated vendor modifications. New app fixes
need a new exact-source sign_candidate run only after code review/tests.

Hardware acceptance uses fresh backup and normal /S /UPDATE, verifies actual
installed/runtime hashes, then Tic/Tak and Stray ordinary/pair/repeat Start/Stop,
two independent fresh handshakes, source-bound primary/reserve traffic, bounded
owned fault injection, role/WARM correctness, IPv4/IPv6/split/DNS/LAN/SSH,
partial-failure cleanup and bounded Start-button observations. Measure UDP
recovery and long-lived TCP behavior separately. No PASS from handshakes alone.

## References

- Existing Windows evidence: /Users/altzxd/Documents/Panel/WINDOWS-SHARED-VIP-RESEARCH-2026-09-29.md.
- [Wintun API and adapter/session lifetime](https://git.zx2c4.com/wintun/about/).
- [WFP engine static/dynamic session lifetime](https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmengineopen0).
- Existing common server allocation: app/client_redundancy.py and
  app/client_pools.py in nelomai-panel; read-only reference, no changes.
