# Windows stable VIP carrier implementation plan

## Native code-lifetime join — 02 Oct18:44UTC

- [ ] Add a genuine process-lifetime Wintun image anchor before exposing SDK
  entry: actual `GetModuleHandleExW(PIN | FROM_ADDRESS)` ACK, source/actual
  engine-owner continuity, original attempt retained before postflight,
  Err/unwind/reentry/unknown denial, and no session/serialized-KeyLock retention.
- [ ] Permit repeated cold load only against that actual retained process anchor
  plus current independent signed source/owner verification, never a same-name
  foreign DLL. Require a NEW session LoadLibrary ACK and existing package/lease
  gates. Keep no-C disposition separate from SDK-called Retired closure.
- [ ] TDD the production protocol through external loader/auth doubles, strict
  actual MSVC graph verification, then bounded native acceptance before factory.
  Module pinning prevents code unmapping; it does NOT acknowledge SDK worker or
  resource rundown. Preserve all terminal native/pair/key/DATA obligations.

Actual Startup retained transfer and native LoadLibrary-ACK read suppliers have
completed and are under Main independent review. Original parent HKEY capture
passed45 targeted tests and both strict host/MSVC compilation; root absence still
DENY. Final-stage/Commit concurrency measurement is pending new helper review.

## Current dependency join — 02 Oct18:24UTC

Portable Pair retained construction is implemented and Main independently ran
70 pair tests (exit0). Actual Startup→IO/journal→Pair retained transfer and
actual original LoadLibrary-ACK read pins are still joining; no factory selection
or SDK/unload permission follows from either portable result.

The sole fresh own-HKCU v2 negative execution at18:04:53–55 passed independent
value, namespace and preopened-writer conflict/rollback, preservation and every
acquired native close ACK. Independent18:06:56 postflight confirmed all four
processes absent and retained test keys/mutations unchanged. Both-host evidence
hashes match. This closes failure-disposition measurement only, not production
root deletion or writer exclusion. Positive and historical failing probes are
not repeated/relabelled. New final-stage→Commit helper preparation is separate,
code-only pending Main full review; its native behavior is NOT yet measured.

Primary contract read18:19: [RegOpenKeyTransactedW](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regopenkeytransactedw)
explicitly states that a non-transacted operation before commit rolls back the
transaction. [ZwCreateKeyTransacted](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwcreatekeytransacted)
defines transaction participation for operations using associated key handles;
[NtDeleteKey](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwdeletekey)
is handle-bound and requires separate closes. These support the next hypothesis,
not compound native acceptance. Full security/SACL, actual original parent/key
capture, final commit interleaving and SDK/registry-root lifetime remain OPEN.

Bounded readonly18:09:18 query of the exact historical own carrier GUID
c00c75d4-0490-43e1-af0e-36555129204a found six Tcpip/Tcpip6 paths absent across
CurrentControlSet/ControlSet001/ControlSet002. This two-day/post-reboot observation
does NOT authenticate immediate SDK root rundown or authorize deleting another
key. No SDK/NIC/route/service/registry mutation was performed. Factory remains
legacy; installed successful candidate unchanged; no new build/install/testVPN.

## Next caller-retention join — 02 Oct17:40UTC

Before selecting the native factory, close the earlier Pair Fresh publication
gap as well as Session Starting. `CarrierNativePair::new` currently takes actual
IO/journal by value before fallible Fresh load/CAS/readback and returns no owner
on failure. Add a separate caller-retained constructor (borrowed original input
slots and destination), retain the full coordinator before first store IO, and
permanently deny forward after uncertain publication. Explicit same-scope close
still requires the actual existing cleanup/native authority; absent/equal DATA
cannot authenticate adoption. Preserve ordinary constructor and legacy behavior.
Test actual public production constructor calls with write/lost ACK/unwind,
foreign/nonempty journal, duplicate destination, invalid input and exact original
retention. Then join actual Startup with caller-retained transfer; do not enable
factory merely because the portable constructor tests pass.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete Windows hot standby with one owned local VPN-IP carrier, two independent addressless native members, verified reserve traffic and complete cleanup.

**Architecture:** Keep the common server session/peer/address algorithm unchanged. Windows alone separates logical addresses/DNS from native WG/AWG member profiles. Durable carrier/member/network records and exactly attested fail-closed WFP authorization coordinate Start, Switch, Stop and cleanup-only recovery.

**Tech Stack:** Rust, existing Windows-service/native IPC, Windows IP Helper/WFP, installed signed WireGuardNT/AWG/Wintun, existing protected record CAS.

**Spec:** `docs/superpowers/specs/2026-09-29-windows-stable-vip-carrier-design.md`

## Global constraints

- Work in existing `main` checkout; no new branch/worktree, public release/deploy or gate bypass.
- Preserve both dirty vendor submodules, keys, auth files, protected journals, evidence and unrelated user files.
- No Windows-specific server allocation or API/configuration format; no production manual DB/network/agent changes.
- Ordinary tunnels and Android/macOS/Linux behavior stay unchanged.
- No physical/global weak-host, forwarding, firewall/event collection or BFE restart. No driver installation/removal as a diagnostic workaround.
- Native gates are prerequisites to factory enablement; unproved security is not a reason to remove identity conditions.
- Diagnostics use only fresh exact-owned TEST-NET resources, routes at most30s and retained-process watchdog at most60s.
- Review inline until clean. Human delegated implementation without questions; do not claim a separate user design review occurred.
- After integrated verified code, push main and dispatch only `mode=sign_candidate`, version0.3.3, exactsource, all release flagsfalse. No candidate builds for unused scaffolding.
- Successful candidate is not rebuilt/redownloaded/reinstalled. Check a new build every10min; diagnose red before retry.
- After full hardware tests, preserve report and prove own cleanup; `shutdown /s /t 0` WITHOUT `/f`, verify command acceptance/SSH unavailability, then pause monitor.

## Review focus

### Current integration checkpoint — 02 Oct 17:18 UTC

Main original initial DATA retirement now requires prior actual cleanup handoff,
SAME retained initial ACK/J and a concrete completed-NoC issuer. Genuine compiled
conservative baseline RED2 -> GREEN2; native ownership64 PASS. No active journal
read/CAS can occur after actual index retirement. Pauli fixed eager unborn DATA
capture using real protected execution identity: capture only inside canonical
cleanup handoff and retain before postflight. Main reviewed completed issuer's
PURE callbacks, exact original/context/ten-record proof, no SDK/J reentry.

The explicit initial-NoC completion bridge now orders actual SessionStopped save
ACK -> original DATA retirement ACK -> files.complete ACK -> original alias
release. Compiled RED3 -> GREEN3, expanded4 PASS; each Err/unwind is sticky and
cannot resume live persistence or rerun retirement. Legacy completion unchanged.
The bridge has NOT selected the factory. A new caller-retained common control
preparation API is being implemented to retain owner/store before Starting save.

Fresh whole workspace3974 PASS/0fail/1ignored111summaries EXIT0; actual strict
MSVC alltargets metadata EXIT0 and host strict EXIT0, fmt/diff EXIT0 at this
snapshot (before the additional fourth completion test and preparation work).
No native SDK execution or integrated function acceptance follows from these.

Actual own-HKCU write-enlist proof16:59 EXIT1: positive delete/commit/4closes PASS;
independent value/namespace mutation0 then NtDelete0xc0190003/RollbackTRUE/NOcommit.
Negative branches did not explicitly close native handles and are NOT complete.
Read-only17:05 child/writers absent and mutations retained; evidence SHA matches.
This is detected transaction invalidation, not writer exclusion or product root
deletion authority. Frozen tests are not rerun; new bounded explicit-close and
preopened-writer helper preparation is separate. Product G still requires actual
root absence; restore/handle close cannot grant it. Transaction write-enlist must
precede own-value restoration; manual deletion of OS-populated keys is forbidden.
Factory OFF/legacy selected; no push/candidate/install/testVPN.

### Current integration checkpoint — 02 Oct 16:40 UTC

Factory selection remains OFF; the installed signed candidate is unchanged.
The prior key-root disposition gate intentionally requires genuine root absence,
not APIPA restoration or a handle-close ACK. The 16:18 own-HKCU test disproved
read-only relative-TxR empty-key isolation: an independent accepted value write
was deleted. Do not enable that primitive. A separate 16:38 rollback-only
control passed (actual NtDelete, synchronous rollback, four explicit closes,
original sampled metadata preserved). This proves only that measured path's
transaction participation, not concurrent-writer exclusion. A bounded separate
write-enlist-before-empty-read test is the next hypothesis; no ACL/OS lock or
parent/name delete fallback is authorized. Exact evidence is in Panel research.

The original initial-journal cleanup channel now has 62 host ownership tests
passing: actual retained publication ACK and SAME J, permanent forward closure,
no attach/CAS rearm, no no-C relabelling after real key advancement. The genuine
initialized-Assembly/no-native-effects consumer and authenticated initial DATA
retirement are still joining. Current MSVC strict failures are unused supplier
methods; do not suppress them or equate host tests with native acceptance.
Known partial module/key/carrier/graph cuts and complete factory/hardware gates
below remain open. Keep progress/checkpoints explicit rather than marking a
whole task complete from a narrow unit or native diagnostic result.

- TCP route/classification differs from the passing UDP probe: wrong-protocol traffic must not piggyback on packet/forward exceptions.
- Cold driver state differs between WG and AWG: capability must not silently install a driver or work only after switching from Stray.
- Reused numeric interface indices, names or lost native-create ACKs grant no authority to adopt/delete foreign adapters.
- Legacy protected records remain cleanup-only; unknown versions/extra fields cannot become a live carrier or lose their cleanup obligation.
- DNS API success, two handshakes or non-VPN Internet cannot substitute for source-bound primary/reserve/resolver traffic.

## File map

- `redundancy.rs`: separate validated zeroizing pair-native rendering; ordinary renderer unchanged.
- New `member_carrier.rs` / `member_carrier_tests.rs`: portable identity, phase, protected CAS and exact row mutation ownership.
- New `windows/member_carrier.rs`: trusted installed DLL, fresh native carrier, retained session, bounded readiness/closure.
- `member_guard.rs` / `windows/member_guard.rs`: versioned carrier/egress identities, policy layers/conditions and exact split-engine snapshots.
- `member_pair.rs` / `windows/member_pair.rs`: integrate source-carrier vs egress proofs, DNS and lifecycle ordering.
- `windows/member_session.rs` and protected file enumeration: carrier records/completion, explicit legacy cleanup-only decoder.
- Existing `member_owner`/route/probe contracts: minimum explicit parameter changes for separate source identity.
- Existing unit/integration suites: real coordinator serialization, partial effects, replay and ownership regressions.
- Private Panel evidence root36555129204/windows: bounded native proof helpers/results; never ship these helpers in the application.

### Task 1: Close native design gates before enablement

**Files:** Private bounded diagnostic helpers/results; spec evidence section.

**Interfaces:** Produce measured accepted policy conditions and carrier/driver lifetime requirements. Later tasks cannot enable a native factory until these are recorded with exact evidence.

- [x] Fresh baseline `cargo test --workspace`:2067PASS/0fail/1ignored/110suites, preserved log `/tmp/nelomai-carrier-night30-workspace-baseline.log`.
- [x] Wrong-destination UDP: own transport block; positive controls reach independent sink, all8WFPIDs and own NIC/routes/IPs absent.
- [ ] Wrong-protocol TCP: investigate failing trial, then prove authorization at exact carrier+next-hop identity without allowing raw/fragments/foreign/transit or breaking active TCP.
- [x] Scoped IPv4 withdrawal/new-flow reactivation09:38: own freshC79 VIP5.4/addressless realWG B75 initialHTTP301; withdrawing exactallows aborts existing10053/blocks fresh10013 with trial ALE153504drops2; bind next actual13772 BEFORE installing exactallows restores freshHTTP301. Wholewrapperexit0; independent09:47 all12IDs/NIC-IP-route0/APIPAvaluesabsent and panelnormalStopACK. Native/resultSHA recordedresearch. ExistingTCP continuity/IPv6/generaldata/maincheckbox remain OPEN; later BFE read has expireddrops0, not new negative acceptance. Do not repeat successful narrow gate.
- [x] Additional IPv4 diagnostic sentinel23:38:56: ALE exact next-hop index/LUID plus carrier LUID/src/dst/protocol6 blocked TCP10013/ownALEdrop1, UDP positives retained;9IDs/NIC/routes/IPs absent. Full versioned active/standby policy and existing-flow re-auth remain unproved.
- [x] IPv6 diagnostic sentinel00:05:11: original triple TCP→sink1, exact ALE124959→Winsock10013/drop1, withdrawalTCP→sink1, positiveUDP retained. All5IDs/NIC/routes/IPs absent; SHA recorded in research. This closes only the sentinel counterpart, NOT complete authorization/re-auth.
- [x] IPv4/IPv6 NEW-flow ALE role distinction00:36–00:39: exact probe allows UDP only; active allows newTCP to independent BLOCKsink; withdrawing active blocksnewTCP, withdrawing probe blocksUDP. Wrongports/foreignsource blocked;7v6/11v4 capturedIDs/NIC/routes/IPsabsent. This is not establishedTCP/route re-auth or generalactive-data proof; original main wrong-protocol checkbox remains OPEN until those cases close.
- [ ] New Wintun address-only carrier: retained session/finite shutdown, source readiness/reply delivery and actual resolver behavior with addressless member; no data/probe default route to carrier.
- [x] Fresh Wintun readiness/finiteclose diagnostic00:56: existingmatching signedpackage permitsrunning0→14 without replacement; exactownGUID/index/LUID,128KiBsession, /32Tentative→Preferred<=5s, boundeddrain/sessionend/addressreadabsence/NIC-IP-localroute0. First wrong-description attestation failed before addresses; corrected exacttype/provider/GUID checks, preserved failed evidence. Actualreply/DNS/newcarrier traffic and durableownership stillOPEN; do not mark whole carrier checkboxcomplete.
- [x] Scoped fresh C+realWG boundreply03:21: uniquePreferred4.2/32 onC/addresslessB/precreatedAPIPA0,5/5validDNSreplies/exactALE+triple, eachmissingpermit/withdrawalblocked; native5IDsabsent/weakbaselines/C-B-IP-route0. WholewrapperfailedPS5nestedarraycleanup; independentexactownvalue restoration03:30, evidencepreserved. AutomaticSourceSelectionCimException and actualWindowsresolver OPEN; do not repeat successful boundDNSproof or infer unboundapplication support.
- [x] NarrowIPv4source-selection03:43: exact GetBestRoute2 NULL/explicitsource + no-send UDP default/explicit-egress/explicitbind onfreshownTESTNETtwoWintunC/B, defaultchoosesC, forcedBwithoutbindfails1232/10065. IndependentactualWGv4 03:53 wildcardUDP/noVIPbind/noforcedegress autochoosesC5.2,5/5validDNSreplies/withdrawalblocked,wholewrapperexit0/all5IDs+resources+APIPAvaluescleaned. Find-NetRoute MI_RESULT6 is not ordinarysource-failureproof. Do not repeat.
- [ ] Actual Windows resolver on newly configured ownedC, AWG-new-carrier, and default/split/TCP/general-data selection remain separately gated; direct UDP DNS/handshakes/API-write do not close them.
- [x] Scoped actual IPv4 Windows resolver04:37: DnsQueryEx pDnsServerList=NULL configured-C and default-index0 success; all active DNS permits withdrawn caused timeout/cancel and own ALE drops6. Exact C DNS/metric roundtrip restored;8IDs/NIC/IP/routes/registry absent independently04:39. Wrapper final CIM1018 failure retained separately. No held-port standby/general DNS/split/failover claim; AWG/defaultTCP/main combined gate remains OPEN.
- [x] Scoped fresh-C/addresslessAWG IPv4 proof05:55: uniqueC73/a40...a Preferred3.2/32/session, AWGCarrier3 B75/dca... ownSCM, bounded capturedconfigRAM/SYSTEM-onlypipe, exactheldUDP53/ALE+triple 5/5valid61byteDNSanswers; withdrawal10060/transportdrop1. Wholewrapperexit0, independent05:57 eightIDs146051–146058/NIC/IP/route/service/hostprocess0/APIPAvaluesabsent. SevenevidenceSHAremoteMATCH; v1–v3 orchestrationfailures retained. No fullpair/generaldata/IPv6AWG/staticbase-crash claim; do not repeat accepted gate.
- [ ] Cold WG/AWG carrier bootstrap: inspect installed driver ownership/loading; support both without silent driver replacement or report a capability failure before effects.
- [x] True injected transit MECHANISM with independent positive control, both families: own TEST-NET ingress only, current forward exception rejects it; no physical/global forwarding. Product adapter/recovery/fullpolicy acceptance remains open.
- [x] IPv4 injected-transit subgate01:51: own freshWintunC/nopeerWG B, nonlocal192.0.2.220; current OUTBOUND_PASS_THRU condition blocks at forwardbase, removing onlythatcondition reaches independentFORWARD BLOCKsink; restoring blocksagain. All18IDs/NIC-IP-routesabsent/ownbaselinesrestored. Initial packet-sink positive missing retained NOTPASS; v6 counterpart stillOPEN, main checkbox notclosed.
- [x] IPv6 counterpart06:12:32 correctedv2: ownC75/b70...a source::211, injectionnonlocal::220 viaB77/...b; passThroughOnly→base147833drop1, removeONLYALL0x40000→independentFORWARDsink147835drop1, restored→baseDrop1. All14IDs/NIC-IP-route0/rowsrestored/exit0, independent06:15:45 cleanup. Native24d5a745/result03813cd2 SHA remoteMATCH. Initialv1socketinvalidargument beforeWFP retained; v2hostorderIPv6UNICAST_IF CompileOnlyregressionPASS. NotactualIPv6peer/product/failoveracceptance; do not repeat.
- [x] Native mechanism proof IPv4/IPv6 01:30–01:32: static nonpersistent ALE base/sublayer survive creatorengineclose; independent child dynamic UDP allow referencesstatic sublayer; exact retainedchildkill removesallow while SAMEbase againblocks heldsocket, all10v4/6v6IDs/subkeys/NIC-IP-routes absent. Product protected-store/all-base recovery remainsTask5, no BFE restart. Initial metadata/child failures retained; explicitINDEXED64 permit and exact capturedsubweight65531. Task4 must represent8ALEconditions/flags without weakeninglegacydecoder.
- [ ] Review all results against spec, revise policy only from measured classification, then permit Task2–5 integration. Do not mark unresolved gates PASS.

### Task 2: Logical/native configuration separation

**Files:** `crates/windows-service/src/redundancy.rs`, renderer tests and `member_pair.rs` parsing tests.

**Interfaces:** `pair_configuration(input: &str) -> Result<PairConfiguration, ServiceError>` returns zeroizing `native`, canonical logical `addresses: Vec<ipnet::IpNet>` and `dns: Vec<IpAddr>`. `PairConfiguration::matches_network(&self, other: &Self) -> bool` compares the validated logical network, not keys/endpoint/AllowedIPs.

- [x] Tests: same logical VIP/DNS with different peers yields equal network; native retains peer/AWG fields and `Table=off`, excludes Address/DNS/hooks; ordinary rendering retains Address.
- [x] RED observed for missing validation; correctedpositive fixture mutation RED→GREEN; original malformed synthetic key corrected and not claimed as acceptance.
- [x] Separate rendering uses existing section/hook/frame and actual MemberParameters validation. One usable IPv4/32; duplicates/unknown/misplaced network fields/unsupported IPv6 rejected before effects. IPv6 remains gated on native implementation.
- [x] Negatives cover broad masks, repeated addresses/DNS, mismatched sibling VIP, unknown/misplaced fields, hooks, max frame/NUL, bad DNS, reserved addresses. Secret-bearing native rendering is zeroizing, errors contain no input.
- [x] Local commit6839e9db82a099d841c10e7549acf8218a8ef250 after inline review/fix/407windows-servicePASS13suites/2073workspacePASS111suites/strict hostClippy/fmt/diffPASS. No factory change, push or unused-scaffold candidate; nativeWindowsCI still required before integrated acceptance.

### Task 3: Durable owned carrier lifecycle

**Files:** New portable/native carrier modules; `lib.rs` module declaration; protected record store.

**Interfaces:** Portable `Intent { scope, addresses }`, `Record { version, intent, phase, proof, pending_rows }`, `CarrierIo` exact inspect/create/configure/restore/close, `CarrierJournal` durable compare_exchange, `CarrierOwner::prepare/stop` returning an exact `InterfaceProof`. Native implementation consumes validated Task2 addresses and trusted existing driver capability from Task1.

- [x] Portable scoped RED→GREEN state-machine tests for journal-before-create, captured proof-before-address publication and address readiness-before-use; nativeadapter remainsOPEN.
- [x] Portable foreign/index reuse, stale boot/runtime/generation, ambiguous create ACK, changed weak-host baseline, lost CAS ACK and each partial native effect; failures retain cleanup obligations without adoption/deletion.31tests/fresh438servicePASS/mainreview/local9028e29; native effects notclaimed.
- [x] Portable phases prepared/created/configured/closing/stopped with exact pending mutation/readback and deterministic new carrier key domain. No nativeadapter/store/factory enabled.
- [x] Protected store scoped integration3fbfa8f: fixed64KiB carrier file, exact authenticated fullscope/boot/runtime/epoch, exactCAS/reread/lostACKrevocation, cleanup-only reopen, completion/empty/retirement carrier checks, legacyabsentcarrier compatibility.25newstoretests+fileboundtest, maininline scopedreview/fresh464servicePASS/2130workspacePASS0fail1ignored111suites/strictClippyfmt. Nativeadapter/fullrow fidelity/NEWlayoutmandatorycarrier and factory remainOPEN; no push/scaffoldcandidate.
- [ ] Implement Windows adapter/session handles using audited installed DLL/API; require fresh exact-name/GUID absence and bounded cancellable draining/closure. Driver capability/load path must match Task1, not guess API side effects.
- [x] Scoped retained Wintun substrate7b54241: real nine audited APIs, original adapter/session/DLL references, exact native identity/absence, finite cooperative drain/close and required real precreation receipt. Main read all896 code/682 tests/report; fresh29 standalonePASS and actual MSVC alltargetsClippyPASS. Real authenticated pre-load package/module authority and hard in-flight native-call supervision remain OPEN; no factory/native acceptance.
- [x] Scoped actual signed DLL source pin8a08a48: kernelcurrentexe/fullsignedInstallation/allpayloads, fixed signed shared-library entry, actualheldArcMutationGuard and private/non-reparse/single-link noWRITE-noDELETE-sharing source/ancestor handle continuity. FourportabletestsRED→GREEN; freshfull2250PASS/strict host+MSVCalltargets/fmt/diff/mainreview. TwoactualWin32owned-temp tests crosscompiled ONLY, nativeCI notRUN. Package maintenance/exec/effectauthority/creatorinventory/factoryremainOPEN; no executableload or capability acceptance.
- [ ] Extend native/durable ownership to exact precreation C/A/B interface-key and APIPA-value authority. Require RegCreateKeyEx CREATED_NEW_KEY ACK and journal-before-effects; ambiguous ACK cannot adopt/delete. Exact baseline/current/pending restoration without key-tree deletion; full native address/IP-interface metadata, not only logical rows, mandatory before factory.
- [x] Scoped cold data-only package + actual safe source-preload composition e48fedd: audited raw PE/embedded INF, real SetupAPI/DriverStore/alllegacy-problemdevice/SCM/pendingrename/signature/catalog queries and retained readonly pins; original signed WintunSource/heldArc owner source→package→source bracket with irreversible failure/unwind revocation. Main read ALL1510code/619tests/report;28package+3wrapper tests, freshfull2281PASS/strict host+MSVCalltargets/fmt/diff. Native execution UNRUN; coldStopped/noWintundevices only, not post-load/create/effect/module/factory authority. No unused-scaffold candidate.
- [x] Actual cold DATA gate01Oct00:17UTC v10 PASS after e39776d narrow unrelated pending-delete proof + local0e72c55 exact two-name SYS alias proof and exact SHA256-pinned CAT's actual SHA1 member tags. Native inventory/trust/bytes/member signatures and full repeat reattest accepted; 2294workspace/strict host+actualMSVC/fmt/diff PASS. No OS queue/file/driver changes. This closes DATA preflight ONLY, not executable load/module/effect/factory authorization; see current Panel HANDOFF/evidence oct01-package-readback-v10.
- [x] Scoped native key/row boundaries3b2de68 plus protected full-row journals4df9344: exact64KiB C/A/B namespaces, full typed metadata, all8-record inventory, raw/typed revision firewall, shared fresh-ACK revocation and cleanup-only reopen. Main read allcode/diffs/new1284tests/report and fixed old5-owner fixture with actual three typed row lifecycles, no inventory reduction; fresh2246workspacePASS/0fail/1ignored111suites. Nativeeffects not accepted.
- [x] Scoped actual KEY-only authority7b54241+retained MutationGuard continuity6b53ac9: real signed installed runtime/hash/boot/held lock/private root/protected pending bytes/fresh permission/native absence rechecks; 112key-host/70contractsPASS/strict host+MSVC. Original creator inventory, package/module authority, full concrete effect tests and factory composition remain OPEN; no successful defaults.
- [ ] Implement five-second Tentative wait with owner reattestation each read; duplicate/deprecated/error fails immediately. Persist exact baseline/current/pending weak-host/address rows; restore only exact own CAS matches.
- [x] Scoped retained RowOwner readiness inline reviewed/committed local82aaa2c after human resume01OctMSK: acknowledged original creation + full native/protected row checks each poll,5s cooperative deadline/cancellation/permanent revocation;56focused/678expandedhost andfresh2284workspacePASS, strict host/MSVCalltargetsClippy/fmt/diffPASS. No native readiness/hard-call interruption/concrete creator/module/factory acceptance. Fresh post-reboot DATA-ONLY package gate remains MaintenanceRequired from2foreign pending deletion pairs, no system/queue changes; full Task3/above integration checkbox remains OPEN.
- [ ] Run portable suite/native CI checks, review and commit. Keep native factory disabled until all gates and Task5 composition pass.
- [x] Local scoped e2589df original cold module/source/SAME-KeyLock/package pin and kernel installation lease substrate. Main reviewed actual code +28lock/8module tests; full2336PASS, strict host+actualMSVC/fmt/diff. Actual SYSTEM kernel-only01Oct01:30:56 helper851eade2... PASS proves recursive/exact mutex compatibility and upstream alias availability after native ERROR_DUP_NAME52 fix; no DLL/NIC effects. New owned protected ProgramData evidence directory, own temporary task removed01:32:47 with exact Ready/SYSTEM/action guards. Executable/native effect/post-create package/creator/factory acceptance remains OPEN; no push/scaffold candidate.

### Task 4: Versioned fail-closed authorization

**Files:** Portable/native member guard and tests; expected snapshot serialization.

**Interfaces:** Carrier proof distinct from `[Member;2]` egress proofs; typed PacketV4/V6, forward source/destination identities, raw/pass-through flags and any Task1-proven additional authorization layer. Preserve split static-base/dynamic-permit exchange plans and full exact snapshots.

- [ ] Write failing policy tests for exact carrier/egress separation and Task1 TCP/raw/transit conditions, both families, identity reuse and unknown condition/version rejection.
- [x] Portable sidecar scoped c85951a: typed four-layer v4/v6 policy/domainv2/exactC-A-Bproofs, strict fullsnapshots, durableJournaledPlan/capturedpriority-beforeallow, splitfaultmatrix/foreign/stale guards; 21tests RED→GREEN, mainreadall845+954lines, fresh2151workspacePASS0fail1ignored111suites/strictserviceClippyfmt. No legacy/native decoder or factory enabled; remaining native tests and complete Task4 OPEN. Nativeadapter code delegatedGodel06:00 to disjointnewWindowsfiles only.
- [ ] Implement only natively proven policy; static blocks survive dynamic allow process exit, with no cross-engine atomicity claim and no removal of ownership guards.
- [ ] Test each partial exchange/lost ACK, withdraw-before-route-switch, verify-before-active-publication and allow absence-before-releasing exclusive ports.
- [ ] Add legacy policy decoder used ONLY to close old records with old keys; no active migration or missing-field carrier inference.
- [ ] Run complete windows-service suite, strict host/native Clippy/CI; review and commit. No unused-scaffold candidate.

### Task 5: Pair/coordinator integration and recovery

**Files:** Portable/native pair, session store/completion, source probe and DNS/network owner call sites.

**Interfaces:** Task2 logical intent plus Task3 carrier proof plus Task4 versioned guard; native member owner hashes exactly the addressless rendering. Protected completion includes C+A+B and expected network/guard universe.

- [ ] Write failing real coordinator tests: Start C once then independent A/B; B attach/rebind/switch never recreates C; mismatched logical network rejects before effects.
- [ ] Compose Start: durable claim/carrier/readiness, addressless primary, exact bases, owned routes/DNS on C, verified dynamic allows/data; reserve remains primary-first background.
- [x] Scoped actual MemberOwner addressless consumer0c852d9: strict logical pair scope/address/config and real WG/AWG detector before same durable Prepare/config-CAS/Start/Running/Stop flow; six regressions/full2300PASS/strict checks. Ordinary renderer unchanged. This does not enable carrier factory or complete Start/Switch/Stop composition.
- [ ] Compose Switch: generation/carrier/target proof, durable intent, withdraw/readback old allows, exact route/DNS transition, new allows, verified data, publish and existing idempotent server ACK.
- [ ] Compose Stop: durable closing, allow absence, held sockets, network/weak rows, exact members, carrier addresses/session, native absence, bases, protected tombstone and existing panel worker. No speculative auth race.
- [ ] Tests for every partial Start/Switch/Stop commit, legacy cleanup-only replay, foreign resources, WARM last primary, unknown versions and stale generations; ensure no ordinary/platform/server behavior change.
- [ ] Full workspace, desktop/core regressions, strict Clippy/fmt/diff and native Windows CI. Re-review/fix until clean, then integrate factory; repeat complete verification after enablement.

#### Task 5 installer execution-role integration (02Oct)

Actual NSIS preinstall executes the NEW embedded helper from PLUGINSDIR before
the incoming runtime is unpacked. That process is not the OLD engine and its
temporary directory cannot satisfy the native privileged payload ACL contract.
No authentication fallback or temporary-path ACL relaxation is permitted.

- [x] TDD real signed fixture: NEW helper metadata/executable bytes authenticate
  as staging DATA only; wrong hash/signature/file role/slot/foreign layout deny.
- [x] Temporary bootstrap may only copy signature-verified helper + immutable
  signed metadata into a fresh exclusively created private child of the pinned
  existing Nelomai privileged root. No native/SCM/route/registry cleanup there.
- [x] Launch the staged helper with a dedicated cleanup-only execution role,
  bounded retained child lifetime. Authenticate actual protected executable,
  full OLD installed selected slot, SAME owner lock/private records each edge.
  No incoming DLL needs to be loaded or copied for this cleanup-only lane.
- [x] Preserve failed stage/evidence and all old ownership obligations. Never
  replace a foreign/existing stage or manually erase auth/journals. Update NSIS
  and extracted signed-package gates to bind metadata/helper to the new bundle.
- [ ] Verify host/MSVC/build then normal hardware /S /UPDATE with fresh backup;
  code/packaging verification alone is not installer acceptance.

Code-only verification 02Oct13:07UTC: actual signed installer recovery20PASS,
contracts71PASS (including same-size dispatcher tamper and distinct signed
Stable engine vs Latest dispatcher substitution), scripts182PASS/6skips.
Actual MSVC alltargets strict EXIT0 in
`/tmp/nelomai-oct02-native-state-backend-final-clippy.log` after original
state-backend getter and Copy-clone corrections; strict contracts HOST EXIT0.
This dated snapshot does not close final installer checkbox: no new candidate
or native installer execution has occurred, and product factory stays gated.

#### Task 5 epoch join — original birth domain versus current execution

Source-confirmed prerequisite (01Oct23:40UTC): common SessionControl deliberately
publishes epoch1 ->2 before native rebind ->3 after successful validation.
`validated_network_rebind_advances_epoch_twice_and_requires_fresh_evidence`
pins this contract. Do not remove the second increment or relax stale callbacks.
The new native Runtime currently compares immutable birth Context with current
Session epoch, so it cannot yet rebind. This is OPEN, not an external blocker.

**Files:** new `windows/member_carrier_epoch.rs` and tests; original protected
`windows/member_session.rs` ACK trace; `member_carrier_key_authority.rs`,
`member_carrier_pair_io.rs` and coordinator joins after the trace is verified.

**Interfaces:** same-backend/successful-claim original Session ACK history and
opaque current ACK read, privately produced by the actual Session CAS path.
These are factual read capabilities, not SDK permissions. The immutable
carrier birth Context must remain separate from a explicitly renewed execution
lease. Runtime/native journal effects need the SAME original execution lease,
current protected ACK and actual Calling/Pair/resource parents; arbitrary old
Context acceptance or copying the observed epoch into Context is forbidden.

- [ ] TDD actual ProtectedSessionFiles transaction path: initial claim, actual
  Session write ACK, Running epoch1, suspended epoch2 and completion epoch3;
  changed backend/scope/boot/runtime, missing ACK, lost write/readback ACK,
  reentry/unwind and file replacement all deny. Retain original ACK before
  fallible postflight; do not mint ACK from equal JSON or a missing file.
- [ ] Implement current Session ACK trace without changing legacy behavior or
  Runtime.verify permissions. Native current-reader and consumer registrations
  must share the actual original, not a strong ownership cycle.
- [ ] Implement explicit execution renewal for native Rebind and the exact
  completion transition. Reattest SAME C and actual A/B generations; no C
  recreation or birth-journal rewrite. Journal CAS must remain scoped to the
  original native record owner and current execution ACK, never blanket access
  to records with a lower epoch.
- [ ] Regression joins cover guard withdrawal before physical mutation, stale
  physical path versus owned row deletion, old held-probe callbacks, network
  plan recapture, both epoch transitions, skipped epochs and every lost ACK.
  Keep forward authority revoked on ambiguity and preserve scoped cleanup.
- [ ] Run actual native type-bound compilation, fresh complete tests and inline
  review before factory selection; this subsection is not acceptance evidence.

### Task 6: Candidate and real acceptance

**Files:** Checkpoint/handoff, per-run private verification/inventory and Windows evidence.

- [ ] Push reviewed main and verify exact remote SHA. Dispatch release.yml once with candidate-only parameters above; record CI/source/run and monitor every10min.
- [ ] Red CI: read logs, establish cause, add regression/fix/re-review and push new exact-source candidate; infra retry only addressed after cause.
- [ ] Both success: read verifier fully and pass ALL parameters; validate22assets, SHA256, runtime/updater/Mac signatures, skipped publish and absent v0.3.3 tag/release. Do not repeat successful build.
- [ ] Fresh backup/logs and normal `/S /UPDATE`, preserve login/data; LimitedUI actual runtime/files exact candidate SHA.
- [ ] Tic/Tak+Stray ordinary/pair/repeat Start/Stop, cold capability, TWO independent handshakes and actual source-bound primary/reserve traffic. Exact-flow fault injection with auto-revert/SSH preserved; measure recovery vs TCP continuity separately.
- [ ] Verify role/WARM last primary, IPv4/IPv6/split/resolver, LAN/SSH, services/routes/addresses/leases cleanup and bounded Start semantic/pixel observations. A failed/unperformed row is never PASS.
- [ ] Save report/evidence, stop only own test VPN, prove cleanup, remove only exact-owned nonrunning temporary tasks; normal shutdown without `/f`, acceptance+SSH failure, then pause monitor.
