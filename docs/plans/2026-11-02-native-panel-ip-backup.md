# Native panel IP backup implementation plan

Goal: add the already approved 45.144.221.68 fallback to native Android background
requests and support uploads. The user explicitly specified the order:
nelomai.ru, nelomai.top, then direct IP. The direct-IP connection retains an
approved HTTPS hostname, path, headers and normal SNI/certificate validation;
after pre-HTTP TLS failure it may try the other approved name on the same IP.

Execute personally on the current main source and existing local HTTPS changes.
No push, commit, APK/candidate, emulator, publication or production modification.
Original source stays internal; all generated files, tests, cache and logs on SSD.

Design: keep the existing request/retry boundaries. Normal DNS attempts do not
receive the IP early. An explicit third-route tag selects a numeric-address DNS
resolver without changing the URL. DNS lookup is bounded to one second for the two
approved hostnames; at most one unresolved OS query per hostname is shared across
callers, using two bounded workers. Completed answers are not cached here.
Other hostnames retain normal resolution and never receive the panel IP.

Background transport already uses OkHttp. Support uploader moves its direct native
HTTPS request from HttpsURLConnection to the same already used OkHttp 4.12.0, whose
DNS hook avoids custom certificate verifiers or SSL socket tricks. It remains
independent of ClientApi/runtime IPC/account credentials. Both paths keep one-shot
bodies, the existing overall deadline, sticky cancellation and no repeat after
HTTP transmission. Preserve support parsing, limits, privacy and public results.

This is an implementation choice, not a new user-approved API/library version:
reuse the existing library version, declare it directly for the container module.
The existing Rust DNS transport is outside this native-only change.

- [x] RED: permanent route-order regressions show only two attempts before change.
- [x] Add the shared bounded DNS policy and direct-IP route marker, with scope,
  stall/recovery, concurrent caller and interruption tests.
- [x] Integrate the background client's third route and real DNS hook.
- [x] Integrate support uploads with the same library and IP selection; retain
  prior behavior tests using request/response doubles at the Call boundary.
- [x] Actual loopback TLS through the production client-selection hooks: failed
  DNS for both names, third-route numeric destination, proper Host/SNI and payload,
  rejected wrong/untrusted certificates and no HTTP replay. See the review fix
  below for the bounded alternate TLS identity within the final numeric phase.
- [x] Focused mutation checks and nearby JVM tests, not unrelated Rust/full suites.
- [x] Personal review, restored snapshot/source proof and handoff with test limits.

The one-second DNS timeout is necessary: a stalled OS lookup must not consume the
entire request before the numeric route. Outstanding timed-out OS queries remain
bounded/coalesced until they actually finish; cancelling only a waiter must not
create an unbounded stream of DNS jobs. Existing 30-second operation limits stay.


Result (2026-11-03): 89 targeted JVM cases pass, and the actual Android container
Kotlin compilation passes with generated inputs from the exact locked Tauri/Wry
packages. No Rust/native build or APK packaging was run. Eight mutations were
caught (IP hooks/order/hostname verification/partial replay/DNS scope/deadline),
then restored; final source matches the SSD snapshot. A further proxy regression
was RED, then fixed: the numeric route explicitly uses Proxy.NO_PROXY.

Both native client-selection hooks also performed real read-only GET /health on
45.144.221.68 with URL/SNI nelomai.top, standard trust/hostname validation and
TLS 1.3: both HTTP 200. No report or authenticated mutation was sent to production.
Wrong-name/untrusted certificates, actual Host/SNI/body, HTTP 408/503/redirect,
partial writes, DNS stalls/concurrency and cancellation are covered locally.

The IP phase preserves an approved HTTPS identity rather than turning the URL
into an IP URL. Following the review fix below, either approved name may be used;
at least one valid certificate and a reachable panel host remain necessary.
Actual Android OS/emulator/device behavior and APK acceptance were not run.
The existing Rust transport/order is unchanged.
Evidence: /Volumes/Apple-VM/Nelomai/android-050/logs/native-panel-ip-20261102/.

## Review fix — 2026-11-03

The last-name-only IP policy above is superseded by the confirmed review P2 and
the user's instruction to fix it. Keep `.ru -> .top -> IP`; only when the first
IP attempt fails TLS before HTTP, try the other approved hostname on the same IP.
No new DNS lookup, dependency, verifier or deadline. TCP failure on the numeric
route still stops immediately; after any HTTP starts, no identity retry.

- [x] Extend both permanent TLS suites with the combined primary-DNS/backup-TLS
  outage and both-DNS outage cases; observe RED with the original code.
- [x] Add the one bounded pre-HTTP TLS-identity transition in the two existing
  retry loops. Preserve the direct-IP tag, Host replacement, deadline and cancel.
- [x] Verify real TLS/name/body/auth, untrusted certificate rejection, cancellation
  before the alternate IP identity and no replay after partial/complete sends.
- [x] Run targeted native suites, focused regression mutations and container
  Kotlin compilation on the SSD. Review the fix delta, update evidence/handoff.

No commit, push, APK/candidate, emulator, publication or production changes.

Fix verification: 90 targeted native JVM cases passed. Both new real-TLS
regressions were RED before the fix; the successful cases cover primary DNS
failure with backup TLS failure and both DNS names unavailable. The final TLS
suites and late-write cases passed again after restoring six detected mutations
(deadline reset, hostname-verification bypass and post-HTTP replay in each
client). Actual container Kotlin compilation passed. DNS/socket remapping and
test trust roots are controlled; standard hostname verification is real.
Evidence: logs/native-panel-ip-20261102/certificate-fix/ on Apple-VM.
