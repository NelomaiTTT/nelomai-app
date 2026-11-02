# Panel HTTPS backup

The user explicitly selected a separate HTTPS address to reserve both domain and
certificate. Extend existing transports, personally and locally on the current
main source e5e2f2ec49226c21b4be2241945711c2be78f196. No push, APK/candidate build,
publication or production changes.

The approved clean HTTPS origins are https://nelomai.ru:443 and
https://nelomai.top:443. Either can use the other once; the default remains .ru.
Preserve path/query/body/auth headers; derive Host and SNI from the alternate URL
and validate its own certificate normally. The existing numeric DNS backup stays
available in the shared Rust resolver for both exact panel names. Other origins,
userinfo and nonstandard ports must not acquire failover.

API login/bootstrap/runtime operations use the common send boundary. Retry at
most once, only after a confirmed DNS/TCP/TLS connection failure before HTTP
transmission. No health preflight, sticky origin, new retry framework or worker.
EOF/read ambiguity, HTTP status and invalid payloads do not replay a submission.
Disable redirects in the common panel client; both attempts share its existing
total timeout. Candidate/route latency probes remain direct measurements of their
requested endpoint: redirecting them would falsify the measured route.

Android updater uses the common transport for manifest and APK GET. Origin/path,
expected version, size, hash and signer gates remain enforced. Desktop updater
uses its supported multiple-manifest-endpoint mechanism (which can also try the
second GET after an HTTP error), then one connect-error fallback for the validated
artifact URL. Existing signature and install barriers remain. Check/download have
single bounded deadlines. No new runtime dependency or reqwest version. The
Android TLS integration test adds only the already used/locked rustls as a dev dependency.

Android native background requests use existing OkHttp calls, cancellation and
EventListener lifecycle: do not retry once headers/body have started. The native
diagnostic uploader separates connection establishment from report writing and
only switches after a definite connection failure, including a timeout during
connection setup before the report. It keeps the existing total 30-second deadline
and cancellation. Timeouts while writing the report or reading its response do not retry.

- [x] Preserve prior DNS-only diff and source hashes.
- [x] RED/GREEN loopback TLS with distinct ru/top certificates: URL, Host/SNI,
  body/auth, TLS/connect failures, no replay after EOF/status/redirect, strict
  origin scope, rejecting the wrong/untrusted backup certificate, shared deadline.
- [x] Integrate API and Android updater; test manifest/APK download and tampered
  payload rejection through real TLS, filesystem and existing validation gates.
- [x] Integrate desktop updater using supported hooks; macOS library compile and
  shared endpoint-policy tests. Actual desktop updater execution remains untested.
- [x] Native Android background and support uploader compilation/JVM tests,
  cancellation and no repeat after sending; native connection errors are injected.
- [x] Eight focused Rust mutations and two native regressions are detected;
  restore source before green runs. Rust API/updater suite and Android compile pass.
- [x] Read-only real /health: controlled local TLS stall for primary, then real
  nelomai.top, its own certificate and standard TLS validation; HTTP 200 in 1377ms.
- [x] Final personal review, source/snapshot hashes and handoff.

Limits: both names currently share one panel host; this is domain/certificate
redundancy, not a second panel server. No emulator/device, APK signing/installation,
release or production modification in this task. Android downloader tests replace
only the installer with a recording handler; native JVM tests inject transport
failures. Existing installed applications require a later authorized release.


## Review fixes (2026-11-02)

Both P2 findings from the personal review are fixed locally:

- RequestBody is one-shot: OkHttp cannot replay an already sent background POST
  internally after HTTP 408/503. Its normal address recovery and the explicit
  HTTPS-origin backup remain available before transmission.
- Diagnostic uploader accepts SocketTimeoutException only in its connection-setup
  catch. Report writes and response reads remain outside that catch. At most one
  backup attempt, existing deadline and cancellation stay in force.

Permanent regressions were RED on the original defects, then GREEN. Actual
loopback HTTP exercises OkHttp's inner retry engine (408 and 503/Retry-After: 0),
plus the real next-IP connection recovery. Support tests inject connect timeout,
partial body write, EOF/read timeout and cancellation; no retry after report bytes.
All 50 focused background/timing/auth JVM cases and 22 support cases pass.
A deliberate global retry disable is caught by the next-IP test; the SSD mutation
is restored and the fallback class passes again. No unrelated Rust suites repeated:
the Rust implementation and dependencies are unchanged by these two fixes.
No APK, emulator/device, push, commit, release or production change.
Evidence: SSD logs/panel-https-backup-20261102/review-fixes/.


## Subsequent native IP integration (2026-11-03)

The user requested the previously missing native IP reserve and explicitly chose
native route order .ru -> .top -> direct IP. See 2026-11-02-native-panel-ip-backup.md.
Support uploads now use the existing OkHttp 4.12.0 rather than HttpsURLConnection;
EventListener/body state and one-shot requests retain the pre-send retry boundary.
Both native paths use bounded/coalesced DNS and an explicit final numeric route,
with the HTTPS hostname/certificate identity retained. Prior review-fix results
above describe their historical snapshots; current evidence is native-panel-ip-20261102.
