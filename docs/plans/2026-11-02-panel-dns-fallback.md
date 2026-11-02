# Panel DNS fallback

User request: add a backup panel IP to the application after the Beget DNS outage.
Base: main 8e75162f9966deffe07ab83a150cdc40d259cf58. Work personally; no push,
APK/candidate build, publication or production changes.

Keep https://nelomai.ru as the origin. Resolve through the OS first. Only for
the exact panel hostname, use 45.144.221.68 after a DNS error, empty result or
one-second DNS timeout. Preserve HTTPS verification, SNI, Host, authentication,
existing request deadlines and update signature/origin checks. Resolve before
sending; never replay a request to implement fallback. A successful DNS answer
always wins, including after recovery. Other names retain normal OS resolution.

Use reqwest's resolver hook in the common API/reset/fresh-probe clients and
Android updater. The desktop updater uses reqwest 0.13 rather than 0.12; pass
the same resolver's address snapshot through its existing configure_client hook
for both manifest and artifact requests. No new DNS service, cache, HTTP retry
mechanism or runtime dependency version.

Checks (all generated files/caches on Apple-VM, source env.sh):

- [x] RED: controlled DNS error, empty response, stall and hostname scope tests.
- [x] GREEN: common resolver and API/Android/desktop update integration.
- [x] Real loopback HTTPS: correct SNI/Host/body, one POST, reject untrusted
  certificate and wrong hostname; preserve a server error without replay.
- [x] API/updater package tests, targeted desktop compile and formatting.
- [x] Targeted mutations: omitted fallback, ignored healthy DNS, removed
  hostname restriction and wrong timeout boundary. Restore and verify sources.
- [x] Review final diff and document tested mechanisms and remaining limits.

This only survives failure of DNS, not failure of the panel host. Existing
installed binaries gain this behavior only after an explicitly authorized update.

Review follow-up (2026-11-02): HTTPS tests now use the unchanged public factory
and production PanelDns. A current-thread scoped, RAII-restored cfg(test) fixture
replaces only the OS lookup result and backup destination (loopback). No custom
reqwest resolver is installed by the tests. Confirmed old tests missed removal
of the factory's resolver; corrected tests detect that mutation, omitted fallback
and disabled certificate validation. All 71 API/updater tests pass after restore.
No APK build, push, publication, production or device changes.

## Follow-up: independent backup DNS name (2026-11-02)

After setting up nelomai.top, the user asked to continue. Implement the smallest
extension of the existing DNS mechanism: healthy nelomai.ru DNS wins; otherwise
use addresses resolved for nelomai.top; keep the numeric backup when both fail.
This is the implementer's default, not a separate HTTPS-origin failover feature.
The URL, TLS identity, authentication and updater origin/signature policies stay
nelomai.ru. A separate HTTPS origin remains a distinct choice discussed with the user.

Resolve the two exact names concurrently within the SAME one-second deadline.
Return healthy primary DNS immediately, without waiting for the backup. If the
backup finishes first, retain its result while giving the primary its existing
budget. No new dependency, DNS cache, HTTP retry or background task. Other hosts
use only their normal OS lookup. Reset/recovery continues using the common factory.

- [x] RED: secondary DNS success after primary error/empty/stall; primary wins
  even when secondary responds first; one shared deadline and healthy fast path.
- [x] GREEN: extend only the shared resolver and its existing HTTPS DNS fixtures.
- [x] Real loopback HTTPS through the public factory: distinguish secondary
  addresses from the static IP, preserve SNI/Host/body and reject bad certificates.
- [x] API/updater tests and relevant compile checks in a fresh SSD source snapshot.
- [x] Focused mutations: omit secondary lookup, ignore healthy primary, renew the
  timeout budget or disconnect the public resolver; restore and compare sources.
- [x] Read-only real HTTPS /health using the secondary DNS route; review and handoff.

No push, APK/candidate build, publication, production mutation or device tests.

Result: 80 API/updater cases plus one additional empty-secondary regression PASS;
all seven focused mutations detected; macOS library and Android API/updater
checks PASS. Public factory reached real /health in 316ms with primary DNS failure
injected, real OS DNS for nelomai.top, and an unreachable static backup. URL and
certificate validation remained nelomai.ru. Ephemeral live-test changes were
removed from the SSD snapshot. This is DNS fallback: it does not switch HTTPS
origin after TCP/TLS/HTTP failure or make the panel server itself redundant.


## Superseded by the explicit HTTPS-origin choice

The user selected a separate HTTPS address and independent certificate after the
DNS-only default above. The current uncommitted implementation therefore also
switches the URL/Host/SNI to nelomai.top on a definite pre-HTTP connect failure.
See 2026-11-02-panel-https-backup.md for the final scope and verification limits;
the historical DNS-only results above describe that earlier snapshot only.
