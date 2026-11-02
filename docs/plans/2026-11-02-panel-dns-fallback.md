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
