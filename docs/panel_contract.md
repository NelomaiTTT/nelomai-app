# Panel contract

The native client talks only to the versioned panel API under
`/api/client/v1`. A breaking change requires a new `/api/client/v2` prefix;
fields may be added to v1 only when an older client can safely ignore them.

## Contract source

JSON Schemas live in `contracts/schemas`, shared examples in
`contracts/fixtures`, and checked Rust types in `crates/contracts`. The Python
fixture check is intentionally standard-library-only so the panel can run it
without adding a runtime dependency.

Enums that select a network layer, route, connection mode, platform, update
requirement, or connection state are closed. An unknown value must stop the
operation and trigger a bootstrap/update check; it must never silently fall
back to another route.

## Security boundary

Candidate IDs are opaque and short-lived. The client never receives server
inventory, agent credentials, SSH details, or internal server IDs. Probe
results are advisory; the panel validates freshness and makes the final server
selection.

After an authenticated bootstrap, the native layer requests candidates for the
selected layer and measures their HTTPS probe endpoints without an
authorization header. At most four probes run concurrently and each request
has a three-second timeout. Results are cached independently for Tic and Stray
for no longer than five minutes or the earliest candidate expiry, whichever
comes first. The cache is cleared on login, logout, and peer rebinding.
Personal Tic mode uses the already bound user peer and therefore performs no
candidate request or latency probe.

The webview can request a refresh and display its progress, but cannot supply
probe results to a connection command. The native application replaces any
caller-provided values with its own current measurements before
`connections/start`. If a measurement is unavailable, the panel remains the
only authority allowed to select an alternate server.

The isolated HTTP flow test in `crates/client-application/tests/http_flow.rs`
exercises login, peer binding, candidate measurement, dynamic Stray start,
pin, stop, warm reconnect, unpin, peer unbinding, and logout through the real
`ClientApi` serialization boundary. It never uses production accounts, peers,
or endpoints.

A pinned Stray configuration and a temporary alternate lease are stored in
separate protected slots. Starting an alternate connection must never replace
the pinned configuration. Unbinding stops the local tunnel and clears both
slots only after the panel confirms the operation.

WireGuard configuration is a privileged native payload. It must pass directly
from the authenticated API layer to `TunnelController`; frontend state, common
error payloads, analytics, audit events, and application logs must never
contain it. Common errors contain exactly `request_id`, `code`, and `message`.

## Diagnostic reports

An authenticated device can explicitly send a bounded diagnostic report to:

```text
POST /api/client/v1/diagnostics
Authorization: Bearer <access token>
Content-Type: application/json
```

The native layer assembles the report; the webview never receives log contents.
Reports contain structured application events and, when readable, the bounded
tail of the privileged tunnel helper log. Passwords, session tokens, and
WireGuard configuration must never be logged. The panel applies a second
redaction pass, accepts at most 512 KiB once per minute per device, keeps five
reports per device for no longer than 30 days, and exposes them only to an
administrator.

## Compatibility

- Unknown optional object fields are ignored by v1 clients.
- Required fields cannot be removed or change meaning in v1.
- Unknown routing or security enums are rejected.
- Timestamps use UTC RFC 3339.
- `operation_id` makes connection mutations idempotent.
- Artifact downloads stay on authenticated relative `/api/client/v1` URLs.

## Application updates

Bootstrap remains the source of update policy. `update_available` tells the
client to display an offer, while `required` blocks new tunnel connections
until a compatible version is installed. Disabling automatic updates does not
hide that offer and does not bypass a required update.

Authenticated bootstrap requests from update-capable clients include:

```text
X-Nelomai-App-Version: <running semantic version>
```

The panel records this value before calculating compatibility. The header is
optional for older clients and never replaces the signed manifest version
check performed by the updater.

Native clients request a dynamic updater manifest from:

```text
GET /api/client/v1/updates/manifest/{target}/{current_version}
Authorization: Bearer <access token>
```

The panel returns `204` when no update is available. Otherwise it returns the
signed manifest described by `update-manifest.schema.json`. Its artifact URL
must remain under:

```text
https://nelomai.ru/api/client/v1/updates/artifacts/{artifact}
```

The same bearer header is used for the artifact request. The client rejects a
different origin, credentials embedded in the URL, query strings, fragments,
and paths outside this prefix before sending the token. Desktop packages are
verified by the Tauri updater using its embedded public key. An Android
manifest additionally contains `sha256` and `size_bytes`; its `signature`
field is the SHA-256 fingerprint of the APK signing certificate. Android
checks all three values before opening the system installer.
