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

The webview can request a refresh and display its progress, but cannot supply
probe results to a connection command. The native application replaces any
caller-provided values with its own current measurements before
`connections/start`. If a measurement is unavailable, the panel remains the
only authority allowed to select an alternate server.

WireGuard configuration is a privileged native payload. It must pass directly
from the authenticated API layer to `TunnelController`; frontend state, common
error payloads, analytics, audit events, and application logs must never
contain it. Common errors contain exactly `request_id`, `code`, and `message`.

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

Desktop clients request a dynamic updater manifest from:

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
and paths outside this prefix before sending the token. The Tauri updater then
verifies the artifact signature using the public key embedded at build time.
