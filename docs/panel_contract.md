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

