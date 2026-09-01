# Isolated E2E test matrix

This matrix tracks Task 16 coverage without production users, peers, or
endpoints.

| Scenario | Coverage |
| --- | --- |
| Login, peer selection, bind, dynamic Stray, stop, warm reconnect | Real HTTP client test |
| Fixed personal Tic without candidate probes | Application regression test and visual smoke |
| Pin and unpin Stray | Real HTTP client test |
| Temporary alternate without losing the pinned Stray | Core storage regression test |
| Unbind clears app configurations and returns to peer selection | Real HTTP client and core tests |
| Expired access and critical update blocks | Core runtime and frontend tests |
| Offline start with a valid saved Stray | Core runtime tests |
| Concurrent start and stop single-flight behavior | Core runtime tests |
| Android recovery-v2 allocates and restores one primary plus one standby | Panel, contract, and Android coordinator tests |
| Hard/soft Android failover keeps one TUN and never enters the legacy stalled-stop path | Go fake-TUN and Android state-machine tests |
| Process death replays the redundant journal and safely resolves pending candidates | Android recovery-store and coordinator tests |
| User setting or panel kill switch releases only the exact standby member | Panel API, Android capability-store, and coordinator tests |
| Personal Tic, non-Android, recovery-v1, and old clients remain single-backend | Panel, Rust contract, command, and Android compatibility tests |
| Session-scoped stop cannot terminate a later pinned session or reuse a quarantined address | Panel lifecycle and concurrency tests |
| Current, previous, and tampered updates | Panel API and signed-release synchronization tests |
| Critical update policy | Core runtime and frontend tests |
| Secret-free logs and frontend DTOs | Core, command, contract, and helper tests |

The panel repository now runs these scenarios against an isolated database and
fake persistent agent; no production user, peer, endpoint, or artifact is used:

- 100 authenticated application sessions through four FastAPI instances;
- 50 simultaneous HTTP starts through those application instances;
- application-instance recreation while leases remain active;
- agent restart and reconciliation with ready, leased, warm, and pinned peers;
- injected agent failure and safe failed-lease state;
- automatic refill to a 30-ready-peer target;
- current/previous rotation, invalid manifest signature, and tampered artifact;
- ten simultaneous downloads of one update artifact.

The following scenarios remain platform or later lifecycle checks:

- app-bound peer key rotation after unbind;
- a real signed installer update on Windows, macOS, and Linux;
- Android package installation after its signing certificate is provisioned;
- real-device Android failover under Wi-Fi/mobile handoff, radio loss, process
  death, and sustained power/allocation pressure;
- guarded production rollout, agent capability verification, and explicit
  enablement of the hot-standby kill switch.

All hot-standby checks above use isolated databases, fake agents, fake TUNs, or
local Android/native builds. They do not deploy, migrate production data,
update agents, or enable the production capability.
