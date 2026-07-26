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
| Current, previous, critical, and tampered updates | Updater tests and release workflow |
| Secret-free logs and frontend DTOs | Core, command, contract, and helper tests |

The following scenarios require the isolated panel and agent test environment
and are not simulated by the client repository:

- 100 concurrent application sessions and 50 simultaneous starts;
- panel worker restart during every lease transition;
- agent restart with ready, leased, warm, and pinned peers;
- automatic refill of a 30-peer test pool;
- app-bound peer key rotation after unbind;
- ten simultaneous downloads of one update artifact.
