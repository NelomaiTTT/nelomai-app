# Linux hot standby 0.4.x: native lifecycle first

Date: 2026-10-21. Base: `768aef8018d4f187fc4b1d93212bf644ab52957a`.
Scope: `Future/linux-hot-standby-0.4.0`, based on the accepted Windows SHA in the existing
isolated checkout. The Windows branch stays at `768aef8`; its acceptance is retained;
main, other branches, vendor, production panel/agents and public release are outside this work.

## Outcome and constraints

Two concurrently live leased tunnels; primary becomes usable before reserve preparation finishes.
A failover preserves the session VIP and does not recreate the pair. Stop removes owned local
interfaces/routes/rules/DNS promptly, independently of eventual server lease reconciliation.
Start, attach, role confirmation and cleanup retain existing scope/generation/ownership guards.
Use existing system facilities; no new packet-forwarding runtime, private protocol or kill switch.
The previously deferred kill switch remains outside 0.4.x.

First target is Ubuntu 24.04 LTS x86_64 in a separate Hyper-V VM, initially 8 vCPU / 16 GiB,
120 GiB dynamic VHDX on the host NVMe. Windows test VM stays off during Linux work.
Host VPN must not supply an unintended outer path for acceptance. Do not shut down the host
using earlier completed shutdown instructions; a fresh request is required.

## Selected composition

Keep `NativePairFactory -> CompositeBackend/SessionControl -> SessionNetwork -> LinuxNetwork`.
It already exists and is constructed by the production Unix service. Do not replace it with
the Windows carrier, a proxy, network namespaces for user applications, or a custom tunnel.

* Ordinary WireGuard uses the kernel implementation and Generic Netlink already used by
  `LinuxBackend`; AmneziaWG3 retains the bundled pinned userspace implementation.
* Both members keep the same session VIP while alive. Ordinary data routes select the current
  member. Each member has its own policy table and output-interface rule for bound health probes;
  the standby has no ordinary fallback data route.
* Existing `iproute2` calls use rtnetlink. Retain this adapter initially. Measure its real cost
  before adding direct Netlink plumbing or changing transaction granularity. A single-route
  replace must not be described as an atomic whole-policy or DNS transaction.
* DNS uses existing `systemd-resolved` per-link D-Bus methods and routing domain `~.`.
  Do not overwrite `/etc/resolv.conf` or restart system networking. Initially require the existing
  supported resolved stub mode; report that boundary explicitly rather than silently falling back.
* Reply-path filtering changes only owned member links to loose mode; no machine-wide sysctl.
* The existing root systemd service, owner-authenticated Unix socket, boot identity, native
  interface group/index and write-ahead ownership records remain the recovery authority.
  Kernel WG creation uses exclusive RTM_NEWLINK with a nonzero random group in the same
  request. Linux 6.8 does not apply IFLA_IFALIAS during link creation; the real factory test
  exposed that unsupported assumption. Group is a correlation marker, not a credential;
  the original launcher, private scoped journal, boot and exact ifindex still authorize use.
  Keep groups within INT_MAX for iproute2 compatibility. Old unfinished alias journals
  remain fenced; do not migrate them by adopting a same-named interface.

## First executable check

One opt-in root-only native test in the disposable VM runs the real factory/coordinator with
real kernel WG peers and real DNS/TCP fixtures. External peers are laboratory infrastructure,
not doubles for native ownership decisions. Exercise Start, attach, fresh standby health,
primary endpoint failure, authorized promotion, traffic, Stop, fresh-scope repeat Start and cleanup.
Keep failure output and timings for each boundary. Fix only an observed first break, then repeat
the same scenario. Passing this fixture does not prove real-panel or signed-GUI acceptance.

After native lifecycle: installed GUI + real panel leases, WG/AWG3 modes, crash recovery,
DNS/routes restored, repeat Start, and Linux-only signed candidate acceptance. Record primary
readiness separately from reserve readiness; measure detection separately from route switching.
Local cleanup should stay near the previous 4–5 second target; no arbitrary multi-second sleeps
or deadline inflation to hide failures. End-to-end timings remain measured results, not promises.

Initial real-factory run in Ubuntu 24.04 / kernel 6.8.0-147: primary ready 1160 ms,
standby ready another 15027 ms, primary UDP loss to local B selection 8342 ms, Stop 774 ms,
repeat Start 1288 ms and repeat Stop 432 ms. Both Stop checks restored the independently
observed interfaces, IPv4/IPv6 routes/rules and resolved state. Lab peers and role ACK fixture
do not establish panel/installed-GUI acceptance. Linux TX failure evidence includes native
`tx_dropped`: local OUTPUT loss freezes successful `tx_packets`, so using only that counter
prevented corroboration and promotion. Shared health thresholds remain unchanged.
Kernel WG receive-counter semantics, AWG3, real panel and crash recovery remain to be verified.

## Primary documentation reviewed

* Kernel rtnetlink route API: https://www.kernel.org/doc/html/latest/netlink/specs/rt-route.html
* WireGuard routing and bound outer socket: https://www.wireguard.com/netns/
* Kernel TUN lifecycle (only if a userspace transport needs it): https://docs.kernel.org/networking/tuntap.html
* Kernel RPF and source marks: https://www.kernel.org/doc/html/latest/networking/ip-sysctl.html
* Resolved per-link API: https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.resolve1.html
* Resolved VPN integration: https://systemd.io/RESOLVED-VPNS/
* iproute2 route commands: https://man7.org/linux/man-pages/man8/ip-route.8.html
* Canonical image: https://cloud-images.ubuntu.com/releases/noble/release-20261017/

All are system/user-space control APIs or existing implementations; no paid OS-vendor signing
or new kernel module is required for the selected first WireGuard path.
