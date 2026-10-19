# Android AWG prelude pacing

Approved scope: personally implement the tested I1–I5 then100ms behavior. No APK/release build, production deployment or0.4 access.

1. Regressions: real first handshake through admission must emit nothing before protection; after admission send configured I packets separately, wait100ms, then junk/init. Cover retry, no-preamble traffic, cancellation on close/rebind, prelude send failure and bounded startup queue.
2. Preserve metadata through one optional SendHandshake capability from device/peer to existing Android admissionBind. Retain existing complete pending batch, with its prelude boundary. No new worker/queue; pacing synchronous and cancellable per socket generation. Keep old behavior for transports without this capability.
3. AndroidSplitTunnel: AWG3 identified by headerProtectionKey, no explicit I settings: supply the tested five280-byte ASCII I packets. Preserve explicit custom preambles and timers; ordinary WG unchanged.
4. Represent native edits solely in existing tracked parent vendor patches. Work from clean pinned exports plus existing patches; do not overwrite dirty vendor worktrees.
5. Run failing regressions then targeted/full native race tests and Kotlin unit tests; verify both patches apply to pinned sources with memory patches. Review final diff personally. No commit/push/build unless requested.

Completed locally 2026-10-19: all five implementation/verification steps. 1172 Kotlin tests passed; full native Go and Android bridge suites passed with race detector. Fresh pinned exports accept both updated network patches plus unchanged memory patches; changed source bytes match tested files. Vendor synchronization was restricted to files matching the original patched baseline. Final diff check clean. Hardware acceptance of the new native implementation remains pending; no APK build, commit, push or deployment performed.

Review follow-up: ordinary Android awgTurnOn also uses admissionBind. Added generation-token admission after Java socket protection on initial Start and rebind, with fail-closed cleanup. Existing JNI socket getters expose pending descriptors through admissionBind. Shared pacing implementation retained. 1177 JVM tests and full bridge race suite PASS; Android JNI syntax check and fresh network+memory patch application PASS.
