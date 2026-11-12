# Desktop Support Diagnostics Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans or superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make diagnostics reachable on every Nelomai screen on macOS, Windows, and Linux, and let the user collect, save, and manually send a report during an app, runtime, account, or network failure.

**Architecture:** A desktop-only Rust collector builds a bounded snapshot without contacting the account broker, runtime, or panel. The normal UI and the common process's startup-failure window can export that snapshot or send its frozen bytes through the panel's existing support route. Platform-specific probes contribute independently and never require elevation.

**Tech Stack:** Rust, Tauri, Svelte, the existing client API transport, and native desktop file dialogs and service diagnostics.

**Spec:** [Agreed behavior](#agreed-behavior).

## Agreed behavior

- Show «Диагностика» on every application screen, including loading, login, preparation, connection, update, and startup failure. Application-owned overlays must also offer entry to diagnostics. Native OS dialogs are outside the application's UI.
- Provide «Собрать отчёт», «Сохранить отчёт», and «Отправить в поддержку». Saving works offline. Collecting, saving, and sending work with no session or failed runtime. Sending occurs only after a user action.
- Collect startup, login, refresh, and recovery logs; service state and errors; component version and launch identity; and relevant OS events. Show collection failures and truncation in the report. Include an explicit reason category for local broker rejection when the service can determine it.
- Scope the first pass to an on-demand snapshot. A continuous verbose recording mode requires its own retention and UX design.

## Global constraints

- Work in the isolated desktop worktree on `Future/desktop-0.4.0`. Keep the Android activity and existing authenticated and automatic diagnostics flows separate from this desktop addition.
- Do not read Keychain contents, passwords, tokens, installation secrets, tunnel private keys, or whole private state files. Use bounded, allowlisted fields before serialization. Drop incomplete first log records and reject symlinks and Windows reparse redirects out of the approved roots.
- No sudo, UAC, helper repair, or network mutation on the collection path. Each probe has a bounded budget and cannot block export when unavailable. Persist only the file the user selects, with no background upload or temporary share cache.
- Use a v4 report UUID and one immutable serialized payload per collection. Explicit retry and local save use that same payload. A new collection creates a new UUID.
- Use the existing support endpoint `POST /api/client/v1/diagnostics/support` and preserve desktop TLS verification, endpoint selection, deadline, and non-replay guarantees. The checked-in panel contract already supports an optional support code and bounded unattributed reports. Verify compatibility against the intended panel version before acceptance.
- Keep the compact, serialized JSON body at or below 384 KiB for the checked-in panel's default 512 KiB body limit. Keep helper text at or below 64 KiB. Include the desktop OS in the allowlisted header inside `application_log`, since an unattributed report has no verified `device.platform` and the current schema has no submitted OS field.
- Put local caches, builds, fixtures, temporary files, and verification output on the mounted external Apple-VM SSD. Use the existing review and release gates.

## Review focus

1. Startup failure occurs before application state and runtime IPC are available. The common failure window still exports and sends a snapshot.
2. Update and recovery overlays cover the usual app header. Diagnostics stays reachable in the topmost application UI and keeps existing focus handling.
3. A local log is redirected or malformed, or a service probe stalls. The snapshot omits the unsafe input, records the reason, and preserves the other sections.
4. Panel auth is missing, a POST loses its response after HTTP starts, or the save dialog is cancelled. The file remains exportable, there is no hidden HTTP retry or partial destination, and an explicit retry uses the same UUID and bytes.
5. A helper rejects an unexpected UID, path, or executable hash. The report identifies the reason category without granting access or publishing credential material.

## Task 1 — Build a snapshot independently of runtime state

**Files:** Add `src-tauri/src/support_diagnostics.rs` for the standalone collector and focused Rust tests. Reuse bounded log readers from `src-tauri/src/diagnostics.rs` where their ownership requirements permit it. Wire module registration in `src-tauri/src/lib.rs`.

**Interface:** `collect_desktop_support_report(data_dir: &Path) -> Result<DesktopSupportReport, SupportDiagnosticError>`. `DesktopSupportReport` owns an opaque UUID, an immutable serialized payload, and structured section availability for the UI. Pass the actual application data root from Tauri. Resolve current and retained diagnostics from the approved runtime layout with a bounded directory count. Accept only known log names. Keep runtime slot and version labels separate from verified active identity.

- [ ] Add a failing test `support_snapshot_without_runtime_keeps_current_and_previous_events`. Build a snapshot using just a temporary data tree, with missing helper state and malformed lines. Assert a v4 UUID, both usable log tails, an unavailable marker, and a valid panel-shaped JSON payload.
- [ ] Add failing `support_snapshot_bounds_wire_bytes_and_excludes_sensitive_inputs` cases for invalid UTF-8, escaped byte expansion, truncated lines, sensitive fields, Unix links and Windows reparse paths. Assert valid JSON within 384 KiB and no raw secret or redirected content.
- [ ] Run `cargo test --locked -p nelomai-app --lib support_snapshot` and confirm the tests fail for the missing collector or missing guard.
- [ ] Implement the snapshot with section budgets and dependency-free reads for app, login, refresh, update, and migration diagnostics.
- [ ] Re-run the focused tests and `cargo test --locked -p nelomai-app --lib diagnostics::`. Expected: both new collector tests and existing diagnostic report tests pass. On Windows use the repository's existing manifest-aware library harness. Validate panel compatibility with a local request fixture.

## Task 2 — Add native diagnostics and exact refusal categories

**Files:** Extend the collector in `src-tauri/src/support_diagnostics.rs` with platform probes. Reuse the existing desktop helper diagnostic hooks from `src-tauri/src/platform` only when they can run without runtime IPC. Adjust rejection classification in `crates/contracts/src/dispatcher.rs` and propagate bounded reason categories through `crates/unix-service/src/socket.rs` and `crates/unix-service/src/main.rs`. Inspect the Windows service's existing equivalent before adding platform-specific categories.

**Interface:** Each probe returns a named section or an explicit unavailable reason. Broker checks preserve the existing success and denial behavior. Diagnostics distinguish `uid_mismatch`, `path_mismatch`, `executable_digest_mismatch`, and `executable_unavailable_or_changed` when the check has that evidence. Keep the external protocol error compatible.

- [ ] Add failing tests that vary one broker input at a time and assert both the correct category and unchanged denial. Verify that a successful peer still reaches the command handler and that a rejected peer reaches no native operation.
- [ ] Add a failing test for an unavailable or timed-out native probe; assert that all other sections remain exportable and the report identifies the failed section.
- [ ] Implement bounded read-only checks. On macOS collect launchd state, protected and visible bundle metadata, and targeted OS errors; on Windows service and process state plus Nelomai-filtered event data; on Linux unit and process state plus Nelomai-filtered journal data. Use helper logs where readable. Record absence or access denial in each section.
- [ ] Run `cargo test --locked -p nelomai-contracts --lib broker`, `cargo test --locked -p nelomai-unix-service --lib dispatcher`, and the focused collector tests. Expected: reason categories and rejection behavior pass. Exercise all three native collectors with ordinary user privileges. Compare rejection before and after on a native helper fixture.

## Task 3 — Make diagnostics reachable throughout the desktop UI

**Files:** Add `src/lib/SupportDiagnostics.svelte` and its UI tests. Modify `src/routes/+page.svelte`, `src/lib/native-client.ts`, `src-tauri/src/lib.rs`, `src-tauri/src/container.rs`, and `static/startup-failure.html`. Add the Tauri dialog plugin to desktop dependencies and initialize it on the desktop builders. Open the dialog in Rust and grant no generic dialog or filesystem permissions to the renderer. Restrict the common failure window to the specific support actions.

**Interface:** Desktop IPC exposes `app_collect_support_diagnostics`, `app_save_support_diagnostics`, and, in Task 4, `app_send_support_diagnostics`. The renderer carries a report ID and availability metadata. Rust keeps the snapshot bytes and opens the Save dialog, with no renderer-supplied filesystem path or upload destination.

- [ ] Add a failing UI matrix test covering every `AppView` and application overlay. Assert the action remains keyboard reachable and independent of the busy state of login, update, and tunnel operations. Add a native failure-window test with no managed `NativeApplication` or `CommonState`.
- [ ] Add a failing export test covering dialog cancellation, offline save, and write failure. Assert cancellation creates no file, save preserves exact bytes, and a failed write does not replace an existing file.
- [ ] Register the restricted commands in the desktop runtime and common startup-failure window. Add a global entry in the normal app shell and an entry in the active overlay where it would obscure or trap focus from the shell. Wire the same collect and save contract into the failure page.
- [ ] Run `npm run test:unit -- src/lib/SupportDiagnostics.test.ts src/lib/native-client.test.ts`, `npm run check`, and the affected native IPC checks. Expected: access across all view states and IPC command parity. Exercise the system file dialog and startup-failure entry on each desktop OS.

## Task 4 — Send a frozen report before login

**Files:** Add a desktop support POST method in `crates/client-api/src/lib.rs` using the existing panel transport. Wire `app_send_support_diagnostics` in the support module and both desktop entry points. Add transport and workflow tests.

**Interface:** `upload_support_diagnostics(report_bytes: &[u8], support_code: Option<&str>)` sends to the fixed support route and returns a report receipt or a safe failure category. Keep the optional support code outside the snapshot and report logs.

- [ ] Add failing transport tests proving no account credentials are attached, valid support code is in the existing header only, and an accepted HTTP request is never silently replayed after EOF. Include the existing eligible pre-HTTP failover case and a total deadline check.
- [ ] Add failing workflow tests proving that rejection, offline mode, and deadline leave the snapshot saveable. Assert explicit retry and local export use the same report ID and exact bytes, and collecting again replaces the snapshot with a new ID.
- [ ] Implement the POST, result presentation, and manual retry against the checked-in support contract. Show the short report ID after success. Keep errors actionable without logging raw response contents.
- [ ] Run `cargo test --locked -p nelomai-client-api support_diagnostics`, the focused frontend tests, and the affected IPC checks. Expected: direct support upload, retained export, and no replay. On a compatible staging panel, confirm an unattributed desktop report and a report with a support code can both be found by ID. Check legacy authenticated uploads still work.

## Acceptance

- [ ] On macOS, Windows, and Linux, verify collection and export while signed out, preparing, connected, and in an application-owned overlay.
- [ ] With the app unable to start its runtime, open diagnostics in the common failure window, save an offline report, and send the same snapshot once the network is available.
- [ ] Exercise one missing native source and one local broker rejection on a test installation. Confirm the report includes the available evidence and identifies the relevant reason category.
- [ ] Verify the UI accurately reports offline and panel failures, the export remains available, and the feature does not trigger OS elevation or background delivery.
