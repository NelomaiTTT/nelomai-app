import page from "../routes/+page.svelte?raw";
import ts from "typescript";
import { parse } from "svelte/compiler";
import { commandCode, commandMessage } from "./native-client";
import { describe, expect, it } from "vitest";
import { beginConnectionStart, beginConnectionStop, initialConnectionActionState, isCurrentConnectionAction,
  beginRuntimeStateSync, initialRuntimeStateSync, canBeginConnectionAction,
  finishConnectionStart, finishConnectionStop, prepareConnectionStartForPlatform } from "./connection-action";
import { clearOwnedConnectionIntentNotice } from "./connection-intent-notice";
import { primaryAction, type Phase, type ConnectionIntentStatus, bindingPreferenceUpdateRequest, connectionEgressMode } from "./app-model";

// Execute the page's actual async callback with controlled native replies. No
// duplicate implementation of its application/epoch checks in the test.
const script = page.match(/<script lang="ts">([\s\S]*?)<\/script>/)![1];
const ast = ts.createSourceFile("page.ts", script, ts.ScriptTarget.Latest, true);
const callback = ast.statements.find((node) => ts.isFunctionDeclaration(node)
  && node.name?.text === "synchronizeRuntimeState")!;
const sharedFunctions = ast.statements.filter((node) => ts.isFunctionDeclaration(node)
  && ["applyRuntimeChannelClosure", "requireRuntimeChannelOpen", "observeUpdateStatus", "readDesktopTunnelBackend", "defenderRepairStatusMessage"].includes(node.name?.text ?? ""))
  .map((node) => node.getText(ast)).join("\n");
const executable = ts.transpile(sharedFunctions + callback.getText(ast), { target: ts.ScriptTarget.ES2022 });
const synchronize = new Function("context", "foreground = true", `with (context) { ${executable}; return synchronizeRuntimeState(foreground); }`);
const toggleCallback = ast.statements.find((node) => ts.isFunctionDeclaration(node)
  && node.name?.text === "toggleConnection")!;
const toggle = new Function("context", `with (context) { ${ts.transpile(sharedFunctions + toggleCallback.getText(ast),
  { target: ts.ScriptTarget.ES2022 })}; return toggleConnection(); }`);
function executePageFunction(name: string, context: unknown, ...args: unknown[]) {
  const fn = ast.statements.find((node) => ts.isFunctionDeclaration(node) && node.name?.text === name)!;
  return new Function("context", "args", `with (context) { ${ts.transpile(
    sharedFunctions + fn.getText(ast), { target: ts.ScriptTarget.ES2022 })};
    return ${name}(...args); }`)(context, args);
}

// Evaluate the real Svelte rendering condition, not a copied UI predicate.
const template = parse(page, { modern: true });
const modalBlock = template.fragment.nodes.filter((node) => node.type === "IfBlock")
  .find((node) => node.consequent.nodes.some((child) => child.type === "Component"
    && child.name === "SplitTunnelSettings"))!;
// Svelte's Acorn nodes carry offsets omitted by the base ESTree declarations.
const modalTest = modalBlock.test as typeof modalBlock.test & { start: number; end: number };
const modalVisible = new Function("context",
  `with (context) { return ${page.slice(modalTest.start, modalTest.end)}; }`);

// Find and evaluate the actual button expression, including asynchronous phase
// changes. This catches presentation regressions that a callback-only test misses.
function findConnectButton(node: any): any {
  if (!node || typeof node !== "object") return null;
  if (node.type === "RegularElement" && node.name === "button" &&
      node.attributes.some((attribute: any) => attribute.name === "class" &&
        attribute.value?.some((value: any) => value.data === "connect-button"))) return node;
  for (const child of Object.values(node)) {
    for (const value of Array.isArray(child) ? child : [child]) {
      const found = findConnectButton(value);
      if (found) return found;
    }
  }
  return null;
}
const connectButton = findConnectButton(template.fragment);
const buttonLabelExpression = connectButton.fragment.nodes
  .find((node: any) => node.type === "RegularElement" && node.name === "span")
  .fragment.nodes.find((node: any) => node.type === "ExpressionTag").expression;
const buttonLabel = new Function("context", `with (context) { return ${
  page.slice(buttonLabelExpression.start, buttonLabelExpression.end)}; }`);

function fixture() {
  let reply!: (value: unknown) => void;
  let reject!: (reason: unknown) => void;
  const response = new Promise((resolve, fail) => { reply = resolve; reject = fail; });
  const context = {
    busy: false, bootstrapPending: false, runtimeStateSync: initialRuntimeStateSync(), bootstrap: { binding: {} },
    phase: "ready", connection: null, runtimeWarning: "tunnel_runtime_stopped" as string | null,
    runtimeChannelClosed: false, runtimeSelectionBusy: false,
    startupRetry: { cancel: () => {}, checkpoint: () => () => true },
    splitTunnelOpen: false, splitTunnelState: null,
    splitTunnelBusy: false, splitTunnelLoaded: false, splitTunnelApplications: [],
    pinnedStray: null, loadPeers: async () => {},
    connectionActionState: initialConnectionActionState(),
    localStopPendingCleanup: false, connectionMetrics: null, reserveState: null,
    desktopActiveSlot: null, desktopTunnelBackend: null as "worker" | "legacy" | null, connectionIntentStatus: "none", nextRetryAtUnix: null,
    ownedConnectionIntentNotice: null, error: null, view: "connection",
    nativeClient: { state: () => response, recordStartupStage: () => {} },
    readDesktopActiveSlot: () => null, viewForAppState: () => "connection",
    loadSplitTunnel: async () => {}, isCurrentConnectionAction, clearOwnedConnectionIntentNotice, commandCode, commandMessage,
    beginRuntimeStateSync, initialRuntimeStateSync,
  };
  const state = { phase: "connected", connection: null, warning: null, metrics: null,
    reserveState: null, connectionIntentStatus: "none", nextRetryAtUnix: null, desktopTunnelBackend: null as "worker" | "legacy" | null };
  return { context, reply, reject, state };
}

function logoutFixture() {
  const result = fixture();
  Object.assign(result.context, {
    startupRetry: { cancel: () => {}, schedule: () => {}, checkpoint: () => () => true }, startupPending: false,
    peers: [{ id: 1 }], selectedPeerId: "1", password: "test-password",
    diagnosticsStatus: null, updateStatus: null, updateRequestSequence: 0, updateAppliedSequence: 0, notifications: [],
    notificationUnreadCount: 0, notificationNextCursor: null,
    notificationHistoryExpanded: false, notificationsOpen: false, changelogOpen: false,
    clearUpdateTimer: () => {},
  });
  return result;
}

describe("async Stop presentation", () => {
  function stopFixture() {
    const result = fixture();
    const { context } = result;
    Object.assign(context, {
      phase: "connected", splitTunnelBlocksStart: false, runtimeStatus: null,
      bootstrap: { device: { id: "own-device", platform: "android" }, binding: {} },
      canBeginConnectionAction, beginConnectionStart, beginConnectionStop,
      finishConnectionStart, finishConnectionStop,
    });
    Object.defineProperty(context, "connectionAction", { get: () => primaryAction({
      phase: context.phase as Phase,
      connectionIntentStatus: context.connectionIntentStatus as ConnectionIntentStatus,
    }) });
    return result;
  }

  it("shows confirmed local closure while Stop is still waiting for panel cleanup", async () => {
    const { context, state } = stopFixture();
    let finishStop!: () => void;
    Object.assign(context.nativeClient, {
      stop: () => new Promise<void>((resolve) => { finishStop = resolve; }),
      state: async () => ({ ...state, phase: "stopping", localStopPendingCleanup: true }),
    });
    const stopping = toggle(context);
    await synchronize(context, false);
    expect(buttonLabel(context)).toBe("Выключен");
    expect(context.connectionActionState.cancelBusy).toBe(true);
    expect(canBeginConnectionAction(context.connectionActionState, context.busy, false)).toBe(false);
    finishStop();
    await stopping;
  });

  it("ignores a Stop progress poll that arrives after Stop has completed", async () => {
    const { context, state } = stopFixture();
    let finishStop!: () => void;
    let replyProgress!: (value: unknown) => void;
    let reads = 0;
    Object.assign(context.nativeClient, {
      stop: () => new Promise<void>((resolve) => { finishStop = resolve; }),
      state: () => ++reads === 1
        ? new Promise((resolve) => { replyProgress = resolve; })
        : Promise.resolve({ ...state, phase: "ready", localStopPendingCleanup: false }),
    });
    const stopping = toggle(context);
    const poll = synchronize(context, false);
    finishStop();
    await stopping;
    expect(buttonLabel(context)).toBe("Старт");
    replyProgress({ ...state, phase: "stopping", localStopPendingCleanup: true });
    await poll;
    expect(buttonLabel(context)).toBe("Старт");
    expect(context.localStopPendingCleanup).toBe(false);
  });

  it("does not restore a green or connected state from a poll while Stop is pending", async () => {
    for (const phase of ["ready", "connected"]) {
      const { context, state } = stopFixture();
      let finishStop!: () => void;
      Object.assign(context.nativeClient, {
        stop: () => new Promise<void>((resolve) => { finishStop = resolve; }),
        state: async () => ({ ...state, phase, localStopPendingCleanup: false }),
      });
      const stopping = toggle(context);
      await synchronize(context, false);
      expect(context.phase).toBe("stopping");
      expect(buttonLabel(context)).toBe("Выключаем");
      finishStop();
      await stopping;
    }
  });

  it("keeps shutdown presentation between Stop acceptance and the authoritative state reply", async () => {
    const { context, reply, state } = stopFixture();
    let acceptStop!: () => void;
    let stateRequested!: () => void;
    const requested = new Promise<void>((resolve) => { stateRequested = resolve; });
    const readState = context.nativeClient.state;
    Object.assign(context.nativeClient, {
      stop: () => new Promise<void>((resolve) => { acceptStop = resolve; }),
      state: () => { stateRequested(); return readState(); },
    });
    const pending = toggle(context);
    expect(context.phase).toBe("stopping");
    expect(buttonLabel(context)).toBe("Выключаем");
    acceptStop();
    await requested;
    const phaseAfterAcceptance = context.phase;
    reply({ ...state, phase: "stopping", connectionIntentStatus: "none" });
    await pending;
    expect(phaseAfterAcceptance).toBe("stopping");
    expect(context.connectionActionState.cancelBusy).toBe(false);
    expect(buttonLabel(context)).toBe("Выключаем");
  });

  it("keeps Выключаем after IPC settles until a later poll confirms completion", async () => {
    const { context, reply, state } = stopFixture();
    Object.assign(context.nativeClient, { stop: async () => null });
    const pending = toggle(context);
    reply({ ...state, phase: "stopping" });
    await pending;
    expect(context.busy).toBe(false);
    expect(buttonLabel(context)).toBe("Выключаем");
    context.nativeClient.state = async () => ({ ...state, phase: "ready" });
    await synchronize(context, false);
    expect(buttonLabel(context)).toBe("Старт");
  });

  it("keeps automatic recovery cancellable instead of presenting it as user shutdown", () => {
    const { context } = stopFixture();
    context.phase = "stopping";
    context.connectionIntentStatus = "recovering";
    expect(buttonLabel(context)).toBe("Стоп");
    expect(canBeginConnectionAction(context.connectionActionState, false, true)).toBe(true);
  });

  it("shows confirmed local shutdown separately from a pending Stop", () => {
    const { context } = stopFixture();
    context.phase = "stopping";
    context.localStopPendingCleanup = true;
    expect(buttonLabel(context)).toBe("Выключен");
  });

  it("restores Stop after a failed cancellation while the tunnel remains connected", async () => {
    const { context, reply, state } = stopFixture();
    Object.assign(context.nativeClient, { stop: async () => { throw { code: "temporarily_unavailable" }; } });
    const pending = toggle(context);
    reply(state);
    await pending;
    expect(context.phase).toBe("connected");
    expect(context.connectionActionState.cancelBusy).toBe(false);
    expect(buttonLabel(context)).toBe("Стоп");
    expect(context.error).not.toBeNull();
  });
});

describe("foreground native state callback", () => {
  it("finishes an explicit logout without replacing the confirmed-closure screen with login", async () => {
    const { context, reject } = logoutFixture();
    context.phase = "connected";
    let finishLogout!: () => void;
    Object.assign(context.nativeClient, {
      logout: () => new Promise<void>((resolve) => { finishLogout = resolve; }),
    });
    const sync = synchronize(context);
    const logout = executePageFunction("logout", context);
    reject({ code: "runtime_channel_closed" });
    await sync;
    expect(context.view).toBe("unavailable");
    finishLogout();
    await logout;
    expect(context.bootstrap).toBeNull(); // Explicit owner-confirmed sign-out still completes.
    expect(context.phase).toBe("error");
    expect(context.view).toBe("unavailable");
    expect(context.runtimeChannelClosed).toBe(true);
    expect(context.runtimeWarning).toBe("runtime_channel_closed");
    expect(context.error).toContain("службой подключения");
    expect(context.busy).toBe(false);
  });

  it("still presents login after a normal successful logout on an open channel", async () => {
    const { context } = logoutFixture();
    Object.assign(context.nativeClient, { logout: async () => {} });
    await executePageFunction("logout", context);
    expect(context.bootstrap).toBeNull();
    expect(context.phase).toBe("signed_out");
    expect(context.view).toBe("sign_in");
    expect(context.runtimeChannelClosed).toBe(false);
    expect(context.busy).toBe(false);
  });

  it("ignores a queued login submission after closure without losing the recovery presentation", async () => {
    const { context } = fixture();
    let logins = 0;
    Object.assign(context, {
      diagnosticsStatus: null, login: "test", password: "test-password", deviceName: "test",
      DEVICE_NAME_MAX_LENGTH: 100,
    });
    Object.assign(context.nativeClient, {
      login: async () => { logins++; throw { code: "start_cancelled" }; },
    });
    executePageFunction("applyRuntimeChannelClosure", context, { code: "runtime_channel_closed" });
    const closureError = context.error;
    await executePageFunction("submitLogin", context, { preventDefault: () => {} });
    expect(logins).toBe(0);
    expect(context.phase).toBe("error");
    expect(context.view).toBe("unavailable");
    expect(context.error).toBe(closureError);
    expect(context.busy).toBe(false);
  });

  it("handles confirmed EOF during an unrelated busy action without losing the cleanup barrier", async () => {
    const { context, reject } = fixture();
    context.phase = "connected";
    context.localStopPendingCleanup = true;
    const account = context.bootstrap;
    const pending = synchronize(context);
    context.busy = true;
    reject({ code: "runtime_channel_closed" });
    await pending;
    expect(context.phase).toBe("error");
    expect(context.view).toBe("unavailable");
    expect(context.runtimeChannelClosed).toBe(true);
    expect(context.bootstrap).toBe(account);
    expect(context.localStopPendingCleanup).toBe(true);
  });

  it("still discards a successful snapshot during an unrelated busy action", async () => {
    const { context, reply, state } = fixture();
    const pending = synchronize(context);
    context.busy = true;
    reply(state);
    await pending;
    expect(context.phase).toBe("ready");
    expect(context.runtimeChannelClosed).toBe(false);
  });

  it("closes split settings on EOF and does not render them if history reopens the overlay", () => {
    const { context } = fixture();
    Object.assign(context, { splitTunnelOpen: true, splitTunnelState: { warning: null } });
    expect(modalVisible(context)).toBeTruthy();
    executePageFunction("applyRuntimeChannelClosure", context, { code: "runtime_channel_closed" });
    expect(context.splitTunnelOpen).toBe(false);
    context.splitTunnelOpen = true; // A queued history event cannot expose the modal again.
    expect(modalVisible(context)).toBeFalsy();
  });

  for (const [name, args] of [
    ["saveSplitTunnel", [{}]],
    ["loadSplitTunnel", [true]],
    ["addSplitTunnelAddressRule", ["example.test", "this_device"]],
    ["removeSplitTunnelAddressRule", [1, "this_device"]],
  ] as const) {
    it(`rejects ${name} without issuing a native request after confirmed closure`, async () => {
      const { context } = fixture();
      context.runtimeChannelClosed = true;
      let requests = 0;
      const nativeState = async () => { requests++; return { warning: null }; };
      Object.assign(context.nativeClient, {
        saveSplitTunnel: async () => { requests++; return { saved: true, state: { warning: null } }; },
        splitTunnelInstalledApplications: async () => { requests++; return []; },
        refreshSplitTunnel: nativeState, addSplitTunnelAddressRule: nativeState,
        removeSplitTunnelAddressRule: nativeState,
      });
      await expect(executePageFunction(name, context, ...args)).rejects.toMatchObject({
        code: "runtime_channel_closed",
      });
      expect(requests).toBe(0);
    });
  }

  it("keeps the closure screen when an already queued unbind succeeds late", async () => {
    const { context, reject } = fixture();
    context.phase = "connected";
    let stateRequested!: () => void;
    const entered = new Promise<void>((resolve) => { stateRequested = resolve; });
    const state = context.nativeClient.state;
    let finishUnbind!: () => void;
    Object.assign(context.nativeClient, {
      saveSplitTunnel: async () => { throw { code: "temporarily_unavailable" }; },
      state: () => { stateRequested(); return state(); },
      unbindPeer: () => new Promise<void>((resolve) => { finishUnbind = resolve; }),
    });
    const account = context.bootstrap;
    const split = executePageFunction("saveSplitTunnel", context, {}).catch(() => {});
    await entered;
    const unbind = executePageFunction("unbindPeer", context);
    reject({ code: "runtime_channel_closed" });
    await split;
    expect(context.view).toBe("unavailable");
    finishUnbind();
    await unbind;
    expect(context.phase).toBe("error");
    expect(context.view).toBe("unavailable");
    expect(context.bootstrap).toBe(account);
    expect(context.runtimeChannelClosed).toBe(true);
  });

  it("does not confirm or resubmit a split restart when its first Save reply arrives after EOF", async () => {
    const { context } = fixture();
    let finish!: (value: unknown) => void;
    let saves = 0;
    let confirmations = 0;
    Object.assign(context, { window: { confirm: () => { confirmations++; return true; } } });
    Object.assign(context.nativeClient, {
      saveSplitTunnel: () => { saves++; return new Promise((resolve) => { finish = resolve; }); },
    });
    const pending = executePageFunction("saveSplitTunnel", context, {});
    executePageFunction("applyRuntimeChannelClosure", context, { code: "runtime_channel_closed" });
    finish({ saved: false, requiresReconnectConfirmation: true, state: { warning: null } });
    await expect(pending).rejects.toMatchObject({ code: "runtime_channel_closed" });
    expect(confirmations).toBe(0);
    expect(saves).toBe(1);
    expect(context.splitTunnelState).toBeNull();
  });

  it("does not issue forced synchronization after EOF arrives during the application-list read", async () => {
    const { context } = fixture();
    let finish!: (value: unknown) => void;
    let refreshes = 0;
    Object.assign(context.nativeClient, {
      splitTunnelInstalledApplications: () => new Promise((resolve) => { finish = resolve; }),
      refreshSplitTunnel: async () => { refreshes++; return { warning: null }; },
    });
    const pending = executePageFunction("loadSplitTunnel", context, true);
    executePageFunction("applyRuntimeChannelClosure", context, { code: "runtime_channel_closed" });
    finish([{ packageName: "test.package" }]);
    await pending;
    expect(refreshes).toBe(0);
    expect(context.splitTunnelApplications).toEqual([]);
    expect(context.splitTunnelState).toBeNull();
    expect(context.view).toBe("unavailable");
  });
  it("removes protected presentation on confirmed owner closure without losing the account or cleanup barrier", async () => {
    const { context, reject } = fixture();
    context.phase = "connected";
    context.localStopPendingCleanup = true;
    Object.assign(context, {
      connection: { leaseId: "old" }, connectionMetrics: { bytes: 42 }, reserveState: "ready",
    });
    const account = context.bootstrap;
    const pending = synchronize(context);
    reject({ code: "runtime_channel_closed", message: "private detail" });
    await pending;
    expect(context.phase).toBe("error");
    expect(context.view).toBe("unavailable");
    expect(context.error).toContain("службой подключения");
    expect(context.bootstrap).toBe(account);
    expect(context.localStopPendingCleanup).toBe(true);
    expect(context.connection).toBeNull();
    expect(context.connectionMetrics).toBeNull();
    expect(context.reserveState).toBeNull();
    expect(context.runtimeStateSync.pending).toBe(false);
  });

  it("does not confuse a transient network error with closed IPC", async () => {
    const { context, reject } = fixture();
    context.phase = "connected";
    const pending = synchronize(context);
    reject({ code: "temporarily_unavailable" });
    await pending;
    expect(context.phase).toBe("connected");
    expect(context.error).toBeNull();
  });

  it("ignores a closed-channel reply retired by a newer Stop", async () => {
    const { context, reject } = fixture();
    context.phase = "connected";
    const pending = synchronize(context);
    context.connectionActionState = beginConnectionStop(context.connectionActionState).state;
    context.phase = "stopping";
    reject({ code: "runtime_channel_closed" });
    await pending;
    expect(context.phase).toBe("stopping");
    expect(context.error).toBeNull();
  });

  it("does not apply owner closure to a replaced account view", async () => {
    const { context, reject } = fixture();
    context.phase = "connected";
    const pending = synchronize(context);
    context.bootstrap = { binding: {} };
    context.phase = "signed_out";
    reject({ code: "runtime_channel_closed" });
    await pending;
    expect(context.phase).toBe("signed_out");
    expect(context.error).toBeNull();
  });

  it("does not expose a fresh Start if EOF follows a successful Start", async () => {
    const { context } = fixture();
    let starts = 0;
    Object.assign(context, {
      bootstrap: { device: { id: "own-device", platform: "android" }, binding: {} },
      connectionAction: "start", runtimeStatus: null, splitTunnelBlocksStart: false,
      runtimeStartBlocked: () => false, selectedLayer: "tic", ticConnectionMode: "dynamic",
      routeMode: "via_tak", selectedEgressMode: "ipv4", antivirusStartFailure: false,
      prepareConnectionStartForPlatform, canBeginConnectionAction, beginConnectionStart,
      beginConnectionStop, finishConnectionStart, finishConnectionStop,
      pendingBindingPreferenceRequest: () => null,
    });
    Object.assign(context.nativeClient, {
      prepareTunnel: async () => {},
      start: async () => { starts++; return { status: "connected", connection: { leaseId: "own" } }; },
      state: async () => { throw { code: "runtime_channel_closed" }; },
    });
    await toggle(context);
    expect(context.view).toBe("unavailable");
    expect(context.phase).toBe("error");
    expect(context.connectionIntentStatus).toBe("blocked_terminal");
    expect(context.error).toContain("службой подключения");
    await toggle(context);
    expect(starts).toBe(1);
  });

  it("does not advertise retry through the same permanently closed owner", async () => {
    const { context } = fixture();
    context.runtimeChannelClosed = true;
    context.runtimeWarning = "runtime_channel_closed";
    context.localStopPendingCleanup = true;
    let bootstraps = 0;
    Object.assign(context.nativeClient, { bootstrap: async () => { bootstraps++; } });
    await executePageFunction("restore", context);
    expect(bootstraps).toBe(0);
    expect(context.localStopPendingCleanup).toBe(true);
    expect(page).toContain("{#if !runtimeChannelClosed}");
  });

  it("removes protected presentation if the split-error state read discovers EOF", async () => {
    const { context } = fixture();
    context.phase = "connected";
    const failure = { code: "temporarily_unavailable" };
    Object.assign(context.nativeClient, {
      saveSplitTunnel: async () => { throw failure; },
      state: async () => { throw { code: "runtime_channel_closed" }; },
    });
    await expect(executePageFunction("saveSplitTunnel", context, {})).rejects.toBe(failure);
    expect(context.view).toBe("unavailable");
    expect(context.phase).toBe("error");
    expect(context.connectionIntentStatus).toBe("blocked_terminal");
  });

  for (const first of ["periodic", "split"] as const) {
    it(`discards a late successful ${first} reply after the other reader observes EOF`, async () => {
      const { context, reply, state } = fixture();
      context.phase = "connected";
      const response = context.nativeClient.state();
      let reads = 0;
      Object.assign(context.nativeClient, {
        state: () => ++reads === 1 ? response : Promise.reject({ code: "runtime_channel_closed" }),
        saveSplitTunnel: async () => { throw { code: "temporarily_unavailable" }; },
      });
      const split = () => executePageFunction("saveSplitTunnel", context, {}).catch(() => {});
      const pending = first === "periodic" ? synchronize(context) : split();
      await Promise.resolve();
      await (first === "periodic" ? split() : synchronize(context));
      expect(context.phase).toBe("error");
      reply(state);
      await pending;
      expect(context.phase).toBe("error");
      expect(context.view).toBe("unavailable");
      expect(context.runtimeChannelClosed).toBe(true);
    });
  }

  it("keeps closure sticky when a late split warning update clears ordinary warnings", async () => {
    const { context } = fixture();
    executePageFunction("applyRuntimeChannelClosure", context, { code: "runtime_channel_closed" });
    context.runtimeWarning = null;
    let bootstraps = 0;
    Object.assign(context.nativeClient, { bootstrap: async () => { bootstraps++; } });
    await executePageFunction("restore", context);
    expect(bootstraps).toBe(0);
    expect(context.runtimeChannelClosed).toBe(true);
    expect(context.view).toBe("unavailable");
  });

  it("renders full-relaunch guidance from the closure latch, not a mutable action error", () => {
    const closedView = page.match(/\{#if runtimeChannelClosed\}([\s\S]*?)\{:else if error\}/)?.[1];
    expect(closedView).toBeDefined();
    expect(closedView).toContain("Полностью завершите Nelomai");
    expect(closedView).toContain("Данные очищать не нужно");
    expect(closedView).not.toContain("{error}");
  });

  it("does not expose a blocking state during a periodic poll", async () => {
    const { context, reply, state } = fixture();
    const pending = synchronize(context, false);
    const blocking = context.runtimeStateSync.blocking;
    reply(state);
    await pending;
    expect(blocking).toBe(false);
  });
  it("exposes pending reconciliation and applies the authoritative local reply", async () => {
    const { context, reply, state } = fixture();
    const pending = synchronize(context);
    expect(context.runtimeStateSync.blocking).toBe(true);
    reply(state);
    await pending;
    expect(context.phase).toBe("connected");
    expect(context.runtimeWarning).toBeNull();
    expect(context.runtimeStateSync.blocking).toBe(false);
  });

  it.each([true, false])("reconciles a recovering intent after an error on foreground=%s", async (foreground) => {
    const { context, reply, state } = fixture();
    context.phase = "error";
    context.connectionIntentStatus = "recovering";
    const pending = synchronize(context, foreground);
    reply(state);
    await pending;
    expect(context.phase).toBe("connected");
    expect(context.connectionIntentStatus).toBe("none");
    expect(context.runtimeStateSync.pending).toBe(false);
  });

  it.each(["none", "blocked_terminal"])("does not poll an error with intent status %s", async (status) => {
    const { context, reply, state } = fixture();
    context.phase = "error";
    context.connectionIntentStatus = status;
    const pending = synchronize(context);
    reply(state);
    await pending;
    expect(context.phase).toBe("error");
    expect(context.connectionIntentStatus).toBe(status);
    expect(context.runtimeStateSync.pending).toBe(false);
  });

  it("does not disable Start on periodic polls, and ignores a late poll after Start", async () => {
    const { context, reply, state } = fixture();
    const pending = synchronize(context, false);
    expect(context.runtimeStateSync.pending).toBe(true);
    expect(context.runtimeStateSync.blocking).toBe(false);
    expect(canBeginConnectionAction(context.connectionActionState, context.busy, false, context.runtimeStateSync.blocking)).toBe(true);
    context.connectionActionState = beginConnectionStart(context.connectionActionState).state;
    context.phase = "connecting";
    reply({ ...state, phase: "ready" });
    await pending;
    expect(context.phase).toBe("connecting");
    expect(context.runtimeStateSync.pending).toBe(false);
  });

  it("promotes the same pending request on foreground wake and releases the barrier on failure", async () => {
    const { context, reply } = fixture();
    let calls = 0;
    const nativeState = context.nativeClient.state;
    context.nativeClient.state = () => { calls++; return nativeState(); };
    const pending = synchronize(context, false);
    await synchronize(context);
    expect(calls).toBe(1);
    expect(context.runtimeStateSync.blocking).toBe(true);
    reply(null);
    await pending;
    expect(context.runtimeStateSync.blocking).toBe(false);
    expect(context.phase).toBe("ready");
  });

  it("discards a reply captured before a newer Stop", async () => {
    const { context, reply, state } = fixture();
    const pending = synchronize(context);
    context.connectionActionState = beginConnectionStop(context.connectionActionState).state;
    context.phase = "stopping";
    context.runtimeWarning = null;
    reply(state);
    await pending;
    expect(context.phase).toBe("stopping");
    expect(context.runtimeWarning).toBeNull();
  });

  it("discards a reply from a previous authenticated view", async () => {
    const { context, reply, state } = fixture();
    const pending = synchronize(context);
    context.bootstrap = { binding: {} };
    context.phase = "signed_out";
    reply(state);
    await pending;
    expect(context.phase).toBe("signed_out");
  });

  it("does not invent an unexpected-stop notice for a confirmed voluntary stop", async () => {
    const { context, reply, state } = fixture();
    context.phase = "connected";
    const pending = synchronize(context);
    reply({ ...state, phase: "ready", localStopPendingCleanup: true });
    await pending;
    expect(context.phase).toBe("ready");
    expect(context.localStopPendingCleanup).toBe(true);
    expect(context.error).toBeNull();
  });
});

describe("binding changed outside the open UI", () => {
  it.each(["peer_binding_required", "binding_conflict"])("refreshes after preference sync rejects %s", async (code) => {
    let refreshed = 0;
    const context = {
      runtimeChannelClosed: false, bootstrapPending: false,
      bootstrap: {}, connectionActionState: initialConnectionActionState(), isCurrentConnectionAction,
      appPreferences: null, ticConnectionMode: "personal", error: null,
      nativeClient: { setTicEgressMode: async () => ({}) },
      syncBindingPreferences: async () => { throw { code }; },
      refreshProbes: async () => {}, commandCode, commandMessage,
      restore: async () => { refreshed++; },
    };
    await executePageFunction("setTicEgressMode", context, { currentTarget: { value: "prefer_ipv6" } });
    expect(refreshed).toBe(1);
  });

  it("does not refresh from a preference rejection after a newer Stop", async () => {
    let reject!: (error: unknown) => void;
    let refreshed = 0;
    const context = {
      runtimeChannelClosed: false, bootstrapPending: false,
      bootstrap: {}, connectionActionState: initialConnectionActionState(), isCurrentConnectionAction,
      appPreferences: null, ticConnectionMode: "personal", error: null,
      nativeClient: { setTicEgressMode: async () => ({}) },
      syncBindingPreferences: () => new Promise((_resolve, fail) => { reject = fail; }),
      refreshProbes: async () => {}, commandCode, commandMessage,
      restore: async () => { refreshed++; },
    };
    const pending = executePageFunction("setTicEgressMode", context, { currentTarget: { value: "prefer_ipv6" } });
    await Promise.resolve();
    context.connectionActionState = beginConnectionStop(context.connectionActionState).state;
    reject({ code: "binding_conflict" });
    await pending;
    expect(refreshed).toBe(0);
  });

  it("discards a bootstrap refresh overtaken by Stop without clearing its busy state", async () => {
    const { context } = fixture();
    let complete!: (value: unknown) => void;
    let applied = 0;
    Object.assign(context, {
      startupRetry: { cancel: () => {}, checkpoint: () => () => true }, startupPending: false, refreshPending: false,
      diagnosticsStatus: null, startupSlow: false, startupTimer: null,
      window: { setTimeout: () => 1, clearTimeout: () => {} },
      applyBootstrap: async () => { applied++; },
    });
    Object.assign(context.nativeClient, { bootstrap: () => new Promise((resolve) => { complete = resolve; }) });
    const pending = executePageFunction("restore", context);
    context.connectionActionState = beginConnectionStop(context.connectionActionState).state;
    context.busy = true;
    context.phase = "stopping";
    complete({ binding: null });
    await pending;
    expect(applied).toBe(0);
    expect(context.phase).toBe("stopping");
    expect(context.busy).toBe(true);
  });

  it.each(["signed_out", "authentication_outcome_unknown"])("shows explicit Login after bootstrap reports %s", async (code) => {
    const { context } = fixture();
    let passwordSubmissions = 0;
    Object.assign(context, {
      startupRetry: { cancel: () => {}, schedule: () => {}, checkpoint: () => () => true }, startupPending: false, refreshPending: false,
      retryPendingStartup: () => {},
      diagnosticsStatus: null, startupSlow: false, startupTimer: null,
      window: { setTimeout: () => 1, clearTimeout: () => {} },
      nativeClient: { bootstrap: async () => { throw { code }; }, recordStartupStage: () => {},
        login: () => { passwordSubmissions++; } },
    });
    await executePageFunction("restore", context);
    expect(context.view).toBe("sign_in");
    expect(context.phase).toBe("signed_out");
    expect(context.error).toBe(code === "signed_out" ? null : commandMessage({ code }, "login"));
    expect(passwordSubmissions).toBe(0);
  });

  it("discards the bootstrap state read if Stop takes ownership while it waits", async () => {
    const { context, reply, state } = fixture();
    Object.assign(context, {
      startupRetry: { cancel: () => {}, checkpoint: () => () => true }, startupPending: false,
      selectedLayer: "tic", ticConnectionMode: "personal", routeMode: "via_tak",
      refreshUpdateStatus: () => {}, refreshUpdateOffer: () => {}, refreshNotifications: () => {}, refreshRuntimeStatus: async () => {},
      refreshProbes: async () => {},
    });
    const response = { defaults: { layer: "tic", tic_connection_mode: "personal", route_mode: "via_tak" },
      update: { required: false }, access: { can_connect: true }, binding: {} };
    const pending = executePageFunction("applyBootstrap", context, response);
    context.connectionActionState = beginConnectionStop(context.connectionActionState).state;
    context.busy = true;
    context.phase = "stopping";
    reply({ ...state, phase: "ready" });
    await pending;
    expect(context.phase).toBe("stopping");
  });

  it("applies a current bootstrap even when reactive state wraps the response", async () => {
    const { context, reply, state } = fixture();
    let stored = context.bootstrap;
    Object.defineProperty(context, "bootstrap", {
      get: () => stored,
      set: (value) => { stored = new Proxy(value, {}); },
    });
    Object.assign(context, {
      startupRetry: { cancel: () => {}, checkpoint: () => () => true }, startupPending: false,
      selectedLayer: "tic", ticConnectionMode: "personal", routeMode: "via_tak",
      refreshUpdateStatus: () => {}, refreshUpdateOffer: () => {}, refreshNotifications: () => {}, refreshRuntimeStatus: async () => {},
      refreshProbes: async () => {},
    });
    const response = { defaults: { layer: "tic", tic_connection_mode: "personal", route_mode: "via_tak" },
      update: { required: false }, access: { can_connect: true }, binding: {} };
    const pending = executePageFunction("applyBootstrap", context, response);
    reply(state);
    await pending;
    expect(context.phase).toBe("connected");
  });

  it.each(["peer_binding_required", "binding_conflict"])("refreshes after Start rejects %s without retrying Start", async (code) => {
    const { context } = fixture();
    let starts = 0;
    let refreshed = 0;
    Object.assign(context, {
      bootstrap: { device: { id: "own-device", platform: "windows" }, binding: {} },
      connectionAction: "start", runtimeStatus: null, splitTunnelBlocksStart: false,
      runtimeStartBlocked: () => false, selectedLayer: "tic", ticConnectionMode: "dynamic",
      routeMode: "via_tak", selectedEgressMode: "ipv4", antivirusStartFailure: false,
      prepareConnectionStartForPlatform, canBeginConnectionAction, beginConnectionStart,
      beginConnectionStop, finishConnectionStart, finishConnectionStop,
      pendingBindingPreferenceRequest: () => ({ expected_binding_id: "old" }),
      waitForSettlement: async () => {}, START_FAILURE_DIAGNOSTICS_UI_TIMEOUT_MILLIS: 10,
      restore: async () => { refreshed++; context.phase = "needs_peer_binding"; context.view = "peer_selection"; },
    });
    Object.assign(context.nativeClient, {
      prepareTunnel: async () => {},
      start: async () => { starts++; throw { code }; },
      state: async () => ({ phase: "ready", connection: null }),
      queueStartFailureDiagnostics: async () => {},
    });
    await toggle(context);
    expect(refreshed).toBe(1);
    expect(starts).toBe(1);
    expect(context.view).toBe("peer_selection");
    expect(context.busy).toBe(false);
  });
});


describe("binding preferences across native Start", () => {
  function bindingFixture() {
    const { context } = fixture();
    let server = { id: "binding-1", peer_id: "peer-1", preferred_layer: "stray",
      tic_connection_mode: "dynamic", route_mode: "standalone", egress_mode: "ipv4" };
    const requests: any[] = [];
    const c: any = Object.assign(context, {
      startupRetry: { cancel: () => {}, checkpoint: () => () => true }, pinnedStray: null,
      bootstrap: { device: { id: "own-device", platform: "android" }, binding: { ...server } },
      connectionAction: "start", runtimeStatus: null, splitTunnelBlocksStart: false,
      runtimeStartBlocked: () => false, selectedLayer: "tic", ticConnectionMode: "dynamic",
      routeMode: "via_tak", selectedEgressMode: "ipv4", antivirusStartFailure: false,
      appPreferences: { dynamicTicEgressMode: "ipv4", personalTicEgressMode: "ipv4" },
      prepareConnectionStartForPlatform, canBeginConnectionAction, beginConnectionStart,
      beginConnectionStop, finishConnectionStart, finishConnectionStop,
      connectionEgressMode, bindingPreferenceUpdateRequest,
      waitForSettlement: async () => {}, START_FAILURE_DIAGNOSTICS_UI_TIMEOUT_MILLIS: 10,
      restore: async () => {},
    });
    c.pendingBindingPreferenceRequest = () => executePageFunction("pendingBindingPreferenceRequest", c);
    Object.assign(c.nativeClient, {
      prepareTunnel: async () => {},
      start: async (request: any) => {
        requests.push(request);
        if (request.bindingRequest) {
          expect(request.bindingRequest.expected_binding_id).toBe(server.id);
          expect(request.bindingRequest.peer_id).toBe(server.peer_id);
          server = { ...server, ...request.bindingRequest };
        }
        return { status: "connected", connection: { layer: request.layer }, nextRetryAtUnix: null };
      },
      stop: async () => null,
      state: async () => ({ phase: "ready", connection: null, connectionIntentStatus: "none" }),
      queueStartFailureDiagnostics: async () => {},
    });
    return { c, requests, get server() { return server; } };
  }

  it.each(["connected", "recovering", "failed"])("saves the return to Stray after %s Start", async (outcome) => {
    const f = bindingFixture();
    const start = f.c.nativeClient.start;
    f.c.nativeClient.start = async (request: any) => {
      const result = await start(request); // Binding can commit before the tunnel outcome.
      if (f.requests.length !== 1) return result;
      if (outcome === "failed") throw { code: "temporarily_unavailable" };
      return { ...result, status: outcome };
    };
    await toggle(f.c);
    expect(f.server.preferred_layer).toBe("tic");
    f.c.connectionAction = "stop";
    await toggle(f.c);
    f.c.connectionAction = "start";
    f.c.selectedLayer = "stray";
    f.c.routeMode = "standalone";
    await toggle(f.c);
    expect(f.requests[1].bindingRequest).toMatchObject({ preferred_layer: "stray",
      expected_binding_id: "binding-1", peer_id: "peer-1" });
    expect(f.server.preferred_layer).toBe("stray");
    expect(f.c.error).toBeNull();
  });

  it("does not skip restoring dynamic Tic after a personal Start", async () => {
    const f = bindingFixture();
    Object.assign(f.c.bootstrap.binding, { preferred_layer: "tic", route_mode: "via_tak" });
    f.c.ticConnectionMode = "personal";
    await toggle(f.c);
    f.c.connectionAction = "stop";
    await toggle(f.c);
    f.c.connectionAction = "start";
    f.c.ticConnectionMode = "dynamic";
    await toggle(f.c);
    expect(f.requests[1].bindingRequest?.tic_connection_mode).toBe("dynamic");
    expect(f.server.tic_connection_mode).toBe("dynamic");
  });

  it("saves the desired mode even when a native bind changed it after bootstrap", async () => {
    const f = bindingFixture();
    f.server.preferred_layer = "tic";
    f.server.route_mode = "via_tak";
    f.c.selectedLayer = "stray";
    f.c.routeMode = "standalone";
    await toggle(f.c);
    expect(f.server.preferred_layer).toBe("stray");
    expect(f.requests[0].bindingRequest).toMatchObject({ expected_binding_id: "binding-1",
      peer_id: "peer-1", preferred_layer: "stray" });
  });

  it("does not dispatch Start if preparation was cancelled", async () => {
    const f = bindingFixture();
    f.c.nativeClient.prepareTunnel = async () => {
      f.c.connectionActionState = beginConnectionStop(f.c.connectionActionState).state;
    };
    await toggle(f.c);
    expect(f.requests).toHaveLength(0);
  });

  it.each([
    ["connecting", "recovering"], ["connected", "none"],
    ["error", "blocked_terminal"], ["ready", "none"],
  ])("restores Stray after UI recreation while native state is %s/%s", async (phase, intentStatus) => {
    const first = bindingFixture();
    const commitBinding = first.c.nativeClient.start;
    let pendingRequest: any;
    first.c.nativeClient.start = async (request: any) => {
      pendingRequest = request;
      return { status: "recovering", connection: null, nextRetryAtUnix: 42 };
    };
    await toggle(first.c);
    expect(first.server.preferred_layer).toBe("stray");

    // A different page instance bootstraps before the independent native bind
    // commits. The state reply alone cannot prove which preferences were saved.
    const second = bindingFixture();
    let nativePhase = phase;
    Object.assign(second.c, { startupPending: false,
      refreshUpdateStatus: () => {}, refreshUpdateOffer: () => {}, refreshNotifications: () => {},
      refreshRuntimeStatus: async () => {}, refreshProbes: async () => {},
    });
    second.c.nativeClient.state = async () => ({ phase: nativePhase, connection: null,
      connectionIntentStatus: intentStatus, nextRetryAtUnix: null });
    await executePageFunction("applyBootstrap", second.c, {
      ...second.c.bootstrap, defaults: { layer: "stray", tic_connection_mode: "dynamic", route_mode: "standalone" },
      access: { can_connect: true, state: "active" }, update: { required: false }, pinned_stray: null,
    });
    await commitBinding(pendingRequest);
    expect(first.server.preferred_layer).toBe("tic");
    second.c.nativeClient.stop = async () => { nativePhase = "ready"; return null; };
    second.c.connectionAction = "stop";
    await toggle(second.c);
    let repeatedRequest: any;
    second.c.nativeClient.start = async (request: any) => {
      repeatedRequest = request;
      nativePhase = "connected";
      return commitBinding(request);
    };
    second.c.connectionAction = "start";
    await toggle(second.c);
    expect(first.server.preferred_layer).toBe("stray");
    expect(repeatedRequest.bindingRequest).toMatchObject({ expected_binding_id: "binding-1",
      peer_id: "peer-1", preferred_layer: "stray" });
    expect(second.c.error).toBeNull();
  });

  it("retries the desired preferences even if a rejected Start did not commit the bind", async () => {
    const f = bindingFixture();
    const start = f.c.nativeClient.start;
    f.c.nativeClient.start = async () => { throw { code: "temporarily_unavailable" }; };
    await toggle(f.c);
    expect(f.server.preferred_layer).toBe("stray");
    f.c.nativeClient.start = start;
    f.c.selectedLayer = "stray";
    f.c.routeMode = "standalone";
    await toggle(f.c);
    expect(f.requests[0].bindingRequest).toMatchObject({ preferred_layer: "stray",
      expected_binding_id: "binding-1" });
  });

  it("never constructs a new binding or reuses an old binding ID from uncertain preferences", async () => {
    const f = bindingFixture();
    await toggle(f.c);
    f.c.bootstrap = { device: { id: "another-device", platform: "android" }, binding: null };
    expect(f.c.pendingBindingPreferenceRequest()).toBeNull();
    f.c.bootstrap.binding = { ...f.server, id: "binding-2", peer_id: "peer-2" };
    expect(f.c.pendingBindingPreferenceRequest()).toMatchObject({ expected_binding_id: "binding-2",
      peer_id: "peer-2" });
  });

  it("does not trust the old snapshot after Stop overtakes a dispatched Start", async () => {
    const f = bindingFixture();
    let finish!: (value: unknown) => void;
    let dispatched!: () => void;
    const started = new Promise<void>(resolve => { dispatched = resolve; });
    const start = f.c.nativeClient.start;
    f.c.nativeClient.start = async (request: any) => {
      await start(request);
      return new Promise(resolve => { finish = resolve; dispatched(); });
    };
    const pending = toggle(f.c);
    await started;
    f.c.connectionActionState = beginConnectionStop(f.c.connectionActionState).state;
    f.c.phase = "stopping";
    finish({ status: "connected", connection: { layer: "tic" }, nextRetryAtUnix: null });
    await pending;
    expect(f.c.phase).toBe("stopping");
    f.c.selectedLayer = "stray";
    f.c.routeMode = "standalone";
    expect(f.c.pendingBindingPreferenceRequest()).toMatchObject({ preferred_layer: "stray",
      expected_binding_id: "binding-1" });
  });
});

describe("desktop async Stop", () => {
  it("keeps stopping until the authoritative state reply", async () => {
    const { context, reply, state } = fixture();
    let accepted!: () => void;
    let stateRequested!: () => void;
    const requested = new Promise<void>(resolve => { stateRequested = resolve; });
    const readState = context.nativeClient.state;
    Object.assign(context, {
      phase: "connected", connectionAction: "stop", splitTunnelBlocksStart: false, runtimeStatus: null,
      bootstrap: { device: { id: "own-device", platform: "windows" }, binding: {} },
      canBeginConnectionAction, beginConnectionStart, beginConnectionStop, finishConnectionStart, finishConnectionStop,
    });
    Object.assign(context.nativeClient, {
      stop: () => new Promise<void>(resolve => { accepted = resolve; }),
      state: () => { stateRequested(); return readState(); },
    });
    const pending = toggle(context);
    const immediatePhase = context.phase;
    accepted();
    await requested;
    const acceptedPhase = context.phase;
    reply({ ...state, phase: "ready" });
    await pending;
    expect(immediatePhase).toBe("stopping");
    expect(acceptedPhase).toBe("stopping");
    expect(context.phase).toBe("ready");
  });
});


describe("Windows Defender repair and transport warning", () => {
  function findBannerBlock(node: any): any {
    if (!node || typeof node !== "object") return null;
    if (node.type === "IfBlock" && node.consequent.nodes.some((child: any) => child.type === "RegularElement"
      && child.name === "section" && child.attributes.some((a: any) => a.name === "class"
        && a.value?.some((v: any) => v.data === "defender-banner")))) return node;
    for (const child of Object.values(node)) {
      for (const value of Array.isArray(child) ? child : [child]) {
        const found = findBannerBlock(value);
        if (found) return found;
      }
    }
    return null;
  }
  const block = findBannerBlock(template.fragment);
  const test = block.test as typeof block.test & { start: number; end: number };
  const helpers = ast.statements.filter((node) => ts.isFunctionDeclaration(node)
    && ["usesLegacyAwgDll", "defenderBannerVisible"].includes(node.name?.text ?? ""))
    .map((node) => node.getText(ast)).join("\n");
  const visible = new Function("context", `with (context) { ${ts.transpile(helpers,
    { target: ts.ScriptTarget.ES2022 })}; return !!(${page.slice(test.start, test.end)}); }`);
  const feedback = block.alternate?.nodes.find((node: any) => node.type === "IfBlock")?.test;
  const feedbackVisible = new Function("context", `with (context) { ${ts.transpile(helpers,
    { target: ts.ScriptTarget.ES2022 })}; return !!(${feedback ? page.slice(feedback.start, feedback.end) : "false"}); }`);
  const blockerDeclaration = ast.statements.filter(ts.isVariableStatement)
    .flatMap((node) => [...node.declarationList.declarations])
    .find((node) => node.name.getText(ast) === "reportedThirdPartyBlocker")!;
  const blockerExpression = (blockerDeclaration.initializer as ts.CallExpression).arguments[0].getText(ast);
  const readBlocker = new Function("context", `with (context) { return (${blockerExpression}); }`);
  function defenderFixture(): any {
    return {
      phase: "ready", selectedLayer: "stray", connection: null,
      desktopActiveSlot: null, reserveState: null, desktopTunnelBackend: "legacy",
      runtimeChannelClosed: false,
      appPreferences: { useReserveConnection: false },
      reportedThirdPartyBlocker: null,
      windowsDefender: { supported: true, state: "missing", dllPresent: true },
      defenderRepairBusy: false, defenderRepairMessage: null,
      defenderStatusRevision: 0,
      nativeClient: { repairWindowsDefender: async () => ({ supported: true, state: "missing", dllPresent: true }) },
    };
  }
  it("warns for the selected legacy DLL transport and a missing component", () => {
    const c = defenderFixture();
    expect(visible(c)).toBe(true);
    c.windowsDefender.state = "excluded";
    expect(visible(c)).toBe(false);
    c.windowsDefender.dllPresent = false;
    expect(visible(c)).toBe(true);
  });
  it("does not warn about the DLL for a prospective reserve worker or TIC", () => {
    const c = defenderFixture();
    c.appPreferences.useReserveConnection = true;
    expect(visible(c)).toBe(false);
    c.appPreferences.useReserveConnection = false;
    c.selectedLayer = "tic";
    expect(visible(c)).toBe(false);
  });
  it.each(["warming", "ready", "unavailable", "failover", "degraded"])("uses actual worker state %s after preferences change", (reserve) => {
    const c = defenderFixture();
    Object.assign(c, { phase: "connected", connection: { layer: "stray" }, reserveState: reserve, desktopTunnelBackend: "worker" });
    expect(visible(c)).toBe(false);
    c.windowsDefender.dllPresent = false;
    expect(visible(c)).toBe(false);
  });
  it("uses the actual active slot before reserve status arrives", () => {
    const c = defenderFixture();
    Object.assign(c, { phase: "connected", connection: { layer: "stray" }, desktopActiveSlot: "A", desktopTunnelBackend: "worker" });
    expect(visible(c)).toBe(false);
  });
  it("does not hide a running legacy DLL warning when next-start preferences change", () => {
    const c = defenderFixture();
    Object.assign(c, { phase: "connected", connection: { layer: "stray" }, selectedLayer: "tic" });
    c.appPreferences.useReserveConnection = true;
    expect(visible(c)).toBe(true);
  });
  it.each([null, undefined, "invalid"])("does not infer legacy from an unknown initial backend marker %s", (backend) => {
    const c = defenderFixture();
    Object.assign(c, { phase: "connected", connection: { layer: "stray", lease_id: "worker" }, desktopTunnelBackend: backend });
    expect(visible(c)).toBe(false);
  });
  it.each([null, "worker"])("does not label a pending connection with backend %s as legacy", (backend) => {
    const c = defenderFixture();
    Object.assign(c, { phase: "connecting", desktopTunnelBackend: backend });
    expect(visible(c)).toBe(false);
  });
  it("uses next-start preferences after a worker has stopped", () => {
    const c = defenderFixture();
    Object.assign(c, { phase: "ready", desktopTunnelBackend: "worker" });
    expect(visible(c)).toBe(true);
  });
  it.each([["legacy", true], ["worker", false], [null, false]])("uses confirmed backend %s rather than next-start preferences in error", (backend, warning) => {
    const c = defenderFixture();
    Object.assign(c, { phase: "error", connection: { layer: "stray" }, desktopTunnelBackend: backend });
    c.appPreferences.useReserveConnection = backend === "legacy";
    expect(visible(c)).toBe(warning);
  });
  it("keeps a successful worker Start unknown after two non-EOF state failures", async () => {
    const f = fixture();
    const c: any = Object.assign(f.context, defenderFixture(), {
      bootstrap: { device: { id: "own-device", platform: "windows" }, binding: {} },
      connectionAction: "start", runtimeStatus: null, splitTunnelBlocksStart: false,
      runtimeStartBlocked: () => false, ticConnectionMode: "dynamic",
      routeMode: "standalone", selectedEgressMode: "ipv4", antivirusStartFailure: false,
      prepareConnectionStartForPlatform, canBeginConnectionAction, beginConnectionStart,
      beginConnectionStop, finishConnectionStart, finishConnectionStop,
      pendingBindingPreferenceRequest: () => null,
    });
    c.appPreferences.useReserveConnection = true;
    let finishStart!: (value: unknown) => void;
    let startRequested!: () => void;
    const requested = new Promise<void>(resolve => { startRequested = resolve; });
    c.nativeClient.start = () => {
      startRequested();
      return new Promise(resolve => { finishStart = resolve; });
    };
    let reads = 0;
    c.nativeClient.state = async () => { reads++; throw { code: "tunnel_failed" }; };
    const pending = toggle(c);
    await requested;
    // The new preference belongs to the next connection only.
    c.appPreferences.useReserveConnection = false;
    finishStart({ status: "connected", connection: { layer: "stray", lease_id: "worker" }, nextRetryAtUnix: null });
    await pending;
    expect(reads).toBe(2);
    expect(c.phase).toBe("error");
    expect(c.runtimeChannelClosed).toBe(false);
    expect(c.connection.lease_id).toBe("worker");
    expect(c.desktopTunnelBackend).toBeNull();
    expect(c.busy).toBe(false);
    expect(visible(c)).toBe(false);
  });
  it.each([["worker", false], ["legacy", true], [null, false]])("keeps backend %s unknown after runtime channel closure", (backend, before) => {
    const f = fixture();
    const c: any = Object.assign(f.context, defenderFixture(), {
      phase: "connected", connection: { layer: "stray" }, desktopTunnelBackend: backend,
    });
    // This preference applies to the next Start, not the unobserved runtime.
    c.appPreferences.useReserveConnection = false;
    expect(visible(c)).toBe(before);
    executePageFunction("applyRuntimeChannelClosure", c, { code: "runtime_channel_closed" });
    expect(c.runtimeChannelClosed).toBe(true);
    expect(c.phase).toBe("error");
    expect(c.desktopTunnelBackend).toBeNull();
    expect(visible(c)).toBe(false);
  });
  it.each(["worker", "replacement"])("keeps worker status loss unknown and recognizes confirmed legacy lease %s", async (nextLease) => {
    const f = fixture();
    const c: any = Object.assign(f.context, defenderFixture());
    let current: any = { ...f.state, phase: "connected", connection: { layer: "stray", lease_id: "worker" },
      reserveState: "ready", desktopActiveSlot: "A", desktopTunnelBackend: "worker" };
    c.nativeClient.state = async () => current;
    c.readDesktopActiveSlot = (value: unknown) => executePageFunction("readDesktopActiveSlot", c, value);
    await synchronize(c);
    expect(visible(c)).toBe(false);
    // The native timeout/error reply omits both slot and backend. Actual async
    // reconciliation must retire old values rather than guess a legacy DLL.
    current = { ...current, reserveState: null, desktopActiveSlot: undefined, desktopTunnelBackend: undefined };
    c.appPreferences.useReserveConnection = false;
    await synchronize(c);
    expect(c.desktopTunnelBackend).toBeNull();
    expect(visible(c)).toBe(false);
    // A new confirmed legacy start must not inherit the old worker kind,
    // even when a pinned connection reuses the same lease identifier.
    current = { ...current, connection: { layer: "stray", lease_id: nextLease }, desktopTunnelBackend: "legacy" };
    c.appPreferences.useReserveConnection = true;
    await synchronize(c);
    expect(c.desktopTunnelBackend).toBe("legacy");
    expect(visible(c)).toBe(true);
  });
  it("uses a confirmed legacy reply even if an error path retains old reserve presentation", () => {
    const c = defenderFixture();
    Object.assign(c, { phase: "connected", connection: { layer: "stray" }, reserveState: "ready", desktopActiveSlot: "A" });
    expect(visible(c)).toBe(true);
  });
  it("keeps a specifically reported antivirus blocker visible", () => {
    const c = defenderFixture();
    Object.assign(c, { desktopActiveSlot: "B", reserveState: "ready", antivirusStartFailure: true,
      activeThirdPartyAntivirus: { name: "Test AV" } });
    c.reportedThirdPartyBlocker = readBlocker(c);
    expect(visible(c)).toBe(true);
    c.runtimeChannelClosed = true;
    expect(visible(c)).toBe(true);
  });
  it.each(["missing", "unavailable", "inactive"])("does not report successful repair for %s status", async (state) => {
    const c = defenderFixture();
    c.nativeClient.repairWindowsDefender = async () => ({ supported: true, state, dllPresent: true });
    await executePageFunction("repairWindowsDefender", c);
    expect(c.windowsDefender.state).toBe(state);
    expect(c.defenderRepairMessage).not.toMatch(/Исключение добавлено|готов к запуску/);
    expect(c.defenderRepairBusy).toBe(false);
    expect(visible(c) || feedbackVisible(c)).toBe(true);
  });
  it.each(["missing", "unavailable", "inactive"])("keeps explicit %s repair feedback after an accepted unknown transport reply", async (state) => {
    const f = fixture();
    const c: any = Object.assign(f.context, defenderFixture(), {
      phase: "connected", connection: { layer: "stray", lease_id: "legacy" },
    });
    c.nativeClient.repairWindowsDefender = async () => ({ supported: true, state, dllPresent: true });
    await executePageFunction("repairWindowsDefender", c);
    expect(visible(c) || feedbackVisible(c)).toBe(true);
    c.nativeClient.state = async () => ({ ...f.state, phase: "connected", connection: c.connection,
      reserveState: null, desktopTunnelBackend: undefined });
    await synchronize(c);
    expect(c.desktopTunnelBackend).toBeNull();
    expect(c.defenderRepairBusy).toBe(false);
    expect(c.defenderRepairMessage).toBeTruthy();
    expect(visible(c)).toBe(false);
    expect(feedbackVisible(c)).toBe(true);
  });
  it.each(["defender_exclusion_repair_cancelled", "defender_exclusion_repair_failed"])("keeps explicit %s feedback under unknown transport", async (code) => {
    const f = fixture();
    const c: any = Object.assign(f.context, defenderFixture(), {
      phase: "connected", connection: { layer: "stray", lease_id: "legacy" }, commandMessage,
    });
    c.nativeClient.repairWindowsDefender = async () => { throw { code }; };
    c.nativeClient.windowsDefenderStatus = async () => c.windowsDefender;
    c.refreshWindowsDefender = () => executePageFunction("refreshWindowsDefender", c);
    await executePageFunction("repairWindowsDefender", c);
    c.nativeClient.state = async () => ({ ...f.state, phase: "connected", connection: c.connection,
      reserveState: null, desktopTunnelBackend: undefined });
    await synchronize(c);
    expect(c.defenderRepairMessage).toBe(commandMessage({ code }, "start"));
    expect(visible(c)).toBe(false);
    expect(feedbackVisible(c)).toBe(true);
    expect(c.defenderRepairBusy).toBe(false);
  });
  it("reports success only for a confirmed exclusion with an intact component", async () => {
    const c = defenderFixture();
    c.nativeClient.repairWindowsDefender = async () => ({ supported: true, state: "excluded", dllPresent: true });
    await executePageFunction("repairWindowsDefender", c);
    expect(visible(c) || feedbackVisible(c)).toBe(false);
    c.nativeClient.repairWindowsDefender = async () => ({ supported: true, state: "excluded", dllPresent: false });
    await executePageFunction("repairWindowsDefender", c);
    expect(c.defenderRepairMessage).not.toMatch(/готов к запуску/);
    expect(c.defenderRepairMessage).toMatch(/восстановить/);
  });
  it.each(["before", "after"])("keeps missing-component repair feedback when backend becomes unknown %s repair", async (order) => {
    const f = fixture();
    const c: any = Object.assign(f.context, defenderFixture(), {
      phase: "connected", connection: { layer: "stray", lease_id: "legacy" },
    });
    c.nativeClient.repairWindowsDefender = async () => ({ supported: true, state: "excluded", dllPresent: false });
    c.nativeClient.state = async () => ({ ...f.state, phase: "connected", connection: c.connection,
      reserveState: null, desktopTunnelBackend: undefined });
    if (order === "before") await synchronize(c);
    await executePageFunction("repairWindowsDefender", c);
    if (order === "after") await synchronize(c);
    expect(c.desktopTunnelBackend).toBeNull();
    expect(c.defenderRepairMessage).toMatch(/восстановить/);
    expect(c.defenderRepairBusy).toBe(false);
    expect(visible(c)).toBe(false);
    expect(feedbackVisible(c)).toBe(true);
  });
  it("does not reveal completed repair success after a later missing-component status", async () => {
    const c = defenderFixture();
    Object.assign(c, { phase: "connected", desktopTunnelBackend: "worker" });
    c.nativeClient.repairWindowsDefender = async () => ({ supported: true, state: "excluded", dllPresent: true });
    await executePageFunction("repairWindowsDefender", c);
    expect(visible(c) || feedbackVisible(c)).toBe(false);
    c.nativeClient.windowsDefenderStatus = async () => ({ supported: true, state: "excluded", dllPresent: false });
    await executePageFunction("refreshWindowsDefender", c);
    expect(c.windowsDefender.dllPresent).toBe(false);
    expect(visible(c) || feedbackVisible(c)).toBe(false);
  });
  it.each(["missing", "unavailable"])("reconciles repair guidance with fresh %s status", async (state) => {
    const c = defenderFixture();
    Object.assign(c, { phase: "connected", desktopTunnelBackend: null });
    c.nativeClient.repairWindowsDefender = async () => ({ supported: true, state: "excluded", dllPresent: false });
    await executePageFunction("repairWindowsDefender", c);
    expect(feedbackVisible(c)).toBe(true);
    c.nativeClient.windowsDefenderStatus = async () => ({ supported: true, state, dllPresent: state === "missing" });
    await executePageFunction("refreshWindowsDefender", c);
    expect(c.defenderRepairMessage).not.toMatch(/Исключение подтверждено|переустановите/);
    expect(feedbackVisible(c)).toBe(true);
  });
  it("does not restore obsolete reinstall guidance after a healthy status resolves it", async () => {
    const c = defenderFixture();
    Object.assign(c, { phase: "connected", desktopTunnelBackend: null });
    c.nativeClient.repairWindowsDefender = async () => ({ supported: true, state: "excluded", dllPresent: false });
    await executePageFunction("repairWindowsDefender", c);
    c.nativeClient.windowsDefenderStatus = async () => ({ supported: true, state: "excluded", dllPresent: true });
    await executePageFunction("refreshWindowsDefender", c);
    expect(feedbackVisible(c)).toBe(false);
    c.nativeClient.windowsDefenderStatus = async () => ({ supported: true, state: "missing", dllPresent: true });
    await executePageFunction("refreshWindowsDefender", c);
    expect(feedbackVisible(c)).toBe(false);
  });
  it.each(["before", "during"])("does not overwrite a newer Repair result with a status request started %s Repair", async (order) => {
    const c = defenderFixture();
    Object.assign(c, { phase: "connected", desktopTunnelBackend: null });
    let finishStatus!: (value: unknown) => void;
    c.nativeClient.windowsDefenderStatus = () => new Promise(resolve => { finishStatus = resolve; });
    let pending: any;
    if (order === "before") pending = executePageFunction("refreshWindowsDefender", c);
    let finishRepair!: (value: unknown) => void;
    c.nativeClient.repairWindowsDefender = () => new Promise(resolve => { finishRepair = resolve; });
    const repair = executePageFunction("repairWindowsDefender", c);
    if (order === "during") pending = executePageFunction("refreshWindowsDefender", c);
    finishRepair({ supported: true, state: "excluded", dllPresent: false });
    await repair;
    finishStatus({ supported: true, state: "excluded", dllPresent: true });
    await pending;
    expect(c.windowsDefender.dllPresent).toBe(false);
    expect(feedbackVisible(c)).toBe(true);
  });
  it.each(["older", "newer"])("keeps the latest requested status when the %s reply completes first", async (first) => {
    const c = defenderFixture();
    const replies: Array<(value: unknown) => void> = [];
    c.nativeClient.windowsDefenderStatus = () => new Promise(resolve => { replies.push(resolve); });
    const older = executePageFunction("refreshWindowsDefender", c);
    const newer = executePageFunction("refreshWindowsDefender", c);
    const oldStatus = { supported: true, state: "excluded", dllPresent: false };
    const newStatus = { supported: true, state: "unavailable", dllPresent: true };
    if (first === "older") { replies[0](oldStatus); await older; replies[1](newStatus); }
    else { replies[1](newStatus); await newer; replies[0](oldStatus); }
    await Promise.all([older, newer]);
    expect(c.windowsDefender).toEqual(newStatus);
  });
  it("preserves a newer Repair error when an older status request completes", async () => {
    const c = defenderFixture();
    Object.assign(c, { phase: "connected", desktopTunnelBackend: null, commandMessage });
    c.nativeClient.repairWindowsDefender = async () => ({ supported: true, state: "excluded", dllPresent: false });
    await executePageFunction("repairWindowsDefender", c);
    let finishStatus!: (value: unknown) => void;
    let reads = 0;
    c.nativeClient.windowsDefenderStatus = () => ++reads === 1
      ? new Promise(resolve => { finishStatus = resolve; })
      : Promise.reject({ code: "tunnel_failed" });
    const pending = executePageFunction("refreshWindowsDefender", c);
    c.nativeClient.repairWindowsDefender = async () => { throw { code: "tunnel_failed" }; };
    c.refreshWindowsDefender = () => executePageFunction("refreshWindowsDefender", c);
    await executePageFunction("repairWindowsDefender", c);
    finishStatus({ supported: true, state: "unavailable", dllPresent: false });
    await pending;
    expect(c.defenderRepairMessage).toBe(commandMessage({ code: "tunnel_failed" }, "start"));
    expect(feedbackVisible(c)).toBe(true);
    expect(c.defenderRepairBusy).toBe(false);
  });
  it.each(["before", "during"])("preserves an identical newer Repair error when a status request starts %s Repair", async (order) => {
    const c = defenderFixture();
    Object.assign(c, { phase: "connected", desktopTunnelBackend: null, commandMessage });
    c.nativeClient.repairWindowsDefender = async () => { throw { code: "tunnel_failed" }; };
    c.nativeClient.windowsDefenderStatus = async () => { throw { code: "tunnel_failed" }; };
    c.refreshWindowsDefender = () => executePageFunction("refreshWindowsDefender", c);
    await executePageFunction("repairWindowsDefender", c);
    let finishStatus!: (value: unknown) => void;
    let reads = 0;
    c.nativeClient.windowsDefenderStatus = () => ++reads === 1
      ? new Promise(resolve => { finishStatus = resolve; })
      : Promise.reject({ code: "tunnel_failed" });
    let failRepair!: (reason: unknown) => void;
    c.nativeClient.repairWindowsDefender = () => new Promise((_, reject) => { failRepair = reject; });
    let pendingStatus: any;
    if (order === "before") pendingStatus = executePageFunction("refreshWindowsDefender", c);
    const pendingRepair = executePageFunction("repairWindowsDefender", c);
    if (order === "during") pendingStatus = executePageFunction("refreshWindowsDefender", c);
    failRepair({ code: "tunnel_failed" });
    await pendingRepair;
    finishStatus({ supported: true, state: "unavailable", dllPresent: false });
    await pendingStatus;
    expect(c.defenderRepairMessage).toBe(commandMessage({ code: "tunnel_failed" }, "start"));
    expect(feedbackVisible(c)).toBe(true);
    expect(c.defenderRepairBusy).toBe(false);
  });
  it.each(["defender_exclusion_repair_cancelled", "tunnel_failed"])("retains the current Repair error %s after a changed status refresh", async (code) => {
    const c = defenderFixture();
    Object.assign(c, { phase: "connected", desktopTunnelBackend: null, commandMessage });
    c.nativeClient.repairWindowsDefender = async () => { throw { code }; };
    c.nativeClient.windowsDefenderStatus = async () => ({ supported: true, state: "unavailable", dllPresent: false });
    c.refreshWindowsDefender = () => executePageFunction("refreshWindowsDefender", c);
    await executePageFunction("repairWindowsDefender", c);
    expect(c.defenderRepairMessage).toBe(commandMessage({ code }, "start"));
    expect(feedbackVisible(c)).toBe(true);
    expect(c.defenderRepairBusy).toBe(false);
  });
  it("does not hide a failed Repair behind an interim healthy status when confirmation fails", async () => {
    const c = defenderFixture();
    Object.assign(c, { commandMessage });
    let failRepair!: (reason: unknown) => void;
    c.nativeClient.repairWindowsDefender = () => new Promise((_, reject) => { failRepair = reject; });
    let reads = 0;
    c.nativeClient.windowsDefenderStatus = async () => {
      if (++reads === 1) return { supported: true, state: "excluded", dllPresent: true };
      throw { code: "tunnel_failed" };
    };
    c.refreshWindowsDefender = () => executePageFunction("refreshWindowsDefender", c);
    const pending = executePageFunction("repairWindowsDefender", c);
    await executePageFunction("refreshWindowsDefender", c);
    failRepair({ code: "tunnel_failed" });
    await pending;
    expect(c.defenderRepairMessage).toBe(commandMessage({ code: "tunnel_failed" }, "start"));
    expect(visible(c) || feedbackVisible(c)).toBe(true);
    expect(c.defenderRepairBusy).toBe(false);
  });
  it("hides repair failure feedback if a fresh post-failure check confirms an intact exclusion", async () => {
    const c = defenderFixture();
    Object.assign(c, { commandMessage });
    c.nativeClient.repairWindowsDefender = async () => { throw { code: "tunnel_failed" }; };
    c.nativeClient.windowsDefenderStatus = async () => ({ supported: true, state: "excluded", dllPresent: true });
    c.refreshWindowsDefender = () => executePageFunction("refreshWindowsDefender", c);
    await executePageFunction("repairWindowsDefender", c);
    expect(visible(c) || feedbackVisible(c)).toBe(false);
    expect(c.defenderRepairBusy).toBe(false);
  });
});
