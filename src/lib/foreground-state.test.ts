import page from "../routes/+page.svelte?raw";
import ts from "typescript";
import { parse } from "svelte/compiler";
import { describe, expect, it } from "vitest";
import { beginConnectionStart, beginConnectionStop, initialConnectionActionState, isCurrentConnectionAction,
  beginRuntimeStateSync, initialRuntimeStateSync, canBeginConnectionAction, finishConnectionStart,
  finishConnectionStop, prepareConnectionStartForPlatform } from "./connection-action";
import { clearOwnedConnectionIntentNotice } from "./connection-intent-notice";
import { commandCode, commandMessage } from "./native-client";
import { primaryAction, type Phase, type ConnectionIntentStatus } from "./app-model";

// Execute the page's actual async callback with controlled native replies. No
// duplicate implementation of its application/epoch checks in the test.
const script = page.match(/<script lang="ts">([\s\S]*?)<\/script>/)![1];
const ast = ts.createSourceFile("page.ts", script, ts.ScriptTarget.Latest, true);
const callback = ast.statements.find((node) => ts.isFunctionDeclaration(node)
  && node.name?.text === "synchronizeRuntimeState")!;
const sharedFunctions = ast.statements.filter((node) => ts.isFunctionDeclaration(node)
  && ["applyRuntimeChannelClosure", "requireRuntimeChannelOpen"].includes(node.name?.text ?? ""))
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
    busy: false, runtimeStateSync: initialRuntimeStateSync(), bootstrap: { binding: {} },
    phase: "ready", connection: null, runtimeWarning: "tunnel_runtime_stopped" as string | null,
    runtimeChannelClosed: false,
    splitTunnelOpen: false, splitTunnelState: null,
    splitTunnelBusy: false, splitTunnelLoaded: false, splitTunnelApplications: [],
    pinnedStray: null, loadPeers: async () => {},
    connectionActionState: initialConnectionActionState(),
    localStopPendingCleanup: false, connectionMetrics: null, reserveState: null,
    desktopActiveSlot: null, connectionIntentStatus: "none", nextRetryAtUnix: null,
    ownedConnectionIntentNotice: null, error: null, view: "connection",
    nativeClient: { state: () => response, recordStartupStage: () => {} },
    readDesktopActiveSlot: () => null, viewForAppState: () => "connection",
    loadSplitTunnel: async () => {}, isCurrentConnectionAction, clearOwnedConnectionIntentNotice,
    beginRuntimeStateSync, initialRuntimeStateSync, commandCode, commandMessage,
  };
  const state = { phase: "connected", connection: null, warning: null, metrics: null,
    reserveState: null, connectionIntentStatus: "none", nextRetryAtUnix: null };
  return { context, reply, reject, state };
}

function logoutFixture() {
  const result = fixture();
  Object.assign(result.context, {
    startupRetry: { cancel: () => {}, schedule: () => {} }, startupPending: false,
    peers: [{ id: 1 }], selectedPeerId: "1", password: "test-password",
    diagnosticsStatus: null, updateStatus: null, notifications: [],
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

describe("binding changed outside the open UI", () => {
  it.each(["peer_binding_required", "binding_conflict"])("refreshes after preference sync rejects %s", async (code) => {
    let refreshed = 0;
    const context = {
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
      startupRetry: { cancel: () => {} }, startupPending: false, refreshPending: false,
      diagnosticsStatus: null, startupSlow: false, startupTimer: null,
      window: { setTimeout: () => 1, clearTimeout: () => {} },
      applyBootstrap: async () => { applied++; },
    });
    Object.assign(context.nativeClient, { bootstrap: () => new Promise((resolve) => { complete = resolve; }) });
    const pending = executePageFunction("restore", context);
    context.connectionActionState = beginConnectionStop(context.connectionActionState).state;
    context.phase = "stopping";
    complete({ binding: null });
    await pending;
    expect(applied).toBe(0);
    expect(context.phase).toBe("stopping");
    expect(context.busy).toBe(true);
  });

  it("discards the bootstrap state read if Stop takes ownership while it waits", async () => {
    const { context, reply, state } = fixture();
    Object.assign(context, {
      startupRetry: { cancel: () => {} }, startupPending: false,
      selectedLayer: "tic", ticConnectionMode: "personal", routeMode: "via_tak",
      refreshUpdateStatus: () => {}, refreshNotifications: () => {}, refreshRuntimeStatus: async () => {},
      refreshProbes: async () => {},
    });
    const response = { defaults: { layer: "tic", tic_connection_mode: "personal", route_mode: "via_tak" },
      update: { required: false }, access: { can_connect: true }, binding: {} };
    const pending = executePageFunction("applyBootstrap", context, response);
    context.connectionActionState = beginConnectionStop(context.connectionActionState).state;
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
      startupRetry: { cancel: () => {} }, startupPending: false,
      selectedLayer: "tic", ticConnectionMode: "personal", routeMode: "via_tak",
      refreshUpdateStatus: () => {}, refreshNotifications: () => {}, refreshRuntimeStatus: async () => {},
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
      bootstrap: { device: { id: "own-device", platform: "android" }, binding: {} },
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
