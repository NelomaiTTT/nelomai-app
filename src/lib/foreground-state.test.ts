import page from "../routes/+page.svelte?raw";
import ts from "typescript";
import { commandCode, commandMessage } from "./native-client";
import { describe, expect, it } from "vitest";
import { beginConnectionStart, beginConnectionStop, initialConnectionActionState, isCurrentConnectionAction,
  beginRuntimeStateSync, initialRuntimeStateSync, canBeginConnectionAction,
  finishConnectionStart, finishConnectionStop, prepareConnectionStartForPlatform } from "./connection-action";
import { clearOwnedConnectionIntentNotice } from "./connection-intent-notice";

// Execute the page's actual async callback with controlled native replies. No
// duplicate implementation of its application/epoch checks in the test.
const script = page.match(/<script lang="ts">([\s\S]*?)<\/script>/)![1];
const ast = ts.createSourceFile("page.ts", script, ts.ScriptTarget.Latest, true);
const callback = ast.statements.find((node) => ts.isFunctionDeclaration(node)
  && node.name?.text === "synchronizeRuntimeState")!;
const executable = ts.transpile(callback.getText(ast), { target: ts.ScriptTarget.ES2022 });
const synchronize = new Function("context", "foreground = true", `with (context) { ${executable}; return synchronizeRuntimeState(foreground); }`);

function fixture() {
  let reply!: (value: unknown) => void;
  const response = new Promise((resolve) => { reply = resolve; });
  const context = {
    busy: false, runtimeStateSync: initialRuntimeStateSync(), bootstrap: { binding: {} },
    phase: "ready", connection: null, runtimeWarning: "tunnel_runtime_stopped" as string | null,
    connectionActionState: initialConnectionActionState(),
    localStopPendingCleanup: false, connectionMetrics: null, reserveState: null,
    desktopActiveSlot: null, connectionIntentStatus: "none", nextRetryAtUnix: null,
    ownedConnectionIntentNotice: null, error: null, view: "connection",
    nativeClient: { state: () => response, recordStartupStage: () => {} },
    readDesktopActiveSlot: () => null, viewForAppState: () => "connection",
    loadSplitTunnel: async () => {}, isCurrentConnectionAction, clearOwnedConnectionIntentNotice, commandCode, commandMessage,
    beginRuntimeStateSync, initialRuntimeStateSync,
  };
  const state = { phase: "connected", connection: null, warning: null, metrics: null,
    reserveState: null, connectionIntentStatus: "none", nextRetryAtUnix: null };
  return { context, reply, state };
}

describe("foreground native state callback", () => {
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

function executePageFunction(name: string, context: object, ...args: unknown[]) {
  const node = ast.statements.find((node) => ts.isFunctionDeclaration(node) && node.name?.text === name)!;
  const source = ts.transpile(node.getText(ast), { target: ts.ScriptTarget.ES2022 });
  return new Function("context", "args", `with (context) { ${source}; return ${name}(...args); }`)(context, args);
}
const toggle = (context: object) => executePageFunction("toggleConnection", context);
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
    context.busy = true;
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
