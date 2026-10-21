import page from "../routes/+page.svelte?raw";
import ts from "typescript";
import { commandCode, commandMessage } from "./native-client";
import { describe, expect, it } from "vitest";
import { beginConnectionStart, beginConnectionStop, initialConnectionActionState, isCurrentConnectionAction,
  beginRuntimeStateSync, initialRuntimeStateSync, canBeginConnectionAction,
  finishConnectionStart, finishConnectionStop, prepareConnectionStartForPlatform } from "./connection-action";
import { clearOwnedConnectionIntentNotice } from "./connection-intent-notice";
import { bindingPreferenceUpdateRequest, connectionEgressMode } from "./app-model";

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


describe("binding preferences across native Start", () => {
  function bindingFixture() {
    const { context } = fixture();
    let server = { id: "binding-1", peer_id: "peer-1", preferred_layer: "stray",
      tic_connection_mode: "dynamic", route_mode: "standalone", egress_mode: "ipv4" };
    const requests: any[] = [];
    const c: any = Object.assign(context, {
      startupRetry: { cancel: () => {} }, pinnedStray: null,
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
      refreshUpdateStatus: () => {}, refreshNotifications: () => {},
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
