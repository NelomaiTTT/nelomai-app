import page from "../routes/+page.svelte?raw";
import ts from "typescript";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { StartupRetry } from "./startup-retry";
import { beginConnectionStop, initialConnectionActionState, isCurrentConnectionAction } from "./connection-action";
import { commandCode, commandMessage } from "./native-client";
import { viewForAppState } from "./app-model";

// Execute the page's handlers and retry controller, replacing only native API,
// browser visibility and time. This catches missing lifecycle wiring as well
// as controller errors; the test does not implement its own restore loop.
const script = page.match(/<script lang="ts">([\s\S]*?)<\/script>/)![1];
const ast = ts.createSourceFile("page.ts", script, ts.ScriptTarget.Latest, true);
const names = ["restore", "applyBootstrap", "retryPendingStartup", "wakeStartup", "isAndroidRuntime", "logout", "applyRuntimeChannelClosure"];
const functions = ast.statements.filter(node => ts.isFunctionDeclaration(node) && names.includes(node.name?.text ?? ""))
  .map(node => node.getText(ast)).join("\n");
const handlers: string[] = [];
const registrations: string[] = [];
const removals: string[] = [];
function walk(node: ts.Node) {
  if (ts.isVariableDeclaration(node) && ["handleOnline", "handleVisibility"].includes(node.name.getText(ast))) {
    handlers.push("const " + node.getText(ast) + ";");
  }
  if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression) &&
    node.expression.expression.getText(ast) === "window" &&
    ts.isStringLiteral(node.arguments[0]) && node.arguments[0].text === "nelomai-network-restored") {
    if (node.expression.name.text === "addEventListener") registrations.push(node.getText(ast) + ";");
    if (node.expression.name.text === "removeEventListener") removals.push(node.getText(ast) + ";");
  }
  ts.forEachChild(node, walk);
}
walk(ast);
const evaluate = new Function("context", `with (context) { ${ts.transpile(functions + "\n" + handlers.join("\n"),
  {target: ts.ScriptTarget.ES2022})}; return {restore, logout, handleOnline, handleVisibility,
  attach() { ${registrations.join("\n")} }, detach() { ${removals.join("\n")} } }; }`);
const response = { defaults: { layer: "tic", tic_connection_mode: "personal", route_mode: "via_tak" },
  update: { required: false }, access: { can_connect: true }, binding: {},
  device: { id: "own-device", platform: "android" } };
const readyState = {phase: "ready", connection: null, warning: null, metrics: null, reserveState: null,
  connectionIntentStatus: "none", nextRetryAtUnix: null, localStopPendingCleanup: false};

function fixture(call: () => Promise<unknown>) {
  const listeners = new Map<string, () => void>();
  const context: Record<string, any> = {
    runtimeChannelClosed: false, bootstrapPending: false, ownedConnectionIntentNotice: null, busy: false, bootstrap: null, runtimeSelectionBusy: false, runtimeStatus: null,
    connectionActionState: initialConnectionActionState(), startupRetry: new StartupRetry(),
    startupPending: false, refreshPending: false, startupSlow: false, startupTimer: null,
    localStopPendingCleanup: false, diagnosticsStatus: null, error: null, view: "unavailable",
    phase: "server_unavailable", pinnedStray: null, selectedLayer: "tic", ticConnectionMode: "personal",
    routeMode: "via_tak", connection: null, connectionIntentStatus: "none", nextRetryAtUnix: null,
    connectionMetrics: null, reserveState: null, desktopActiveSlot: null, runtimeWarning: null,
    navigator: {userAgent: "Mozilla/5.0 (Linux; Android 16)"}, document: {visibilityState: "visible"},
    listeners, window: {setTimeout, clearTimeout,
      addEventListener: (name: string, callback: () => void) => listeners.set(name, callback),
      removeEventListener: (name: string) => listeners.delete(name)},
    commandCode, commandMessage, isCurrentConnectionAction, viewForAppState,
    refreshUpdateStatus: () => {}, refreshNotifications: () => {}, refreshRuntimeStatus: async () => {},
    loadSplitTunnel: async () => {}, refreshProbes: async () => {}, refreshUpdateOffer: async () => {},
    synchronizeRuntimeState: async () => {}, clearUpdateTimer: () => {},
    nativeClient: {bootstrap: call, state: async () => readyState, wakeConnectionIntent: async () => {},
      recordStartupStage: () => {}, logout: async () => {}},
    peers: [], selectedPeerId: "", password: "", updateStatus: null, splitTunnelState: null,
    splitTunnelApplications: [], splitTunnelOpen: false, splitTunnelLoaded: false, notifications: [],
    notificationUnreadCount: 0, notificationNextCursor: null, notificationHistoryExpanded: false,
    notificationsOpen: false, changelogOpen: false,
  };
  return {context, page: evaluate(context)};
}

describe("Android bootstrap recovery through lifecycle events", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it("recovers from a short outage automatically and bounds a sustained outage", async () => {
    let available = false;
    let attempts = 0;
    const f = fixture(async () => { attempts++; if (!available) throw {code: "temporarily_unavailable"}; return response; });
    await f.page.restore();
    await vi.advanceTimersByTimeAsync(2000);
    expect(attempts).toBe(2);
    available = true;
    await vi.advanceTimersByTimeAsync(2000);
    expect(attempts).toBe(3);
    expect(f.context.view).toBe("connection");
    expect(vi.getTimerCount()).toBe(0);
  });

  for (const event of ["handleOnline", "handleVisibility"]) {
    it(`${event} starts a new bounded attempt after the old budget is exhausted`, async () => {
      let available = false;
      let attempts = 0;
      const f = fixture(async () => { attempts++; if (!available) throw {code: "temporarily_unavailable"}; return response; });
      await f.page.restore();
      await vi.advanceTimersByTimeAsync(60000);
      expect(attempts).toBe(3);
      expect(vi.getTimerCount()).toBe(0);
      available = true;
      f.page[event]();
      await vi.advanceTimersByTimeAsync(1);
      expect(attempts).toBe(4);
      expect(f.context.view).toBe("connection");
      expect(vi.getTimerCount()).toBe(0);
    });
  }

  it("does not overlap a bootstrap or discard a network wake during its last attempt", async () => {
    let attempts = 0;
    let reject!: (reason: unknown) => void;
    const f = fixture(async () => {
      if (++attempts < 3) throw {code: "temporarily_unavailable"};
      if (attempts === 3) return new Promise((_, fail) => {reject = fail;});
      return response;
    });
    await f.page.restore();
    await vi.advanceTimersByTimeAsync(4000);
    expect(attempts).toBe(3);
    for (let i = 0; i < 10; i++) f.page.handleOnline();
    expect(attempts).toBe(3);
    reject({code: "temporarily_unavailable"});
    await vi.advanceTimersByTimeAsync(2000);
    expect(attempts).toBe(4);
    expect(f.context.view).toBe("connection");
  });

  it("subscribes to native physical-network wakes and removes the subscription", async () => {
    let available = false;
    let attempts = 0;
    const f = fixture(async () => { attempts++; if (!available) throw {code: "temporarily_unavailable"}; return response; });
    f.page.attach();
    await f.page.restore(); await vi.advanceTimersByTimeAsync(60000);
    available = true;
    f.context.listeners.get("nelomai-network-restored")?.();
    await vi.advanceTimersByTimeAsync(1);
    expect(attempts).toBe(4);
    expect(f.context.view).toBe("connection");
    f.page.detach();
    expect(f.context.listeners.size).toBe(0);
  });

  it.each(["signed_out", "access_expired", "update_required", "auth_recovery_required", "storage_unavailable", "runtime_channel_closed"])(
    "does not retry terminal %s on network or visibility changes", async code => {
      let attempts = 0;
      const f = fixture(async () => { attempts++; throw {code}; });
      await f.page.restore(); f.page.handleOnline(); f.page.handleVisibility();
      await vi.advanceTimersByTimeAsync(60000);
      expect(attempts).toBe(1);
    });

  it("retains desktop's existing temporary-error behavior", async () => {
    let attempts = 0;
    const f = fixture(async () => { attempts++; throw {code: "temporarily_unavailable"}; });
    f.context.navigator.userAgent = "Mozilla/5.0 (Macintosh)";
    await f.page.restore(); f.page.handleOnline(); f.page.handleVisibility();
    await vi.advanceTimersByTimeAsync(60000);
    expect(attempts).toBe(3);
  });

  it.each(["hidden", "switching", "logout", "disposed", "cleanup"])("ignores wake after %s", async mode => {
    let attempts = 0;
    const f = fixture(async () => { attempts++; throw {code: "temporarily_unavailable"}; });
    await f.page.restore(); await vi.advanceTimersByTimeAsync(60000);
    const before = attempts;
    if (mode === "hidden") f.context.document.visibilityState = "hidden";
    if (mode === "switching") f.context.runtimeSelectionBusy = true;
    if (mode === "logout") await f.page.logout();
    if (mode === "disposed") f.context.startupRetry.dispose();
    if (mode === "cleanup") f.context.localStopPendingCleanup = true;
    f.page.handleOnline(); f.page.handleVisibility();
    await vi.advanceTimersByTimeAsync(60000);
    expect(attempts).toBe(before);
  });

  it.each(["bootstrap", "state"])("rejects a late %s response after Stop", async stage => {
    let finish!: (value: unknown) => void;
    const f = fixture(async () => response);
    f.context.nativeClient[stage] = () => new Promise(resolve => {finish = resolve;});
    const pending = f.page.restore();
    await Promise.resolve();
    f.context.connectionActionState = beginConnectionStop(f.context.connectionActionState).state;
    f.context.connection = null; f.context.phase = "ready"; f.context.view = "connection";
    finish(stage === "bootstrap" ? response : {...readyState, phase: "connected", connection: {id: "old"}});
    await pending;
    expect(f.context.connection).toBeNull();
    expect(f.context.phase).toBe("ready");
    if (stage === "bootstrap") expect(f.context.bootstrap).toBeNull();
  });

  it("does not let a scheduled retry clear an unfinished Stop cleanup", async () => {
    let attempts = 0;
    const f = fixture(async () => { attempts++; throw {code: "temporarily_unavailable"}; });
    await f.page.restore();
    f.context.localStopPendingCleanup = true;
    await vi.advanceTimersByTimeAsync(60000);
    expect(attempts).toBe(1);
    expect(f.context.localStopPendingCleanup).toBe(true);
  });
});
