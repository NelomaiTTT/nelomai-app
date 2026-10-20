import page from "../routes/+page.svelte?raw";
import ts from "typescript";
import { parse } from "svelte/compiler";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { StartupRetry } from "./startup-retry";
import { beginConnectionStop, initialConnectionActionState, isCurrentConnectionAction } from "./connection-action";
import { commandCode, commandMessage } from "./native-client";
import { viewForAppState } from "./app-model";

// Exercise the page's real restore/retry and lifecycle callbacks, with only the
// native boundary replaced by controlled responses.
const script = page.match(/<script lang="ts">([\s\S]*?)<\/script>/)![1];
const ast = ts.createSourceFile("page.ts", script, ts.ScriptTarget.Latest, true);
const names = ["restore", "retryPendingStartup", "applyBootstrap", "applyRuntimeChannelClosure", "selectRuntime", "restartRuntime", "logout"];
const functions = ast.statements.filter((node) => ts.isFunctionDeclaration(node)
  && names.includes(node.name?.text ?? "")).map((node) => node.getText(ast)).join("\n");
const callbacks = new Function("context", `with (context) { ${ts.transpile(functions,
  { target: ts.ScriptTarget.ES2022 })}; return { ${names.join(",")} }; }`);

// Evaluate the page's real presentation while native replies are still pending.
function elementsWithClass(node: any, className: string): any[] {
  if (!node || typeof node !== "object") return [];
  const matches = node.type === "RegularElement" && node.attributes.some((attribute: any) =>
    attribute.name === "class" && attribute.value?.some((value: any) =>
      value.data?.split(" ").includes(className))) ? [node] : [];
  for (const child of Object.values(node)) {
    for (const value of Array.isArray(child) ? child : [child]) {
      matches.push(...elementsWithClass(value, className));
    }
  }
  return matches;
}

function presentationExpression(element: any) {
  const expression = element.fragment.nodes.find((node: any) => node.type === "ExpressionTag").expression;
  return new Function("context", `with (context) { return ${page.slice(expression.start, expression.end)}; }`);
}

const template = parse(page, { modern: true });
const messagePanels = elementsWithClass(template.fragment, "message-panel");
const unavailableHeading = presentationExpression(messagePanels[messagePanels.length - 1].fragment.nodes
  .find((node: any) => node.type === "RegularElement" && node.name === "h1"));
const statusElement = elementsWithClass(template.fragment, "status")[0];
const headerStatus = presentationExpression(statusElement);
const statusPhase = statusElement.attributes.find((attribute: any) => attribute.name === "data-phase")
  .value.expression;
const headerPhase = new Function("context", `with (context) { return ${page.slice(statusPhase.start, statusPhase.end)}; }`);
const response = { defaults: { layer: "tic", tic_connection_mode: "personal", route_mode: "via_tak" },
  update: { required: false }, access: { can_connect: true }, binding: {}, device: { id: "own-device" } };

function fixture(bootstrap: () => Promise<unknown>) {
  const context: Record<string, any> = {
    busy: false, bootstrap: null, runtimeChannelClosed: false, runtimeSelectionBusy: false,
    connectionActionState: initialConnectionActionState(), startupRetry: new StartupRetry(),
    startupPending: false, bootstrapPending: false, refreshPending: false, startupSlow: false, startupTimer: null,
    localStopPendingCleanup: false, diagnosticsStatus: null, error: null, view: "unavailable",
    phase: "server_unavailable", pinnedStray: null, selectedLayer: "tic", ticConnectionMode: "personal",
    routeMode: "via_tak", connection: null, connectionIntentStatus: "none", nextRetryAtUnix: null,
    connectionMetrics: null, reserveState: null, runtimeWarning: null, splitTunnelOpen: false,
    ownedConnectionIntentNotice: null, runtimeStatus: null,
    phaseLabels: { server_unavailable: "Сервер недоступен", error: "Ошибка" },
    window: { setTimeout, clearTimeout }, commandCode, commandMessage, isCurrentConnectionAction,
    viewForAppState, loadSplitTunnel: async () => {}, refreshProbes: async () => {},
    refreshUpdateStatus: () => {}, refreshNotifications: () => {}, refreshRuntimeStatus: async () => {},
    scheduleRuntimeStatusRefresh: () => {}, runtimeStatusRefresher: { commit: () => {} },
    nativeClient: { bootstrap, state: async () => ({ phase: "ready", connection: null, warning: null,
      metrics: null, reserveState: null, connectionIntentStatus: "none", nextRetryAtUnix: null,
      localStopPendingCleanup: false }),
      recordStartupStage: () => {}, runtimeSelect: async () => ({}), restartRuntime: async () => {},
      logout: async () => {} },
    peers: [], selectedPeerId: "", password: "", updateStatus: null, splitTunnelState: null,
    splitTunnelApplications: [], splitTunnelLoaded: false, notifications: [], notificationUnreadCount: 0,
    notificationNextCursor: null, notificationHistoryExpanded: false, notificationsOpen: false,
    changelogOpen: false, clearUpdateTimer: () => {},
  };
  return { context, page: callbacks(context) };
}

describe("bounded bootstrap recovery", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it("shows preparation instead of an outage while bootstrap is in flight", async () => {
    let finish!: (value: unknown) => void;
    const f = fixture(() => new Promise((resolve) => { finish = resolve; }));
    const running = f.page.restore();
    expect(f.context.busy).toBe(true);
    expect(f.context.view).toBe("unavailable");
    expect(unavailableHeading(f.context)).toBe("Подключаемся к панели");
    expect(headerStatus(f.context)).toBe("Подготовка приложения");
    expect(headerPhase(f.context)).toBe("preparing");
    finish(response);
    await running;
    expect(f.context.view).toBe("connection");
    expect(f.context.busy).toBe(false);
  });

  it("keeps preparation visible until authoritative runtime state arrives", async () => {
    let finish!: (value: unknown) => void;
    const f = fixture(async () => response);
    f.context.nativeClient.state = () => new Promise((resolve) => { finish = resolve; });
    const running = f.page.restore();
    await Promise.resolve();
    expect(f.context.busy).toBe(true);
    expect(f.context.view).toBe("unavailable");
    expect(unavailableHeading(f.context)).toBe("Подключаемся к панели");
    expect(headerStatus(f.context)).toBe("Подготовка приложения");
    expect(headerPhase(f.context)).toBe("preparing");
    finish({ phase: "ready", connection: null, warning: null, metrics: null,
      reserveState: null, connectionIntentStatus: "none", nextRetryAtUnix: null,
      localStopPendingCleanup: false });
    await running;
    expect(f.context.view).toBe("connection");
    expect(f.context.phase).toBe("ready");
    expect(f.context.busy).toBe(false);
  });

  for (const stage of ["bootstrap", "state"]) {
    it(`shows an actual ${stage} failure after the request settles`, async () => {
      const f = fixture(async () => response);
      f.context.nativeClient[stage] = async () => { throw { code: "temporarily_unavailable" }; };
      await f.page.restore();
      expect(f.context.busy).toBe(false);
      expect(f.context.view).toBe("unavailable");
      expect(unavailableHeading(f.context)).toBe("Сейчас сервис недоступен");
      expect(headerStatus(f.context)).toBe("Сервер недоступен");
      expect(headerPhase(f.context)).toBe("server_unavailable");
      expect(f.context.error).toBeTruthy();
    });
  }

  for (const terminalPhase of ["error", "server_unavailable"]) {
    for (const ancillary of ["refreshRuntimeStatus", "loadSplitTunnel"]) {
      it(`shows returned ${terminalPhase} while ${ancillary} is pending`, async () => {
        const f = fixture(async () => response);
        f.context.nativeClient.state = async () => ({ phase: terminalPhase, connection: null,
          warning: null, metrics: null, reserveState: null, connectionIntentStatus: "none",
          nextRetryAtUnix: null, localStopPendingCleanup: false });
        let finish!: () => void;
        f.context[ancillary] = () => new Promise<void>((resolve) => { finish = resolve; });
        const running = f.page.restore();
        await vi.advanceTimersByTimeAsync(0);
        try {
          expect(f.context.phase).toBe(terminalPhase);
          expect(f.context.view).toBe("unavailable");
          expect(f.context.busy).toBe(true);
          expect(unavailableHeading(f.context)).toBe("Сейчас сервис недоступен");
          expect(headerStatus(f.context)).toBe(terminalPhase === "error" ? "Ошибка" : "Сервер недоступен");
          expect(headerPhase(f.context)).toBe(terminalPhase);
        } finally {
          finish();
          await running;
        }
      });
    }
  }

  it("does not let a pending startup hide confirmed owner channel closure", () => {
    const f = fixture(async () => response);
    Object.assign(f.context, { startupPending: true, bootstrapPending: true, refreshPending: true, busy: true });
    f.page.applyRuntimeChannelClosure({ code: "runtime_channel_closed" });
    expect(unavailableHeading(f.context)).toBe("Сейчас сервис недоступен");
    expect(headerStatus(f.context)).toBe("Ошибка");
    expect(headerPhase(f.context)).toBe("error");
    expect(f.context.connectionIntentStatus).toBe("blocked_terminal");
  });

  it("recovers a temporary startup failure without a second click", async () => {
    let calls = 0;
    const f = fixture(async () => { if (++calls === 1) throw { code: "temporarily_unavailable" }; return response; });
    await f.page.restore();
    await vi.advanceTimersByTimeAsync(1999);
    expect(calls).toBe(1);
    await vi.advanceTimersByTimeAsync(1);
    expect(calls).toBe(2);
    expect(f.context.view).toBe("connection");
    expect(f.context.error).toBeNull();
    expect(vi.getTimerCount()).toBe(0);
  });

  it("stops after two automatic attempts during a sustained outage", async () => {
    let calls = 0;
    const f = fixture(async () => { calls++; throw { code: "temporarily_unavailable" }; });
    await f.page.restore();
    await vi.advanceTimersByTimeAsync(60000);
    expect(calls).toBe(3);
    expect(f.context.view).toBe("unavailable");
    expect(f.context.busy).toBe(false);
    expect(vi.getTimerCount()).toBe(0);
    await f.page.restore();
    await vi.advanceTimersByTimeAsync(60000);
    expect(calls).toBe(6);
  });

  it("manual retry retires the old timer", async () => {
    let calls = 0;
    const f = fixture(async () => { if (++calls === 1) throw { code: "temporarily_unavailable" }; return response; });
    await f.page.restore();
    await f.page.restore();
    await vi.advanceTimersByTimeAsync(60000);
    expect(calls).toBe(2);
  });

  for (const code of ["signed_out", "auth_recovery_required", "access_expired", "update_required", "runtime_channel_closed"]) {
    it(`stops automatic retry on ${code}`, async () => {
      let calls = 0;
      const f = fixture(async () => { calls++; throw { code: calls === 1 ? "temporarily_unavailable" : code }; });
      await f.page.restore();
      await vi.advanceTimersByTimeAsync(60000);
      expect(calls).toBe(2);
      expect(vi.getTimerCount()).toBe(0);
    });
  }

  for (const cancellation of ["stop", "account", "logout", "runtime", "restart", "closed", "unmount"]) {
    it(`does not issue a delayed bootstrap after ${cancellation}`, async () => {
      let calls = 0;
      const f = fixture(async () => { calls++; throw { code: "temporarily_unavailable" }; });
      await f.page.restore();
      if (cancellation === "stop") f.context.connectionActionState = beginConnectionStop(f.context.connectionActionState).state;
      if (cancellation === "account") f.context.bootstrap = { device: { id: "other-device" } };
      if (cancellation === "logout") await f.page.logout();
      if (cancellation === "runtime") await f.page.selectRuntime(true);
      if (cancellation === "restart") await f.page.restartRuntime();
      if (cancellation === "closed") f.page.applyRuntimeChannelClosure({ code: "runtime_channel_closed" });
      if (cancellation === "unmount") f.context.startupRetry.dispose();
      await vi.advanceTimersByTimeAsync(60000);
      expect(calls).toBe(1);
    });
  }

  it("does not let a retired request clear a newer bootstrap's busy state", async () => {
    const pending: { finish: (value: unknown) => void; reject: (reason: unknown) => void }[] = [];
    const f = fixture(() => new Promise((finish, reject) => { pending.push({ finish, reject }); }));
    const first = f.page.restore();
    const second = f.page.restore();
    pending[0].reject({ code: "temporarily_unavailable" });
    await first;
    expect(f.context.busy).toBe(true);
    expect(unavailableHeading(f.context)).toBe("Подключаемся к панели");
    pending[1].finish(response);
    await second;
    expect(f.context.busy).toBe(false);
    expect(f.context.view).toBe("connection");
  });

  it("does not hide an authoritative state failure after bootstrap succeeds", async () => {
    const f = fixture(async () => response);
    f.context.nativeClient.state = async () => { throw { code: "signed_out" }; };
    await f.page.restore();
    expect(f.context.view).toBe("sign_in");
    expect(vi.getTimerCount()).toBe(0);
  });

  it("does not reset the retry limit when state remains temporarily unavailable", async () => {
    let calls = 0;
    const f = fixture(async () => { calls++; return response; });
    f.context.nativeClient.state = async () => { throw { code: "temporarily_unavailable" }; };
    await f.page.restore();
    await vi.advanceTimersByTimeAsync(60000);
    expect(calls).toBe(3);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("does not apply a late state snapshot after runtime selection", async () => {
    let finish!: (value: unknown) => void;
    const f = fixture(async () => response);
    f.context.nativeClient.state = () => new Promise((ok) => { finish = ok; });
    const running = f.page.restore();
    await Promise.resolve();
    await f.page.selectRuntime(true);
    finish({ phase: "ready" });
    await running;
    expect(f.context.view).toBe("unavailable");
  });

  it("does not rearm or apply a late response after runtime selection", async () => {
    for (const failed of [false, true]) {
      let finish!: (value: unknown) => void;
      let reject!: (error: unknown) => void;
      let calls = 0;
      const f = fixture(() => { calls++; return new Promise((ok, fail) => { finish = ok; reject = fail; }); });
      const running = f.page.restore();
      await f.page.selectRuntime(true);
      if (failed) reject({ code: "temporarily_unavailable" }); else finish(response);
      await running;
      await vi.advanceTimersByTimeAsync(60000);
      expect(calls).toBe(1);
      expect(f.context.bootstrap).toBeNull();
    }
  });
});
