import page from "../routes/+page.svelte?raw";
import ts from "typescript";
import { describe, expect, it } from "vitest";
import { beginConnectionStop, initialConnectionActionState, isCurrentConnectionAction } from "./connection-action";
import { clearOwnedConnectionIntentNotice } from "./connection-intent-notice";

// Execute the page's actual async callback with controlled native replies. No
// duplicate implementation of its application/epoch checks in the test.
const script = page.match(/<script lang="ts">([\s\S]*?)<\/script>/)![1];
const ast = ts.createSourceFile("page.ts", script, ts.ScriptTarget.Latest, true);
const callback = ast.statements.find((node) => ts.isFunctionDeclaration(node)
  && node.name?.text === "synchronizeRuntimeState")!;
const executable = ts.transpile(callback.getText(ast), { target: ts.ScriptTarget.ES2022 });
const synchronize = new Function("context", `with (context) { ${executable}; return synchronizeRuntimeState(); }`);

function fixture() {
  let reply!: (value: unknown) => void;
  const response = new Promise((resolve) => { reply = resolve; });
  const context = {
    busy: false, runtimeStateBusy: false, bootstrap: { binding: {} },
    phase: "ready", connection: null, runtimeWarning: "tunnel_runtime_stopped" as string | null,
    connectionActionState: initialConnectionActionState(),
    localStopPendingCleanup: false, connectionMetrics: null, reserveState: null,
    desktopActiveSlot: null, connectionIntentStatus: "none", nextRetryAtUnix: null,
    ownedConnectionIntentNotice: null, error: null, view: "connection",
    nativeClient: { state: () => response, recordStartupStage: () => {} },
    readDesktopActiveSlot: () => null, viewForAppState: () => "connection",
    loadSplitTunnel: async () => {}, isCurrentConnectionAction, clearOwnedConnectionIntentNotice,
  };
  const state = { phase: "connected", connection: null, warning: null, metrics: null,
    reserveState: null, connectionIntentStatus: "none", nextRetryAtUnix: null };
  return { context, reply, state };
}

describe("foreground native state callback", () => {
  it("exposes pending reconciliation and applies the authoritative local reply", async () => {
    const { context, reply, state } = fixture();
    const pending = synchronize(context);
    expect(context.runtimeStateBusy).toBe(true);
    reply(state);
    await pending;
    expect(context.phase).toBe("connected");
    expect(context.runtimeWarning).toBeNull();
    expect(context.runtimeStateBusy).toBe(false);
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
