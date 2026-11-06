import { describe, expect, it, vi } from "vitest";
import ts from "typescript";
import page from "../routes/+page.svelte?raw";
import type { UpdateStatus } from "./app-model";
import { UpdateOfferRefresher } from "./update-offer-refresher";
import { canConfirmUpdate, updatePrompt } from "./update-presentation";
import { updateDiagnosticStage, updateRefreshDiagnosticStage, updateStatusNeedsPolling } from "./update-diagnostics";

// Execute the actual page callbacks; only IPC replies and timers are controlled.
const script = page.match(/<script lang="ts">([\s\S]*?)<\/script>/)![1];
const ast = ts.createSourceFile("page.ts", script, ts.ScriptTarget.Latest, true);
const callbacks = ast.statements.filter(node => ts.isFunctionDeclaration(node)
  && ["refreshUpdateStatus", "observeUpdateStatus", "refreshUpdateOffer"].includes(node.name?.text ?? ""))
  .map(node => node.getText(ast)).join("\n");
const createPage = new Function("context", `with(context) {
  ${ts.transpile(callbacks, { target: ts.ScriptTarget.ES2022 })}
  return {refreshUpdateStatus, refreshUpdateOffer, observeUpdateStatus};
}`);
const idle: UpdateStatus = { protocol: 2, supported: true, automatic: true, phase: "idle",
  version: null, notes: null, required: false, downloaded: 0, total: null, errorCode: null,
  offerId: null, promptPending: false, updateAvailable: false };
const checking: UpdateStatus = { ...idle, phase: "checking", errorCode: "update_refresh_pending" };
const available: UpdateStatus = { ...idle, phase: "available", version: "0.4.2",
  offerId: "offer-042", promptPending: true, updateAvailable: true };
const failed: UpdateStatus = { ...idle, errorCode: "update_refresh_service" };
const errorMessage = "Не удалось проверить обновление. Повторите позже.";
function deferred() {
  let resolve!: (status: UpdateStatus) => void;
  let reject!: (reason: Error) => void;
  const promise = new Promise<UpdateStatus>((ok, fail) => { resolve = ok; reject = fail; });
  return { promise, resolve, reject };
}
function fixture() {
  const nativeClient = { updateStatus: vi.fn(async () => idle), checkUpdate: vi.fn(async () => checking),
    recordStartupStage: vi.fn() };
  const timers: Array<() => Promise<void>> = [];
  const context = { nativeClient, bootstrap: {}, updateStatus: idle as UpdateStatus | null,
    updateRequestSequence: 0, updateAppliedSequence: 0, updateOfferRefresher: new UpdateOfferRefresher<UpdateStatus>(),
    updateDialogId: null, updateUiVisible: true, view: "settings", manualUpdatePending: null as unknown,
    manualUpdateResult: null as string | null, updateTimer: null, lastRecordedUpdateState: null,
    canConfirmUpdate, updatePrompt, updateRefreshDiagnosticStage, updateDiagnosticStage, updateStatusNeedsPolling,
    clearUpdateTimer: () => { timers.length = 0; },
    window: { setTimeout: (callback: () => Promise<void>) => { timers.push(callback); return timers.length; } },
  };
  return { context, timers, ...createPage(context) };
}

describe("manual update result ownership", () => {
  it.each([available, failed, idle])("waits for the current check before showing $phase/$errorCode", async status => {
    const f = fixture(), old = deferred(), ack = deferred();
    f.context.nativeClient.updateStatus.mockReturnValueOnce(old.promise);
    f.context.nativeClient.checkUpdate.mockReturnValueOnce(ack.promise);
    const poll = f.refreshUpdateStatus(), manual = f.refreshUpdateOffer("manual");
    old.resolve(idle); await poll;
    expect(f.context.manualUpdateResult).toBe("Проверяем…");
    // An ordinary read still updates the general status while Manual is in flight.
    expect(f.context.updateAppliedSequence).toBe(1);
    ack.resolve(checking); await manual;
    f.context.nativeClient.updateStatus.mockResolvedValue(status);
    await f.timers.shift()!();
    expect(f.context.manualUpdateResult).toBe(status.errorCode ? errorMessage
      : status.updateAvailable ? "Найдена версия 0.4.2" : "У вас актуальная версия.");
  });

  it.each([false, true])("excludes a poll started before Manual ACK even if returned after it (early=%s)", async early => {
    const f = fixture(), old = deferred(), ack = deferred();
    f.context.nativeClient.checkUpdate.mockReturnValueOnce(ack.promise);
    const manual = f.refreshUpdateOffer("manual");
    f.context.nativeClient.updateStatus.mockReturnValueOnce(old.promise);
    const poll = f.refreshUpdateStatus();
    if (early) { old.resolve(idle); await poll; }
    ack.resolve(checking); await manual;
    if (!early) { old.resolve(idle); await poll; }
    expect(f.context.manualUpdateResult).toBe("Проверяем…");
    // A newer pre-ACK read must not suppress scheduling a fresh post-ACK read.
    expect(f.timers.length).toBeGreaterThan(0);
    f.context.nativeClient.updateStatus.mockResolvedValue(available);
    await f.timers.shift()!();
    expect(f.context.manualUpdateResult).toBe("Найдена версия 0.4.2");
  });

  it.each([available, failed, idle])("accepts an immediate terminal check reply: $phase/$errorCode", async status => {
    const f = fixture(); f.context.nativeClient.checkUpdate.mockResolvedValue(status);
    await f.refreshUpdateOffer("manual");
    expect(f.context.manualUpdateResult).toBe(status.errorCode ? errorMessage
      : status.updateAvailable ? "Найдена версия 0.4.2" : "У вас актуальная версия.");
  });

  it("reports the current check rejection even after an unrelated newer poll", async () => {
    const f = fixture(), ack = deferred();
    f.context.nativeClient.checkUpdate.mockReturnValueOnce(ack.promise);
    const manual = f.refreshUpdateOffer("manual");
    await f.refreshUpdateStatus();
    ack.reject(new Error("IPC failed")); await manual;
    expect(f.context.manualUpdateResult).toBe(errorMessage);
  });

  it.each([false, true])("does not complete a repeated Manual from the previous ACK (failure=%s)", async failure => {
    const f = fixture(), old = deferred(), current = deferred();
    f.context.nativeClient.checkUpdate.mockReturnValueOnce(old.promise).mockReturnValueOnce(current.promise);
    const first = f.refreshUpdateOffer("manual"), second = f.refreshUpdateOffer("manual");
    if (failure) old.reject(new Error("old failure")); else old.resolve(idle);
    await first;
    expect(f.context.manualUpdateResult).toBe("Проверяем…");
    current.resolve(available); await second;
    expect(f.context.manualUpdateResult).toBe("Найдена версия 0.4.2");
  });

  it("does not complete repeated Manual from a poll of the previous check", async () => {
    const f = fixture(), old = deferred(), current = deferred();
    await f.refreshUpdateOffer("manual");
    f.context.nativeClient.updateStatus.mockReturnValueOnce(old.promise);
    const poll = f.refreshUpdateStatus();
    f.context.nativeClient.checkUpdate.mockReturnValueOnce(current.promise);
    const manual = f.refreshUpdateOffer("manual");
    old.resolve(idle); await poll;
    expect(f.context.manualUpdateResult).toBe("Проверяем…");
    current.resolve(available); await manual;
    expect(f.context.manualUpdateResult).toBe("Найдена версия 0.4.2");
  });

  it("does not restart status polling from an ACK overtaken by logout", async () => {
    const f = fixture(), ack = deferred();
    f.context.nativeClient.checkUpdate.mockReturnValueOnce(ack.promise);
    const manual = f.refreshUpdateOffer("manual");
    // The authenticated-bootstrap and sequence fence committed by successful logout.
    Object.assign(f.context, { bootstrap: null, view: "sign_in" });
    f.observeUpdateStatus(null);
    f.context.clearUpdateTimer();
    ack.resolve(checking); await manual;
    expect(f.timers).toHaveLength(0);
    expect(f.context.updateStatus).toBeNull();
    expect(f.context.nativeClient.updateStatus).not.toHaveBeenCalled();
  });
});
