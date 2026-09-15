import { describe, expect, it, vi } from "vitest";

import { RuntimeStatusRefresher } from "./runtime-status-refresher";

interface TestStatus {
  phase: "auth_resuming" | "complete";
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((resolvePromise) => {
    resolve = resolvePromise;
  });
  return { promise, resolve };
}

describe("runtime status refresher", () => {
  it("discards an older pending response after a newer complete response", async () => {
    const pending = deferred<TestStatus>();
    const complete = deferred<TestStatus>();
    const applied: TestStatus[] = [];
    const refresher = new RuntimeStatusRefresher<TestStatus>();

    const first = refresher.run(() => pending.promise, (status) => applied.push(status));
    const second = refresher.run(() => complete.promise, (status) => applied.push(status));

    complete.resolve({ phase: "complete" });
    await second;
    pending.resolve({ phase: "auth_resuming" });
    await first;

    expect(applied).toEqual([{ phase: "complete" }]);
  });

  it("keeps the current status when the newest refresh fails", async () => {
    const applied = vi.fn<(status: TestStatus) => void>();
    const refresher = new RuntimeStatusRefresher<TestStatus>();

    await expect(
      refresher.run(
        () => Promise.reject(new Error("runtime unavailable")),
        applied,
      ),
    ).resolves.toBeNull();

    expect(applied).not.toHaveBeenCalled();
  });
});
