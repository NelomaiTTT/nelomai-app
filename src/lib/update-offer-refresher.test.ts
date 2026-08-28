import { describe, expect, it, vi } from "vitest";

import { UpdateOfferRefresher } from "./update-offer-refresher";

interface TestStatus {
  phase: string;
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

describe("update offer refresher", () => {
  it("deduplicates simultaneous foreground refreshes", async () => {
    const request = deferred<TestStatus>();
    const load = vi.fn(() => request.promise);
    const apply = vi.fn<(status: TestStatus) => void>();
    const refresher = new UpdateOfferRefresher<TestStatus>();
    const status = { phase: "available" };

    const first = refresher.run(load, apply);
    const second = refresher.run(load, apply);

    expect(first).toBe(second);
    expect(load).toHaveBeenCalledTimes(1);
    request.resolve(status);
    await expect(Promise.all([first, second])).resolves.toEqual([
      status,
      status,
    ]);
    expect(apply).toHaveBeenCalledOnce();
    expect(apply).toHaveBeenCalledWith(status);
  });

  it("does not replace the last status when refresh fails", async () => {
    const request = deferred<TestStatus>();
    const initial = { phase: "idle" };
    let lastStatus = initial;
    const apply = vi.fn((status: TestStatus) => {
      lastStatus = status;
    });
    const refresher = new UpdateOfferRefresher<TestStatus>();

    const refresh = refresher.run(() => request.promise, apply);
    request.reject(new Error("panel unavailable"));

    await expect(refresh).resolves.toBeNull();
    expect(apply).not.toHaveBeenCalled();
    expect(lastStatus).toBe(initial);
  });
});
