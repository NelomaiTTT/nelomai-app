import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { StartupRetry } from "./startup-retry";

describe("startup admission retry", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());
  it("resumes the screen after pending admission without a second click", () => {
    const retry = new StartupRetry();
    let view = "pending";
    retry.schedule("runtime_startup_pending", () => { view = "dashboard"; });
    vi.advanceTimersByTime(1000);
    expect(view).toBe("pending");
    vi.advanceTimersByTime(5000);
    expect(view).toBe("dashboard");
  });
  it("manual retry cancels an older scheduled attempt", () => {
    const retry = new StartupRetry();
    let attempts = 0;
    retry.schedule("runtime_startup_pending", () => { attempts++; });
    retry.cancel();
    vi.runAllTimers();
    expect(attempts).toBe(0);
  });
  it("success, logout and permanent errors cancel pending work", () => {
    for (const code of [null, "signed_out", "invalid_refresh_token", "storage_unavailable"]) {
      const retry = new StartupRetry();
      let attempts = 0;
      retry.schedule("runtime_startup_pending", () => { attempts++; });
      retry.schedule(code, () => { attempts++; });
      vi.runAllTimers();
      expect(attempts).toBe(0);
    }
  });
  it("does not retry after unmount, including a late in-flight response", () => {
    const retry = new StartupRetry();
    let attempts = 0;
    retry.schedule("runtime_startup_pending", () => { attempts++; });
    retry.dispose();
    retry.schedule("runtime_startup_pending", () => { attempts++; });
    vi.runAllTimers();
    expect(attempts).toBe(0);
  });
});
