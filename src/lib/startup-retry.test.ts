import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { StartupRetry } from "./startup-retry";

describe("startup admission retry", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());
  it("deduplicates refresh recovery and disposes its timer", () => {
    const retry = new StartupRetry();
    let attempts = 0;
    retry.schedule("auth_refresh_pending", () => { attempts++; });
    retry.schedule("auth_refresh_pending", () => { attempts++; });
    vi.advanceTimersByTime(5000);
    expect(attempts).toBe(1);
    retry.schedule("auth_refresh_pending", () => { attempts++; });
    retry.dispose();
    vi.runAllTimers();
    expect(attempts).toBe(1);
  });
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
    for (const code of [null, "signed_out", "auth_recovery_required", "invalid_refresh_token", "storage_unavailable"]) {
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
  it("retries temporary bootstrap failures twice, then stops scheduling", () => {
    const retry = new StartupRetry();
    let attempts = 0;
    const attempt = () => {
      attempts++;
      retry.schedule("temporarily_unavailable", attempt);
    };
    retry.schedule("temporarily_unavailable", attempt);
    vi.advanceTimersByTime(1999);
    expect(attempts).toBe(0);
    vi.advanceTimersByTime(1);
    expect(attempts).toBe(1);
    vi.advanceTimersByTime(10000);
    expect(attempts).toBe(2);
    expect(vi.getTimerCount()).toBe(0);
  });
  it("manual cancellation renews the temporary retry budget", () => {
    const retry = new StartupRetry();
    let attempts = 0;
    const attempt = () => {
      attempts++;
      retry.schedule("temporarily_unavailable", attempt);
    };
    retry.schedule("temporarily_unavailable", attempt);
    vi.advanceTimersByTime(10000);
    expect(attempts).toBe(2);
    retry.cancel();
    retry.schedule("temporarily_unavailable", attempt);
    vi.advanceTimersByTime(10000);
    expect(attempts).toBe(4);
  });
  it("rescheduling a pending timer does not consume a retry", () => {
    const retry = new StartupRetry();
    let attempts = 0;
    const attempt = () => { attempts++; retry.schedule("temporarily_unavailable", attempt); };
    retry.schedule("temporarily_unavailable", attempt);
    retry.schedule("temporarily_unavailable", attempt);
    vi.advanceTimersByTime(10000);
    expect(attempts).toBe(2);
  });
  it("cancels a temporary retry on authoritative or ambiguous auth failures", () => {
    for (const code of ["signed_out", "auth_recovery_required", "invalid_refresh_token",
      "access_expired", "update_required", "runtime_channel_closed", "auth_outcome_unknown"]) {
      const retry = new StartupRetry();
      let attempts = 0;
      retry.schedule("temporarily_unavailable", () => { attempts++; });
      retry.schedule(code, () => { attempts++; });
      vi.runAllTimers();
      expect(attempts).toBe(0);
    }
  });

});
