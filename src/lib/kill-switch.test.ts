import { describe, expect, it, vi } from "vitest";
import { KillSwitchControls, confirmAndroidTransition, type KillSwitchStatus } from "./kill-switch";

const armed: KillSwitchStatus = { vpnActive: false, supported: true, enabled: true, disclosed: true, state: "armed", error: null, cause: null, externalLockdown: false };
function fixture() {
  const api = { killSwitchStatus: vi.fn().mockResolvedValue(armed), setKillSwitchPreference: vi.fn().mockResolvedValue(armed), stopProtection: vi.fn().mockResolvedValue(undefined), retryProtectedConnection: vi.fn().mockResolvedValue(undefined) };
  const change = vi.fn();
  return { api, change, controls: new KillSwitchControls(api, change) };
}
function deferred<T>() { let resolve!: (value: T) => void; const promise = new Promise<T>((done) => resolve = done); return { promise, resolve }; }

describe("local protection controls", () => {
  it("does not mutate on dismissed first disclosure", async () => {
    const { api, controls } = fixture();
    api.killSwitchStatus.mockResolvedValue({ ...armed, enabled: false, disclosed: false, state: "off" });
    await controls.refresh();
    await controls.setEnabled(true, () => false);
    expect(api.setKillSwitchPreference).not.toHaveBeenCalled();
  });
  it("never lets an old armed snapshot overwrite a completed Stop", async () => {
    const { api, controls } = fixture();
    await controls.refresh();
    const read = deferred<KillSwitchStatus>();
    api.killSwitchStatus.mockReturnValueOnce(read.promise).mockResolvedValue({ ...armed, state: "off" });
    const old = controls.refresh();
    await controls.stop();
    read.resolve(armed); await old;
    expect(controls.status?.state).toBe("off");
    expect(api.stopProtection).toHaveBeenCalledOnce();
  });
  it("reports unknown on IPC loss instead of retaining armed or claiming off", async () => {
    const { api, controls } = fixture(); await controls.refresh();
    api.killSwitchStatus.mockRejectedValue(new Error("unavailable"));
    await controls.refresh();
    expect(controls.status?.state).toBe("unknown");
    expect(controls.status?.enabled).toBeNull();
  });
  it("Stop remains dispatchable during a stuck preference operation", async () => {
    const { api, controls } = fixture(); await controls.refresh();
    const write = deferred<KillSwitchStatus>(); api.setKillSwitchPreference.mockReturnValue(write.promise);
    const pending = controls.setEnabled(false, () => true);
    api.killSwitchStatus.mockResolvedValue({ ...armed, state: "off" });
    await controls.stop(); expect(api.stopProtection).toHaveBeenCalledOnce();
    write.resolve(armed); await pending;
    expect(controls.status?.state).toBe("off");
  });
  it("does not erase saved preference or retry after failed Stop", async () => {
    const { api, controls } = fixture(); await controls.refresh();
    api.stopProtection.mockRejectedValue(new Error("tunnel_stop_unconfirmed"));
    await expect(controls.stop()).rejects.toThrow("tunnel_stop_unconfirmed");
    expect(api.setKillSwitchPreference).not.toHaveBeenCalled();
    expect(api.retryProtectedConnection).not.toHaveBeenCalled();
  });
  it("confirmed blocked disable carries explicit consent; cancellation is inert", async () => {
    const { api, controls } = fixture(); api.killSwitchStatus.mockResolvedValue({ ...armed, state: "blocked" });
    await controls.refresh(); await controls.setEnabled(false, () => false);
    expect(api.setKillSwitchPreference).not.toHaveBeenCalled();
    await controls.setEnabled(false, () => true);
    expect(api.setKillSwitchPreference).toHaveBeenCalledWith(false, true);
  });
});

describe("Android transition confirmation", () => {
  it("requires confirmation for active protection, unknown state and every runtime switch", () => {
    const confirm = vi.fn().mockReturnValue(false);
    expect(confirmAndroidTransition(armed, "update", false, confirm)).toBe(false);
    expect(confirmAndroidTransition({ ...armed, state: "unknown" }, "update", false, confirm)).toBe(false);
    expect(confirmAndroidTransition({ ...armed, enabled: false, state: "off" }, "runtime", false, confirm)).toBe(false);
    expect(confirm).toHaveBeenCalledTimes(3);
  });
  it("does not warn about an absent active protection, or change desktop flow", () => {
    const confirm = vi.fn().mockReturnValue(true);
    expect(confirmAndroidTransition({ ...armed, state: "off" }, "update", false, confirm)).toBe(true);
    expect(confirm.mock.calls[0][0]).toContain("если подключение успеет начаться");
    expect(confirmAndroidTransition(null, "runtime", true, confirm)).toBe(true);
    expect(confirm).toHaveBeenCalledOnce();
  });
});

it("warns about a native VPN even before bootstrap has loaded", () => {
  const confirm = vi.fn().mockReturnValue(false);
  expect(confirmAndroidTransition({ ...armed, enabled: false, state: "off", vpnActive: true }, "update", false, confirm)).toBe(false);
  expect(confirm).toHaveBeenCalledOnce();
});

it("an old poll cannot replace a fresh transition snapshot", async () => {
  const { api, controls } = fixture();
  const read = deferred<KillSwitchStatus>();
  api.killSwitchStatus.mockReturnValueOnce(read.promise).mockResolvedValue({ ...armed, state: "off" });
  const old = controls.refresh(); await controls.refresh(true);
  read.resolve(armed); await old;
  expect(controls.status?.state).toBe("off");
});

it("blocked disable verifies local Stop before saving the preference", async () => {
  const { api, controls } = fixture();
  api.killSwitchStatus.mockResolvedValue({ ...armed, state: "blocked" });
  await controls.refresh();
  api.stopProtection.mockRejectedValueOnce(new Error("stop unconfirmed"));
  await expect(controls.setEnabled(false, () => true)).rejects.toThrow("stop unconfirmed");
  expect(api.setKillSwitchPreference).not.toHaveBeenCalled();
  await controls.setEnabled(false, () => true);
  expect(api.setKillSwitchPreference).toHaveBeenCalledOnce();
  expect(api.stopProtection.mock.invocationCallOrder.at(-1)).toBeLessThan(api.setKillSwitchPreference.mock.invocationCallOrder[0]);
});
