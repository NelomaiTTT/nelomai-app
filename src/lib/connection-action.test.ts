import { describe, expect, it } from "vitest";

import {
  beginConnectionStart,
  beginConnectionStop,
  canBeginConnectionAction,
  initialConnectionActionState,
  isCurrentConnectionAction,
  prepareConnectionStartForPlatform,
} from "./connection-action";

describe("connection action coordination", () => {
  it("allows Stop while Start is in flight but rejects a second cancellation", () => {
    const started = beginConnectionStart(initialConnectionActionState());

    expect(canBeginConnectionAction(started.state, true, true)).toBe(true);
    const stopping = beginConnectionStop(started.state);
    expect(canBeginConnectionAction(stopping.state, true, true)).toBe(false);
    expect(canBeginConnectionAction(stopping.state, true, false)).toBe(false);
  });

  it("invalidates a late Start result as soon as Stop begins", () => {
    const started = beginConnectionStart(initialConnectionActionState());
    expect(isCurrentConnectionAction(started.state, started.token)).toBe(true);

    const stopping = beginConnectionStop(started.state);

    expect(isCurrentConnectionAction(stopping.state, started.token)).toBe(false);
    expect(isCurrentConnectionAction(stopping.state, stopping.token)).toBe(true);
  });

  it("awaits Android VPN preparation before allowing start", async () => {
    const events: string[] = [];

    const current = await prepareConnectionStartForPlatform(
      "android",
      "device-1",
      async (deviceId) => { events.push(`prepare:${deviceId}`); },
      () => { events.push("current"); return true; },
    );

    expect(current).toBe(true);
    expect(events).toEqual(["prepare:device-1", "current"]);
  });

  it("rejects refused Android VPN preparation", async () => {
    const refusal = { code: "vpn_permission_denied" };
    let checkedCurrent = false;

    await expect(prepareConnectionStartForPlatform(
      "android",
      "device-1",
      async () => { throw refusal; },
      () => { checkedCurrent = true; return true; },
    )).rejects.toBe(refusal);
    expect(checkedCurrent).toBe(false);
  });

  it("does not prepare the tunnel on desktop", async () => {
    let preparations = 0;

    const current = await prepareConnectionStartForPlatform(
      "windows",
      "device-1",
      async () => { preparations += 1; },
      () => true,
    );

    expect(current).toBe(true);
    expect(preparations).toBe(0);
  });

  it("does not allow a stale start after Android preparation completes", async () => {
    let finishPreparation: (() => void) | undefined;
    let current = true;
    const preparation = prepareConnectionStartForPlatform(
      "android",
      "device-1",
      () => new Promise<void>((resolve) => { finishPreparation = resolve; }),
      () => current,
    );

    current = false;
    finishPreparation?.();

    await expect(preparation).resolves.toBe(false);
  });
});
