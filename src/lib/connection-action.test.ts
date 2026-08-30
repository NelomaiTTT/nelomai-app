import { describe, expect, it } from "vitest";

import {
  beginConnectionStart,
  beginConnectionStop,
  canBeginConnectionAction,
  initialConnectionActionState,
  isCurrentConnectionAction,
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
});
