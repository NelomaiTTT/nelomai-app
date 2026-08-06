import { describe, expect, it } from "vitest";
import {
  historyStateForOverlay,
  overlayFromHistoryState,
} from "./navigation";

describe("overlay history", () => {
  it("recognizes only application overlay entries", () => {
    expect(overlayFromHistoryState({ nelomaiOverlay: "split_tunnel" })).toBe(
      "split_tunnel",
    );
    expect(overlayFromHistoryState({ nelomaiOverlay: "notifications" })).toBe(
      "notifications",
    );
    expect(overlayFromHistoryState({ nelomaiOverlay: "unknown" })).toBeNull();
    expect(overlayFromHistoryState(null)).toBeNull();
  });

  it("preserves framework history state when opening an overlay", () => {
    expect(historyStateForOverlay({ index: 3 }, "split_tunnel")).toEqual({
      index: 3,
      nelomaiOverlay: "split_tunnel",
    });
  });
});
