export type AppOverlay = "split_tunnel" | "notifications" | "changelog";

const OVERLAY_HISTORY_KEY = "nelomaiOverlay";

export function overlayFromHistoryState(state: unknown): AppOverlay | null {
  if (!state || typeof state !== "object") return null;
  const overlay = (state as Record<string, unknown>)[OVERLAY_HISTORY_KEY];
  return overlay === "split_tunnel" ||
    overlay === "notifications" ||
    overlay === "changelog"
    ? overlay
    : null;
}

export function historyStateForOverlay(
  state: unknown,
  overlay: AppOverlay,
): Record<string, unknown> {
  const current = state && typeof state === "object"
    ? (state as Record<string, unknown>)
    : {};
  return { ...current, [OVERLAY_HISTORY_KEY]: overlay };
}
