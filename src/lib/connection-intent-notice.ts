import type { Phase } from "./app-model";

export function connectionIntentNoticeForPhase(
  phase: Phase,
  title: string,
  body: string,
): string | null {
  if (phase === "connected") return null;
  return `${title}. ${body}`;
}

export function clearOwnedConnectionIntentNotice(
  error: string | null,
  ownedNotice: string | null,
  phase?: Phase,
): { error: string | null; ownedNotice: string | null } {
  if (phase !== undefined && phase !== "connected") {
    return { error, ownedNotice };
  }
  return {
    error: error === ownedNotice ? null : error,
    ownedNotice: null,
  };
}
