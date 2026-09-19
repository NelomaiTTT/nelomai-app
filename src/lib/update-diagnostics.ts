import type { UpdateStatus } from "./app-model";
import type { StartupStage } from "./native-client";

export function updateStatusNeedsPolling(status: UpdateStatus): boolean {
  return (
    status.errorCode === "update_refresh_pending" ||
    status.errorCode === "update_install_preparing" ||
    status.phase === "downloading" ||
    (status.supported && status.automatic && status.phase === "available")
  );
}

export function updateRefreshDiagnosticStage(
  wasRefreshing: boolean,
  status: UpdateStatus,
): StartupStage | null {
  const refreshing = status.errorCode === "update_refresh_pending";
  if (!wasRefreshing && refreshing) return "update_refresh_started";
  if (wasRefreshing && !refreshing) {
    return status.errorCode !== null
      ? "update_refresh_failed"
      : "update_refresh_completed";
  }
  return null;
}

export function updateDiagnosticStage(
  phase: UpdateStatus["phase"],
): StartupStage | null {
  switch (phase) {
    case "available":
      return "update_available";
    case "downloading":
      return "update_downloading";
    case "ready_to_restart":
      return "update_ready_to_restart";
    case "awaiting_installation":
      return "update_awaiting_installation";
    case "failed":
      return "update_failed";
    case "idle":
      return null;
  }
}
