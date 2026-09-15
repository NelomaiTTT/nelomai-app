import type { UpdateStatus } from "./app-model";
import type { StartupStage } from "./native-client";

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
