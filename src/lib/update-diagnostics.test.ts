import { describe, expect, it } from "vitest";
import { updateDiagnosticStage } from "./update-diagnostics";

describe("updateDiagnosticStage", () => {
  it("maps observable update phases to allowlisted diagnostic stages", () => {
    expect(updateDiagnosticStage("available")).toBe("update_available");
    expect(updateDiagnosticStage("downloading")).toBe("update_downloading");
    expect(updateDiagnosticStage("ready_to_restart")).toBe("update_ready_to_restart");
    expect(updateDiagnosticStage("awaiting_installation")).toBe("update_awaiting_installation");
    expect(updateDiagnosticStage("failed")).toBe("update_failed");
  });

  it("does not log idle polling", () => {
    expect(updateDiagnosticStage("idle")).toBeNull();
  });
});
