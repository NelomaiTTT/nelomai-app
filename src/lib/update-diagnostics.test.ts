import { describe, expect, it } from "vitest";
import {
  updateDiagnosticStage,
  updateRefreshDiagnosticStage,
  updateStatusNeedsPolling,
} from "./update-diagnostics";

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

  it("keeps polling while a panel refresh is still running", () => {
    expect(
      updateStatusNeedsPolling({
        supported: true,
        automatic: false,
        phase: "idle",
        version: null,
        notes: null,
        required: false,
        downloaded: 0,
        total: null,
        errorCode: "update_refresh_pending",
      }),
    ).toBe(true);
  });

  it("keeps polling during install preparation without logging a refresh", () => {
    const status = {
      supported: true,
      automatic: false,
      phase: "available" as const,
      version: "0.2.20",
      notes: null,
      required: false,
      downloaded: 0,
      total: null,
      errorCode: "update_install_preparing",
    };
    expect(updateStatusNeedsPolling(status)).toBe(true);
    expect(updateRefreshDiagnosticStage(false, status)).toBeNull();
  });

  it("records refresh start, completion and failure once per transition", () => {
    const status = {
      supported: true,
      automatic: false,
      phase: "idle" as const,
      version: null,
      notes: null,
      required: false,
      downloaded: 0,
      total: null,
      errorCode: null,
    };
    expect(
      updateRefreshDiagnosticStage(false, {
        ...status,
        errorCode: "update_refresh_pending",
      }),
    ).toBe("update_refresh_started");
    expect(updateRefreshDiagnosticStage(true, status)).toBe("update_refresh_completed");
    expect(
      updateRefreshDiagnosticStage(true, {
        ...status,
        errorCode: "update_refresh_service",
      }),
    ).toBe("update_refresh_failed");
    expect(updateRefreshDiagnosticStage(false, status)).toBeNull();
  });
});
