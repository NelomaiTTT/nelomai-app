import { describe, expect, it } from "vitest";

import {
  bindingPreferenceUpdateRequest,
  bindingPreferencesMatch,
  bindingRequest,
  connectionEgressMode,
  defaultRouteModeForLayer,
  hasSecondaryStop,
  primaryAction,
  recoveryCopy,
  requiresServerProbes,
  runtimeRestartRequired,
  runtimeSelectorVisible,
  runtimeStartBlocked,
  visibleConnectionIntentStatus,
  viewForPhase,
  viewForAppState,
  type Bootstrap,
  type BootstrapDefaults,
  type Connection,
  type RuntimeStatus,
} from "./app-model";

const defaults: BootstrapDefaults = {
  layer: "stray",
  tic_connection_mode: "dynamic",
  route_mode: "standalone",
};

describe("viewForPhase", () => {
  it.each([
    ["signed_out", "sign_in"],
    ["needs_peer_binding", "peer_selection"],
    ["access_expired", "access_expired"],
    ["update_required", "update_required"],
    ["ready", "connection"],
    ["connecting", "connection"],
    ["connected", "connection"],
  ] as const)("maps %s to %s", (phase, expected) => {
    expect(viewForPhase(phase)).toBe(expected);
  });
});

describe("bindingRequest", () => {
  it("keeps the exact peer selected by the user and the panel defaults", () => {
    const bootstrap = { defaults } as Bootstrap;

    expect(bindingRequest("peer-without-handshake", bootstrap, "prefer_ipv6")).toEqual({
      peer_id: "peer-without-handshake",
      preferred_layer: "stray",
      tic_connection_mode: "dynamic",
      route_mode: "standalone",
      egress_mode: "ipv4",
    });
  });

  it("keeps IPv6 only for a Tic connection routed through Tak", () => {
    const bootstrap = {
      defaults: {
        layer: "tic",
        tic_connection_mode: "personal",
        route_mode: "via_tak",
      },
    } as Bootstrap;

    expect(bindingRequest("peer-15", bootstrap, "prefer_ipv6").egress_mode).toBe(
      "prefer_ipv6",
    );
  });
});

describe("bindingPreferencesMatch", () => {
  const binding = {
    id: "binding-1",
    peer_id: "peer-15",
    interface_id: "interface-1",
    interface_name: "Tic",
    slot: 15,
    preferred_layer: "tic",
    tic_connection_mode: "dynamic",
    route_mode: "via_tak",
    egress_mode: "ipv4",
  } as const;

  it("does not synchronize a dynamic egress preference through the personal peer binding", () => {
    expect(
      bindingPreferencesMatch(
        binding,
        "tic",
        "dynamic",
        "via_tak",
        "prefer_ipv6",
      ),
    ).toBe(true);
  });

  it("still requires an exact egress mode for a personal Tic binding", () => {
    expect(
      bindingPreferencesMatch(
        { ...binding, tic_connection_mode: "personal" },
        "tic",
        "personal",
        "via_tak",
        "prefer_ipv6",
      ),
    ).toBe(false);
  });

  it("hands a changed binding to the connection start owner instead of applying it early", () => {
    expect(
      bindingPreferenceUpdateRequest(
        { ...binding, tic_connection_mode: "personal" },
        "tic",
        "personal",
        "via_tak",
        "prefer_ipv6",
      ),
    ).toEqual({
      peer_id: "peer-15",
      preferred_layer: "tic",
      tic_connection_mode: "personal",
      route_mode: "via_tak",
      egress_mode: "prefer_ipv6",
    });
    expect(
      bindingPreferenceUpdateRequest(
        binding,
        "tic",
        "dynamic",
        "via_tak",
        "prefer_ipv6",
      ),
    ).toBeNull();
  });
});

describe("panel contract", () => {
  it("uses the exact API version and lease statuses returned by the panel", () => {
    const apiVersion: Bootstrap["api_version"] = "1";
    const statuses: Connection["status"][] = [
      "allocating",
      "issued",
      "connected",
      "warm",
      "released",
      "failed",
    ];

    expect(apiVersion).toBe("1");
    expect(statuses).toHaveLength(6);
  });
});

describe("requiresServerProbes", () => {
  it("skips measurements only for a fixed personal Tic peer", () => {
    expect(requiresServerProbes("tic", "personal")).toBe(false);
    expect(requiresServerProbes("tic", "dynamic")).toBe(true);
    expect(requiresServerProbes("stray", "dynamic")).toBe(true);
  });
});

describe("defaultRouteModeForLayer", () => {
  it("routes Tic through Tak and keeps Stray standalone", () => {
    expect(defaultRouteModeForLayer("tic")).toBe("via_tak");
    expect(defaultRouteModeForLayer("stray")).toBe("standalone");
  });
});

describe("connectionEgressMode", () => {
  const preferences = {
    personalTicEgressMode: "prefer_ipv6",
    dynamicTicEgressMode: "ipv4",
  } as const;

  it("keeps personal and dynamic Tic choices independent", () => {
    expect(connectionEgressMode("tic", "via_tak", "personal", preferences)).toBe(
      "prefer_ipv6",
    );
    expect(connectionEgressMode("tic", "via_tak", "dynamic", preferences)).toBe(
      "ipv4",
    );
  });

  it("forces Stray and standalone Tic to IPv4", () => {
    expect(connectionEgressMode("stray", "standalone", "dynamic", preferences)).toBe(
      "ipv4",
    );
    expect(connectionEgressMode("tic", "standalone", "personal", preferences)).toBe(
      "ipv4",
    );
  });
});

describe("connection intent recovery", () => {
  it("keeps Stop available while the native coordinator is recovering", () => {
    expect(
      primaryAction({
        phase: "connecting",
        connectionIntentStatus: "recovering",
      }),
    ).toBe("stop");
    expect(recoveryCopy("recovering")).not.toContain("Старт ещё раз");
    expect(recoveryCopy("recovering")).not.toContain("недоступна");
  });

  it("keeps Stop available for a legacy connection still being established", () => {
    expect(
      primaryAction({
        phase: "connecting",
        connectionIntentStatus: "none",
      }),
    ).toBe("stop");
  });

  it("does not present a confirmed connected tunnel as recovering", () => {
    expect(visibleConnectionIntentStatus("connected", "recovering")).toBe("none");
    expect(visibleConnectionIntentStatus("connecting", "recovering")).toBe(
      "recovering",
    );
  });

  it("offers an explicit retry or stop after terminal recovery", () => {
    expect(
      primaryAction({
        phase: "error",
        connectionIntentStatus: "blocked_terminal",
      }),
    ).toBe("retry");
    expect(recoveryCopy("blocked_terminal")).toContain("Повторить");
    expect(
      viewForAppState({
        phase: "error",
        connectionIntentStatus: "blocked_terminal",
      }),
    ).toBe("connection");
    expect(hasSecondaryStop({ connectionIntentStatus: "blocked_terminal" })).toBe(true);
  });
});

const runtimeStatus = (overrides: Partial<RuntimeStatus> = {}): RuntimeStatus => ({
  containerVersion: "0.2.16",
  selectedSlot: "latest",
  activeSlot: "latest",
  pendingSlot: null,
  latestVersion: "0.2.16",
  stableVersion: null,
  runtimeContractVersion: 1,
  manifestVerified: true,
  stableAvailable: false,
  switchId: null,
  phase: null,
  engineRole: "primary",
  ...overrides,
});

describe("runtime selector view", () => {
  it("hides the selector when stable is absent or equal to latest", () => {
    expect(runtimeSelectorVisible(runtimeStatus())).toBe(false);
    expect(
      runtimeSelectorVisible(
        runtimeStatus({
          stableAvailable: true,
          stableVersion: "0.2.16",
        }),
      ),
    ).toBe(false);
  });

  it("shows only a distinct verified stable runtime", () => {
    expect(
      runtimeSelectorVisible(
        runtimeStatus({
          stableAvailable: true,
          stableVersion: "0.2.15",
        }),
      ),
    ).toBe(true);
    expect(
      runtimeSelectorVisible(
        runtimeStatus({
          manifestVerified: false,
          stableAvailable: true,
          stableVersion: "0.2.15",
        }),
      ),
    ).toBe(false);
  });

  it("blocks start for pending work and until the selected runtime is relaunched", () => {
    expect(runtimeStartBlocked(runtimeStatus({ pendingSlot: "stable" }))).toBe(true);
    expect(
      runtimeStartBlocked(
        runtimeStatus({
          selectedSlot: "stable",
          activeSlot: "latest",
          stableAvailable: true,
          stableVersion: "0.2.15",
          phase: "complete",
        }),
      ),
    ).toBe(true);
    expect(runtimeRestartRequired(runtimeStatus())).toBe(false);
  });
});
