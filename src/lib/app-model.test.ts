import { describe, expect, it } from "vitest";

import {
  bindingPreferencesMatch,
  bindingRequest,
  connectionEgressMode,
  defaultRouteModeForLayer,
  requiresServerProbes,
  viewForPhase,
  type Bootstrap,
  type BootstrapDefaults,
  type Connection,
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
