import { describe, expect, it } from "vitest";

import {
  bindingRequest,
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

    expect(bindingRequest("peer-without-handshake", bootstrap)).toEqual({
      peer_id: "peer-without-handshake",
      preferred_layer: "stray",
      tic_connection_mode: "dynamic",
      route_mode: "standalone",
    });
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
