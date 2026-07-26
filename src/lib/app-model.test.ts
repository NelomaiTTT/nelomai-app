import { describe, expect, it } from "vitest";

import {
  bindingRequest,
  viewForPhase,
  type Bootstrap,
  type BootstrapDefaults,
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
