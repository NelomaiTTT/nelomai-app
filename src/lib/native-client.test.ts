import { describe, expect, it, vi } from "vitest";

import { createNativeClient } from "./native-client";

describe("native client", () => {
  it("keeps credentials inside the login command request", async () => {
    const invoke = vi.fn().mockResolvedValue({ request_id: "bootstrap" });
    const client = createNativeClient(invoke);

    await client.login({
      login: "andrej",
      password: "secret",
      deviceName: "MacBook",
      platformVersion: "15.5",
    });

    expect(invoke).toHaveBeenCalledWith("app_login", {
      request: {
        login: "andrej",
        password: "secret",
        deviceName: "MacBook",
        platformVersion: "15.5",
      },
    });
  });

  it("passes the exact selected peer to the native binding command", async () => {
    const invoke = vi.fn().mockResolvedValue({ binding: null });
    const client = createNativeClient(invoke);
    const request = {
      peer_id: "peer-5",
      preferred_layer: "tic" as const,
      tic_connection_mode: "personal" as const,
      route_mode: "via_tak" as const,
    };

    await client.bindPeer(request);

    expect(invoke).toHaveBeenCalledWith("app_bind_peer", { request });
  });

  it("keeps probe measurements in the native layer", async () => {
    const invoke = vi.fn().mockResolvedValue({ layer: "stray", probes: [] });
    const client = createNativeClient(invoke);

    await client.refreshProbes("stray");
    await client.start({
      layer: "stray",
      ticConnectionMode: "dynamic",
      routeMode: "standalone",
      allowAlternate: true,
    });

    expect(invoke).toHaveBeenNthCalledWith(1, "app_refresh_probes", {
      layer: "stray",
    });
    expect(invoke).toHaveBeenNthCalledWith(2, "app_start", {
      request: {
        layer: "stray",
        ticConnectionMode: "dynamic",
        routeMode: "standalone",
        allowAlternate: true,
      },
    });
  });
});
