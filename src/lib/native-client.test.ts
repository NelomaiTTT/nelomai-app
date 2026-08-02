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

  it("routes VPN preparation through the native layer", async () => {
    const invoke = vi.fn().mockResolvedValue(undefined);
    const client = createNativeClient(invoke);

    await client.prepareTunnel();

    expect(invoke).toHaveBeenCalledWith("app_prepare_tunnel");
  });

  it("routes desktop preferences through native commands", async () => {
    const invoke = vi.fn().mockResolvedValue({ closeToTray: true });
    const client = createNativeClient(invoke);

    await client.preferences();
    await client.setCloseToTray(false);

    expect(invoke).toHaveBeenNthCalledWith(1, "app_preferences");
    expect(invoke).toHaveBeenNthCalledWith(2, "app_set_close_to_tray", {
      enabled: false,
    });
  });

  it("routes pin, unpin, and peer replacement through native commands", async () => {
    const invoke = vi.fn().mockResolvedValue({});
    const client = createNativeClient(invoke);

    await client.pinStray();
    await client.unpinStray("lease-1");
    await client.unbindPeer();

    expect(invoke).toHaveBeenNthCalledWith(1, "app_pin_stray");
    expect(invoke).toHaveBeenNthCalledWith(2, "app_unpin_stray", {
      request: { leaseId: "lease-1" },
    });
    expect(invoke).toHaveBeenNthCalledWith(3, "app_unbind_peer");
  });

  it("requests diagnostic upload without exposing report contents to the UI", async () => {
    const invoke = vi.fn().mockResolvedValue({
      request_id: "request-1",
      report_id: "report-1",
      received_bytes: 1024,
    });
    const client = createNativeClient(invoke);

    const response = await client.sendDiagnostics();

    expect(invoke).toHaveBeenCalledWith("app_send_diagnostics");
    expect(response.report_id).toBe("report-1");
  });

  it("keeps notification inbox and push registration in native commands", async () => {
    const invoke = vi.fn().mockResolvedValue({});
    const client = createNativeClient(invoke);

    await client.notifications(42);
    await client.markNotificationRead(51);
    await client.markAllNotificationsRead();
    await client.registerPushToken("fcm-token");

    expect(invoke).toHaveBeenNthCalledWith(1, "app_notifications", { cursor: 42 });
    expect(invoke).toHaveBeenNthCalledWith(2, "app_notification_read", {
      messageId: 51,
    });
    expect(invoke).toHaveBeenNthCalledWith(3, "app_notifications_read_all");
    expect(invoke).toHaveBeenNthCalledWith(4, "app_register_push_token", {
      token: "fcm-token",
    });
  });

  it("keeps update authorization and artifacts inside native commands", async () => {
    const invoke = vi.fn().mockResolvedValue({ phase: "available" });
    const client = createNativeClient(invoke);

    await client.updateStatus();
    await client.setAutomaticUpdates(false);
    await client.installUpdate();
    await client.restartForUpdate();

    expect(invoke).toHaveBeenNthCalledWith(1, "app_update_status");
    expect(invoke).toHaveBeenNthCalledWith(2, "app_update_set_automatic", {
      enabled: false,
    });
    expect(invoke).toHaveBeenNthCalledWith(3, "app_update_install");
    expect(invoke).toHaveBeenNthCalledWith(4, "app_update_restart");
  });

  it("routes every split-tunnel mutation through native commands", async () => {
    const invoke = vi.fn().mockResolvedValue({});
    const client = createNativeClient(invoke);
    const request = {
      mode: "exclude_selected" as const,
      excludeLocalNetworks: true,
      selectedPackages: [
        {
          packageId: "com.example.browser",
          displayName: "Browser",
        },
      ],
    };

    await client.splitTunnelState();
    await client.splitTunnelInstalledApplications();
    await client.saveSplitTunnel(request, true);
    await client.refreshSplitTunnel();
    await client.addSplitTunnelAddressRule("example.com", "all_devices");
    await client.removeSplitTunnelAddressRule(42, "all_devices");

    expect(invoke).toHaveBeenNthCalledWith(1, "app_split_tunnel_state");
    expect(invoke).toHaveBeenNthCalledWith(
      2,
      "app_split_tunnel_installed_applications",
    );
    expect(invoke).toHaveBeenNthCalledWith(3, "app_split_tunnel_save", {
      request,
      confirmReconnect: true,
    });
    expect(invoke).toHaveBeenNthCalledWith(4, "app_split_tunnel_refresh");
    expect(invoke).toHaveBeenNthCalledWith(
      5,
      "app_split_tunnel_add_address_rule",
      {
        request: { value: "example.com", scope: "all_devices" },
      },
    );
    expect(invoke).toHaveBeenNthCalledWith(
      6,
      "app_split_tunnel_remove_address_rule",
      { ruleId: 42, scope: "all_devices" },
    );
  });
});
