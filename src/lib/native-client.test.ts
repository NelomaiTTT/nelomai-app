import { describe, expect, it, vi } from "vitest";

import {
  commandMessage,
  createNativeClient,
  waitForSettlement,
} from "./native-client";

function commandError(code: string, message = "server message") {
  return { code, message };
}

describe("native client", () => {
  it("gives network failures an action matching the current operation", () => {
    const error = commandError(
      "temporarily_unavailable",
      "Не удалось связаться с панелью",
    );

    expect(commandMessage(error, "login")).toContain("попробуйте войти снова");
    expect(commandMessage(error, "startup")).toContain("нажмите «Повторить»");
    expect(commandMessage(error, "start")).toContain("нажмите «Старт» ещё раз");
    expect(commandMessage(error, "stop")).toContain("Нажмите «Повторить»");
  });

  it("explains personal server failures without masking local VPN errors", () => {
    const options = { personalPeer: true };

    expect(
      commandMessage(
        commandError("configuration_fetch_failed"),
        "start",
        options,
      ),
    ).toBe(
      "Ваш домашний сервер временно недоступен. Попробуйте позже или используйте динамический режим.",
    );
    expect(
      commandMessage(commandError("personal_peer_unavailable"), "start", options),
    ).toContain("Ваш домашний сервер временно недоступен");
    expect(
      commandMessage(commandError("vpn_permission_denied"), "start", options),
    ).toContain("Разрешите VPN-подключение");
  });

  it("uses the actual retry and start button labels", () => {
    expect(
      commandMessage(commandError("connection_stop_failed"), "stop"),
    ).toContain("Нажмите «Повторить»");
    expect(
      commandMessage(commandError("connection_no_longer_active"), "start"),
    ).toBe("Нажмите «Старт» ещё раз");
    expect(
      commandMessage(commandError("tunnel_service_unavailable"), "start"),
    ).toContain("Нажмите «Старт» ещё раз");
    expect(
      commandMessage(commandError("tunnel_service_unavailable"), "stop"),
    ).toContain("Нажмите «Повторить»");
    expect(commandMessage(commandError("access_expired"), "startup")).toContain(
      "нажмите «Проверить снова»",
    );
  });

  it("names the actual split-tunnel refresh action", () => {
    expect(
      commandMessage(commandError("temporarily_unavailable"), "split_tunnel"),
    ).toContain("«Принудительная синхронизация»");
    expect(
      commandMessage(
        commandError("split_tunnel_policy_unavailable"),
        "split_tunnel",
      ),
    ).toContain("«Принудительная синхронизация»");
  });

  it("explains the safe recovery after a Stray endpoint route failure", () => {
    expect(
      commandMessage(commandError("endpoint_route_unavailable"), "start"),
    ).toContain("Переподключите устройство к сети");
    expect(
      commandMessage(commandError("endpoint_route_lost"), "start"),
    ).toContain("Stray остановлен для защиты");
  });

  it("explains recovery when the AWG3 runtime rejects the issued profile", () => {
    expect(
      commandMessage(commandError("amneziawg_profile_mismatch"), "start"),
    ).toContain("параметры Stray");
    expect(
      commandMessage(commandError("awg3_profile_apply_failed"), "start"),
    ).toContain("отправьте логи");
  });

  it("explains how to recover a Defender-blocked AWG3 runtime", () => {
    expect(
      commandMessage(commandError("defender_exclusion_missing"), "start"),
    ).toContain("Нажмите «Исправить»");
    expect(
      commandMessage(commandError("amneziawg_component_missing"), "start"),
    ).toContain("переустановите последнюю версию");
  });

  it("offers IPv4 when the IPv6 pool is not ready", () => {
    expect(
      commandMessage(
        { code: "ipv6_pool_unavailable", message: "internal" },
        "start",
      ),
    ).toBe(
      "IPv6-подключение пока недоступно. Выберите IPv4 или попробуйте позже.",
    );
  });

  it("explains what to change after an AWG3 handshake timeout", () => {
    expect(
      commandMessage(commandError("tunnel_handshake_timeout"), "start"),
    ).toContain("Переключите Wi‑Fi или мобильный интернет");
  });

  it("keeps an unknown safe native message as the fallback", () => {
    expect(
      commandMessage(commandError("invalid_credentials", "Неверный логин или пароль."), "login"),
    ).toBe("Неверный логин или пароль.");
    expect(commandMessage(new Error("private detail"), "start")).toBe(
      "Не удалось выполнить действие. Повторите попытку.",
    );
  });

  it("stops waiting for a background task without cancelling it", async () => {
    vi.useFakeTimers();
    try {
      let finishTask: (() => void) | undefined;
      const task = new Promise<void>((resolve) => {
        finishTask = resolve;
      });
      const waiting = waitForSettlement(task, 100);

      await vi.advanceTimersByTimeAsync(100);

      await expect(waiting).resolves.toBe(false);
      finishTask?.();
      await task;
    } finally {
      vi.useRealTimers();
    }
  });

  it("finishes the UI wait when the background task rejects", async () => {
    await expect(
      waitForSettlement(Promise.reject(new Error("storage unavailable")), 100),
    ).resolves.toBe(true);
  });

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
      egress_mode: "prefer_ipv6" as const,
    };

    await client.bindPeer(request);

    expect(invoke).toHaveBeenCalledWith("app_bind_peer", { request });
  });

  it("keeps probe measurements in the native layer", async () => {
    const invoke = vi.fn().mockResolvedValue({ layer: "stray", probes: [] });
    const client = createNativeClient(invoke);

    await client.refreshProbes("stray", "ipv4");
    await client.start({
      deviceId: "11111111-1111-4111-8111-111111111111",
      layer: "stray",
      ticConnectionMode: "dynamic",
      routeMode: "standalone",
      egressMode: "ipv4",
      allowAlternate: true,
    });

    expect(invoke).toHaveBeenNthCalledWith(1, "app_refresh_probes", {
      layer: "stray",
      egressMode: "ipv4",
    });
    expect(invoke).toHaveBeenNthCalledWith(2, "app_start", {
      request: {
        deviceId: "11111111-1111-4111-8111-111111111111",
        layer: "stray",
        ticConnectionMode: "dynamic",
        routeMode: "standalone",
        egressMode: "ipv4",
        allowAlternate: true,
      },
    });
  });

  it("routes VPN preparation through the native layer", async () => {
    const invoke = vi.fn().mockResolvedValue(undefined);
    const client = createNativeClient(invoke);

    await client.prepareTunnel("11111111-1111-4111-8111-111111111111");

    expect(invoke).toHaveBeenCalledWith("app_prepare_tunnel", {
      deviceId: "11111111-1111-4111-8111-111111111111",
    });
  });

  it("routes Defender status and repair through native commands", async () => {
    const invoke = vi.fn().mockResolvedValue({ supported: true, state: "excluded" });
    const client = createNativeClient(invoke);

    await client.windowsDefenderStatus();
    await client.repairWindowsDefender();

    expect(invoke).toHaveBeenNthCalledWith(1, "app_windows_defender_status");
    expect(invoke).toHaveBeenNthCalledWith(2, "app_windows_defender_repair");
  });

  it("queues start failure diagnostics with the authenticated device", async () => {
    const invoke = vi.fn().mockResolvedValue(undefined);
    const client = createNativeClient(invoke);

    await client.queueStartFailureDiagnostics(
      "11111111-1111-4111-8111-111111111111",
      "configuration_fetch_failed",
    );

    expect(invoke).toHaveBeenCalledWith(
      "app_queue_start_failure_diagnostics",
      {
        deviceId: "11111111-1111-4111-8111-111111111111",
        errorCode: "configuration_fetch_failed",
      },
    );
  });

  it("routes desktop preferences through native commands", async () => {
    const invoke = vi.fn().mockResolvedValue({ closeToTray: true });
    const client = createNativeClient(invoke);

    await client.preferences();
    await client.setCloseToTray(false);
    await client.setDnsProvider("quad9");
    await client.setTicEgressMode("personal", "prefer_ipv6");

    expect(invoke).toHaveBeenNthCalledWith(1, "app_preferences");
    expect(invoke).toHaveBeenNthCalledWith(2, "app_set_close_to_tray", {
      enabled: false,
    });
    expect(invoke).toHaveBeenNthCalledWith(3, "app_set_dns_provider", {
      provider: "quad9",
    });
    expect(invoke).toHaveBeenNthCalledWith(4, "app_set_tic_egress_mode", {
      connectionMode: "personal",
      egressMode: "prefer_ipv6",
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

  it("records only a named startup stage through the native layer", async () => {
    const invoke = vi.fn().mockResolvedValue(undefined);
    const client = createNativeClient(invoke);

    await client.recordStartupStage("frontend_first_frame");

    expect(invoke).toHaveBeenCalledWith("app_record_startup_stage", {
      stage: "frontend_first_frame",
    });
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
    await client.refreshUpdate();
    await client.setAutomaticUpdates(false);
    await client.installUpdate();
    await client.restartForUpdate();

    expect(invoke).toHaveBeenNthCalledWith(1, "app_update_status");
    expect(invoke).toHaveBeenNthCalledWith(2, "app_update_refresh");
    expect(invoke).toHaveBeenNthCalledWith(3, "app_update_set_automatic", {
      enabled: false,
    });
    expect(invoke).toHaveBeenNthCalledWith(4, "app_update_install");
    expect(invoke).toHaveBeenNthCalledWith(5, "app_update_restart");
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
