import { render } from "svelte/server";
import { describe, expect, it } from "vitest";

import SplitTunnelSettings from "./SplitTunnelSettings.svelte";
import type {
  InstalledApplication,
  SplitTunnelState,
} from "./split-tunnel";

const applications: InstalledApplication[] = [
  {
    packageId: "com.example.browser",
    displayName: "Browser",
    system: false,
  },
];

function state(androidApiLevel: number): SplitTunnelState {
  return {
    available: true,
    enabled: true,
    mode: "exclude_selected",
    excludeLocalNetworks: true,
    mandatoryExcludedPackages: [],
    suggestedNameFragments: [],
    selectedPackages: [],
    warning: null,
    capabilities: {
      platform: "android",
      androidApiLevel,
      addressSplitTunnel: androidApiLevel >= 33,
      applicationSplitTunnel: androidApiLevel >= 33,
    },
  };
}

describe("SplitTunnelSettings", () => {
  it("shows the mode, local-network option, search, and application", () => {
    const { body } = render(SplitTunnelSettings, {
      props: {
        state: state(35),
        applications,
        busy: false,
        onclose: () => {},
        onsave: async () => true,
        onrefresh: async () => {},
      },
    });

    expect(body).toContain("Исключить выбранные");
    expect(body).toContain("Исключить локальные адреса");
    expect(body).toContain("Поиск приложений");
    expect(body).toContain("Browser");
  });

  it("labels mandatory packages as always outside the VPN in include-only mode", () => {
    const includeOnly = state(35);
    includeOnly.mode = "include_selected";
    includeOnly.mandatoryExcludedPackages = ["com.example.browser"];
    const { body } = render(SplitTunnelSettings, {
      props: {
        state: includeOnly,
        applications,
        busy: false,
        onclose: () => {},
        onsave: async () => true,
        onrefresh: async () => {},
      },
    });

    expect(body).toContain("Всегда вне VPN");
  });

  it("keeps settings visible but explains the Android 12 limitation", () => {
    const { body } = render(SplitTunnelSettings, {
      props: {
        state: state(32),
        applications,
        busy: false,
        onclose: () => {},
        onsave: async () => true,
        onrefresh: async () => {},
      },
    });

    expect(body).toContain("Split-tunnel доступен на Android 13 и новее");
    expect(body).toContain("Browser");
  });

  it("shows only address settings on desktop", () => {
    const desktop = state(35);
    desktop.capabilities = {
      platform: "windows",
      androidApiLevel: null,
      addressSplitTunnel: true,
      applicationSplitTunnel: false,
    };
    const { body } = render(SplitTunnelSettings, {
      props: {
        state: desktop,
        applications,
        busy: false,
        onclose: () => {},
        onsave: async () => true,
        onrefresh: async () => {},
      },
    });

    expect(body).toContain("Исключить локальные адреса");
    expect(body).toContain(
      "На компьютере локальная сеть всегда доступна напрямую",
    );
    expect(body).not.toContain("Режим приложений");
    expect(body).not.toContain("Browser");
  });

  it("explains a failed reconnect after the physical network changes", () => {
    const warningState = state(35);
    warningState.warning = "split_tunnel_network_reconnect_failed";
    const { body } = render(SplitTunnelSettings, {
      props: {
        state: warningState,
        applications,
        busy: false,
        onclose: () => {},
        onsave: async () => true,
        onrefresh: async () => {},
      },
    });

    expect(body).toContain(
      "Не удалось обновить подключение после смены сети",
    );
    expect(body).not.toContain("Панель временно недоступна");
  });
});
