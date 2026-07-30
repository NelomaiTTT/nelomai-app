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
});
