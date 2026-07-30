import { describe, expect, it } from "vitest";

import {
  buildApplicationRows,
  emptyIncludeSelection,
  type InstalledApplication,
  type SplitTunnelState,
} from "./split-tunnel";

const state: SplitTunnelState = {
  available: true,
  enabled: true,
  mode: "exclude_selected",
  excludeLocalNetworks: true,
  mandatoryExcludedPackages: ["com.example.mandatory"],
  suggestedNameFragments: ["Яндекс", "MAX"],
  selectedPackages: ["com.example.selected"],
  warning: null,
  capabilities: {
    platform: "android",
    androidApiLevel: 35,
    addressSplitTunnel: true,
    applicationSplitTunnel: true,
  },
};

const applications: InstalledApplication[] = [
  {
    packageId: "com.example.system",
    displayName: "System utility",
    system: true,
  },
  {
    packageId: "com.example.selected",
    displayName: "Selected",
    system: false,
  },
  {
    packageId: "com.example.mandatory",
    displayName: "Яндекс MAX",
    system: false,
  },
  {
    packageId: "com.example.suggested",
    displayName: "Яндекс Карты",
    system: false,
  },
];

describe("split-tunnel application model", () => {
  it("locks mandatory packages and never repeats them as suggestions", () => {
    const rows = buildApplicationRows(state, applications, "", true);
    const mandatory = rows.find(
      (row) => row.packageId === "com.example.mandatory",
    );

    expect(mandatory).toMatchObject({
      mandatory: true,
      selected: true,
      suggested: false,
      locked: true,
    });
    expect(
      rows.find((row) => row.packageId === "com.example.suggested"),
    ).toMatchObject({
      suggested: true,
      locked: false,
    });
  });

  it("keeps regular applications before optional system applications", () => {
    expect(
      buildApplicationRows(state, applications, "", true).map(
        (row) => row.packageId,
      ),
    ).toEqual([
      "com.example.mandatory",
      "com.example.selected",
      "com.example.suggested",
      "com.example.system",
    ]);
  });

  it("filters by display name and package ID without changing flags", () => {
    expect(
      buildApplicationRows(state, applications, "SELECTED", false),
    ).toEqual([
      expect.objectContaining({
        packageId: "com.example.selected",
        selected: true,
      }),
    ]);
  });

  it("blocks include-only only when no available application is selected", () => {
    expect(
      emptyIncludeSelection(
        { ...state, mode: "include_selected", selectedPackages: [] },
        applications,
      ),
    ).toBe(true);
    expect(
      emptyIncludeSelection(
        {
          ...state,
          mode: "include_selected",
          selectedPackages: ["com.example.selected"],
        },
        applications,
      ),
    ).toBe(false);
    expect(
      emptyIncludeSelection(
        {
          ...state,
          mode: "include_selected",
          selectedPackages: [],
          capabilities: {
            ...state.capabilities,
            applicationSplitTunnel: false,
          },
        },
        applications,
      ),
    ).toBe(false);
  });
});
