import { render } from "svelte/server";
import { describe, expect, it, vi } from "vitest";

import RuntimeSelector from "./RuntimeSelector.svelte";
import {
  createRuntimeSelectorActions,
  type RuntimeStatus,
} from "./app-model";

function status(overrides: Partial<RuntimeStatus> = {}): RuntimeStatus {
  return {
    containerVersion: "0.2.16",
    selectedSlot: "latest",
    activeSlot: "latest",
    pendingSlot: null,
    latestVersion: "0.2.16",
    stableVersion: "0.2.15",
    runtimeContractVersion: 1,
    manifestVerified: true,
    stableAvailable: true,
    switchId: null,
    phase: null,
    engineRole: "primary",
    ...overrides,
  };
}

describe("RuntimeSelector", () => {
  it("renders no toggle for the 0.2.16 single-runtime manifest", () => {
    const { body } = render(RuntimeSelector, {
      props: {
        status: status({ stableAvailable: false, stableVersion: null }),
        busy: false,
        onselect: async () => {},
        onrestart: async () => {},
      },
    });

    expect(body).not.toContain("Runtime");
    expect(body).not.toContain("Стабильная");
  });

  it("renders distinct verified versions and contract metadata", () => {
    const { body } = render(RuntimeSelector, {
      props: {
        status: status(),
        busy: false,
        onselect: async () => {},
        onrestart: async () => {},
      },
    });

    expect(body).toContain("Использовать стабильную версию");
    expect(body).toContain("0.2.16 → 0.2.15");
    expect(body).toContain("Контракт 1");
  });

  it("deduplicates a pending selection request", async () => {
    let resolveSelection: (() => void) | undefined;
    const onselect = vi.fn(
      () =>
        new Promise<void>((resolve) => {
          resolveSelection = resolve;
        }),
    );
    const actions = createRuntimeSelectorActions(onselect, async () => {});

    const first = actions.select(true);
    const duplicate = actions.select(true);

    expect(onselect).toHaveBeenCalledTimes(1);
    expect(duplicate).toBe(first);
    resolveSelection?.();
    await first;
  });

  it("keeps the app open for later and uses only full restart for restart now", async () => {
    const onrestart = vi.fn().mockResolvedValue(undefined);
    const actions = createRuntimeSelectorActions(async () => {}, onrestart);

    actions.later();
    expect(onrestart).not.toHaveBeenCalled();

    await actions.restartNow();
    expect(onrestart).toHaveBeenCalledTimes(1);
  });
});
