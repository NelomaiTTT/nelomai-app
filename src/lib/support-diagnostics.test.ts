import { render } from "svelte/server";
import { describe, expect, it } from "vitest";
import SupportDiagnosticsButton from "./SupportDiagnosticsButton.svelte";
import { supportDiagnosticsBridge } from "./support-diagnostics";

describe("pre-login support diagnostics", () => {
  it("offers diagnostics when the native container bridge is present", () => {
    const bridge = supportDiagnosticsBridge({ NelomaiSupportDiagnostics: { open() {} } });
    const { body } = render(SupportDiagnosticsButton, { props: { bridge } });
    expect(body).toMatch(/type="button"/);
    expect(body).toContain("Диагностика");
    expect(body).not.toContain("disabled");
  });

  it("does not offer an Android action without its native bridge", () => {
    const { body } = render(SupportDiagnosticsButton, { props: { bridge: supportDiagnosticsBridge({}) } });
    expect(body).not.toContain("<button");
    expect(supportDiagnosticsBridge({ NelomaiSupportDiagnostics: { open: "wrong type" } })).toBeNull();
  });

  it("opens diagnostics through the bridge without passing account data", () => {
    const calls: unknown[][] = [];
    const bridge = supportDiagnosticsBridge({ NelomaiSupportDiagnostics: { open(...args: unknown[]) { calls.push(args); } } });
    bridge?.open();
    expect(calls).toEqual([[]]);
  });
});
