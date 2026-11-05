import { render } from "svelte/server";
import { describe, expect, it } from "vitest";
import KillSwitchPanel from "./KillSwitchPanel.svelte";
import { unknownProtection, type KillSwitchStatus } from "./kill-switch";
function panel(status: KillSwitchStatus) {
  return render(KillSwitchPanel, { props: { status, busy: true, onenabled() {}, onstop() {}, onretry() {} } }).body;
}
describe("protection panel independent of authentication", () => {
  it("keeps local Stop usable while another operation is busy and status is unknown", () => {
    const html = panel(unknownProtection());
    expect(html).toContain("Статус защиты неизвестен");
    expect(html).toMatch(/<button[^>]*>Выключить VPN и блокировку<\/button>/);
    expect(html.match(/<button[^>]*>Выключить VPN и блокировку/)?.[0]).not.toContain("disabled");
    expect(html).toContain("Как работает защита");
  });
  it("explains blocked scope and independent Android lockdown", () => {
    const html = panel({ ...unknownProtection(), enabled: true, state: "blocked", externalLockdown: true });
    expect(html).toContain("Интернет заблокирован для защиты IP");
    expect(html).toContain("Повторить сейчас");
    expect(html).toContain("Локальный Stop её не отключает");
    expect(html).toContain("Исключения split tunneling сохраняют прямой доступ");
  });
  it("does not call a saved enabled preference active before the first connection", () => {
    const html = panel({ ...unknownProtection(), enabled: true, state: "off", error: null });
    expect(html).toContain("Защита включится после успешного VPN-подключения");
    expect(html).not.toContain("Защита активна");
  });
});
