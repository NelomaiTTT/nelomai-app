import { describe, expect, it } from "vitest";

import { CHANGELOG, defineChangelog } from "./changelog";

describe("application changelog", () => {
  it("starts with the user-facing 0.2.14 entry", () => {
    expect(CHANGELOG[0]).toEqual({
      version: "0.2.14",
      items: ["Исправили запуск VPN-подключения на Android."],
    });
  });

  it("keeps the user-facing 0.2.13 entry", () => {
    expect(CHANGELOG[1]).toEqual({
      version: "0.2.13",
      items: [
        "Убрали активные ошибки при начале подключения.",
        "Снизили влияние диагностики на память устройства.",
        "Улучшили проверку доступных обновлений.",
        "Исправили работу split-tunnel в macOS.",
        "Добавили историю изменений приложения.",
      ],
    });
  });

  it("rejects a repeated version", () => {
    expect(() =>
      defineChangelog([
        { version: "0.2.14", items: ["Первое изменение."] },
        { version: "0.2.14", items: ["Второе изменение."] },
      ]),
    ).toThrow("duplicate_changelog_version");
  });

  it("rejects duplicate items in one version after whitespace normalization", () => {
    expect(() =>
      defineChangelog([
        {
          version: "0.2.14",
          items: ["Исправили подключение.", "  Исправили   подключение.  "],
        },
      ]),
    ).toThrow("duplicate_changelog_item");
  });

  it("rejects empty version entries", () => {
    expect(() =>
      defineChangelog([{ version: "0.2.14", items: [] }]),
    ).toThrow("empty_changelog_entry");
  });

  it("rejects whitespace-only versions", () => {
    expect(() =>
      defineChangelog([{ version: "   ", items: ["Исправили подключение."] }]),
    ).toThrow("empty_changelog_version");
  });

  it("rejects whitespace-only items", () => {
    expect(() =>
      defineChangelog([{ version: "0.2.14", items: ["   "] }]),
    ).toThrow("empty_changelog_item");
  });
});
