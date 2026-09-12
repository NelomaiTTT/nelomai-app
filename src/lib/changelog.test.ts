import { describe, expect, it } from "vitest";

import { CHANGELOG, defineChangelog } from "./changelog";

describe("application changelog", () => {
  it("includes the current release and intermediate releases in the offline fallback", () => {
    expect(CHANGELOG.slice(0, 4).map(entry => entry.version)).toEqual(["0.2.19", "0.2.18", "0.2.17", "0.2.16"]);
    expect(CHANGELOG[0].items).toEqual([
      "Исправлены ложные ошибки авторизации и подготовки приложения при запуске.",
      "Android: исправлена ошибка подготовки приложения, которая могла приводить к остановке туннеля.",
      "Android: исправлен запуск счётчиков трафика и фоновых задач после восстановления приложения.",
      "Android: устранены лишние запуски VPN-службы при выключенном подключении.",
      "Android: исправлено восстановление фоновой авторизации.",
      "Раздел «Что нового» теперь получает актуальные описания версий с панели и сохраняет их локально.",
    ]);
  });

  it("keeps the user-facing 0.2.15 entry", () => {
    expect(CHANGELOG.find(entry => entry.version === "0.2.15")).toEqual({
      version: "0.2.15",
      items: [
        "Улучшили автоматическое восстановление подключения.",
        "Исправили переподключение после выхода macOS из сна.",
        "Исправили состояние приложения после выключения VPN через плитку Android.",
      ],
    });
  });

  it("keeps the user-facing 0.2.14 entry", () => {
    expect(CHANGELOG.find(entry => entry.version === "0.2.14")).toEqual({
      version: "0.2.14",
      items: ["Исправили запуск VPN-подключения на Android."],
    });
  });

  it("keeps the user-facing 0.2.13 entry", () => {
    expect(CHANGELOG.find(entry => entry.version === "0.2.13")).toEqual({
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
