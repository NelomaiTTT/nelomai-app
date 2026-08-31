export interface ChangelogEntry {
  version: string;
  items: readonly string[];
}

export function defineChangelog(
  entries: readonly ChangelogEntry[],
): readonly ChangelogEntry[] {
  const versions = new Set<string>();
  return entries.map((entry) => {
    const version = entry.version.trim();
    if (!version) throw new Error("empty_changelog_version");
    if (versions.has(version)) throw new Error("duplicate_changelog_version");
    versions.add(version);

    if (entry.items.length === 0) throw new Error("empty_changelog_entry");
    const items = entry.items.map((item) => item.trim().replace(/\s+/g, " "));
    const normalizedItems = new Set<string>();
    for (const item of items) {
      if (!item) throw new Error("empty_changelog_item");
      const normalized = item.toLocaleLowerCase("ru-RU");
      if (normalizedItems.has(normalized)) {
        throw new Error("duplicate_changelog_item");
      }
      normalizedItems.add(normalized);
    }
    return { version, items };
  });
}

export const CHANGELOG = defineChangelog([
  {
    version: "0.2.14",
    items: ["Исправили запуск VPN-подключения на Android."],
  },
  {
    version: "0.2.13",
    items: [
      "Убрали активные ошибки при начале подключения.",
      "Снизили влияние диагностики на память устройства.",
      "Улучшили проверку доступных обновлений.",
      "Исправили работу split-tunnel в macOS.",
      "Добавили историю изменений приложения.",
    ],
  },
]);
