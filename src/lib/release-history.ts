import { CHANGELOG } from "./changelog";

export interface ReleaseHistoryEntry { version: string; notes: string }
interface CacheStorage { getItem(key: string): string | null; setItem(key: string, value: string): void }
const CACHE_KEY = "nelomai.ru.release-history.v1";
const FALLBACK = CHANGELOG.map(entry => ({ version: entry.version, notes: entry.items.map(item => `• ${item}`).join("\n") }));

export function parseReleaseHistory(value: unknown): ReleaseHistoryEntry[] {
  const data = value as { api_version?: unknown; entries?: unknown } | null;
  if (!data || data.api_version !== "1" || !Array.isArray(data.entries) || data.entries.length > 50) throw Error("invalid_release_history");
  const versions = new Set<string>();
  return data.entries.map(entry => {
    if (!entry || typeof entry.version !== "string" || !entry.version.trim() || entry.version.length > 64 ||
      typeof entry.notes !== "string" || [...entry.notes].length > 20_000 || versions.has(entry.version)) throw Error("invalid_release_history");
    versions.add(entry.version);
    return { version: entry.version, notes: entry.notes };
  });
}

/** Public presentation data only; never reads or updates account/connection state. */
export class ReleaseHistory {
  private current: ReleaseHistoryEntry[] = FALLBACK;
  private pending: Promise<ReleaseHistoryEntry[]> | null = null;
  constructor(private storage: CacheStorage | null, private load: () => Promise<unknown>) {
    try {
      const cached = storage?.getItem(CACHE_KEY);
      if (cached && cached.length <= 4 * 1024 * 1024) this.current = parseReleaseHistory(JSON.parse(cached));
    } catch { /* A broken or unavailable cache does not block the dialog. */ }
  }
  read(): ReleaseHistoryEntry[] { return this.current; }
  refresh(): Promise<ReleaseHistoryEntry[]> {
    if (this.pending) return this.pending;
    this.pending = this.load().then(value => {
      const entries = parseReleaseHistory(value);
      this.current = entries;
      try { this.storage?.setItem(CACHE_KEY, JSON.stringify({ api_version: "1", entries })); } catch { /* Quota/private mode: retain in memory. */ }
      return entries;
    }).finally(() => { this.pending = null; });
    return this.pending;
  }
}
