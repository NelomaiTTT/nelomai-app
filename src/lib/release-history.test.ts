import { describe, expect, it } from "vitest";
import { ReleaseHistory, parseReleaseHistory } from "./release-history";

const response = { api_version: "1", entries: [{ version: "0.2.18", notes: "Исправлено.\nВторая строка." }] };
function storage(initial: string | null = null) {
  let value = initial;
  return { getItem: () => value, setItem: (_key: string, next: string) => { value = next; } };
}

describe("panel release history", () => {
  it("persists panel edits and reads them offline after reopening", async () => {
    const cache = storage();
    const history = new ReleaseHistory(cache, async () => response);
    expect(await history.refresh()).toEqual(response.entries);
    const offline = new ReleaseHistory(cache, async () => { throw Error("offline"); });
    expect(offline.read()).toEqual(response.entries);
    await expect(offline.refresh()).rejects.toThrow();
    expect(offline.read()).toEqual(response.entries);
    const edited = { ...response, entries: [{ version: "0.2.18", notes: "Уточнение" }] };
    expect(await new ReleaseHistory(cache, async () => edited).refresh()).toEqual(edited.entries);
    expect(new ReleaseHistory(cache, async () => response).read()).toEqual(edited.entries);
  });

  it("does not replace good history with malformed server data", async () => {
    const cache = storage(JSON.stringify(response));
    const history = new ReleaseHistory(cache, async () => ({ api_version: "1", entries: [{}] }));
    await expect(history.refresh()).rejects.toThrow();
    expect(history.read()).toEqual(response.entries);
  });

  it("falls back to bundled notes on a missing or corrupt cache", () => {
    for (const data of [null, "broken", JSON.stringify({ api_version: "2", entries: [] })]) {
      expect(new ReleaseHistory(storage(data), async () => response).read().length).toBeGreaterThan(0);
    }
  });

  it("still displays fresh notes when local storage is unavailable", async () => {
    const cache = { getItem: () => { throw Error("denied"); }, setItem: () => { throw Error("quota"); } };
    const history = new ReleaseHistory(cache, async () => response);
    expect(history.read().length).toBeGreaterThan(0);
    expect(await history.refresh()).toEqual(response.entries);
    expect(history.read()).toEqual(response.entries);
  });

  it("coalesces concurrent refreshes so an older response cannot overwrite a newer one", async () => {
    let finish!: (value: unknown) => void;
    let requests = 0;
    const history = new ReleaseHistory(storage(), () => { requests++; return new Promise(resolve => { finish = resolve; }); });
    const a = history.refresh();
    const b = history.refresh();
    finish(response);
    expect(await a).toEqual(response.entries);
    expect(await b).toEqual(response.entries);
    expect(requests).toBe(1);
  });

  it("accepts an authoritative empty history and preserves literal plain text", async () => {
    expect(parseReleaseHistory({ api_version: "1", entries: [] })).toEqual([]);
    expect(parseReleaseHistory({ api_version: "1", entries: [{ version: "0.3.0", notes: "<script>test</script>\n- пункт" }] })[0].notes).toBe("<script>test</script>\n- пункт");
  });

  it("rejects unsupported, duplicate and excessive entries before caching", () => {
    for (const bad of [
      { ...response, api_version: "2" },
      { ...response, entries: [response.entries[0], response.entries[0]] },
      { ...response, entries: [{ version: " ", notes: "test" }] },
      { ...response, entries: [{ version: "0.3.0", notes: "x".repeat(20_001) }] },
      { ...response, entries: Array.from({ length: 51 }, (_, i) => ({ version: `0.0.${i}`, notes: "ok" })) },
    ]) expect(() => parseReleaseHistory(bad)).toThrow();
  });
});
