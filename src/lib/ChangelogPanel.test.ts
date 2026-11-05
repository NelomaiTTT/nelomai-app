import { render } from "svelte/server";
import { describe, expect, it } from "vitest";

import ChangelogPanel from "./ChangelogPanel.svelte";
import { ReleaseHistory } from "./release-history";

describe("ChangelogPanel", () => {
  it("renders panel text and line breaks without treating HTML as markup", () => {
    const { body } = render(ChangelogPanel, {
      props: {
        history: new ReleaseHistory({
          getItem: () => JSON.stringify({ api_version: "1", platform: "macos", entries: [{ version: "0.2.18", notes: "Добавили новую функцию.\n<script>evil()</script>" }] }),
          setItem: () => {},
        }, async () => { throw Error("offline"); }),
        onclose: () => {},
      },
    });

    expect(body).toContain("Что нового");
    expect(body).toContain("Версия 0.2.18");
    expect(body).toContain("Добавили новую функцию.\n&lt;script>evil()&lt;/script>");
    expect(body).not.toContain("<script>evil()");
  });
  it("shows desktop 0.4.0 and Android 0.3.11 from their scoped cached histories", () => {
    for (const payload of [
      { api_version: "1", platform: "macos", entries: [{ version: "0.4.0", notes: "Desktop" }] },
      { api_version: "1", platform: "android", entries: [{ version: "0.3.11", notes: "Android" }] },
    ]) {
      const { body } = render(ChangelogPanel, {
        props: {
          history: new ReleaseHistory({
            getItem: (key: string) => key === "nelomai.ru.release-history.v2" ? JSON.stringify(payload) : null,
            setItem: () => {},
          }, async () => { throw Error("offline"); }),
          onclose: () => {},
        },
      });
      expect(body).toContain(`Версия ${payload.entries[0].version}`);
      expect(body).toContain(payload.entries[0].notes);
    }
  });

});
