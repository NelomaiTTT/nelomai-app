import { render } from "svelte/server";
import { describe, expect, it } from "vitest";

import ChangelogPanel from "./ChangelogPanel.svelte";
import { ReleaseHistory } from "./release-history";

describe("ChangelogPanel", () => {
  it("renders panel text and line breaks without treating HTML as markup", () => {
    const { body } = render(ChangelogPanel, {
      props: {
        history: new ReleaseHistory({
          getItem: () => JSON.stringify({ api_version: "1", entries: [{ version: "0.2.18", notes: "Добавили новую функцию.\n<script>evil()</script>" }] }),
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
});
