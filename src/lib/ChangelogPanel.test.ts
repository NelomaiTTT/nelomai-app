import { render } from "svelte/server";
import { describe, expect, it } from "vitest";

import ChangelogPanel from "./ChangelogPanel.svelte";

describe("ChangelogPanel", () => {
  it("renders version entries as concise user-facing lists", () => {
    const { body } = render(ChangelogPanel, {
      props: {
        entries: [
          {
            version: "0.2.14",
            items: ["Добавили новую функцию.", "Исправили подключение."],
          },
        ],
        onclose: () => {},
      },
    });

    expect(body).toContain("Что нового");
    expect(body).toContain("Версия 0.2.14");
    expect(body).toContain(">Добавили новую функцию.</li>");
    expect(body).toContain(">Исправили подключение.</li>");
  });
});
