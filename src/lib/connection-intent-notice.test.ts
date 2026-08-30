import { describe, expect, it } from "vitest";
import { clearOwnedConnectionIntentNotice } from "./connection-intent-notice";

describe("connection intent notice ownership", () => {
  it("clears only the notice that recovery owns", () => {
    const notice = "Восстанавливаем подключение";

    expect(clearOwnedConnectionIntentNotice(notice, notice)).toEqual({
      error: null,
      ownedNotice: null,
    });
    expect(clearOwnedConnectionIntentNotice("Ошибка входа", notice)).toEqual({
      error: "Ошибка входа",
      ownedNotice: null,
    });
  });
});
