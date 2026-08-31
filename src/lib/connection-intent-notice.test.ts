import { describe, expect, it } from "vitest";
import {
  clearOwnedConnectionIntentNotice,
  connectionIntentNoticeForPhase,
} from "./connection-intent-notice";

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

  it("does not reintroduce a recovery banner over a connected tunnel", () => {
    expect(
      connectionIntentNoticeForPhase(
        "connected",
        "Проверяем подключение",
        "Повторная проверка выполняется автоматически.",
      ),
    ).toBeNull();
    expect(
      connectionIntentNoticeForPhase(
        "connecting",
        "Проверяем подключение",
        "Повторная проверка выполняется автоматически.",
      ),
    ).toBe(
      "Проверяем подключение. Повторная проверка выполняется автоматически.",
    );
  });

  it("clears a stored recovery notice exactly when the tunnel becomes connected", () => {
    const notice = "Проверяем подключение";

    expect(clearOwnedConnectionIntentNotice(notice, notice, "connecting")).toEqual({
      error: notice,
      ownedNotice: notice,
    });
    expect(clearOwnedConnectionIntentNotice(notice, notice, "connected")).toEqual({
      error: null,
      ownedNotice: null,
    });
  });
});
