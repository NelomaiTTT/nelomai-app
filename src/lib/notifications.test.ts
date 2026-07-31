import { describe, expect, it } from "vitest";
import type { AppNotification } from "./native-client";
import { appendNotificationPage, mergeRefreshedNotifications } from "./notifications";

function notification(id: number, readAt: string | null = null): AppNotification {
  return {
    id,
    kind: "admin_broadcast",
    title: `Сообщение ${id}`,
    body: "Текст",
    url: null,
    created_at: "2026-07-31T12:00:00Z",
    read_at: readAt,
  };
}

describe("notification pagination", () => {
  it("preserves loaded history while refreshing the newest page", () => {
    const current = [notification(5), notification(4), notification(3), notification(2)];
    const refreshed = [notification(6), notification(5, "2026-07-31T12:05:00Z"), notification(4)];

    const result = mergeRefreshedNotifications(current, refreshed);

    expect(result.map((item) => item.id)).toEqual([6, 5, 4, 3, 2]);
    expect(result.find((item) => item.id === 5)?.read_at).toBe("2026-07-31T12:05:00Z");
  });

  it("does not duplicate overlapping rows when appending a page", () => {
    const result = appendNotificationPage(
      [notification(5), notification(4)],
      [notification(4), notification(3)],
    );

    expect(result.map((item) => item.id)).toEqual([5, 4, 3]);
  });
});
