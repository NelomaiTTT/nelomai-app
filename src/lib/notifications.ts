import type { AppNotification } from "./native-client";

export function mergeRefreshedNotifications(
  current: AppNotification[],
  refreshed: AppNotification[],
): AppNotification[] {
  const refreshedIds = new Set(refreshed.map((notification) => notification.id));
  return [
    ...refreshed,
    ...current.filter((notification) => !refreshedIds.has(notification.id)),
  ];
}

export function appendNotificationPage(
  current: AppNotification[],
  page: AppNotification[],
): AppNotification[] {
  const existingIds = new Set(current.map((notification) => notification.id));
  return [
    ...current,
    ...page.filter((notification) => !existingIds.has(notification.id)),
  ];
}
