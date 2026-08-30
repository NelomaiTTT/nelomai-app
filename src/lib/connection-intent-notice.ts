export function clearOwnedConnectionIntentNotice(
  error: string | null,
  ownedNotice: string | null,
): { error: string | null; ownedNotice: null } {
  return {
    error: error === ownedNotice ? null : error,
    ownedNotice: null,
  };
}
