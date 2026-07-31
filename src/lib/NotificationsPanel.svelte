<script lang="ts">
  import { openUrl } from "@tauri-apps/plugin-opener";
  import type { AppNotification } from "./native-client";

  let {
    notifications,
    unreadCount,
    nextCursor,
    busy,
    error,
    onclose,
    onread,
    onreadall,
    onloadmore,
  }: {
    notifications: AppNotification[];
    unreadCount: number;
    nextCursor: number | null;
    busy: boolean;
    error: string | null;
    onclose: () => void;
    onread: (messageId: number) => Promise<void>;
    onreadall: () => Promise<void>;
    onloadmore: () => Promise<void>;
  } = $props();

  async function openNotification(notification: AppNotification) {
    const readPromise = notification.read_at ? Promise.resolve() : onread(notification.id);
    if (!notification.url) {
      await readPromise;
      return;
    }
    const target = new URL(notification.url, "https://nelomai.ru");
    if (target.protocol === "https:" || target.protocol === "http:") {
      await Promise.all([openUrl(target.toString()), readPromise]);
    }
  }

  function formatDate(value: string): string {
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return "";
    return new Intl.DateTimeFormat("ru-RU", {
      day: "2-digit",
      month: "2-digit",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    }).format(date);
  }
</script>

<div class="notifications-overlay" role="presentation">
  <div class="notifications-panel" role="dialog" aria-modal="true" aria-labelledby="notifications-title">
    <header>
      <div>
        <p>События</p>
        <h2 id="notifications-title">Уведомления</h2>
      </div>
      <button class="icon-button" type="button" onclick={onclose} aria-label="Закрыть">×</button>
    </header>

    <div class="toolbar">
      <span>{unreadCount ? `Непрочитанных: ${unreadCount}` : "Всё прочитано"}</span>
      {#if unreadCount}
        <button type="button" onclick={onreadall} disabled={busy}>Прочитать все</button>
      {/if}
    </div>

    {#if error}<p class="error-message">{error}</p>{/if}

    {#if notifications.length}
      <div class="notification-list">
        {#each notifications as notification (notification.id)}
          <article class:unread={!notification.read_at}>
            <div class="notification-heading">
              <div>
                <span>{formatDate(notification.created_at)}</span>
                <h3>{notification.title}</h3>
              </div>
              {#if !notification.read_at}<i aria-label="Не прочитано"></i>{/if}
            </div>
            <p>{notification.body}</p>
            <div class="notification-actions">
              {#if notification.url}
                <button
                  class="primary-action"
                  type="button"
                  onclick={() => openNotification(notification)}
                  disabled={busy}
                >Открыть</button>
              {/if}
              {#if !notification.read_at}
                <button type="button" onclick={() => onread(notification.id)} disabled={busy}>
                  Прочитано
                </button>
              {/if}
            </div>
          </article>
        {/each}
      </div>
      {#if nextCursor}
        <button class="load-more" type="button" onclick={onloadmore} disabled={busy}>
          {busy ? "Загружаем…" : "Показать ещё"}
        </button>
      {/if}
    {:else if !busy}
      <div class="empty-state">
        <strong>Здесь пока тихо</strong>
        <span>Новые сообщения появятся в этом разделе.</span>
      </div>
    {/if}
  </div>
</div>

<style>
  .notifications-overlay {
    position: fixed;
    inset: 0;
    z-index: 1000;
    padding: 24px;
    display: grid;
    place-items: center;
    background: rgba(3, 5, 7, 0.78);
    backdrop-filter: blur(12px);
  }

  .notifications-panel {
    width: min(720px, 100%);
    max-height: min(780px, calc(100vh - 48px));
    padding: 24px;
    display: grid;
    grid-template-rows: auto auto minmax(0, 1fr) auto;
    gap: 18px;
    color: #f5f6f8;
    border: 1px solid #3a444d;
    border-radius: 8px;
    background: #101418;
    box-shadow: 0 28px 80px rgba(0, 0, 0, 0.48);
  }

  header,
  .toolbar,
  .notification-heading,
  .notification-actions {
    display: flex;
    align-items: center;
  }

  header,
  .toolbar,
  .notification-heading {
    justify-content: space-between;
    gap: 16px;
  }

  header p,
  header h2,
  article p,
  article h3 {
    margin: 0;
    letter-spacing: 0;
  }

  header p {
    margin-bottom: 5px;
    color: #68cfc0;
    font-size: 11px;
    font-weight: 720;
    text-transform: uppercase;
  }

  header h2 {
    font-size: 24px;
  }

  button {
    min-height: 36px;
    padding: 0 13px;
    color: #dce2e6;
    border: 1px solid #3a444d;
    border-radius: 6px;
    background: #171d22;
    font: inherit;
    cursor: pointer;
  }

  button:disabled {
    opacity: 0.55;
    cursor: wait;
  }

  .icon-button {
    width: 40px;
    min-height: 40px;
    padding: 0;
    font-size: 25px;
    line-height: 1;
  }

  .toolbar {
    min-height: 40px;
    padding-bottom: 14px;
    color: #aeb6bd;
    border-bottom: 1px solid #2a3036;
    font-size: 13px;
  }

  .notification-list {
    min-height: 0;
    overflow-y: auto;
    display: grid;
    align-content: start;
    gap: 10px;
  }

  article {
    padding: 17px;
    display: grid;
    gap: 12px;
    border: 1px solid #2f373e;
    border-radius: 7px;
    background: #0c1014;
  }

  article.unread {
    border-color: #326a62;
    background: #10221f;
  }

  .notification-heading > div {
    min-width: 0;
    display: grid;
    gap: 4px;
  }

  .notification-heading span {
    color: #8f9aa3;
    font-size: 11px;
  }

  .notification-heading h3 {
    overflow-wrap: anywhere;
    font-size: 16px;
  }

  .notification-heading i {
    width: 9px;
    height: 9px;
    flex: 0 0 auto;
    border-radius: 50%;
    background: #67d5c4;
  }

  article p {
    color: #c1c8cd;
    line-height: 1.5;
    white-space: pre-wrap;
    overflow-wrap: anywhere;
  }

  .notification-actions {
    justify-content: flex-end;
    gap: 8px;
  }

  .primary-action {
    color: #06110f;
    border-color: #67d5c4;
    background: #67d5c4;
    font-weight: 720;
  }

  .load-more {
    width: 100%;
  }

  .empty-state {
    min-height: 220px;
    display: grid;
    place-content: center;
    justify-items: center;
    gap: 7px;
    color: #909aa3;
    text-align: center;
  }

  .empty-state strong {
    color: #fff;
    font-size: 18px;
  }

  .error-message {
    margin: 0;
    color: #ff9999;
    font-size: 13px;
  }

  @media (max-width: 620px) {
    .notifications-overlay {
      padding: 0;
      place-items: stretch;
    }

    .notifications-panel {
      width: 100%;
      max-height: 100vh;
      min-height: 100vh;
      padding: max(18px, env(safe-area-inset-top)) 16px max(18px, env(safe-area-inset-bottom));
      border: 0;
      border-radius: 0;
    }

    .notification-actions button {
      flex: 1;
    }
  }
</style>
