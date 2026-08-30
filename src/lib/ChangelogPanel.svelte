<script lang="ts">
  import { onMount } from "svelte";
  import type { ChangelogEntry } from "./changelog";

  let {
    entries,
    onclose,
  }: {
    entries: readonly ChangelogEntry[];
    onclose: () => void;
  } = $props();

  let dialog: HTMLDivElement;
  let closeButton: HTMLButtonElement;

  onMount(() => {
    const previousFocus =
      document.activeElement instanceof HTMLElement
        ? document.activeElement
        : null;
    const previousBodyOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    closeButton.focus();

    return () => {
      document.body.style.overflow = previousBodyOverflow;
      previousFocus?.focus();
    };
  });

  function handleKeydown(event: KeyboardEvent) {
    if (event.key === "Escape") {
      event.preventDefault();
      event.stopPropagation();
      onclose();
      return;
    }
    if (event.key !== "Tab") return;

    const focusable = Array.from(
      dialog.querySelectorAll<HTMLElement>(
        'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
      ),
    );
    if (focusable.length === 0) {
      event.preventDefault();
      dialog.focus();
      return;
    }

    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (
      (event.shiftKey && document.activeElement === first) ||
      (!event.shiftKey && document.activeElement === last) ||
      !dialog.contains(document.activeElement)
    ) {
      event.preventDefault();
      (event.shiftKey ? last : first).focus();
    }
  }
</script>

<svelte:window onkeydown={handleKeydown} />

<div class="changelog-overlay" role="presentation">
  <div
    bind:this={dialog}
    class="changelog-panel"
    role="dialog"
    tabindex="-1"
    aria-modal="true"
    aria-labelledby="changelog-title"
  >
    <header>
      <div>
        <p>История версий</p>
        <h2 id="changelog-title">Что нового</h2>
      </div>
      <button
        bind:this={closeButton}
        class="icon-button"
        type="button"
        onclick={onclose}
        aria-label="Закрыть"
      >
        ×
      </button>
    </header>

    <div class="version-list">
      {#each entries as entry (entry.version)}
        <article>
          <h3>Версия {entry.version}</h3>
          <ul>
            {#each entry.items as item}
              <li>{item}</li>
            {/each}
          </ul>
        </article>
      {/each}
    </div>
  </div>
</div>

<style>
  .changelog-overlay {
    position: fixed;
    inset: 0;
    z-index: 1000;
    padding: 24px;
    display: grid;
    place-items: center;
    background: rgba(3, 5, 7, 0.78);
    backdrop-filter: blur(12px);
    overscroll-behavior: contain;
  }

  .changelog-panel {
    width: min(680px, 100%);
    max-height: min(780px, calc(100dvh - 48px));
    padding: 24px;
    display: grid;
    grid-template-rows: auto minmax(0, 1fr);
    gap: 22px;
    color: #f5f6f8;
    border: 1px solid #3a444d;
    border-radius: 8px;
    background: #101418;
    box-shadow: 0 28px 80px rgba(0, 0, 0, 0.48);
  }

  header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
  }

  header p,
  header h2,
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
    min-height: 40px;
    color: #dce2e6;
    border: 1px solid #3a444d;
    border-radius: 6px;
    background: #171d22;
    font: inherit;
    cursor: pointer;
  }

  .icon-button {
    width: 40px;
    padding: 0;
    font-size: 25px;
    line-height: 1;
  }

  .version-list {
    min-height: 0;
    overflow-y: auto;
    display: grid;
    align-content: start;
    gap: 12px;
  }

  article {
    padding: 19px;
    display: grid;
    gap: 13px;
    border: 1px solid #2f373e;
    border-radius: 7px;
    background: #0c1014;
  }

  article h3 {
    font-size: 17px;
  }

  ul {
    margin: 0;
    padding-left: 21px;
    display: grid;
    gap: 9px;
    color: #c1c8cd;
    line-height: 1.5;
  }

  li {
    padding-left: 3px;
  }

  @media (max-width: 620px) {
    .changelog-overlay {
      padding: 0;
      place-items: stretch;
    }

    .changelog-panel {
      width: 100%;
      max-height: 100dvh;
      min-height: 100dvh;
      padding:
        max(18px, env(safe-area-inset-top, 0px))
        max(16px, env(safe-area-inset-right, 0px))
        max(18px, env(safe-area-inset-bottom, 0px))
        max(16px, env(safe-area-inset-left, 0px));
      border: 0;
      border-radius: 0;
    }
  }
</style>
