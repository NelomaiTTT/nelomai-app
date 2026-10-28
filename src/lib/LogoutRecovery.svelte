<script lang="ts">
  let { required, busy, onretry }: { required: boolean; busy: boolean; onretry: () => void } = $props();
</script>

{#if required}
  <p>Если предыдущий выход не завершился, повторите его.</p>
  <button class="quiet-button" type="button" disabled={busy} onclick={onretry}>
    Завершить выход
  </button>
{/if}
