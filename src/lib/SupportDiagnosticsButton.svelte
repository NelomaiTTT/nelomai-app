<script lang="ts">
  import { onMount } from "svelte";
  import { supportDiagnosticsBridge, type SupportDiagnosticsBridge } from "./support-diagnostics";

  let { bridge = null }: { bridge?: SupportDiagnosticsBridge | null } = $props();
  let detected = $state<SupportDiagnosticsBridge | null>(null);
  let failed = $state(false);
  onMount(() => { detected = supportDiagnosticsBridge(window); });
  function open() {
    try { (bridge ?? detected)?.open(); failed = false; }
    catch { failed = true; }
  }
</script>

{#if bridge ?? detected}
  <button class="secondary-button" type="button" onclick={open}>Диагностика</button>
  {#if failed}
    <p role="status">Откройте диагностику долгим нажатием на значок Nelomai.</p>
  {/if}
{/if}

<style>
  button {
    min-height: 42px;
    padding: 0 18px;
    color: #effaf8;
    border: 1px solid #3a8075;
    border-radius: 6px;
    background: #173d38;
    font: inherit;
    font-weight: 740;
    cursor: pointer;
  }
</style>
