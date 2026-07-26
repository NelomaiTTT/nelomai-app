<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { onMount } from "svelte";

  interface TunnelProbe {
    platform: string;
    backendAvailable: boolean;
    permissionGranted: boolean;
    backendVersion: string | null;
    error: string | null;
  }

  interface SmokeResult {
    state: "up" | "down" | "unsupported";
    durationMillis: number;
  }

  let probe = $state<TunnelProbe | null>(null);
  let smoke = $state<SmokeResult | null>(null);
  let error = $state<string | null>(null);
  let requestingPermission = $state(false);

  async function loadProbe() {
    error = null;
    try {
      probe = await invoke<TunnelProbe>("plugin:tunnel-android|probe");
    } catch (reason) {
      error = String(reason);
    }
  }

  async function requestPermission() {
    requestingPermission = true;
    error = null;
    try {
      await invoke("plugin:tunnel-android|request_vpn_permission");
      await loadProbe();
    } catch (reason) {
      error = String(reason);
    } finally {
      requestingPermission = false;
    }
  }

  async function runSmoke(command: "start_smoke_tunnel" | "stop_smoke_tunnel") {
    error = null;
    try {
      smoke = await invoke<SmokeResult>(`plugin:tunnel-android|${command}`);
    } catch (reason) {
      error = String(reason);
    }
  }

  onMount(loadProbe);
</script>

<svelte:head>
  <title>Nelomai platform spike</title>
</svelte:head>

<main>
  <p class="eyebrow">Platform feasibility spike</p>
  <h1>Nelomai</h1>

  {#if probe}
    <dl>
      <div>
        <dt>Platform</dt>
        <dd>{probe.platform}</dd>
      </div>
      <div>
        <dt>WireGuard backend</dt>
        <dd>{probe.backendAvailable ? "available" : "unavailable"}</dd>
      </div>
      <div>
        <dt>Backend version</dt>
        <dd>{probe.backendVersion ?? "n/a"}</dd>
      </div>
      <div>
        <dt>VPN permission</dt>
        <dd>{probe.permissionGranted ? "granted" : "required"}</dd>
      </div>
    </dl>

    {#if !probe.permissionGranted && probe.platform === "android"}
      <button onclick={requestPermission} disabled={requestingPermission}>
        {requestingPermission ? "Waiting for Android..." : "Request VPN permission"}
      </button>
    {/if}

    {#if probe.permissionGranted && probe.platform === "android"}
      <div class="actions">
        <button onclick={() => runSmoke("start_smoke_tunnel")}>Start smoke tunnel</button>
        <button class="secondary" onclick={() => runSmoke("stop_smoke_tunnel")}>
          Stop smoke tunnel
        </button>
      </div>
    {/if}

    {#if smoke}
      <p>Smoke tunnel: {smoke.state} ({smoke.durationMillis} ms)</p>
    {/if}

    {#if probe.error}
      <p class="error">{probe.error}</p>
    {/if}
  {:else if !error}
    <p>Loading native backend...</p>
  {/if}

  {#if error}
    <p class="error">{error}</p>
  {/if}
</main>

<style>
  :global(*) {
    box-sizing: border-box;
  }

  :global(body) {
    margin: 0;
    min-width: 320px;
    min-height: 100vh;
    color: #f5f7fa;
    background: #090b0d;
    font-family: system-ui, sans-serif;
  }

  main {
    width: min(680px, calc(100% - 40px));
    margin: 0 auto;
    padding: 48px 0;
  }

  .eyebrow {
    margin: 0 0 8px;
    color: #63c7b7;
    font-size: 13px;
    text-transform: uppercase;
  }

  h1 {
    margin: 0 0 32px;
    font-size: 36px;
  }

  dl {
    margin: 0 0 24px;
    border-top: 1px solid #31363b;
  }

  dl div {
    display: grid;
    grid-template-columns: minmax(140px, 1fr) 1fr;
    gap: 24px;
    padding: 14px 0;
    border-bottom: 1px solid #31363b;
  }

  dt {
    color: #9aa2aa;
  }

  dd {
    margin: 0;
    overflow-wrap: anywhere;
  }

  button {
    min-height: 44px;
    padding: 0 18px;
    border: 1px solid #7be0d0;
    border-radius: 6px;
    color: #07110f;
    background: #7be0d0;
    font: inherit;
    cursor: pointer;
  }

  button:disabled {
    cursor: wait;
    opacity: 0.6;
  }

  .actions {
    display: flex;
    flex-wrap: wrap;
    gap: 12px;
  }

  .secondary {
    color: #f5f7fa;
    background: transparent;
  }

  .error {
    color: #ff8585;
  }
</style>
