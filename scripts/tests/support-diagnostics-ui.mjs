import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { chromium } from "playwright-core";

const port = 1457;
const base = `http://127.0.0.1:${port}`;
const vite = spawn(process.execPath, ["node_modules/vite/bin/vite.js", "--host", "127.0.0.1", "--port", `${port}`, "--strictPort"], { stdio: "pipe" });
let output = "";
vite.stdout.on("data", chunk => { output = (output + chunk).slice(-4000); });
vite.stderr.on("data", chunk => { output = (output + chunk).slice(-4000); });
let browser;
try {
  let ready = false;
  for (let attempt = 0; attempt < 100; attempt++) {
    if (vite.exitCode !== null) throw Error(output);
    try { ready = (await fetch(base, { signal: AbortSignal.timeout(500) })).ok; } catch {}
    if (ready) break;
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  assert(ready, "local UI did not start");
  browser = await chromium.launch({ headless: true, executablePath: process.env.BROWSER_PATH ?? "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge" });
  for (const bridgePresent of [true, false]) {
    const page = await browser.newPage({ viewport: { width: 390, height: 844 } });
    await page.addInitScript(present => {
      window.__diagnosticCalls = [];
      window.__nativeCommands = [];
      if (present) window.NelomaiSupportDiagnostics = { open(...args) { window.__diagnosticCalls.push(args); } };
      window.__TAURI_INTERNALS__ = {
        invoke: async (command, args) => {
          window.__nativeCommands.push({ command, args });
          if (command === "app_bootstrap") throw { code: "signed_out", message: "Sign in required" };
          if (command === "app_state") return { phase: "signed_out", connection: null, connectionIntentStatus: "none", nextRetryAtUnix: null, warning: null, metrics: null };
          if (command === "app_release_history") return { api_version: "1", entries: [] };
          if (command === "plugin:event|listen") return 1;
          return null;
        },
        transformCallback: () => 1,
        unregisterCallback() {},
      };
    }, bridgePresent);
    await page.goto(base);
    await page.getByRole("heading", { name: "Вход в Nelomai" }).waitFor();
    const button = page.getByRole("button", { name: "Диагностика", exact: true });
    if (bridgePresent) {
      assert.equal(await button.getAttribute("type"), "button");
      const callsBefore = await page.evaluate(() => window.__nativeCommands.length);
      await button.click();
      assert.deepEqual(await page.evaluate(() => window.__diagnosticCalls), [[]]);
      assert.deepEqual(await page.evaluate(count => window.__nativeCommands.slice(count), callsBefore), []);
      const dimensions = await page.evaluate(() => ({ content: document.documentElement.scrollWidth, viewport: window.innerWidth }));
      assert(dimensions.content <= dimensions.viewport, "login diagnostics overflows the mobile screen");
    } else assert.equal(await button.count(), 0);
    await page.close();
  }
  console.log("PASS: native pre-login click, no account command, unavailable bridge, mobile layout");
} finally {
  await browser?.close();
  vite.kill("SIGTERM");
}
