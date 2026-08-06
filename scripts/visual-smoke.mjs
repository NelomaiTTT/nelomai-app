import { chromium } from "playwright-core";

const baseUrl = process.env.APP_URL ?? "http://127.0.0.1:1420";
const executablePath =
  process.env.BROWSER_PATH ??
  "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge";

const bootstrap = {
  api_version: "1",
  request_id: "preview-bootstrap",
  access: {
    state: "active",
    can_login: true,
    can_connect: true,
    expires_at: null,
  },
  device: {
    id: "device-1",
    name: "MacBook",
    platform: "macos",
  },
  binding: {
    id: "binding-1",
    peer_id: "peer-5",
    interface_id: "interface-1",
    interface_name: "Основной интерфейс",
    slot: 5,
    preferred_layer: "stray",
    tic_connection_mode: "dynamic",
    route_mode: "standalone",
  },
  connection: null,
  pinned_stray: null,
  defaults: {
    layer: "stray",
    tic_connection_mode: "dynamic",
    route_mode: "standalone",
  },
  update: {
    current_version: "0.1.0",
    minimum_version: null,
    update_available: false,
    required: false,
    release_notes: null,
  },
};

const peers = {
  api_version: "1",
  request_id: "preview-peers",
  peers: [
    {
      id: "unused-peer",
      interface_id: "interface-1",
      interface_name: "Основной интерфейс",
      slot: 3,
      name: "Пир 3",
      comment: "Телефон",
      last_handshake_at: null,
      bound_to_app: false,
      bound_to_this_device: false,
      selectable: true,
    },
    {
      id: "used-peer",
      interface_id: "interface-1",
      interface_name: "Основной интерфейс",
      slot: 2,
      name: "Пир 2",
      comment: null,
      last_handshake_at: "2026-07-26T12:00:00Z",
      bound_to_app: false,
      bound_to_this_device: false,
      selectable: true,
    },
  ],
};

const browser = await chromium.launch({
  executablePath,
  headless: true,
});

try {
  await capture("sign-in", { width: 390, height: 844 }, "signed_out");
  await capture("peers-mobile", { width: 390, height: 844 }, "peers");
  await capture("connection-mobile", { width: 390, height: 844 }, "connection");
  await capture("personal-tic-mobile", { width: 390, height: 844 }, "personal-tic");
  await capture("pinned-stray-mobile", { width: 390, height: 844 }, "pinned-stray");
  await capture("connection-desktop", { width: 1280, height: 800 }, "connection");
} finally {
  await browser.close();
}

async function capture(name, viewport, scenario) {
  const context = await browser.newContext({
    viewport,
    deviceScaleFactor: 1,
    isMobile: viewport.width < 600,
    hasTouch: viewport.width < 600,
  });
  const page = await context.newPage();
  await page.addInitScript(
    ({ fixture, peerFixture, currentScenario, desktop }) => {
      window.__TAURI_CALLS__ = [];
      window.__TAURI_INTERNALS__ = {
        invoke: async (command, args) => {
          window.__TAURI_CALLS__.push({ command, args });
          if (command === "app_bootstrap") {
            if (currentScenario === "signed_out") {
              throw {
                code: "signed_out",
                message: "Нужно снова войти в приложение",
              };
            }
            if (currentScenario === "peers") {
              return { ...fixture, binding: null };
            }
            if (currentScenario === "personal-tic") {
              return {
                ...fixture,
                binding: {
                  ...fixture.binding,
                  preferred_layer: "tic",
                  tic_connection_mode: "personal",
                  route_mode: "via_tak",
                },
                defaults: {
                  layer: "tic",
                  tic_connection_mode: "personal",
                  route_mode: "via_tak",
                },
              };
            }
            if (currentScenario === "pinned-stray") {
              return {
                ...fixture,
                pinned_stray: {
                  lease_id: "pinned-lease",
                  layer: "stray",
                  tic_connection_mode: "dynamic",
                  route_mode: "standalone",
                  status: "warm",
                  pinned: true,
                  stopped_at: "2026-07-26T12:00:00Z",
                },
              };
            }
            return fixture;
          }
          if (command === "app_state") {
            return { phase: "ready", connection: null };
          }
          if (command === "app_preferences") {
            return {
              closeToTraySupported: desktop,
              closeToTray: true,
              dnsProvider: "google",
            };
          }
          if (command === "app_peer_options") {
            return peerFixture;
          }
          if (command === "app_refresh_probes") {
            return {
              layer: args.layer,
              probes: [
                {
                  candidate_id: "preview-candidate",
                  latency_ms: 24.5,
                  measured_at: "2026-07-26T12:00:00Z",
                },
              ],
            };
          }
          return {};
        },
      };
    },
    {
      fixture: bootstrap,
      peerFixture: peers,
      currentScenario: scenario,
      desktop: viewport.width >= 600,
    },
  );

  await page.goto(baseUrl, { waitUntil: "networkidle" });
  await page.waitForTimeout(100);

  const dimensions = await page.evaluate(() => ({
    viewport: window.innerWidth,
    scroll: document.documentElement.scrollWidth,
  }));
  if (dimensions.scroll > dimensions.viewport) {
    throw new Error(
      `${name} has horizontal overflow: ${dimensions.scroll}px > ${dimensions.viewport}px`,
    );
  }

  if (scenario === "signed_out") {
    await page.getByRole("heading", { name: "Вход в Nelomai" }).waitFor();
    await page.getByRole("button", { name: "Войти" }).waitFor();
  } else if (scenario === "peers") {
    await page.getByRole("heading", { name: "Выберите пир" }).waitFor();
    const button = page.getByRole("button", { name: "Использовать этот пир" });
    if (await button.isDisabled()) {
      throw new Error("peer action is disabled despite an available peer");
    }
    await button.click();
    const bindingCall = await lastCall(page, "app_bind_peer");
    if (bindingCall?.args?.request?.peer_id !== "unused-peer") {
      throw new Error("the peer selected by default was not passed to app_bind_peer");
    }
  } else if (scenario === "personal-tic") {
    await page.getByText("Личный пир", { exact: true }).waitFor();
    const refresh = await lastCall(page, "app_refresh_probes");
    if (refresh) {
      throw new Error("personal Tic mode unexpectedly requested server probes");
    }
  } else if (scenario === "pinned-stray") {
    const unpin = page.getByRole("button", { name: "Отменить сохранение Stray" });
    await unpin.waitFor();
    await unpin.click();
    const call = await lastCall(page, "app_unpin_stray");
    if (call?.args?.request?.leaseId !== "pinned-lease") {
      throw new Error("saved Stray action did not pass the pinned lease id");
    }
  } else {
    const start = page.getByRole("button", { name: /Старт/ });
    await start.waitFor();
    await page.getByText("Stray", { exact: true }).waitFor();
    await start.click();
    await page.getByRole("button", { name: /Стоп/ }).waitFor();
    if (!(await lastCall(page, "app_start"))) {
      throw new Error("start button did not call app_start");
    }
    const pin = page.getByRole("button", { name: "Сохранить подключение" });
    await pin.waitFor();
    await pin.click();
    if (!(await lastCall(page, "app_pin_stray"))) {
      throw new Error("saved Stray action did not call app_pin_stray");
    }
  }

  await page.screenshot({
    path: `/tmp/nelomai-${name}.png`,
    fullPage: true,
  });
  await context.close();
}

async function lastCall(page, command) {
  return page.evaluate((expected) => {
    const calls = window.__TAURI_CALLS__ ?? [];
    return [...calls].reverse().find((call) => call.command === expected) ?? null;
  }, command);
}
