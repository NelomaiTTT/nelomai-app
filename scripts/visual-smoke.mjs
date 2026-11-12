import {tmpdir} from "node:os";
import {mkdir} from "node:fs/promises";
const outputDir=process.env.VISUAL_OUTPUT ?? tmpdir();
await mkdir(outputDir,{recursive:true});
import { spawn } from "node:child_process";
import { once } from "node:events";
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
  capabilities: null,
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

let vite = null;
let viteOutput = "";
let browser = null;

try {
  if (!process.env.APP_URL) {
    vite = spawn(
      process.execPath,
      [
        "node_modules/vite/bin/vite.js",
        "--host",
        "127.0.0.1",
        "--port",
        "1420",
        "--strictPort",
      ],
      {
        cwd: process.cwd(),
        stdio: ["ignore", "pipe", "pipe"],
      },
    );
    const recordViteOutput = (chunk) => {
      viteOutput = `${viteOutput}${chunk}`.slice(-20_000);
    };
    vite.stdout.on("data", recordViteOutput);
    vite.stderr.on("data", recordViteOutput);
    await waitForServer(baseUrl, vite, () => viteOutput);
  }
  browser = await chromium.launch({
    executablePath,
    headless: true,
  });
  if (process.env.SUPPORT_DIAGNOSTICS_SMOKE) {
    for (const scenario of ["support-loading", "signed_out", "support-preparing", "server-unavailable", "peers", "connection", "update-consent", "startup-failure"]) {
      await capture(`support-${scenario}`, { width: 1280, height: 800 }, scenario);
    }
    await capture("support-android-hidden", { width: 390, height: 844 }, "signed_out");
  } else if(process.env.UPDATE_RESTART_RECOVERY_SMOKE){
    for(const outcome of ["installed", "not-installed"]){
      await capture(`update-restart-recovery-${outcome}`,{width:1280,height:800},`update-restart-recovery-${outcome}`);
    }
  } else if(process.env.UPDATE_REQUIRED_SMOKE){
    for(const phase of ["ready", "downloading"]){
      await capture(`update-required-${phase}-desktop`,{width:1280,height:800},`update-required-${phase}`);
      await capture(`update-required-${phase}-mobile`,{width:390,height:844},`update-required-${phase}`);
    }
  } else if(process.env.UPDATE_MANUAL_RESULT_SMOKE){
    for(const outcome of ["available", "error", "logout"]){
      await capture(`update-manual-result-${outcome}-desktop`,{width:1280,height:800},`update-manual-result-${outcome}`);
      await capture(`update-manual-result-${outcome}-mobile`,{width:390,height:844},`update-manual-result-${outcome}`);
    }
  } else if(process.env.UPDATE_STALE_SMOKE){
    for(const action of ["later-status", "later-check", "later-error", "confirm-status", "later-check-manual", "later-check-manual-error"]){
      await capture(`update-stale-${action}-desktop`,{width:1280,height:800},`update-stale-${action}`);
      await capture(`update-stale-${action}-mobile`,{width:390,height:844},`update-stale-${action}`);
    }
  } else if(process.env.UPDATE_SMOKE){
    await capture("update-consent-desktop",{width:1280,height:800},"update-consent");
    await capture("update-consent-mobile",{width:390,height:844},"update-consent");
  } else {
  for (const scenario of ["runtime-pending-auto", "runtime-pending-manual", "runtime-pending-logout-failed", "runtime-pending-logout"]) {
    await capture(scenario, { width: 1280, height: 800 }, scenario);
  }
  await capture("sign-in", { width: 390, height: 844 }, "signed_out");
  await capture(
    "bootstrap-error",
    { width: 390, height: 844 },
    "server-unavailable",
  );
  await capture("peers-mobile", { width: 390, height: 844 }, "peers");
  await capture("connection-mobile", { width: 390, height: 844 }, "connection");
  await capture("personal-tic-mobile", { width: 390, height: 844 }, "personal-tic");
  await capture("pinned-stray-mobile", { width: 390, height: 844 }, "pinned-stray");
  await capture("connection-desktop", { width: 1280, height: 800 }, "connection");
  }
} finally {
  try {
    await browser?.close();
  } finally {
    await stopChild(vite);
  }
}

async function capture(name, viewport, scenario) {
  const context = await browser.newContext({
    viewport,
    deviceScaleFactor: 1,
    isMobile: viewport.width < 600,
    hasTouch: viewport.width < 600,
  });
  const page = await context.newPage();
  page.setDefaultTimeout(30000);
  await page.addInitScript(
    ({ fixture, peerFixture, currentScenario, desktop, supportSmoke }) => {
      if (supportSmoke) {
        window.isTauri = true;
        if (!desktop) Object.defineProperty(navigator, "userAgent", { value: "Android" });
      }
      let supportAttempts = 0;
      fixture.device.platform = desktop ? "macos" : "android";
      let connection = null;
      let update={supported:true,automatic:true,protocol:2,phase:"downloading",version:"0.4.1",notes:null,required:false,downloaded:1024,total:2048,errorCode:null,offerId:"fixture-offer",promptPending:true,updateAvailable:true};
      if(currentScenario.startsWith("update-manual-result-"))update={...update,phase:"idle",version:null,offerId:null,promptPending:false,updateAvailable:false};
      if(currentScenario.startsWith("update-required-")){
        fixture.update.required=true;
        fixture.update.update_available=true;
        update={...update,required:true,phase:currentScenario.endsWith("ready")?"ready_to_install":"downloading"};
      }
      window.__TAURI_CALLS__ = [];
      window.__SET_UPDATE_PHASE__ = (phase) => { update = {...update, phase}; };
      window.__UPDATE_CHECKING_READS__ = 0;
      window.__TAURI_INTERNALS__ = {
        invoke: async (command, args) => {
          window.__TAURI_CALLS__.push({ command, args });
          if (command === "app_collect_support_diagnostics") {
            return { reportId: "c4271792-2992-4765-af15-57745d2a835c", bytes: 1024, logSources: 3, incompleteSources: 1, serviceAvailable: false };
          }
          if (command === "app_save_support_diagnostics") return true;
          if (command === "app_send_support_diagnostics") {
            if (++supportAttempts === 1) throw "support_network_unavailable";
            return args.reportId;
          }
          if(currentScenario.startsWith("update-restart-recovery-")){
            if(command==="app_bootstrap")throw {code:"runtime_startup_pending",message:"Preparation pending"};
            if(command==="app_update_status")return {...update,
              phase:currentScenario.endsWith("not-installed")?"ready_to_install":"ready_to_restart",
              promptPending:currentScenario.endsWith("not-installed")};
            if(command==="app_update_restart")return;
            if(command.startsWith("app_update_"))throw Error("Recovery must only read status or request confirmed Restart");
          }
          if(currentScenario.startsWith("update-manual-result-") && command.startsWith("app_update_")){
            if(command==="app_update_status" && !window.__HELD_UPDATE_REPLY__){
              window.__HELD_UPDATE_REPLY__=true;
              const snapshot={...update};
              await new Promise(resolve=>window.__RELEASE_UPDATE_REPLY__=resolve);
              window.__OLD_UPDATE_REPLY_RETURNED__=true;
              return snapshot;
            }
            if(command==="app_update_check" && args.reason==="manual"){
              await new Promise(resolve=>window.__RELEASE_MANUAL_ACK__=resolve);
              update={...update,phase:"checking",errorCode:"update_refresh_pending"};
              window.__FINISH_MANUAL_CHECK__=()=>{
                update=currentScenario.endsWith("error") ? {...update,phase:"idle",errorCode:"update_refresh_service"}
                  : {...update,phase:"available",errorCode:null,version:"0.4.2",offerId:"offer-042",promptPending:true,updateAvailable:true};
              };
            }
            if(command==="app_update_status" && update.phase==="checking")window.__UPDATE_CHECKING_READS__++;
            if(command==="app_update_presented"||command==="app_update_defer")update={...update,promptPending:false};
            return update;
          }
          if((currentScenario==="update-consent"||currentScenario.startsWith("update-stale-")||currentScenario.startsWith("update-required-"))&&command.startsWith("app_update_")){
            const heldCommand=currentScenario.startsWith("update-stale-later-check") ? "app_update_check" : "app_update_status";
            if(currentScenario.startsWith("update-stale-") && command===heldCommand && !window.__HELD_UPDATE_REPLY__){
              window.__HELD_UPDATE_REPLY__=true;
              const snapshot={...update};
              await new Promise(resolve=>window.__RELEASE_UPDATE_REPLY__=resolve);
              window.__OLD_UPDATE_REPLY_RETURNED__=true;
              if(currentScenario==="update-stale-later-error")throw Error("delayed old status failure");
              return snapshot;
            }
            if(currentScenario==="update-stale-later-check-manual-error" && command==="app_update_check" && args.reason==="manual")throw Error("manual check failed");
            if(command==="app_update_status" && update.phase==="checking")window.__UPDATE_CHECKING_READS__++;
            if(command==="app_update_presented"||command==="app_update_defer")update={...update,promptPending:false};
            if(command==="app_update_confirm"){if(args.offerId!==update.offerId)throw Error("stale offer");update={...update,phase:"installing",promptPending:false};}
            if(command==="app_update_check"&&args.reason==="manual")update={...update,promptPending:true};
            return update;
          }
          if (command === "app_bootstrap") {
            if (currentScenario === "support-loading") await new Promise(() => {});
            if (currentScenario === "support-preparing") {
              throw { code: "runtime_startup_pending", message: "Подготовка подключения" };
            }
            if (currentScenario.startsWith("runtime-pending") &&
                window.__TAURI_CALLS__.filter((call) => call.command === "app_bootstrap").length === 1) {
              throw { code: "runtime_startup_pending", message: "Подготовка подключения; повторим автоматически" };
            }
            if (currentScenario === "signed_out") {
              throw {
                code: "signed_out",
                message: "Нужно снова войти в приложение",
              };
            }
            if (currentScenario === "server-unavailable") {
              throw {
                code: "server_unavailable",
                message: "Панель временно недоступна",
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
          if (command === "app_notifications") {
            return { api_version: "1", request_id: "support-notifications", notifications: [], unread_count: 0, next_cursor: null };
          }
          if (command === "app_release_history") {
            if (window.__RELEASE_HISTORY_OFFLINE__) throw { code: "release_history_unavailable" };
            return { api_version: "1", entries: [{ version: "0.2.18", notes: window.__RELEASE_HISTORY_NOTES__ ?? "Текст с панели\n<script>window.changelogInjected = true</script>" }] };
          }
          if (command === "app_state") {
            return {
              phase: connection ? "connected" : "ready",
              connection,
              connectionIntentStatus: "none",
              nextRetryAtUnix: null,
              warning: null,
              metrics: null,
            };
          }
          if (command === "app_start") {
            connection = {
                lease_id: "preview-lease",
                layer: "stray",
                tic_connection_mode: "dynamic",
                route_mode: "standalone",
                egress_mode: "ipv4",
                status: "connected",
                pinned: false,
                stopped_at: null,
            };
            return {
              status: "connected",
              connection,
              nextRetryAtUnix: null,
            };
          }
          if (command === "app_logout" && currentScenario === "runtime-pending-logout-failed") {
            await new Promise((resolve) => setTimeout(resolve, 6000));
            throw { code: "temporarily_unavailable", message: "Отложенный отказ выхода" };
          }
          if (command === "app_preferences") {
            return {
              closeToTraySupported: desktop,
              closeToTray: true,
              dnsProvider: "auto",
            };
          }
          if (command === "runtime_status") {
            return {
              containerVersion: "0.3.0",
              selectedSlot: "latest",
              activeSlot: "latest",
              pendingSlot: null,
              latestVersion: "0.2.16",
              stableVersion: null,
              runtimeContractVersion: 1,
              manifestVerified: true,
              stableAvailable: false,
              switchId: null,
              phase: null,
              engineRole: "primary",
            };
          }
          if (command === "app_split_tunnel_installed_applications") return [];
          if (command === "app_split_tunnel_state") {
            return {
              available: true,
              enabled: false,
              mode: "exclude_selected",
              excludeLocalNetworks: false,
              mandatoryExcludedPackages: [],
              suggestedNameFragments: [],
              selectedPackages: [],
              addressRules: [],
              warning: null,
              capabilities: {
                platform: desktop ? "macos" : "android",
                androidApiLevel: desktop ? null : 35,
                addressSplitTunnel: true,
                applicationSplitTunnel: !desktop,
              },
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
          if (
            command === "app_update_status" ||
            command === "app_update_check"
          ) {
            return {
              supported: true,
              automatic: false,
              phase: "idle",
              version: null,
              notes: null,
              required: false,
              downloaded: 0,
              total: null,
              errorCode: null,
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
      supportSmoke: Boolean(process.env.SUPPORT_DIAGNOSTICS_SMOKE),
    },
  );

  await page.goto(scenario === "startup-failure" ? `${baseUrl}/startup-failure.html` : baseUrl, { waitUntil: "networkidle" });
  if (process.env.SUPPORT_DIAGNOSTICS_SMOKE) {
    await verifySupportDiagnostics(page, scenario, viewport.width >= 600);
    await context.close();
    return;
  }
  await page.waitForTimeout(100);
  if(scenario.startsWith("update-restart-recovery-")){
    await page.waitForFunction(()=>window.__TAURI_CALLS__.some(c=>c.command==="app_update_status"),{},{timeout:3000});
    const restart=page.getByRole("button",{name:"Перезапустить",exact:true});
    if(scenario.endsWith("not-installed")){
      if(await restart.count() || await page.getByRole("dialog").count() || await page.locator(".update-banner").count())throw Error("Recovery offered an uninstalled update before admission");
    }else{
      await restart.waitFor({state:"visible",timeout:3000});
      await page.getByRole("button",{name:"Повторить",exact:true}).click();
      await page.waitForFunction(()=>window.__TAURI_CALLS__.filter(c=>c.command==="app_bootstrap").length>=2);
      await restart.waitFor({state:"visible"});
      await page.reload({waitUntil:"networkidle"});
      await restart.waitFor({state:"visible",timeout:3000});
      await restart.click();
      if(await page.evaluate(()=>window.__TAURI_CALLS__.filter(c=>c.command==="app_update_restart").length)!==1)throw Error("Manual Restart was not dispatched once");
    }
    if(await page.evaluate(()=>window.__TAURI_CALLS__.some(c=>["app_update_confirm","app_update_install","app_update_check"].includes(c.command))))throw Error("Recovery read started a check or installation");
    console.log(`PASS ${name}: pending admission, read-only status, correct Restart/installation visibility`);
    await page.screenshot({path:`${outputDir}/nelomai-${name}.png`,fullPage:true});
    await context.close();return;
  }
  if(scenario.startsWith("update-required-")){
    const dialog=page.getByRole("dialog",{name:"Установить новую версию"});
    const primary=page.locator(".message-panel").getByRole("button",{name:"Обновить",exact:true});
    await page.getByRole("heading",{name:"Нужно обновить Nelomai",exact:true}).waitFor();
    await dialog.waitFor({state:"visible"});
    await dialog.getByRole("button",{name:"Нет, позже",exact:true}).click();
    await dialog.waitFor({state:"hidden"});
    // Reopening is presentation, never consent. Repeated Later must still work.
    for(let attempt=0;attempt<2;attempt++){
      await primary.click({timeout:3000});
      await dialog.waitFor({state:"visible",timeout:3000});
      const premature=await page.evaluate(()=>window.__TAURI_CALLS__.some(c=>["app_update_confirm","app_update_install"].includes(c.command)));
      if(premature)throw Error(`${name}: primary action installed without Yes`);
      if(attempt===0){
        await dialog.getByRole("button",{name:"Нет, позже",exact:true}).click();
        await dialog.waitFor({state:"hidden"});
      }
    }
    await dialog.getByRole("button",{name:"Да",exact:true}).click();
    await dialog.waitFor({state:"hidden"});
    await page.getByText("Устанавливаем обновление. Дождитесь завершения.",{exact:true}).waitFor();
    if(await primary.isVisible())throw Error(`${name}: primary offers consent while installing`);
    const calls=await page.evaluate(()=>window.__TAURI_CALLS__);
    const confirms=calls.filter(c=>c.command==="app_update_confirm");
    if(confirms.length!==1||confirms[0].args.offerId!=="fixture-offer"||calls.some(c=>c.command==="app_update_install"))throw Error(`${name}: incorrect pinned consent dispatch`);
    console.log(`${name}: PASS`);
    await context.close();return;
  }
  if(scenario.startsWith("update-manual-result-")){
    await page.waitForFunction(()=>!!window.__RELEASE_UPDATE_REPLY__);
    await page.getByRole("button",{name:"Проверить обновления",exact:true}).click();
    await page.waitForFunction(()=>!!window.__RELEASE_MANUAL_ACK__);
    if(scenario.endsWith("logout")){
      await page.getByRole("button",{name:"Выйти",exact:true}).click();
      await page.getByRole("heading",{name:"Вход в Nelomai"}).waitFor();
      const reads=await page.evaluate(()=>window.__TAURI_CALLS__.filter(c=>c.command==="app_update_status").length);
      await page.evaluate(()=>{window.__RELEASE_UPDATE_REPLY__();window.__RELEASE_MANUAL_ACK__();});
      await page.waitForTimeout(1200);
      const after=await page.evaluate(()=>window.__TAURI_CALLS__.filter(c=>c.command==="app_update_status").length);
      if(after!==reads)throw Error(`${name}: old ACK restarted polling after Logout`);
      if(!await page.getByRole("heading",{name:"Вход в Nelomai"}).isVisible())throw Error(`${name}: old ACK replaced Logout`);
      console.log(`${name}: PASS`);
      await context.close();return;
    }
    await page.evaluate(()=>window.__RELEASE_UPDATE_REPLY__());
    await page.waitForFunction(()=>window.__OLD_UPDATE_REPLY_RETURNED__);
    // Allow Svelte to render the old snapshot before acknowledging Manual.
    await page.waitForTimeout(100);
    if(!await page.getByText("Проверяем…",{exact:true}).isVisible())throw Error(`${name}: pre-click poll finished Manual`);
    await page.evaluate(()=>window.__RELEASE_MANUAL_ACK__());
    await page.waitForFunction(()=>window.__UPDATE_CHECKING_READS__>0);
    await page.evaluate(()=>window.__FINISH_MANUAL_CHECK__());
    const expected=scenario.endsWith("error") ? "Не удалось проверить обновление. Повторите позже." : "Найдена версия 0.4.2";
    await page.getByText(expected,{exact:true}).waitFor();
    if(await page.getByText("У вас актуальная версия.",{exact:true}).isVisible())throw Error(`${name}: false up-to-date result`);
    const dialog=page.getByRole("dialog",{name:"Установить новую версию"});
    if(scenario.endsWith("error")){
      if(await dialog.isVisible())throw Error(`${name}: failed check opened prompt`);
    }else{
      await dialog.waitFor({state:"visible"});
      await dialog.getByRole("button",{name:"Нет, позже",exact:true}).click();
      await dialog.waitFor({state:"hidden"});
    }
    console.log(`${name}: PASS`);
    await context.close();return;
  }
  if(scenario.startsWith("update-stale-")){
    const dialog=page.getByRole("dialog",{name:"Установить новую версию"});
    await dialog.waitFor({state:"visible"});
    await page.waitForFunction(()=>!!window.__RELEASE_UPDATE_REPLY__);
    const confirm=scenario==="update-stale-confirm-status";
    await dialog.getByRole("button",{name:confirm?"Да":"Нет, позже",exact:true}).click();
    await dialog.waitFor({state:"hidden"});
    if(confirm)await page.getByText("Устанавливаем обновление. Дождитесь завершения.",{exact:true}).waitFor();
    if(scenario.includes("-manual")){
      await page.getByRole("button",{name:"Проверить обновления",exact:true}).click();
      await page.waitForFunction(()=>window.__TAURI_CALLS__.some(c=>c.command==="app_update_check"&&c.args.reason==="manual"),{},{timeout:3000});
      if(scenario.endsWith("-error")){
        await page.getByText("Не удалось проверить обновление. Повторите позже.",{exact:true}).waitFor();
        if(await dialog.isVisible())throw Error("failed Manual reopened a prompt");
      }else{
        await dialog.waitFor({state:"visible"});
        await dialog.getByRole("button",{name:"Нет, позже",exact:true}).click();
        await dialog.waitFor({state:"hidden"});
      }
    }
    await page.evaluate(()=>window.__RELEASE_UPDATE_REPLY__());
    await page.waitForFunction(()=>window.__OLD_UPDATE_REPLY_RETURNED__);
    await page.waitForTimeout(100);
    if(await dialog.isVisible())throw Error(`${name}: stale reply reopened a completed decision`);
    if(confirm){
      if(!await page.getByText("Устанавливаем обновление. Дождитесь завершения.",{exact:true}).isVisible())throw Error(`${name}: stale reply replaced installation status`);
    } else if(!scenario.includes("-manual")) {
      if(!await page.getByRole("button",{name:"Обновить",exact:true}).isVisible())throw Error(`${name}: stale error erased the newer status`);
      await page.getByRole("button",{name:"Проверить обновления",exact:true}).click();
      await dialog.waitFor({state:"visible"});
      await dialog.getByRole("button",{name:"Нет, позже",exact:true}).click();
      await dialog.waitFor({state:"hidden"});
    }
    console.log(`${name}: PASS`);
    await context.close();return;
  }
  if(scenario==="update-consent"){
    if (viewport.width < 600) {
      await page.getByText("Проверять при открытии приложения. Установка — с вашего согласия.", {exact:true}).waitFor();
      if (await page.getByText("Проверять каждые 30 минут. Установка — с вашего согласия.", {exact:true}).count()) throw Error("Android UI advertises a desktop timer");
    }
    const dialog=page.getByRole("dialog",{name:"Установить новую версию"});await dialog.waitFor({state:"visible"});
    await page.screenshot({path:`${outputDir}/nelomai-${name}.png`,fullPage:true});
    await page.evaluate(()=>window.__SET_UPDATE_PHASE__("checking"));
    await page.waitForFunction(()=>window.__UPDATE_CHECKING_READS__>0);
    await page.waitForTimeout(50);
    if(!await dialog.isVisible())throw Error("unanswered prompt disappeared during same-offer checking");
    if(!await dialog.getByRole("button",{name:"Да",exact:true}).isDisabled())throw Error("confirmation allowed during checking");
    if((await page.evaluate(()=>window.__TAURI_CALLS__)).some(c=>c.command==="app_update_confirm"))throw Error("checking submitted consent");
    await page.evaluate(()=>window.__SET_UPDATE_PHASE__("ready_to_install"));
    await page.waitForFunction(()=>{const d=document.querySelector('dialog[open]');return d&&Array.from(d.querySelectorAll('button')).some(b=>b.textContent==='Да'&&!b.disabled)});
    await dialog.getByRole("button",{name:"Нет, позже",exact:true}).click();await dialog.waitFor({state:"hidden"});
    await page.evaluate(()=>document.dispatchEvent(new Event("visibilitychange")));await page.waitForTimeout(1100);
    if(await dialog.isVisible())throw Error("deferred offer repeated on visibility/status polling");
    await page.getByRole("button",{name:"Проверить обновления",exact:true}).click();await dialog.waitFor({state:"visible"});
    await dialog.getByRole("button",{name:"Да",exact:true}).click();await dialog.waitFor({state:"hidden"});
    await page.getByText("Устанавливаем обновление. Дождитесь завершения.",{exact:true}).waitFor();
    const calls=await page.evaluate(()=>window.__TAURI_CALLS__);
    if(calls.filter(c=>c.command==="app_update_confirm").length!==1||calls.some(c=>c.command==="app_update_install"))throw Error("install path bypasses pinned confirmation");
    if(!calls.some(c=>c.command==="app_update_check"&&c.args.reason==="startup"))throw Error("missing authenticated startup retry");
    if(calls.filter(c=>c.command==="app_update_check"&&c.args.reason==="manual").length!==1)throw Error("visibility made a network check");
    const size=await page.evaluate(()=>({scroll:document.documentElement.scrollWidth,width:innerWidth}));if(size.scroll>size.width)throw Error("update dialog overflow");
    await context.close();return;
  }
  if (scenario.startsWith("runtime-pending")) {
    await page.getByRole("heading", { name: "Завершаем подготовку приложения" }).waitFor();
    if (scenario.includes("logout")) {
      await page.getByRole("button", { name: "Выйти", exact: true }).click();
    } else if (scenario.endsWith("manual")) {
      await page.getByRole("button", { name: "Повторить", exact: true }).click();
    }
    if (scenario === "runtime-pending-logout") {
      await page.getByRole("heading", { name: "Вход в Nelomai" }).waitFor();
      if (await page.getByText("Подготовка приложения", { exact: true }).isVisible()) {
        throw new Error("successful logout retained pending startup status");
      }
      await page.waitForTimeout(5500);
    } else {
      await page.getByRole("button", { name: /Старт/ }).waitFor({ timeout: 16000 });
      if (scenario.endsWith("manual")) await page.waitForTimeout(5500);
    }
    const calls = await page.evaluate(() => window.__TAURI_CALLS__.filter((call) => call.command === "app_bootstrap").length);
    if (calls !== (scenario === "runtime-pending-logout" ? 1 : 2)) {
      throw new Error(`${scenario} lost or duplicated bootstrap: ${calls}`);
    }
    await page.screenshot({ path: `${outputDir}/nelomai-${name}.png`, fullPage: true });
    await context.close();
    return;
  }
  if (scenario !== "signed_out" && scenario !== "server-unavailable") {
    await page.waitForFunction(
      () =>
        (window.__TAURI_CALLS__ ?? []).some(
          (call) => call.command === "app_update_status",
        ),
      undefined,
      { timeout: 5_000 },
    );
    await page.evaluate(() => {
      document.dispatchEvent(new Event("visibilitychange"));
    });
    await page.waitForFunction(
      () =>
        (window.__TAURI_CALLS__ ?? []).some(
          (call) => call.command === "app_update_check",
        ),
      undefined,
      { timeout: 5_000 },
    );
  }

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
  } else if (scenario === "server-unavailable") {
    await page
      .getByRole("heading", { name: "Сейчас сервис недоступен" })
      .waitFor();
    if (await page.getByRole("button", { name: "Что нового" }).isVisible()) {
      throw new Error("changelog is visible without an authenticated bootstrap");
    }
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
    const installedVersion = page.locator(".settings-panel > :last-child");
    if ((await installedVersion.textContent()).trim() !== "Версия приложения 0.3.0") {
      throw new Error(`${name} must show the installed container version at the bottom of settings`);
    }
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
    if (name === "connection-desktop") {
      await verifyChangelogLifecycle(page);
    }
  }

  await page.screenshot({
    path: `${outputDir}/nelomai-${name}.png`,
    fullPage: true,
  });
  await context.close();
}

async function verifySupportDiagnostics(page, scenario, desktop) {
  const buttonName = { name: "Диагностика", exact: true };
  if (!desktop) {
    await page.getByRole("heading", { name: "Вход в Nelomai" }).waitFor();
    if (await page.getByRole("button", buttonName).count()) throw Error("Desktop diagnostics appeared on Android");
    return;
  }

  const dialog = page.getByRole("dialog", { name: "Диагностика", exact: true });
  async function open(button) {
    await button.focus();
    await page.keyboard.press("Enter");
    await dialog.waitFor();
  }
  async function close() {
    await page.keyboard.press("Escape");
    await dialog.waitFor({ state: "hidden" });
  }

  if (scenario === "update-consent") {
    const update = page.getByRole("dialog", { name: "Установить новую версию" });
    await open(update.getByRole("button", buttonName));
    await close();
    await update.waitFor();
    return;
  }

  await open(page.getByRole("button", buttonName));
  const collect = dialog.getByRole("button", { name: "Собрать отчёт", exact: true });
  await collect.click();
  await dialog.getByRole("status").getByText("Отчёт готов.").waitFor();
  if (await lastCall(page, "app_send_support_diagnostics")) throw Error("Diagnostics sent without consent");
  const send = dialog.getByRole("button", { name: "Отправить отчёт" });
  const save = dialog.getByRole("button", { name: "Сохранить файл" });
  await send.click();
  await dialog.getByText("Нет связи с панелью.", { exact: false }).waitFor();
  await save.click();
  await dialog.getByText("Отчёт сохранён.").waitFor();
  await send.click();
  await dialog.getByText("Отчёт отправлен. Номер для поддержки: c4271792.").waitFor();
  const sendCall = await lastCall(page, "app_send_support_diagnostics");
  const saveCall = await lastCall(page, "app_save_support_diagnostics");
  if (sendCall.args.reportId !== saveCall.args.reportId || sendCall.args.supportCode !== null) {
    throw Error("Save and explicit retry must use the same report ID");
  }
  await close();

  if (scenario === "connection") {
    await page.getByRole("button", { name: /Старт/ }).click();
    await page.getByRole("button", { name: /Стоп/ }).waitFor();
    await open(page.getByRole("button", buttonName));
    await close();
    for (const label of ["Что нового", "Уведомления", "Split-tunnel"]) {
      await page.getByRole("button", { name: label, exact: true }).click();
      const overlay = page.getByRole("dialog", { name: label, exact: true });
      await open(overlay.getByRole("button", buttonName));
      await page.keyboard.press("Tab");
      if (!(await dialog.evaluate((element) => element.contains(document.activeElement)))) {
        throw Error(`Focus escaped diagnostics from ${label}`);
      }
      await close();
      await overlay.getByRole("button", { name: "Закрыть", exact: true }).click();
      await overlay.waitFor({ state: "hidden" });
    }
  }
}

async function verifyChangelogLifecycle(page) {
  if (await lastCall(page, "app_release_history")) throw new Error("history must not load during startup or VPN connection");
  const opener = page.getByRole("button", { name: "Что нового" });
  await opener.click();

  const dialog = page.getByRole("dialog", { name: "Что нового" });
  await dialog.waitFor();
  await dialog.getByText("Версия 0.2.18", { exact: true }).waitFor();
  await dialog.getByText("Текст с панели", { exact: false }).waitFor();
  if (await page.evaluate(() => Boolean(window.changelogInjected))) throw new Error("release notes executed HTML");
  const close = page.getByRole("button", { name: "Закрыть" });
  if (!(await close.evaluate((element) => element === document.activeElement))) {
    throw new Error("changelog did not move focus into the modal dialog");
  }

  await page.keyboard.press("Tab");
  if (!(await dialog.evaluate((element) => element.contains(document.activeElement)))) {
    throw new Error("changelog allowed focus to leave the modal dialog");
  }

  await page.screenshot({
    path: "/tmp/nelomai-changelog-desktop.png",
    fullPage: true,
  });

  await page.keyboard.press("Escape");
  await dialog.waitFor({ state: "hidden" });
  if (!(await opener.evaluate((element) => element === document.activeElement))) {
    throw new Error("changelog did not restore focus to its opener");
  }

  await page.evaluate(() => { window.__RELEASE_HISTORY_NOTES__ = "Исправленный текст без новой сборки"; });
  await opener.click();
  await dialog.getByText("Исправленный текст без новой сборки", { exact: true }).waitFor();
  await page.keyboard.press("Escape");
  await dialog.waitFor({ state: "hidden" });
  await page.evaluate(() => { window.__RELEASE_HISTORY_OFFLINE__ = true; });
  await opener.click();
  await dialog.getByText("Не удалось обновить историю. Показана сохранённая копия.", { exact: true }).waitFor();
  await dialog.getByText("Исправленный текст без новой сборки", { exact: true }).waitFor();
  await page.keyboard.press("Escape");
  await dialog.waitFor({ state: "hidden" });
  await page.getByRole("button", { name: /Стоп/ }).waitFor();

  await page.getByRole("button", { name: "Выйти" }).click();
  await page.getByRole("heading", { name: "Вход в Nelomai" }).waitFor();
  await page.evaluate(() => window.history.forward());
  await page.waitForTimeout(100);
  if (await dialog.isVisible()) {
    throw new Error("changelog reopened from history after logout");
  }
}

async function lastCall(page, command) {
  return page.evaluate((expected) => {
    const calls = window.__TAURI_CALLS__ ?? [];
    return [...calls].reverse().find((call) => call.command === expected) ?? null;
  }, command);
}

async function waitForServer(url, child, output) {
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) {
      throw new Error(
        `Vite exited before readiness with code ${child.exitCode}:\n${output()}`,
      );
    }
    try {
      const response = await fetch(url, {
        signal: AbortSignal.timeout(1_000),
      });
      if (response.ok) return;
    } catch {
      // Vite has not started listening yet.
    }
    await delay(100);
  }
  throw new Error(`Vite did not become ready within 15 seconds:\n${output()}`);
}

async function stopChild(child) {
  if (!child || child.exitCode !== null) return;
  child.kill("SIGTERM");
  if (await waitForExit(child, 3_000)) return;
  child.kill("SIGKILL");
  if (!(await waitForExit(child, 3_000))) {
    throw new Error("Vite did not stop after SIGKILL");
  }
}

async function waitForExit(child, timeout) {
  if (child.exitCode !== null) return true;
  return Promise.race([
    once(child, "exit").then(() => true),
    delay(timeout).then(() => false),
  ]);
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}
