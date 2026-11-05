export interface KillSwitchStatus {
  vpnActive: boolean | null;
  supported: boolean;
  enabled: boolean | null;
  disclosed: boolean;
  state: "off" | "armed" | "blocked" | "unknown";
  error: string | null;
  cause: string | null;
  externalLockdown: boolean | null;
}
export const killSwitchDisclosure = "Защита включается после успешного VPN-подключения. При сбое выбранный для VPN трафик будет заблокирован до восстановления или вашего Stop. Исключения split tunneling сохраняют прямой доступ. Защита не гарантируется после принудительной остановки, гибели VPN-процесса или перезагрузки устройства. Это не системная блокировка Android. Включить?";
export function unknownProtection(): KillSwitchStatus {
  return { vpnActive: null, supported: true, enabled: null, disclosed: false, state: "unknown", error: "protection_status_unavailable", cause: null, externalLockdown: null };
}
interface ProtectionApi {
  killSwitchStatus(): Promise<KillSwitchStatus | null>;
  setKillSwitchPreference(enabled: boolean, confirmed: boolean): Promise<KillSwitchStatus>;
  stopProtection(): Promise<void>;
  retryProtectedConnection(): Promise<void>;
}
/** One polling stream, but Stop may supersede a hung settings request. */
export class KillSwitchControls {
  status: KillSwitchStatus | null = null;
  busy = false;
  private revision = 0;
  private polling = false;
  private readRevision = 0;
  constructor(private api: ProtectionApi, private changed: () => void) {}
  async refresh(force = false): Promise<void> {
    if (!force && (this.polling || this.busy)) return;
    const revision = this.revision;
    const readRevision = ++this.readRevision;
    this.polling = true;
    try {
      const status = await this.api.killSwitchStatus();
      if (revision === this.revision && readRevision === this.readRevision) this.status = status;
    } catch {
      if (revision === this.revision && readRevision === this.readRevision) this.status = unknownProtection();
    } finally {
      if (readRevision === this.readRevision) this.polling = false;
      this.changed();
    }
  }
  async setEnabled(enabled: boolean, confirm: (message: string) => boolean): Promise<void> {
    if (this.busy || !this.status?.supported || this.status.enabled === null) return;
    if (enabled && !this.status.disclosed && !confirm(killSwitchDisclosure)) return;
    const localStop = !enabled && ["blocked", "unknown"].includes(this.status.state);
    if (localStop &&
        !confirm("VPN и блокировка будут выключены. Трафик сможет идти напрямую, если это разрешено настройками Android. Продолжить?")) return;
    await this.mutate(async () => {
      if (localStop) await this.api.stopProtection();
      return this.api.setKillSwitchPreference(enabled, true);
    });
  }
  async stop(): Promise<void> {
    await this.mutate(async () => { await this.api.stopProtection(); return undefined; });
  }
  async retry(): Promise<void> {
    if (this.busy) return;
    await this.mutate(async () => { await this.api.retryProtectedConnection(); return undefined; });
  }
  private async mutate(action: () => Promise<KillSwitchStatus | undefined>): Promise<void> {
    const revision = ++this.revision;
    this.busy = true; this.changed();
    try {
      const result = await action();
      if (revision === this.revision && result) this.status = result;
    } finally {
      if (revision === this.revision) {
        this.busy = false;
        await this.refresh(true);
      }
    }
  }
}
export function confirmAndroidTransition(status: KillSwitchStatus | null, kind: "update" | "runtime", vpnActive: boolean, confirm: (message: string) => boolean): boolean {
  if (status === null) return true;
  // Consent also covers a Start racing with this snapshot. Do not claim a VPN
  // is active when the native owner has confirmed that it is stopped.
  if (kind === "update" && status.state === "off" && status.vpnActive === false && !vpnActive) {
    return confirm("Установить обновление? Перед установкой VPN будет остановлен, если подключение успеет начаться. Во время установки защита от утечки не действует. Продолжить?");
  }
  const unknown = status.state === "unknown";
  const action = kind === "runtime" ? "переключения версии" : "установки обновления";
  return confirm(`${unknown ? "Текущий статус защиты неизвестен. " : ""}Для ${action} VPN и защита от утечки будут выключены. Трафик сможет идти напрямую. ${kind === "runtime" ? "В другой версии защита может быть недоступна. " : ""}Системная блокировка Android, если включена, сохранится. Продолжить?`);
}
