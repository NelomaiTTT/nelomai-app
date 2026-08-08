export type SplitTunnelMode = "exclude_selected" | "include_selected";

export interface SplitTunnelCapabilities {
  platform: "android" | "windows" | "macos" | "linux" | "unknown";
  androidApiLevel: number | null;
  addressSplitTunnel: boolean;
  applicationSplitTunnel: boolean;
}

export interface SplitTunnelState {
  available: boolean;
  enabled: boolean;
  mode: SplitTunnelMode;
  excludeLocalNetworks: boolean;
  mandatoryExcludedPackages: string[];
  suggestedNameFragments: string[];
  selectedPackages: string[];
  addressRules?: SplitTunnelAddressRule[];
  warning: string | null;
  capabilities: SplitTunnelCapabilities;
}

export interface SplitTunnelAddressRule {
  id: number;
  scope: "this_device" | "all_devices";
  kind: "ipv4" | "domain";
  value: string;
}

export interface InstalledApplication {
  packageId: string;
  displayName: string;
  system: boolean;
}

export interface SplitTunnelApplicationRow extends InstalledApplication {
  available: boolean;
  mandatory: boolean;
  suggested: boolean;
  selected: boolean;
  locked: boolean;
}

export interface SplitTunnelSelectedPackage {
  packageId: string;
  displayName: string;
}

export interface SplitTunnelSettingsUpdate {
  mode: SplitTunnelMode;
  excludeLocalNetworks: boolean;
  selectedPackages: SplitTunnelSelectedPackage[];
}

export interface SplitTunnelSaveResult {
  saved: boolean;
  requiresReconnectConfirmation: boolean;
  state: SplitTunnelState;
}

export function splitTunnelWarningMessage(code: string): string {
  switch (code) {
    case "split_tunnel_apply_failed":
      return "Новые настройки не применились. Продолжаем использовать предыдущие.";
    case "split_tunnel_stop_failed":
      return "Не удалось остановить VPN для применения настроек. Закройте split-tunnel и повторите отключение.";
    case "split_tunnel_rollback_failed":
      return "Подключение не удалось восстановить. Закройте split-tunnel, нажмите «Повторить», затем подключитесь снова.";
    case "split_tunnel_state_save_failed":
      return "VPN продолжает работать, но новые настройки могут не сохраниться после перезапуска. Попробуйте сохранить их ещё раз.";
    case "split_tunnel_network_reconnect_failed":
      return "Не удалось обновить подключение после смены сети. Повторите отключение и подключитесь снова.";
    case "split_tunnel_saved_connection_unavailable":
      return "Не удалось применить новые настройки к текущему подключению. Отключитесь и подключитесь снова.";
    case "split_tunnel_domain_resolution_failed":
      return "Не удалось обновить адрес домена. Используем последний рабочий адрес и повторим позже.";
    case "split_tunnel_domain_resolution_unavailable":
      return "Не удалось определить адрес домена. Проверьте интернет и нажмите «Принудительная синхронизация».";
    case "tunnel_runtime_stopped":
      return "VPN был остановлен системой. Нажмите «Старт», чтобы восстановить подключение.";
    case "tunnel_status_unavailable":
      return "Не удалось проверить состояние VPN. Нажмите «Стоп». Если ошибка останется — перезапустите Nelomai.";
    default:
      return "Используем сохранённые настройки. Панель временно недоступна.";
  }
}

export function buildApplicationRows(
  state: SplitTunnelState,
  applications: InstalledApplication[],
  search: string,
  showSystem: boolean,
): SplitTunnelApplicationRow[] {
  const packageIndex = installedPackageIndex(applications);
  const mandatory = canonicalPackageIds(
    state.mandatoryExcludedPackages,
    packageIndex,
  );
  const selected = canonicalPackageIds(state.selectedPackages, packageIndex);
  const fragments = state.suggestedNameFragments
    .map(normalizeSearch)
    .filter(Boolean);
  const query = normalizeSearch(search);
  const installedPackageIds = new Set(packageIndex.exact.keys());
  const unavailableSelected = state.selectedPackages
    .filter(
      (packageId) =>
        resolveInstalledPackage(packageId, packageIndex) === null &&
        !containsPackageId(state.mandatoryExcludedPackages, packageId),
    )
    .map(
      (packageId): InstalledApplication => ({
        packageId,
        displayName: packageId,
        system: false,
      }),
    );

  return [...applications, ...unavailableSelected]
    .map((application): SplitTunnelApplicationRow => {
      const isMandatory = mandatory.has(application.packageId);
      const isSelected = isMandatory
        ? state.mode === "exclude_selected"
        : selected.has(application.packageId);
      const normalizedName = normalizeSearch(application.displayName);
      return {
        ...application,
        available: installedPackageIds.has(application.packageId),
        mandatory: isMandatory,
        suggested:
          !isMandatory &&
          !isSelected &&
          fragments.some((fragment) => normalizedName.includes(fragment)),
        selected: isSelected,
        locked: isMandatory,
      };
    })
    .filter(
      (application) =>
        !application.system ||
        showSystem ||
        application.mandatory ||
        application.selected,
    )
    .filter((application) => {
      if (!query) return true;
      return (
        normalizeSearch(application.displayName).includes(query) ||
        normalizeSearch(application.packageId).includes(query)
      );
    })
    .sort((first, second) => {
      const systemOrder = Number(first.system) - Number(second.system);
      if (systemOrder !== 0) return systemOrder;
      const statusOrder = rowPriority(first) - rowPriority(second);
      if (statusOrder !== 0) return statusOrder;
      return (
        first.displayName.localeCompare(second.displayName, "ru", {
          sensitivity: "base",
        }) || first.packageId.localeCompare(second.packageId)
      );
    });
}

export function emptyIncludeSelection(
  state: SplitTunnelState,
  applications: InstalledApplication[],
): boolean {
  if (
    !state.available ||
    !state.enabled ||
    state.mode !== "include_selected" ||
    !state.capabilities.applicationSplitTunnel
  ) {
    return false;
  }
  const packageIndex = installedPackageIndex(applications);
  const mandatory = canonicalPackageIds(
    state.mandatoryExcludedPackages,
    packageIndex,
  );
  return !state.selectedPackages.some(
    (packageId) => {
      const installed = resolveInstalledPackage(packageId, packageIndex);
      return installed !== null && !mandatory.has(installed.packageId);
    },
  );
}

export function settingsUpdate(
  mode: SplitTunnelMode,
  excludeLocalNetworks: boolean,
  selectedPackageIds: Iterable<string>,
  applications: InstalledApplication[],
  mandatoryPackageIds: Iterable<string>,
): SplitTunnelSettingsUpdate {
  const packageIndex = installedPackageIndex(applications);
  const selected = new Set(
    [...selectedPackageIds].map(
      (packageId) =>
        resolveInstalledPackage(packageId, packageIndex)?.packageId ?? packageId,
    ),
  );
  const mandatory = canonicalPackageIds(mandatoryPackageIds, packageIndex);
  const applicationsById = new Map(
    applications.map((application) => [application.packageId, application]),
  );
  return {
    mode,
    excludeLocalNetworks,
    selectedPackages: [...selected]
      .filter((packageId) => !mandatory.has(packageId))
      .map((packageId) => ({
        packageId,
        displayName: applicationsById.get(packageId)?.displayName ?? packageId,
      })),
  };
}

function rowPriority(row: SplitTunnelApplicationRow): number {
  if (row.mandatory) return 0;
  if (row.selected) return 1;
  if (row.suggested) return 2;
  return 3;
}

function normalizeSearch(value: string): string {
  return value.trim().toLocaleLowerCase("ru");
}

interface InstalledPackageIndex {
  exact: Map<string, InstalledApplication>;
  folded: Map<string, InstalledApplication | null>;
}

function installedPackageIndex(
  applications: InstalledApplication[],
): InstalledPackageIndex {
  const exact = new Map(
    applications.map((application) => [application.packageId, application]),
  );
  const folded = new Map<string, InstalledApplication | null>();
  for (const application of applications) {
    const key = foldPackageId(application.packageId);
    if (folded.has(key)) folded.set(key, null);
    else folded.set(key, application);
  }
  return { exact, folded };
}

function resolveInstalledPackage(
  packageId: string,
  index: InstalledPackageIndex,
): InstalledApplication | null {
  return index.exact.get(packageId) ?? index.folded.get(foldPackageId(packageId)) ?? null;
}

function canonicalPackageIds(
  packageIds: Iterable<string>,
  index: InstalledPackageIndex,
): Set<string> {
  return new Set(
    [...packageIds].map(
      (packageId) =>
        resolveInstalledPackage(packageId, index)?.packageId ?? packageId,
    ),
  );
}

function containsPackageId(packageIds: Iterable<string>, candidate: string): boolean {
  const foldedCandidate = foldPackageId(candidate);
  return [...packageIds].some(
    (packageId) => foldPackageId(packageId) === foldedCandidate,
  );
}

function foldPackageId(packageId: string): string {
  return packageId.trim().toLowerCase();
}
