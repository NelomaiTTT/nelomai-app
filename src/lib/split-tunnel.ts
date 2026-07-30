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
  warning: string | null;
  capabilities: SplitTunnelCapabilities;
}

export interface InstalledApplication {
  packageId: string;
  displayName: string;
  system: boolean;
}

export interface SplitTunnelApplicationRow extends InstalledApplication {
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

export function buildApplicationRows(
  state: SplitTunnelState,
  applications: InstalledApplication[],
  search: string,
  showSystem: boolean,
): SplitTunnelApplicationRow[] {
  const mandatory = new Set(state.mandatoryExcludedPackages);
  const selected = new Set(state.selectedPackages);
  const fragments = state.suggestedNameFragments
    .map(normalizeSearch)
    .filter(Boolean);
  const query = normalizeSearch(search);

  return applications
    .map((application): SplitTunnelApplicationRow => {
      const isMandatory = mandatory.has(application.packageId);
      const isSelected = isMandatory || selected.has(application.packageId);
      const normalizedName = normalizeSearch(application.displayName);
      return {
        ...application,
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
  const installed = new Set(applications.map((application) => application.packageId));
  const mandatory = new Set(state.mandatoryExcludedPackages);
  return !state.selectedPackages.some(
    (packageId) => installed.has(packageId) && !mandatory.has(packageId),
  );
}

export function settingsUpdate(
  mode: SplitTunnelMode,
  excludeLocalNetworks: boolean,
  selectedPackageIds: Iterable<string>,
  applications: InstalledApplication[],
  mandatoryPackageIds: Iterable<string>,
): SplitTunnelSettingsUpdate {
  const selected = new Set(selectedPackageIds);
  const mandatory = new Set(mandatoryPackageIds);
  return {
    mode,
    excludeLocalNetworks,
    selectedPackages: applications
      .filter(
        (application) =>
          selected.has(application.packageId) &&
          !mandatory.has(application.packageId),
      )
      .map((application) => ({
        packageId: application.packageId,
        displayName: application.displayName,
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
