export interface SupportDiagnosticsBridge {
  open(): void;
}

export function supportDiagnosticsBridge(scope: unknown): SupportDiagnosticsBridge | null {
  if (!scope || typeof scope !== "object") return null;
  const bridge = (scope as { NelomaiSupportDiagnostics?: SupportDiagnosticsBridge }).NelomaiSupportDiagnostics;
  return bridge && typeof bridge.open === "function" ? bridge : null;
}
