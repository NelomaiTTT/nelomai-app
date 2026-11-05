/** Retry unfinished admission and bounded, temporary bootstrap failures only. */
export class StartupRetry {
  private timer: ReturnType<typeof setTimeout> | null = null;
  private disposed = false;
  private temporaryRetries = 0;
  private temporaryFailure = false;
  private generation = 0;

  schedule(code: string | null, retry: () => void) {
    if (this.timer !== null) clearTimeout(this.timer);
    this.timer = null;
    const temporary = code === "temporarily_unavailable";
    this.temporaryFailure = temporary;
    if (this.disposed || (!temporary && code !== "runtime_startup_pending" && code !== "auth_refresh_pending") ||
      (temporary && this.temporaryRetries >= 2)) return;
    this.timer = setTimeout(() => {
      this.timer = null;
      if (temporary) this.temporaryRetries++;
      retry();
    }, temporary ? 2000 : 5000);
  }

  // A meaningful external wake renews the budget even if the last request is
  // still running. It must not invalidate that request or start a parallel one.
  wake(): boolean {
    if (this.disposed || !this.temporaryFailure) return false;
    if (this.timer !== null) clearTimeout(this.timer);
    this.timer = null;
    this.temporaryRetries = 0;
    return true;
  }

  checkpoint(): () => boolean {
    const generation = this.generation;
    return () => !this.disposed && this.generation === generation;
  }

  cancel(resetBudget = true) {
    if (this.timer !== null) clearTimeout(this.timer);
    this.timer = null;
    this.generation++;
    if (resetBudget) {
      this.temporaryRetries = 0;
      this.temporaryFailure = false;
    }
  }

  dispose() {
    this.disposed = true;
    this.cancel();
  }
}
