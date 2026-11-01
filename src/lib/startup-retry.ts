/** Retry unfinished admission and bounded, temporary bootstrap failures only. */
export class StartupRetry {
  private timer: ReturnType<typeof setTimeout> | null = null;
  private disposed = false;
  private temporaryRetries = 0;
  private generation = 0;

  schedule(code: string | null, retry: () => void) {
    if (this.timer !== null) clearTimeout(this.timer);
    this.timer = null;
    const temporary = code === "temporarily_unavailable";
    if (this.disposed || (!temporary && code !== "runtime_startup_pending" && code !== "auth_refresh_pending") ||
      (temporary && this.temporaryRetries >= 2)) return;
    this.timer = setTimeout(() => {
      this.timer = null;
      if (temporary) this.temporaryRetries++;
      retry();
    }, temporary ? 2000 : 5000);
  }

  checkpoint(): () => boolean {
    const generation = this.generation;
    return () => !this.disposed && this.generation === generation;
  }

  cancel(resetBudget = true) {
    if (this.timer !== null) clearTimeout(this.timer);
    this.timer = null;
    this.generation++;
    if (resetBudget) this.temporaryRetries = 0;
  }

  dispose() {
    this.disposed = true;
    this.cancel();
  }
}
