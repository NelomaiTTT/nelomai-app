/** Retry only unfinished runtime admission, not login or arbitrary API errors. */
export class StartupRetry {
  private timer: ReturnType<typeof setTimeout> | null = null;
  private disposed = false;
  schedule(code: string | null, retry: () => void) {
    this.cancel();
    if (this.disposed || (code !== "runtime_startup_pending" && code !== "auth_refresh_pending")) return;
    this.timer = setTimeout(() => {
      this.timer = null;
      retry();
    }, 5000);
  }
  cancel() {
    if (this.timer !== null) clearTimeout(this.timer);
    this.timer = null;
  }
  dispose() {
    this.disposed = true;
    this.cancel();
  }
}
