export class UpdateOfferRefresher<T> {
  private inFlight: Promise<T | null> | null = null;

  run(load: () => Promise<T>, apply: (status: T) => void, manual = false): Promise<T | null> {
    // Manual carries a new user intent (including after Later). Deliver it to
    // the owner, which already coalesces network work without losing that intent.
    if (!manual && this.inFlight) return this.inFlight;
    const request = load()
      .then((status) => {
        apply(status);
        return status;
      })
      .catch(() => null);
    if (manual) return request;
    this.inFlight = request.finally(() => {
      this.inFlight = null;
    });
    return this.inFlight;
  }
}
