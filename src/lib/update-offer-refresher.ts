export class UpdateOfferRefresher<T> {
  private inFlight: Promise<T | null> | null = null;

  run(load: () => Promise<T>, apply: (status: T) => void): Promise<T | null> {
    if (this.inFlight) return this.inFlight;
    this.inFlight = load()
      .then((status) => {
        apply(status);
        return status;
      })
      .catch(() => null)
      .finally(() => {
        this.inFlight = null;
      });
    return this.inFlight;
  }
}
