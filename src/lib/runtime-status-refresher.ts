export class RuntimeStatusRefresher<T> {
  private generation = 0;

  run(load: () => Promise<T>, apply: (status: T) => void): Promise<T | null> {
    const generation = ++this.generation;
    return load()
      .then((status) => {
        if (generation === this.generation) apply(status);
        return status;
      })
      .catch(() => null);
  }
}
