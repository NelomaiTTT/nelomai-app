export class RuntimeStatusRefresher<T> {
  private generation = 0;

  commit(status: T, apply: (status: T) => void): void {
    this.generation += 1;
    apply(status);
  }

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
