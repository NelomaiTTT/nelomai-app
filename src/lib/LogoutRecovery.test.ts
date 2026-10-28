import { render } from "svelte/server";
import { describe, expect, it } from "vitest";
import LogoutRecovery from "./LogoutRecovery.svelte";

describe("logout recovery", () => {
  it("offers a non-submit retry when the previous session needs recovery", () => {
    const { body } = render(LogoutRecovery, { props: { required: true, busy: false, onretry: () => {} } });
    expect(body).toContain('type="button"');
    expect(body).toContain("Завершить выход");
    expect(body).not.toContain(" disabled");
  });

  it("hides the retry for normal sign-in and disables it during an operation", () => {
    expect(render(LogoutRecovery, { props: { required: false, busy: false, onretry: () => {} } }).body).not.toContain("Завершить выход");
    expect(render(LogoutRecovery, { props: { required: true, busy: true, onretry: () => {} } }).body).toContain("disabled");
  });
});
