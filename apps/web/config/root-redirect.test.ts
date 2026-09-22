// @vitest-environment node
import { describe, expect, it } from "vitest";

import { resolveRootRedirect } from "./root-redirect";

describe("resolveRootRedirect", () => {
  it("is off unless the operator asks for it", () => {
    // Absent must keep serving the landing page: every existing deployment
    // has no such variable, and none of them should change behaviour.
    expect(resolveRootRedirect({})).toBeUndefined();
    expect(resolveRootRedirect({ MULTICA_ROOT_REDIRECT: "" })).toBeUndefined();
    expect(resolveRootRedirect({ MULTICA_ROOT_REDIRECT: "   " })).toBeUndefined();
  });

  it("honours a same-origin path", () => {
    expect(resolveRootRedirect({ MULTICA_ROOT_REDIRECT: "/login" })).toBe("/login");
    expect(resolveRootRedirect({ MULTICA_ROOT_REDIRECT: "  /login  " })).toBe("/login");
    expect(resolveRootRedirect({ MULTICA_ROOT_REDIRECT: "/login?sso=1" })).toBe(
      "/login?sso=1",
    );
  });

  it("refuses to send the front door off-site", () => {
    // A typo here bounces every visitor who reaches the root, so each of these
    // falls back to the landing page instead of being honoured.
    for (const value of [
      "https://evil.test/steal",
      "//evil.test/steal",
      "/\\evil.test",
      "evil.test",
      "login",
      "javascript:alert(1)",
    ]) {
      expect(resolveRootRedirect({ MULTICA_ROOT_REDIRECT: value })).toBeUndefined();
    }
  });
});
