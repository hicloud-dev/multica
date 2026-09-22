type RuntimeEnv = Record<string, string | undefined>;

/**
 * Where `/` should send a visitor on a self-hosted instance.
 *
 * By default `/` serves the Multica landing page to anyone without a session.
 * That is the right answer for multica.ai and the wrong one for a private
 * deployment, whose users open the front door expecting a sign-in screen and
 * instead get a page selling them software they already run. Operators opt out
 * by setting MULTICA_ROOT_REDIRECT to a path — `/login` in almost every case.
 *
 * Read at request time in the proxy, so changing it needs a container restart
 * and not a rebuild.
 *
 * Only same-origin paths are honoured. The value comes from the operator
 * rather than from a request, so this guards against a typo turning the front
 * door into an off-site bounce, not against an attacker — but that failure
 * sends away every visitor who ever reaches the root, which is worth a check.
 * Anything rejected falls back to the landing page rather than to a redirect
 * loop or a blank response.
 */
export function resolveRootRedirect(env: RuntimeEnv): string | undefined {
  const raw = env.MULTICA_ROOT_REDIRECT?.trim();
  if (!raw) return undefined;
  // Browsers read "//host" and "/\host" as protocol-relative URLs despite the
  // single leading slash, so a prefix check alone is not enough.
  if (!raw.startsWith("/") || raw.startsWith("//") || raw.startsWith("/\\")) {
    return undefined;
  }
  return raw;
}
