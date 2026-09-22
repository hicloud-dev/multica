import { LoginPage } from "@multica/views/auth";
import { DragStrip } from "@multica/views/platform";
import { useConfigStore } from "@multica/core/config";
import { MulticaIcon } from "@multica/ui/components/common/multica-icon";

function requireRuntimeAppUrl(): string {
  const runtimeConfig = window.desktopAPI.runtimeConfig;
  if (!runtimeConfig.ok) {
    throw new Error(
      "Invariant violated: DesktopLoginPage rendered before App accepted runtime config",
    );
  }
  return runtimeConfig.config.appUrl;
}

export function DesktopLoginPage() {
  const webUrl = requireRuntimeAppUrl();
  const oidcEnabled = useConfigStore((state) => state.oidcEnabled);
  const oidcProviderName = useConfigStore((state) => state.oidcProviderName);

  // Both browser-based flows leave through the same door: the web login page
  // establishes the session where the provider can redirect to it, then hands
  // the token back over the multica:// deep link.
  const openWebLogin = () => {
    window.desktopAPI.openExternal(`${webUrl}/login?platform=desktop`);
  };

  return (
    <div className="flex h-screen flex-col">
      <DragStrip />
      <LoginPage
        logo={<MulticaIcon bordered size="lg" />}
        onSuccess={() => {
          // Auth store update triggers AppContent re-render → shows DesktopShell.
          // Initial workspace navigation happens in routes.tsx via IndexRedirect.
        }}
        onGoogleLogin={openWebLogin}
        // Unlike Google's button, this one appears only once the server has
        // said it has a provider: an SSO button on a deployment without one
        // would open a browser just to show an error.
        sso={oidcEnabled ? { providerName: oidcProviderName } : undefined}
        onSsoLogin={openWebLogin}
      />
    </div>
  );
}
