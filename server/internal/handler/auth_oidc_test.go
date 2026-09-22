package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/multica-ai/multica/server/internal/auth/oidc"
	"github.com/multica-ai/multica/server/internal/testutil"
)

// testIDPDiscovery stands up just enough of a provider for the start endpoint:
// the discovery document, which is all AuthCodeURL needs.
func testIDPDiscovery(t *testing.T) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 srv.URL,
			"authorization_endpoint": srv.URL + "/authorize",
			"token_endpoint":         srv.URL + "/token",
			"jwks_uri":               srv.URL + "/jwks",
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newOIDCTestHandler(t *testing.T) (*Handler, *httptest.Server) {
	t.Helper()
	idp := testIDPDiscovery(t)
	h := newTestHandler(Config{AppURL: "https://app.test", PublicURL: "https://api.test"})
	h.OIDC = oidc.New(oidc.Config{
		Issuer:       idp.URL,
		ClientID:     "multica",
		ClientSecret: "secret",
		Scopes:       oidc.DefaultScopes,
		ProviderName: "Test IdP",
	}, idp.Client())
	return h, idp
}

func findCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, c := range cookies {
		if c.Name == name && c.Value != "" {
			return c
		}
	}
	return nil
}

func TestOIDCStartRedirectsToProviderWithBoundPKCE(t *testing.T) {
	h, idp := newOIDCTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, OIDCStartPath+"?next=/inbox&platform=desktop", nil)
	res := testutil.Call(t, h.OIDCStart, req).Want(http.StatusFound)

	cookie := findCookie(res.Result().Cookies(), oidcTxCookieName)
	if cookie == nil {
		t.Fatal("start did not set the login transaction cookie")
	}
	if !cookie.HttpOnly {
		t.Error("transaction cookie must be HttpOnly")
	}
	// Strict would be withheld on the provider's top-level redirect back here,
	// which is the one request that has to carry it.
	if cookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("transaction cookie SameSite = %v, want Lax", cookie.SameSite)
	}
	if cookie.Path != oidcTxCookiePath {
		t.Errorf("transaction cookie path = %q, want %q", cookie.Path, oidcTxCookiePath)
	}

	tx, ok := openOIDCTx(cookie.Value)
	if !ok {
		t.Fatal("the cookie start just wrote does not open")
	}
	if tx.Next != "/inbox" || tx.Platform != "desktop" {
		t.Errorf("routing values were not carried: %+v", tx)
	}

	loc, err := url.Parse(res.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	if loc.Host != mustHost(t, idp.URL) || loc.Path != "/authorize" {
		t.Fatalf("redirect went to %q, want the provider's authorization endpoint", loc)
	}
	q := loc.Query()
	if q.Get("state") != tx.State {
		t.Error("the state sent to the provider is not the one sealed in the cookie")
	}
	if q.Get("nonce") != tx.Nonce {
		t.Error("the nonce sent to the provider is not the one sealed in the cookie")
	}
	// The whole point of PKCE: the challenge the provider sees must be derived
	// from the verifier only this browser holds.
	if q.Get("code_challenge") != pkceChallenge(tx.Verifier) {
		t.Error("code_challenge is not derived from the sealed verifier")
	}
	if q.Get("code_challenge_method") != "S256" {
		t.Errorf("code_challenge_method = %q, want S256", q.Get("code_challenge_method"))
	}
	if q.Get("redirect_uri") != "https://api.test"+OIDCCallbackPath {
		t.Errorf("redirect_uri = %q, want it derived from MULTICA_PUBLIC_URL", q.Get("redirect_uri"))
	}
}

func TestOIDCStartDropsOffSiteNextValues(t *testing.T) {
	h, _ := newOIDCTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, OIDCStartPath+"?next="+url.QueryEscape("https://evil.test/steal"), nil)
	res := testutil.Call(t, h.OIDCStart, req).Want(http.StatusFound)

	cookie := findCookie(res.Result().Cookies(), oidcTxCookieName)
	if cookie == nil {
		t.Fatal("start did not set the login transaction cookie")
	}
	tx, ok := openOIDCTx(cookie.Value)
	if !ok {
		t.Fatal("transaction cookie does not open")
	}
	if tx.Next != "" {
		t.Fatalf("next = %q, want an off-site destination dropped", tx.Next)
	}
}

func TestOIDCEndpointsWithoutConfiguration(t *testing.T) {
	for _, tt := range []struct {
		name    string
		handler func(*Handler) http.HandlerFunc
		path    string
	}{
		{"start", func(h *Handler) http.HandlerFunc { return h.OIDCStart }, OIDCStartPath},
		{"callback", func(h *Handler) http.HandlerFunc { return h.OIDCCallback }, OIDCCallbackPath},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h := newTestHandler(Config{AppURL: "https://app.test"})
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			res := testutil.Call(t, tt.handler(h), req).Want(http.StatusFound)
			wantSSOError(t, res.Header().Get("Location"), ssoErrNotConfigured)
		})
	}
}

func TestOIDCStartFallsBackToTheAppOriginForTheCallback(t *testing.T) {
	idp := testIDPDiscovery(t)
	// The single-origin self-host leaves MULTICA_PUBLIC_URL unset and proxies
	// /auth/* from the app origin to this server, so that origin serves the
	// callback too.
	h := newTestHandler(Config{AppURL: "https://multica.test"})
	h.OIDC = oidc.New(oidc.Config{
		Issuer:       idp.URL,
		ClientID:     "multica",
		ClientSecret: "secret",
		Scopes:       oidc.DefaultScopes,
	}, idp.Client())

	req := httptest.NewRequest(http.MethodGet, OIDCStartPath, nil)
	res := testutil.Call(t, h.OIDCStart, req).Want(http.StatusFound)

	loc, err := url.Parse(res.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	if got := loc.Query().Get("redirect_uri"); got != "https://multica.test"+OIDCCallbackPath {
		t.Fatalf("redirect_uri = %q, want it derived from the app origin", got)
	}
}

func TestOIDCStartWithoutAnyDeclaredOrigin(t *testing.T) {
	idp := testIDPDiscovery(t)
	// Nothing declares where this deployment lives: no app origin, no public
	// URL, no explicit OIDC_REDIRECT_URI. There is neither a callback to
	// register with the provider nor a login page to report that to, so the
	// operator has to be told directly rather than the user seeing a redirect
	// loop.
	h := newTestHandler(Config{})
	h.OIDC = oidc.New(oidc.Config{
		Issuer:       idp.URL,
		ClientID:     "multica",
		ClientSecret: "secret",
		Scopes:       oidc.DefaultScopes,
	}, idp.Client())

	req := httptest.NewRequest(http.MethodGet, OIDCStartPath, nil)
	var got struct {
		Error string `json:"error"`
	}
	testutil.Call(t, h.OIDCStart, req).Want(http.StatusInternalServerError).JSON(&got)
	if !strings.Contains(got.Error, "MULTICA_APP_URL") {
		t.Fatalf("error %q does not name the variable to set", got.Error)
	}
}

func TestOIDCCallbackRejectsResponsesThatAreNotThisLogin(t *testing.T) {
	validTx := func(t *testing.T) string {
		t.Helper()
		sealed, err := sealOIDCTx(oidcTx{
			State:    "state-1",
			Nonce:    "nonce-1",
			Verifier: "verifier-1",
			Expires:  time.Now().Add(oidcTxTTL).Unix(),
		})
		if err != nil {
			t.Fatalf("seal: %v", err)
		}
		return sealed
	}

	tests := []struct {
		name    string
		query   string
		cookie  func(t *testing.T) string
		wantSSO string
	}{
		{
			name:    "user declined at the provider",
			query:   "?error=access_denied",
			wantSSO: ssoErrAccessDenied,
		},
		{
			name:    "provider reported a configuration failure",
			query:   "?error=unauthorized_client",
			wantSSO: ssoErrProviderError,
		},
		{
			// A code delivered without the cookie that started the attempt is
			// someone else's login being pushed into this browser.
			name:    "no transaction cookie",
			query:   "?code=abc&state=state-1",
			wantSSO: ssoErrStateInvalid,
		},
		{
			name:    "state the provider echoed does not match the sealed one",
			query:   "?code=abc&state=attacker-state",
			cookie:  validTx,
			wantSSO: ssoErrStateInvalid,
		},
		{
			name:  "transaction cookie edited to a chosen state",
			query: "?code=abc&state=attacker-state",
			cookie: func(t *testing.T) string {
				// Keep the signature from a real transaction, swap in a
				// payload whose state the attacker chose.
				forged, err := sealOIDCTx(oidcTx{
					State:    "attacker-state",
					Nonce:    "n",
					Verifier: "v",
					Expires:  time.Now().Add(time.Hour).Unix(),
				})
				if err != nil {
					t.Fatalf("seal: %v", err)
				}
				forgedPayload, _, _ := strings.Cut(forged, ".")
				_, sig, _ := strings.Cut(validTx(t), ".")
				return forgedPayload + "." + sig
			},
			wantSSO: ssoErrStateInvalid,
		},
		{
			name:  "expired transaction",
			query: "?code=abc&state=state-1",
			cookie: func(t *testing.T) string {
				sealed, err := sealOIDCTx(oidcTx{
					State:    "state-1",
					Nonce:    "nonce-1",
					Verifier: "verifier-1",
					Expires:  time.Now().Add(-time.Minute).Unix(),
				})
				if err != nil {
					t.Fatalf("seal: %v", err)
				}
				return sealed
			},
			wantSSO: ssoErrStateInvalid,
		},
		{
			name:    "state matches but the provider sent no code",
			query:   "?state=state-1",
			cookie:  validTx,
			wantSSO: ssoErrLoginFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, _ := newOIDCTestHandler(t)
			req := httptest.NewRequest(http.MethodGet, OIDCCallbackPath+tt.query, nil)
			if tt.cookie != nil {
				req.AddCookie(&http.Cookie{Name: oidcTxCookieName, Value: tt.cookie(t)})
			}
			res := testutil.Call(t, h.OIDCCallback, req).Want(http.StatusFound)
			wantSSOError(t, res.Header().Get("Location"), tt.wantSSO)
		})
	}
}

func TestOIDCCallbackAlwaysClearsTheTransaction(t *testing.T) {
	h, _ := newOIDCTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, OIDCCallbackPath+"?error=access_denied", nil)
	req.AddCookie(&http.Cookie{Name: oidcTxCookieName, Value: "anything"})

	res := testutil.Call(t, h.OIDCCallback, req).Want(http.StatusFound)
	// A transaction is single-use: leaving it behind would let a second code
	// be replayed against the same state.
	for _, c := range res.Result().Cookies() {
		if c.Name == oidcTxCookieName {
			if c.MaxAge >= 0 {
				t.Fatalf("transaction cookie MaxAge = %d, want it expired", c.MaxAge)
			}
			return
		}
	}
	t.Fatal("callback did not clear the transaction cookie")
}

func TestOIDCTransactionSealing(t *testing.T) {
	tx := oidcTx{State: "s", Nonce: "n", Verifier: "v", Expires: time.Now().Add(time.Hour).Unix(), Next: "/inbox"}
	sealed, err := sealOIDCTx(tx)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	got, ok := openOIDCTx(sealed)
	if !ok {
		t.Fatal("a freshly sealed transaction must open")
	}
	if got.State != "s" || got.Nonce != "n" || got.Verifier != "v" || got.Next != "/inbox" {
		t.Fatalf("round trip changed the transaction: %+v", got)
	}

	payload, sig, _ := strings.Cut(sealed, ".")
	for _, tt := range []struct {
		name  string
		value string
	}{
		{"no signature", payload},
		{"signature of another payload", payload + "." + strings.Repeat("A", len(sig))},
		{"payload edited under a kept signature", payload[:len(payload)-2] + "XY." + sig},
		{"empty", ""},
		{"not base64", "!!!.???"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, ok := openOIDCTx(tt.value); ok {
				t.Fatal("openOIDCTx accepted a value it must reject")
			}
		})
	}
}

func TestPKCEChallengeMatchesRFC7636(t *testing.T) {
	// RFC 7636 Appendix B's worked example.
	const (
		verifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
		challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	)
	if got := pkceChallenge(verifier); got != challenge {
		t.Fatalf("pkceChallenge = %q, want %q", got, challenge)
	}
}

func TestSanitizeRelativePath(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{"plain path", "/inbox", "/inbox"},
		{"path with query", "/issues?filter=mine", "/issues?filter=mine"},
		{"empty", "", ""},
		{"absolute url", "https://evil.test/steal", ""},
		{"protocol relative", "//evil.test/steal", ""},
		{"backslash protocol relative", "/\\evil.test", ""},
		{"scheme relative without leading slash", "evil.test", ""},
		{"javascript url", "javascript:alert(1)", ""},
		{"overlong", "/" + strings.Repeat("a", maxOIDCNextLen), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sanitizeRelativePath(tt.raw); got != tt.want {
				t.Fatalf("sanitizeRelativePath(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

// wantSSOError asserts the browser was sent back to the login page carrying a
// specific, translatable reason rather than a generic failure.
func wantSSOError(t *testing.T, location, want string) {
	t.Helper()
	u, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse redirect %q: %v", location, err)
	}
	if u.Path != "/login" {
		t.Fatalf("redirected to %q, want the login page", location)
	}
	if got := u.Query().Get("sso_error"); got != want {
		t.Fatalf("sso_error = %q, want %q (location: %s)", got, want, location)
	}
}

func mustHost(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u.Host
}
