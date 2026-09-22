package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const testClientID = "multica-test"

// fakeIDP is a minimal OpenID provider: discovery, JWKS, token and userinfo,
// each driven by fields the test sets before calling Exchange.
type fakeIDP struct {
	t      *testing.T
	server *httptest.Server
	key    *rsa.PrivateKey
	kid    string

	// issuerOverride replaces the issuer advertised by the discovery
	// document; empty means "advertise my own URL", the honest case.
	issuerOverride string
	idToken        string
	accessToken    string
	userinfo       map[string]any
	tokenStatus    int
	tokenBody      string
	lastTokenForm  url.Values
	userinfoCalls  int
}

func newTestIDP(t *testing.T) *fakeIDP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	idp := &fakeIDP{t: t, key: key, kid: "test-key", accessToken: "test-access-token", tokenStatus: http.StatusOK}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		issuer := idp.issuerOverride
		if issuer == "" {
			issuer = idp.server.URL
		}
		writeTestJSON(w, map[string]any{
			"issuer":                 issuer,
			"authorization_endpoint": idp.server.URL + "/authorize",
			"token_endpoint":         idp.server.URL + "/token",
			"userinfo_endpoint":      idp.server.URL + "/userinfo",
			"jwks_uri":               idp.server.URL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		writeTestJSON(w, map[string]any{"keys": []any{rsaJWK(idp.kid, &idp.key.PublicKey)}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("token endpoint got an unparseable form: %v", err)
		}
		idp.lastTokenForm = r.PostForm
		if idp.tokenStatus != http.StatusOK {
			w.WriteHeader(idp.tokenStatus)
			_, _ = io.WriteString(w, idp.tokenBody)
			return
		}
		writeTestJSON(w, map[string]any{
			"access_token": idp.accessToken,
			"id_token":     idp.idToken,
			"token_type":   "Bearer",
		})
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, _ *http.Request) {
		idp.userinfoCalls++
		if idp.userinfo == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		writeTestJSON(w, idp.userinfo)
	})

	idp.server = httptest.NewServer(mux)
	t.Cleanup(idp.server.Close)
	return idp
}

func (f *fakeIDP) provider() *Provider {
	return New(Config{
		Issuer:       f.server.URL,
		ClientID:     testClientID,
		ClientSecret: "test-secret",
		Scopes:       DefaultScopes,
		ProviderName: "Test IdP",
	}, f.server.Client())
}

// baseClaims is a well-formed id_token payload for this provider.
func (f *fakeIDP) baseClaims(nonce string) jwt.MapClaims {
	return jwt.MapClaims{
		"iss":            f.server.URL,
		"aud":            testClientID,
		"sub":            "user-123",
		"exp":            time.Now().Add(5 * time.Minute).Unix(),
		"iat":            time.Now().Unix(),
		"nonce":          nonce,
		"email":          "Ada@Example.COM",
		"email_verified": true,
		"name":           "Ada Lovelace",
	}
}

func (f *fakeIDP) sign(claims jwt.MapClaims) string {
	return f.signWith(claims, f.key, f.kid)
}

func (f *fakeIDP) signWith(claims jwt.MapClaims, key *rsa.PrivateKey, kid string) string {
	f.t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	signed, err := tok.SignedString(key)
	if err != nil {
		f.t.Fatalf("sign id_token: %v", err)
	}
	return signed
}

func writeTestJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func rsaJWK(kid string, pub *rsa.PublicKey) map[string]any {
	return map[string]any{
		"kty": "RSA",
		"kid": kid,
		"use": "sig",
		"alg": "RS256",
		"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

func TestParseScopes(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want []string
	}{
		{"empty falls back to defaults", "", DefaultScopes},
		{"comma separated", "openid,email,groups", []string{"openid", "email", "groups"}},
		{"space separated", "openid email", []string{"openid", "email"}},
		{"mixed separators and padding", " openid ,  profile ", []string{"openid", "profile"}},
		// Without `openid` the provider runs a plain OAuth2 flow and returns no
		// id_token at all, so every login would fail at the callback.
		{"openid is added back when omitted", "email,profile", []string{"openid", "email", "profile"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ParseScopes(tt.raw); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("ParseScopes(%q) = %v, want %v", tt.raw, got, tt.want)
			}
		})
	}
}

func TestConfigEnabledRequiresAllThreeValues(t *testing.T) {
	full := Config{Issuer: "https://idp.test", ClientID: "id", ClientSecret: "secret"}
	if !full.Enabled() {
		t.Fatal("a fully configured provider must be enabled")
	}
	for _, missing := range []string{"Issuer", "ClientID", "ClientSecret"} {
		cfg := full
		reflect.ValueOf(&cfg).Elem().FieldByName(missing).SetString("")
		if cfg.Enabled() {
			t.Fatalf("provider must be disabled when %s is unset", missing)
		}
	}
}

func TestExchangeReturnsVerifiedClaims(t *testing.T) {
	idp := newTestIDP(t)
	idp.idToken = idp.sign(idp.baseClaims("nonce-1"))

	claims, err := idp.provider().Exchange(context.Background(), "code-1", "verifier-1", "https://app.test/cb", "nonce-1")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if claims.Email != "ada@example.com" {
		t.Errorf("email = %q, want it normalized to lower case", claims.Email)
	}
	if claims.Subject != "user-123" || claims.Name != "Ada Lovelace" {
		t.Errorf("unexpected claims: %+v", claims)
	}
	if claims.EmailVerified == nil || !*claims.EmailVerified {
		t.Errorf("email_verified = %v, want true", claims.EmailVerified)
	}
	// PKCE and the redirect URI have to reach the provider, or the exchange
	// silently degrades to a plain authorization-code grant.
	if got := idp.lastTokenForm.Get("code_verifier"); got != "verifier-1" {
		t.Errorf("code_verifier = %q, want it forwarded", got)
	}
	if got := idp.lastTokenForm.Get("redirect_uri"); got != "https://app.test/cb" {
		t.Errorf("redirect_uri = %q, want it forwarded", got)
	}
	// The provider advertises no token_endpoint_auth_methods_supported, so the
	// spec default (client_secret_basic) applies and the secret must not also
	// appear in the form.
	if idp.lastTokenForm.Get("client_secret") != "" {
		t.Error("client secret must not be sent in the form when Basic auth is used")
	}
	if idp.userinfoCalls != 0 {
		t.Error("userinfo must not be fetched when the id_token already carries an email")
	}
}

func TestExchangeRejectsUntrustworthyIDTokens(t *testing.T) {
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate second key: %v", err)
	}

	tests := []struct {
		name    string
		token   func(idp *fakeIDP) string
		wantErr string
	}{
		{
			name: "nonce from a different login attempt",
			token: func(idp *fakeIDP) string {
				return idp.sign(idp.baseClaims("someone-elses-nonce"))
			},
			wantErr: "nonce",
		},
		{
			name: "audience naming a different client",
			token: func(idp *fakeIDP) string {
				c := idp.baseClaims("nonce-1")
				c["aud"] = "a-different-client"
				return idp.sign(c)
			},
			wantErr: "verification failed",
		},
		{
			name: "issuer that is not this provider",
			token: func(idp *fakeIDP) string {
				c := idp.baseClaims("nonce-1")
				c["iss"] = "https://evil.test"
				return idp.sign(c)
			},
			wantErr: "verification failed",
		},
		{
			name: "expired token",
			token: func(idp *fakeIDP) string {
				c := idp.baseClaims("nonce-1")
				c["exp"] = time.Now().Add(-2 * time.Hour).Unix()
				return idp.sign(c)
			},
			wantErr: "verification failed",
		},
		{
			name: "no expiry at all",
			token: func(idp *fakeIDP) string {
				c := idp.baseClaims("nonce-1")
				delete(c, "exp")
				return idp.sign(c)
			},
			wantErr: "verification failed",
		},
		{
			name: "signed by a key the provider does not publish",
			token: func(idp *fakeIDP) string {
				return idp.signWith(idp.baseClaims("nonce-1"), otherKey, idp.kid)
			},
			wantErr: "verification failed",
		},
		{
			name: "kid naming a key that was never published",
			token: func(idp *fakeIDP) string {
				return idp.signWith(idp.baseClaims("nonce-1"), idp.key, "unknown-kid")
			},
			wantErr: "kid",
		},
		{
			name: "HMAC algorithm substituted for the provider's RSA one",
			token: func(idp *fakeIDP) string {
				tok := jwt.NewWithClaims(jwt.SigningMethodHS256, idp.baseClaims("nonce-1"))
				tok.Header["kid"] = idp.kid
				signed, err := tok.SignedString([]byte("test-secret"))
				if err != nil {
					t.Fatalf("sign HS256: %v", err)
				}
				return signed
			},
			wantErr: "verification failed",
		},
		{
			name: "multiple audiences without an azp naming this client",
			token: func(idp *fakeIDP) string {
				c := idp.baseClaims("nonce-1")
				c["aud"] = []string{testClientID, "another-client"}
				c["azp"] = "another-client"
				return idp.sign(c)
			},
			wantErr: "azp",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idp := newTestIDP(t)
			idp.idToken = tt.token(idp)
			_, err := idp.provider().Exchange(context.Background(), "code-1", "verifier-1", "https://app.test/cb", "nonce-1")
			if err == nil {
				t.Fatal("Exchange accepted an id_token it must reject")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error %q does not mention %q", err, tt.wantErr)
			}
		})
	}
}

func TestExchangeAcceptsMultipleAudiencesWithMatchingAZP(t *testing.T) {
	idp := newTestIDP(t)
	c := idp.baseClaims("nonce-1")
	c["aud"] = []string{testClientID, "another-client"}
	c["azp"] = testClientID
	idp.idToken = idp.sign(c)

	if _, err := idp.provider().Exchange(context.Background(), "code-1", "v", "https://app.test/cb", "nonce-1"); err != nil {
		t.Fatalf("Exchange rejected a token whose azp names this client: %v", err)
	}
}

func TestExchangeSurfacesRejectedCodeSeparately(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		body        string
		wantInvalid bool
	}{
		{"rejected code", http.StatusBadRequest, `{"error":"invalid_grant"}`, true},
		// Everything below is the operator's to fix, not the user's to retry.
		{"bad client credentials", http.StatusUnauthorized, `{"error":"invalid_client"}`, false},
		{"unregistered redirect uri", http.StatusBadRequest, `{"error":"invalid_request"}`, false},
		{"provider outage", http.StatusServiceUnavailable, `{"error":"temporarily_unavailable"}`, false},
		{"5xx that happens to say invalid_grant", http.StatusInternalServerError, `{"error":"invalid_grant"}`, false},
		{"malformed error body", http.StatusBadRequest, `<html>nope</html>`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idp := newTestIDP(t)
			idp.tokenStatus = tt.status
			idp.tokenBody = tt.body
			_, err := idp.provider().Exchange(context.Background(), "code-1", "v", "https://app.test/cb", "nonce-1")
			if err == nil {
				t.Fatal("Exchange must fail when the token endpoint errors")
			}
			if got := errors.Is(err, ErrInvalidGrant); got != tt.wantInvalid {
				t.Fatalf("errors.Is(err, ErrInvalidGrant) = %v, want %v (err: %v)", got, tt.wantInvalid, err)
			}
		})
	}
}

func TestExchangeRejectsDiscoveryIssuerMismatch(t *testing.T) {
	idp := newTestIDP(t)
	// A metadata document that names an issuer other than the one configured
	// would redirect the token and JWKS lookups at a provider the operator
	// never chose.
	idp.issuerOverride = "https://evil.test"
	idp.idToken = idp.sign(idp.baseClaims("nonce-1"))

	_, err := idp.provider().Exchange(context.Background(), "code-1", "v", "https://app.test/cb", "nonce-1")
	if err == nil || !strings.Contains(err.Error(), "does not match OIDC_ISSUER") {
		t.Fatalf("err = %v, want a discovery issuer mismatch", err)
	}
}

func TestExchangeRejectsIDTokenWithoutOpenIDScope(t *testing.T) {
	idp := newTestIDP(t)
	idp.idToken = "" // a plain OAuth2 token response

	_, err := idp.provider().Exchange(context.Background(), "code-1", "v", "https://app.test/cb", "nonce-1")
	if err == nil || !strings.Contains(err.Error(), "openid") {
		t.Fatalf("err = %v, want it to point at the missing openid scope", err)
	}
}

func TestExchangeFallsBackToUserinfoForEmail(t *testing.T) {
	idp := newTestIDP(t)
	claims := idp.baseClaims("nonce-1")
	delete(claims, "email")
	delete(claims, "email_verified")
	delete(claims, "name")
	idp.idToken = idp.sign(claims)
	idp.userinfo = map[string]any{
		"sub":            "user-123",
		"email":          "Grace@Example.com",
		"email_verified": "true", // some providers serialise the bool as a string
		"name":           "Grace Hopper",
	}

	got, err := idp.provider().Exchange(context.Background(), "code-1", "v", "https://app.test/cb", "nonce-1")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if got.Email != "grace@example.com" || got.Name != "Grace Hopper" {
		t.Fatalf("userinfo claims were not merged: %+v", got)
	}
	if got.EmailVerified == nil || !*got.EmailVerified {
		t.Errorf("email_verified = %v, want the string form parsed as true", got.EmailVerified)
	}
}

func TestExchangeRejectsUserinfoForADifferentSubject(t *testing.T) {
	idp := newTestIDP(t)
	claims := idp.baseClaims("nonce-1")
	delete(claims, "email")
	idp.idToken = idp.sign(claims)
	// OIDC Core §5.3.2: a userinfo response for another subject must never be
	// merged, or one account's token could supply another account's email.
	idp.userinfo = map[string]any{"sub": "someone-else", "email": "victim@example.com"}

	_, err := idp.provider().Exchange(context.Background(), "code-1", "v", "https://app.test/cb", "nonce-1")
	if err == nil || !strings.Contains(err.Error(), "sub") {
		t.Fatalf("err = %v, want a userinfo subject mismatch", err)
	}
}

func TestEmailVerifiedFalseIsPreserved(t *testing.T) {
	idp := newTestIDP(t)
	claims := idp.baseClaims("nonce-1")
	claims["email_verified"] = false
	idp.idToken = idp.sign(claims)

	got, err := idp.provider().Exchange(context.Background(), "code-1", "v", "https://app.test/cb", "nonce-1")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	// The package reports the claim; rejecting on it is the handler's call.
	if got.EmailVerified == nil || *got.EmailVerified {
		t.Fatalf("EmailVerified = %v, want a non-nil false", got.EmailVerified)
	}
}

func TestEmailVerifiedAbsentStaysUnstated(t *testing.T) {
	idp := newTestIDP(t)
	claims := idp.baseClaims("nonce-1")
	delete(claims, "email_verified")
	idp.idToken = idp.sign(claims)

	got, err := idp.provider().Exchange(context.Background(), "code-1", "v", "https://app.test/cb", "nonce-1")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	// nil, not false: a provider that never emits the claim would otherwise be
	// unusable.
	if got.EmailVerified != nil {
		t.Fatalf("EmailVerified = %v, want nil when the provider omits the claim", *got.EmailVerified)
	}
}

func TestAuthCodeURLCarriesPKCEAndNonce(t *testing.T) {
	idp := newTestIDP(t)
	raw, err := idp.provider().AuthCodeURL(context.Background(), "https://app.test/cb", "state-1", "nonce-1", "challenge-1")
	if err != nil {
		t.Fatalf("AuthCodeURL: %v", err)
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse authorization URL: %v", err)
	}
	q := u.Query()
	want := map[string]string{
		"client_id":             testClientID,
		"redirect_uri":          "https://app.test/cb",
		"response_type":         "code",
		"scope":                 "openid email profile",
		"state":                 "state-1",
		"nonce":                 "nonce-1",
		"code_challenge":        "challenge-1",
		"code_challenge_method": "S256",
	}
	for k, v := range want {
		if q.Get(k) != v {
			t.Errorf("authorization URL %s = %q, want %q", k, q.Get(k), v)
		}
	}
}

func TestPrefersBasicAuth(t *testing.T) {
	tests := []struct {
		name    string
		methods []string
		want    bool
	}{
		// Discovery §3: client_secret_basic is the default when nothing is said.
		{"unadvertised", nil, true},
		{"advertised", []string{"client_secret_post", "client_secret_basic"}, true},
		{"post only", []string{"client_secret_post"}, false},
		{"case insensitive", []string{"Client_Secret_Basic"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := prefersBasicAuth(tt.methods); got != tt.want {
				t.Fatalf("prefersBasicAuth(%v) = %v, want %v", tt.methods, got, tt.want)
			}
		})
	}
}

func TestJWKRejectsWeakAndMalformedKeys(t *testing.T) {
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate weak key: %v", err)
	}
	tests := []struct {
		name string
		key  map[string]any
	}{
		{"RSA below the minimum size", rsaJWK("k", &weak.PublicKey)},
		{"unsupported key type", map[string]any{"kty": "oct", "k": "AAAA"}},
		{"unsupported curve", map[string]any{"kty": "EC", "crv": "P-192", "x": "AAAA", "y": "AAAA"}},
		{"EC coordinates of the wrong length", map[string]any{"kty": "EC", "crv": "P-256", "x": "AAAA", "y": "AAAA"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, err := json.Marshal(tt.key)
			if err != nil {
				t.Fatalf("marshal jwk: %v", err)
			}
			var entry jwk
			if err := json.Unmarshal(raw, &entry); err != nil {
				t.Fatalf("unmarshal jwk: %v", err)
			}
			if _, err := entry.publicKey(); err == nil {
				t.Fatal("publicKey accepted a key it must reject")
			}
		})
	}
}
