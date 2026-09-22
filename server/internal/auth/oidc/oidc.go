// Package oidc implements the OpenID Connect authorization-code flow this
// server uses for single sign-on. Nothing in here is provider-specific:
// every endpoint comes from the issuer's discovery document, so the same
// configuration shape serves Keycloak (what the self-hosting guide walks
// through), Authentik, Okta, Auth0 and Entra ID.
//
// The flow is confidential-client with PKCE and a nonce. PKCE is not strictly
// required for a client that holds a secret, but it costs one hash and closes
// the code-injection window on a redirect URI that several deployments share.
package oidc

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// DefaultScopes is requested when OIDC_SCOPES is unset. `openid` is what makes
// the request an OIDC one at all; `email` and `profile` carry the claims that
// map onto a Multica user.
var DefaultScopes = []string{"openid", "email", "profile"}

// DefaultProviderName labels the sign-in button when the operator has not
// named their provider. Deliberately generic: the button is the only place
// most users ever see this string, and "SSO" is what an employee is told to
// look for far more often than the product name behind it.
const DefaultProviderName = "SSO"

// maxResponseBytes caps every provider response we read into memory. The
// issuer is operator-configured rather than user-supplied, so this guards
// against a misbehaving provider, not an attacker.
const maxResponseBytes = 1 << 20

// discoveryTTL bounds how long one discovery document is reused. Providers
// rotate endpoints rarely; an hour keeps a realm rename from needing a
// Multica restart without making every login pay for a metadata fetch.
const discoveryTTL = time.Hour

// Config is the deployment's OIDC wiring, read from the environment.
type Config struct {
	// Issuer is the provider's issuer URL with no trailing slash, e.g.
	// https://sso.example.com/realms/multica. Discovery hangs off it.
	Issuer       string
	ClientID     string
	ClientSecret string
	// RedirectURI, when set, overrides the callback URL derived from
	// MULTICA_PUBLIC_URL. Providers match it byte-for-byte against their own
	// registration, so operators behind a proxy that rewrites the public
	// origin need to state it explicitly.
	RedirectURI string
	Scopes      []string
	// ProviderName labels the sign-in button — whatever the operator's users
	// recognise ("Keycloak", "Okta", "Acme SSO").
	ProviderName string
}

// ConfigFromEnv reads the OIDC configuration. Absent variables yield a
// disabled config rather than an error: OIDC is opt-in, and a deployment that
// never sets OIDC_ISSUER must boot exactly as it did before.
func ConfigFromEnv() Config {
	cfg := Config{
		Issuer:       strings.TrimRight(strings.TrimSpace(os.Getenv("OIDC_ISSUER")), "/"),
		ClientID:     strings.TrimSpace(os.Getenv("OIDC_CLIENT_ID")),
		ClientSecret: strings.TrimSpace(os.Getenv("OIDC_CLIENT_SECRET")),
		RedirectURI:  strings.TrimRight(strings.TrimSpace(os.Getenv("OIDC_REDIRECT_URI")), "/"),
		ProviderName: strings.TrimSpace(os.Getenv("OIDC_PROVIDER_NAME")),
		Scopes:       ParseScopes(os.Getenv("OIDC_SCOPES")),
	}
	if cfg.ProviderName == "" {
		cfg.ProviderName = DefaultProviderName
	}
	return cfg
}

// ParseScopes splits a comma- or space-separated scope list.
func ParseScopes(raw string) []string {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n'
	})
	scopes := make([]string, 0, len(fields)+1)
	hasOpenID := false
	for _, f := range fields {
		if f == "" {
			continue
		}
		if f == "openid" {
			hasOpenID = true
		}
		scopes = append(scopes, f)
	}
	if len(scopes) == 0 {
		return append([]string(nil), DefaultScopes...)
	}
	if !hasOpenID {
		// Without `openid` the provider runs a plain OAuth2 flow and returns
		// no id_token — the only thing this package accepts as proof of
		// identity. Adding it back beats failing every login at the callback
		// with an error that points nowhere near the misconfigured variable.
		scopes = append([]string{"openid"}, scopes...)
	}
	return scopes
}

// Enabled reports whether this deployment has configured OIDC. All three
// values are required: the flow is a confidential-client one, so a config
// missing the secret cannot complete a token exchange.
func (c Config) Enabled() bool {
	return c.Issuer != "" && c.ClientID != "" && c.ClientSecret != ""
}

// discovery is the subset of the OpenID provider metadata document this
// package uses.
type discovery struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	UserinfoEndpoint      string   `json:"userinfo_endpoint"`
	JWKSURI               string   `json:"jwks_uri"`
	TokenAuthMethods      []string `json:"token_endpoint_auth_methods_supported"`
}

// Provider performs the flow against one configured issuer. It caches the
// discovery document and signing keys, so callers should build it once at
// boot and hold it for the process lifetime.
type Provider struct {
	cfg        Config
	httpClient *http.Client
	keys       *keySet

	mu        sync.Mutex
	doc       *discovery
	docExpiry time.Time
}

// New builds a Provider. A nil client gets a timeout-bounded default; tests
// pass their own transport.
func New(cfg Config, client *http.Client) *Provider {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	return &Provider{cfg: cfg, httpClient: client, keys: newKeySet(client)}
}

// Config returns the provider's configuration.
func (p *Provider) Config() Config { return p.cfg }

// Claims are the identity fields this server maps onto a Multica user.
type Claims struct {
	Subject string
	Email   string
	// EmailVerified is nil when the provider emits no such claim. That case
	// cannot be treated as "unverified": providers that never send the claim
	// would then be unusable. Present-and-false is the only rejection.
	EmailVerified *bool
	Name          string
	Picture       string
}

// ErrInvalidGrant reports an authorization code the provider rejected — the
// one exchange failure that is the user's to retry rather than the operator's
// to fix.
var ErrInvalidGrant = errors.New("oidc: authorization code was rejected")

// discover returns the provider metadata, fetching it when the cache is cold
// or stale.
func (p *Provider) discover(ctx context.Context) (*discovery, error) {
	p.mu.Lock()
	if p.doc != nil && time.Now().Before(p.docExpiry) {
		doc := p.doc
		p.mu.Unlock()
		return doc, nil
	}
	p.mu.Unlock()

	endpoint := p.cfg.Issuer + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("oidc: build discovery request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc: fetch discovery document: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("oidc: read discovery document: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc: discovery document returned HTTP %d", resp.StatusCode)
	}

	var doc discovery
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("oidc: parse discovery document: %w", err)
	}
	// OpenID Connect Discovery §4.3 requires the document to name the issuer
	// it was fetched for. Skipping the check would let a redirected or
	// hijacked metadata URL point the token and JWKS lookups at a provider
	// the operator never configured.
	if strings.TrimRight(doc.Issuer, "/") != p.cfg.Issuer {
		return nil, fmt.Errorf("oidc: discovery document issuer %q does not match OIDC_ISSUER %q", doc.Issuer, p.cfg.Issuer)
	}
	if doc.AuthorizationEndpoint == "" || doc.TokenEndpoint == "" || doc.JWKSURI == "" {
		return nil, errors.New("oidc: discovery document is missing an authorization, token, or JWKS endpoint")
	}

	p.mu.Lock()
	p.doc = &doc
	p.docExpiry = time.Now().Add(discoveryTTL)
	p.mu.Unlock()
	return &doc, nil
}

// AuthCodeURL builds the provider's authorization URL for one login attempt.
// state, nonce and challenge are per-attempt values the caller also hands to
// the browser, so the callback can prove the response belongs to this attempt.
func (p *Provider) AuthCodeURL(ctx context.Context, redirectURI, state, nonce, challenge string) (string, error) {
	doc, err := p.discover(ctx)
	if err != nil {
		return "", err
	}
	q := url.Values{
		"client_id":             {p.cfg.ClientID},
		"redirect_uri":          {redirectURI},
		"response_type":         {"code"},
		"scope":                 {strings.Join(p.cfg.Scopes, " ")},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	// The endpoint is allowed to carry its own query string (RFC 8414 does not
	// forbid it), so append rather than assume we own the `?`.
	sep := "?"
	if strings.Contains(doc.AuthorizationEndpoint, "?") {
		sep = "&"
	}
	return doc.AuthorizationEndpoint + sep + q.Encode(), nil
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
}

// Exchange trades an authorization code for a verified identity. It validates
// the id_token's signature, issuer, audience, expiry and nonce, and falls back
// to the userinfo endpoint when the provider leaves email out of the token.
func (p *Provider) Exchange(ctx context.Context, code, verifier, redirectURI, nonce string) (*Claims, error) {
	doc, err := p.discover(ctx)
	if err != nil {
		return nil, err
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
	}
	useBasic := prefersBasicAuth(doc.TokenAuthMethods)
	if !useBasic {
		form.Set("client_id", p.cfg.ClientID)
		form.Set("client_secret", p.cfg.ClientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, doc.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("oidc: build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if useBasic {
		// RFC 6749 §2.3.1: both halves are form-urlencoded before base64.
		req.SetBasicAuth(url.QueryEscape(p.cfg.ClientID), url.QueryEscape(p.cfg.ClientSecret))
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc: token exchange request failed: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("oidc: read token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		// Only a well-formed invalid_grant identifies a rejected code, and
		// only on a 4xx. Everything else — bad client credentials, a redirect
		// URI the provider does not know, an unreachable realm — is the
		// operator's to fix and must not be reported to the user as a stale
		// code they can retry past.
		var tokenErr struct {
			Error string `json:"error"`
		}
		if err := json.Unmarshal(body, &tokenErr); err == nil &&
			resp.StatusCode == http.StatusBadRequest && tokenErr.Error == "invalid_grant" {
			return nil, ErrInvalidGrant
		}
		return nil, fmt.Errorf("oidc: token endpoint returned HTTP %d: %s", resp.StatusCode, truncateForLog(body))
	}

	var tok tokenResponse
	if err := json.Unmarshal(body, &tok); err != nil {
		return nil, fmt.Errorf("oidc: parse token response: %w", err)
	}
	if strings.TrimSpace(tok.IDToken) == "" {
		return nil, errors.New("oidc: token response carried no id_token; check that the client requests the `openid` scope")
	}

	claims, err := p.verifyIDToken(ctx, doc, tok.IDToken, nonce)
	if err != nil {
		return nil, err
	}

	// Providers differ on whether email rides in the id_token or only at the
	// userinfo endpoint. This is the documented second half of the contract,
	// not a fallback for a broken first half.
	if claims.Email == "" && doc.UserinfoEndpoint != "" && tok.AccessToken != "" {
		if err := p.mergeUserInfo(ctx, doc, tok.AccessToken, claims); err != nil {
			return nil, err
		}
	}
	return claims, nil
}

// prefersBasicAuth picks the client authentication method for the token
// request. OpenID Connect Discovery §3 makes client_secret_basic the default
// when a provider advertises nothing, and every provider supporting it lists
// it; client_secret_post is used only when it is what the provider offers.
func prefersBasicAuth(methods []string) bool {
	if len(methods) == 0 {
		return true
	}
	for _, m := range methods {
		if strings.EqualFold(strings.TrimSpace(m), "client_secret_basic") {
			return true
		}
	}
	return false
}

func (p *Provider) verifyIDToken(ctx context.Context, doc *discovery, raw, nonce string) (*Claims, error) {
	kid, err := idTokenKeyID(raw)
	if err != nil {
		return nil, err
	}

	keys, err := p.keys.candidates(ctx, doc.JWKSURI, kid)
	if err != nil {
		return nil, err
	}

	opts := []jwt.ParserOption{
		// Pinning the algorithm list is what keeps a token signed with `none`
		// — or with HMAC keyed by a value an attacker can guess — from ever
		// reaching the signature check.
		jwt.WithValidMethods(supportedAlgs),
		// Validate against the provider's own canonical issuer rather than the
		// operator's env value: discover() has already tied the two together,
		// and only this one matches the `iss` claim byte-for-byte when the
		// provider publishes a trailing slash.
		jwt.WithIssuer(doc.Issuer),
		jwt.WithAudience(p.cfg.ClientID),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(time.Minute),
	}

	// One candidate in every ordinary case. More only when the provider omits
	// `kid` while publishing several keys, which leaves no way to choose but
	// to try them.
	claims := jwt.MapClaims{}
	verified := false
	var lastErr error
	for _, key := range keys {
		attempt := jwt.MapClaims{}
		if _, err := jwt.ParseWithClaims(raw, attempt, func(*jwt.Token) (any, error) { return key, nil }, opts...); err != nil {
			lastErr = err
			continue
		}
		claims = attempt
		verified = true
		break
	}
	if !verified {
		if lastErr == nil {
			lastErr = errors.New("no candidate signing keys")
		}
		return nil, fmt.Errorf("oidc: id_token verification failed: %w", lastErr)
	}

	// OIDC Core §3.1.3.7: a token issued for more than one audience must name
	// this client in `azp`, or a token minted for a different client of the
	// same provider would be accepted here.
	if auds, audErr := claims.GetAudience(); audErr == nil && len(auds) > 1 {
		azp, _ := claims["azp"].(string)
		if azp != p.cfg.ClientID {
			return nil, errors.New("oidc: id_token lists multiple audiences and its azp claim does not name this client")
		}
	}

	got, _ := claims["nonce"].(string)
	if subtle.ConstantTimeCompare([]byte(got), []byte(nonce)) != 1 {
		return nil, errors.New("oidc: id_token nonce does not match this login attempt")
	}

	out := &Claims{
		Subject: stringClaim(claims, "sub"),
		Email:   strings.ToLower(strings.TrimSpace(stringClaim(claims, "email"))),
		Name:    strings.TrimSpace(stringClaim(claims, "name")),
		Picture: strings.TrimSpace(stringClaim(claims, "picture")),
	}
	if out.Name == "" {
		out.Name = strings.TrimSpace(stringClaim(claims, "preferred_username"))
	}
	if v, ok := claims["email_verified"]; ok {
		out.EmailVerified = boolClaim(v)
	}
	if out.Subject == "" {
		return nil, errors.New("oidc: id_token carried no sub claim")
	}
	return out, nil
}

// userInfoClaims is the userinfo response shape. email_verified is decoded
// loosely because providers serialise it as both a JSON bool and a string.
type userInfoClaims struct {
	Sub               string `json:"sub"`
	Email             string `json:"email"`
	EmailVerified     any    `json:"email_verified"`
	Name              string `json:"name"`
	PreferredUsername string `json:"preferred_username"`
	Picture           string `json:"picture"`
}

// mergeUserInfo fills in identity fields the id_token left empty.
func (p *Provider) mergeUserInfo(ctx context.Context, doc *discovery, accessToken string, into *Claims) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, doc.UserinfoEndpoint, nil)
	if err != nil {
		return fmt.Errorf("oidc: build userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("oidc: userinfo request failed: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return fmt.Errorf("oidc: read userinfo response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("oidc: userinfo endpoint returned HTTP %d: %s", resp.StatusCode, truncateForLog(body))
	}

	var info userInfoClaims
	if err := json.Unmarshal(body, &info); err != nil {
		return fmt.Errorf("oidc: parse userinfo response: %w", err)
	}
	// OIDC Core §5.3.2: the userinfo subject must match the id_token's, or a
	// response fetched with a token for one account could supply another
	// account's email.
	if subtle.ConstantTimeCompare([]byte(info.Sub), []byte(into.Subject)) != 1 {
		return errors.New("oidc: userinfo sub does not match the id_token sub")
	}

	if into.Email == "" {
		into.Email = strings.ToLower(strings.TrimSpace(info.Email))
	}
	if into.Name == "" {
		into.Name = strings.TrimSpace(info.Name)
	}
	if into.Name == "" {
		into.Name = strings.TrimSpace(info.PreferredUsername)
	}
	if into.Picture == "" {
		into.Picture = strings.TrimSpace(info.Picture)
	}
	if into.EmailVerified == nil && info.EmailVerified != nil {
		into.EmailVerified = boolClaim(info.EmailVerified)
	}
	return nil
}

// idTokenKeyID reads the `kid` from a JWT header. Nothing read here is
// trusted: the value only selects which published key to check the signature
// against, and a forged one simply picks a key the signature fails under.
func idTokenKeyID(raw string) (string, error) {
	segment, _, found := strings.Cut(raw, ".")
	if !found || segment == "" {
		return "", errors.New("oidc: id_token is not a well-formed JWT")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return "", fmt.Errorf("oidc: id_token header is not base64url: %w", err)
	}
	var header struct {
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(decoded, &header); err != nil {
		return "", fmt.Errorf("oidc: id_token header is not JSON: %w", err)
	}
	return header.Kid, nil
}

func stringClaim(claims jwt.MapClaims, key string) string {
	v, _ := claims[key].(string)
	return v
}

// boolClaim reads a claim that is specified as a boolean but is serialised as
// a string by some providers. Anything else yields nil — "not stated" rather
// than a guess.
func boolClaim(v any) *bool {
	switch t := v.(type) {
	case bool:
		return &t
	case string:
		switch strings.ToLower(strings.TrimSpace(t)) {
		case "true":
			b := true
			return &b
		case "false":
			b := false
			return &b
		}
	}
	return nil
}

// truncateForLog bounds a provider error body before it reaches a log line.
func truncateForLog(body []byte) string {
	const max = 512
	s := strings.TrimSpace(string(body))
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}
