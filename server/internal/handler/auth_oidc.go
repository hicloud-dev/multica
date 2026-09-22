package handler

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/multica-ai/multica/server/internal/analytics"
	"github.com/multica-ai/multica/server/internal/auth"
	"github.com/multica-ai/multica/server/internal/auth/oidc"
	"github.com/multica-ai/multica/server/internal/logger"
	obsmetrics "github.com/multica-ai/multica/server/internal/metrics"
	db "github.com/multica-ai/multica/server/pkg/db/generated"
)

// OIDCStartPath is where the login page sends the browser to begin SSO. It is
// published in /api/config rather than hardcoded in the frontend, so an
// already-installed desktop client keeps working if the route ever moves.
const OIDCStartPath = "/auth/oidc/start"

// OIDCCallbackPath is where the identity provider returns the browser. It is
// an API path, not an app one: the provider's redirect is a top-level
// navigation, which is the only context that carries the SameSite=Lax login
// transaction cookie back to this server regardless of how the app and API
// origins are split.
const OIDCCallbackPath = "/auth/oidc/callback"

const (
	// oidcTxCookieName holds the one-login transaction: the state the
	// provider must echo, the nonce the id_token must carry, the PKCE
	// verifier, and where to send the browser afterwards.
	oidcTxCookieName = "multica_oidc_tx"
	// oidcTxCookiePath scopes the cookie to the two OIDC endpoints, so it is
	// never attached to an ordinary API request.
	oidcTxCookiePath = "/auth/oidc"
	// oidcTxTTL bounds how long a started login may sit unfinished. Long
	// enough to type a password and answer an MFA prompt; short enough that a
	// transaction cookie left on a shared machine is not a standing invitation.
	oidcTxTTL = 15 * time.Minute
)

// sso_error codes handed back to the login page. They are a closed set: the
// page maps each to translated copy, and an unmapped value would render as a
// generic failure.
const (
	ssoErrNotConfigured   = "not_configured"
	ssoErrAccessDenied    = "access_denied"
	ssoErrProviderError   = "provider_error"
	ssoErrStateInvalid    = "state_invalid"
	ssoErrLoginFailed     = "login_failed"
	ssoErrAccountDisabled = "account_disabled"
	ssoErrSignupProhibit  = "signup_prohibited"
	ssoErrEmailNotAllowed = "email_not_allowed"
	ssoErrNoEmail         = "no_email"
	ssoErrEmailUnverified = "email_unverified"
	ssoErrCodeInvalid     = "code_invalid"
)

// Caps on the routing values carried across the round trip. They exist so a
// crafted /auth/oidc/start cannot inflate the transaction cookie past what
// browsers will store.
const (
	maxOIDCNextLen        = 2048
	maxOIDCCLICallbackLen = 2048
	maxOIDCCLIStateLen    = 512
)

// oidcTx is the sealed login transaction. Field names are short because the
// whole struct is base64'd into a cookie.
type oidcTx struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Expires  int64  `json:"e"`
	// Routing values the login page needs once the session exists. They live
	// here rather than in the OAuth `state` parameter so they come back
	// server-sealed instead of attacker-editable.
	Next        string `json:"nx,omitempty"`
	Platform    string `json:"p,omitempty"`
	CLICallback string `json:"cc,omitempty"`
	CLIState    string `json:"cs,omitempty"`
}

// oidcProvider returns the configured provider, or false when this deployment
// has not enabled OIDC.
func (h *Handler) oidcProvider() (*oidc.Provider, bool) {
	if h.OIDC == nil || !h.OIDC.Config().Enabled() {
		return nil, false
	}
	return h.OIDC, true
}

// oidcRedirectURI is the callback URL registered with the provider. Providers
// compare it byte-for-byte, so it is derived from an origin the operator
// declared rather than from request headers a proxy could rewrite.
//
// MULTICA_PUBLIC_URL first, because a split deployment reaches the API on its
// own host. It is deliberately left unset on the far more common single-origin
// self-host, though, where the web app proxies /auth/* through to this server
// — so the app origin serves the same callback and is the right second choice.
// An operator whose topology matches neither states OIDC_REDIRECT_URI.
func (h *Handler) oidcRedirectURI() string {
	if h.OIDC != nil {
		if override := h.OIDC.Config().RedirectURI; override != "" {
			return override
		}
	}
	if h.cfg.PublicURL != "" {
		return h.cfg.PublicURL + OIDCCallbackPath
	}
	if appURL := strings.TrimRight(h.cfg.AppURL, "/"); appURL != "" {
		return appURL + OIDCCallbackPath
	}
	return ""
}

// redirectToLogin sends the browser back to the app's login page. It reports
// false when the deployment has not declared an app origin — the one case
// where there is nowhere to send the user and the operator has to be told.
func (h *Handler) redirectToLogin(w http.ResponseWriter, r *http.Request, params url.Values) bool {
	appURL := strings.TrimRight(h.cfg.AppURL, "/")
	if appURL == "" {
		writeError(w, http.StatusInternalServerError,
			"MULTICA_APP_URL (or FRONTEND_ORIGIN) is not set, so SSO cannot return the browser to the app")
		return false
	}
	dest := appURL + "/login"
	if encoded := params.Encode(); encoded != "" {
		dest += "?" + encoded
	}
	http.Redirect(w, r, dest, http.StatusFound)
	return true
}

func (h *Handler) redirectToLoginError(w http.ResponseWriter, r *http.Request, code string) {
	h.redirectToLogin(w, r, url.Values{"sso_error": {code}})
}

// OIDCStart begins a login: it mints the per-attempt secrets, seals them into
// the transaction cookie, and sends the browser to the provider.
func (h *Handler) OIDCStart(w http.ResponseWriter, r *http.Request) {
	p, ok := h.oidcProvider()
	if !ok {
		h.redirectToLoginError(w, r, ssoErrNotConfigured)
		return
	}
	redirectURI := h.oidcRedirectURI()
	if redirectURI == "" {
		slog.Error("oidc start refused: no callback URL could be derived",
			"reason", "set MULTICA_APP_URL (or FRONTEND_ORIGIN), MULTICA_PUBLIC_URL, or OIDC_REDIRECT_URI")
		h.redirectToLoginError(w, r, ssoErrNotConfigured)
		return
	}

	state, err := randomURLSafe(32)
	if err != nil {
		h.redirectToLoginError(w, r, ssoErrLoginFailed)
		return
	}
	nonce, err := randomURLSafe(32)
	if err != nil {
		h.redirectToLoginError(w, r, ssoErrLoginFailed)
		return
	}
	// RFC 7636 §4.1: 32 random bytes base64url-encode to 43 characters, the
	// shortest verifier the spec allows and the length it recommends.
	verifier, err := randomURLSafe(32)
	if err != nil {
		h.redirectToLoginError(w, r, ssoErrLoginFailed)
		return
	}

	q := r.URL.Query()
	tx := oidcTx{
		State:       state,
		Nonce:       nonce,
		Verifier:    verifier,
		Expires:     time.Now().Add(oidcTxTTL).Unix(),
		Next:        sanitizeRelativePath(q.Get("next")),
		CLICallback: capString(q.Get("cli_callback"), maxOIDCCLICallbackLen),
		CLIState:    capString(q.Get("cli_state"), maxOIDCCLIStateLen),
	}
	// Only one platform value means anything to the login page; anything else
	// would ride along unread.
	if q.Get("platform") == "desktop" {
		tx.Platform = "desktop"
	}

	sealed, err := sealOIDCTx(tx)
	if err != nil {
		slog.Error("oidc start failed to seal login transaction", "error", err)
		h.redirectToLoginError(w, r, ssoErrLoginFailed)
		return
	}

	authURL, err := p.AuthCodeURL(r.Context(), redirectURI, state, nonce, pkceChallenge(verifier))
	if err != nil {
		slog.Error("oidc start could not build the authorization URL", "error", err)
		h.redirectToLoginError(w, r, ssoErrProviderError)
		return
	}

	auth.SetTransactionCookie(w, oidcTxCookieName, sealed, oidcTxCookiePath, oidcTxTTL)
	http.Redirect(w, r, authURL, http.StatusFound)
}

// OIDCCallback completes a login started by OIDCStart.
func (h *Handler) OIDCCallback(w http.ResponseWriter, r *http.Request) {
	// The transaction is single-use whatever happens next, so it is cleared
	// before any branch can return.
	auth.ClearTransactionCookie(w, oidcTxCookieName, oidcTxCookiePath)

	p, ok := h.oidcProvider()
	if !ok {
		h.redirectToLoginError(w, r, ssoErrNotConfigured)
		return
	}

	q := r.URL.Query()
	if providerErr := q.Get("error"); providerErr != "" {
		slog.Info("oidc provider declined the login",
			append(logger.RequestAttrs(r), "error", providerErr, "description", q.Get("error_description"))...)
		if providerErr == "access_denied" {
			h.redirectToLoginError(w, r, ssoErrAccessDenied)
			return
		}
		h.redirectToLoginError(w, r, ssoErrProviderError)
		return
	}

	cookie, err := r.Cookie(oidcTxCookieName)
	if err != nil || cookie.Value == "" {
		h.redirectToLoginError(w, r, ssoErrStateInvalid)
		return
	}
	tx, ok := openOIDCTx(cookie.Value)
	if !ok {
		h.redirectToLoginError(w, r, ssoErrStateInvalid)
		return
	}
	// This is the CSRF defence for the whole flow: a code delivered to this
	// endpoint without the state that started the attempt belongs to someone
	// else's login, and must not be redeemed into this browser's session.
	if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(tx.State)) != 1 {
		h.redirectToLoginError(w, r, ssoErrStateInvalid)
		return
	}

	code := q.Get("code")
	if code == "" {
		h.redirectToLoginError(w, r, ssoErrLoginFailed)
		return
	}

	claims, err := p.Exchange(r.Context(), code, tx.Verifier, h.oidcRedirectURI(), tx.Nonce)
	if err != nil {
		if errors.Is(err, oidc.ErrInvalidGrant) {
			h.redirectToLoginError(w, r, ssoErrCodeInvalid)
			return
		}
		slog.Error("oidc token exchange failed", append(logger.RequestAttrs(r), "error", err)...)
		h.redirectToLoginError(w, r, ssoErrLoginFailed)
		return
	}

	email := strings.ToLower(strings.TrimSpace(claims.Email))
	if email == "" {
		slog.Warn("oidc login carried no email claim",
			append(logger.RequestAttrs(r), "subject", claims.Subject,
				"reason", "map an email claim onto the client, or grant the `email` scope")...)
		h.redirectToLoginError(w, r, ssoErrNoEmail)
		return
	}
	// Accounts are matched to existing users by email, so an address the
	// provider itself says it has not verified would let anyone who can
	// register at the IdP claim a colleague's Multica account. A provider
	// that omits the claim entirely says nothing either way and is accepted —
	// requiring it would rule out providers that never emit it.
	if claims.EmailVerified != nil && !*claims.EmailVerified {
		slog.Warn("oidc login rejected: provider reports the email as unverified",
			append(logger.RequestAttrs(r), "email", email)...)
		h.redirectToLoginError(w, r, ssoErrEmailUnverified)
		return
	}

	user, isNew, err := h.findOrCreateUser(r.Context(), email)
	if err != nil {
		h.redirectToLoginError(w, r, ssoSignupErrorCode(err))
		return
	}
	if isNew {
		evt := analytics.Signup(uuidToString(user.ID), user.Email, signupSourceFromRequest(r))
		evt.Properties["auth_method"] = "oidc"
		obsmetrics.RecordEvent(h.Analytics, h.Metrics, evt)
	}

	h.applyOIDCProfile(r, &user, email, claims)

	tokenString, err := h.issueJWT(user)
	if err != nil {
		slog.Warn("oidc login could not issue a session",
			append(logger.RequestAttrs(r), "error", err, "email", email)...)
		h.redirectToLoginError(w, r, ssoSignupErrorCode(err))
		return
	}

	if err := auth.SetAuthCookies(w, tokenString); err != nil {
		slog.Warn("failed to set auth cookies", "error", err)
	}
	if h.CFSigner != nil {
		for _, c := range h.CFSigner.SignedCookies(time.Now().Add(72 * time.Hour)) {
			http.SetCookie(w, c)
		}
	}

	slog.Info("user logged in via oidc",
		append(logger.RequestAttrs(r), "user_id", uuidToString(user.ID), "email", user.Email)...)

	// The session now lives in cookies; the login page picks it up and applies
	// the same post-auth routing every other entry point uses. Nothing secret
	// travels in this URL.
	params := url.Values{"sso": {"1"}}
	if tx.Next != "" {
		params.Set("next", tx.Next)
	}
	if tx.Platform != "" {
		params.Set("platform", tx.Platform)
	}
	if tx.CLICallback != "" {
		params.Set("cli_callback", tx.CLICallback)
	}
	if tx.CLIState != "" {
		params.Set("cli_state", tx.CLIState)
	}
	h.redirectToLogin(w, r, params)
}

// applyOIDCProfile copies name and avatar from the provider when Multica has
// nothing better. It mirrors the Google rule: only overwrite a name that is
// still the email-prefix placeholder findOrCreateUser generated, and only fill
// an avatar that is unset.
func (h *Handler) applyOIDCProfile(r *http.Request, user *db.User, email string, claims *oidc.Claims) {
	newName := user.Name
	newAvatar := user.AvatarUrl
	changed := false

	if claims.Name != "" && user.Name == strings.Split(email, "@")[0] {
		newName = claims.Name
		changed = true
	}
	if claims.Picture != "" && !user.AvatarUrl.Valid {
		newAvatar = pgtype.Text{String: claims.Picture, Valid: true}
		changed = true
	}
	if !changed {
		return
	}

	updated, err := h.Queries.UpdateUser(r.Context(), db.UpdateUserParams{
		ID:        user.ID,
		Name:      newName,
		AvatarUrl: newAvatar,
	})
	if err != nil {
		// A cosmetic update is not worth failing a login over.
		slog.Warn("oidc profile sync failed", "error", err, "user_id", uuidToString(user.ID))
		return
	}
	*user = updated
}

// ssoSignupErrorCode maps a signup/session refusal onto the login page's code
// set, so the user is told which rule stopped them rather than "try again".
func ssoSignupErrorCode(err error) string {
	switch {
	case errors.Is(err, auth.ErrTemporarilyDisabledUser):
		return ssoErrAccountDisabled
	case errors.Is(err, ErrSignupProhibited):
		return ssoErrSignupProhibit
	case errors.Is(err, ErrEmailNotAllowed):
		return ssoErrEmailNotAllowed
	}
	var signupErr SignupError
	if errors.As(err, &signupErr) {
		return ssoErrSignupProhibit
	}
	slog.Error("oidc login failed", "error", err)
	return ssoErrLoginFailed
}

// sealOIDCTx encodes the transaction and appends an HMAC over it.
//
// Signed rather than encrypted: the cookie is HttpOnly and scoped to the OIDC
// paths, so the only party who can read it is the browser it was minted for —
// which already knows its own verifier and nonce. What must not be possible is
// EDITING it, and that is what the signature prevents.
func sealOIDCTx(tx oidcTx) (string, error) {
	payload, err := json.Marshal(tx)
	if err != nil {
		return "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	return encoded + "." + base64.RawURLEncoding.EncodeToString(oidcTxSignature(encoded)), nil
}

func openOIDCTx(value string) (oidcTx, bool) {
	encoded, sig, found := strings.Cut(value, ".")
	if !found {
		return oidcTx{}, false
	}
	presented, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || !hmac.Equal(presented, oidcTxSignature(encoded)) {
		return oidcTx{}, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return oidcTx{}, false
	}
	var tx oidcTx
	if err := json.Unmarshal(payload, &tx); err != nil {
		return oidcTx{}, false
	}
	if tx.State == "" || tx.Nonce == "" || tx.Verifier == "" {
		return oidcTx{}, false
	}
	if time.Now().After(time.Unix(tx.Expires, 0)) {
		return oidcTx{}, false
	}
	return tx, true
}

func oidcTxSignature(encoded string) []byte {
	mac := hmac.New(sha256.New, auth.JWTSecret())
	// Domain separator: the JWT secret keys other HMACs in this server, and
	// without a distinct prefix one of their values could be presented here.
	mac.Write([]byte(oidcTxCookieName))
	mac.Write([]byte{0})
	mac.Write([]byte(encoded))
	return mac.Sum(nil)
}

// pkceChallenge derives the S256 code challenge for a verifier (RFC 7636 §4.2).
func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func randomURLSafe(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// sanitizeRelativePath keeps only same-origin relative destinations. It is the
// Go counterpart of sanitizeNextUrl in @multica/core/auth, and the reason the
// provider round trip cannot turn `next` into an off-site redirect.
func sanitizeRelativePath(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > maxOIDCNextLen {
		return ""
	}
	// "//host" and "/\host" are both read as protocol-relative URLs by
	// browsers despite starting with a single slash.
	if !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") || strings.HasPrefix(raw, "/\\") {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "" || u.Host != "" {
		return ""
	}
	return raw
}

func capString(raw string, max int) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > max {
		return ""
	}
	return raw
}
