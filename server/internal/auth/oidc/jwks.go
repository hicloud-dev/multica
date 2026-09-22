package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// supportedAlgs are the id_token signature algorithms this server accepts.
// The list is asymmetric-only on purpose: an HMAC algorithm here would let a
// token signed with the client secret — a value shared with the provider, and
// present in more places than a private key ever is — pass verification.
var supportedAlgs = []string{
	"RS256", "RS384", "RS512",
	"PS256", "PS384", "PS512",
	"ES256", "ES384", "ES512",
}

const (
	// jwksTTL bounds how long a fetched key set is reused without asking again.
	jwksTTL = time.Hour
	// jwksMinRefresh is the floor between two fetches. Signing-key rotation
	// has to be picked up without a restart, which means an unknown `kid`
	// triggers a refetch — and that is reachable by anyone who can hand this
	// server a token, so the refetch needs a rate of its own.
	jwksMinRefresh = time.Minute
	// minRSAKeyBits rejects undersized RSA keys before one is ever used to
	// verify an identity assertion.
	minRSAKeyBits = 2048
)

// keySet caches a provider's signing keys. Keys are held as crypto public
// keys (`any`), which is what a jwt.Keyfunc returns.
type keySet struct {
	httpClient *http.Client

	mu sync.Mutex
	// byKID holds keys published with a `kid`, which is the normal case.
	byKID map[string]any
	// all holds every usable key in publication order, and serves tokens
	// whose header carries no `kid`.
	all         []any
	expiry      time.Time
	lastAttempt time.Time
}

func newKeySet(client *http.Client) *keySet {
	return &keySet{httpClient: client, byKID: map[string]any{}}
}

// candidates returns the keys a token's header points at, refreshing the cache
// when it is stale or the `kid` is one we have not seen. A token with no `kid`
// gets every published key; the caller tries each, so a provider that omits
// the header is still serviceable.
func (k *keySet) candidates(ctx context.Context, jwksURI, kid string) ([]any, error) {
	if keys, ok := k.lookup(kid); ok {
		return keys, nil
	}
	if err := k.refresh(ctx, jwksURI); err != nil {
		return nil, err
	}
	if keys, ok := k.lookup(kid); ok {
		return keys, nil
	}
	if kid == "" {
		return nil, errors.New("oidc: provider published no usable signing keys")
	}
	return nil, fmt.Errorf("oidc: no published signing key matches id_token kid %q", kid)
}

// lookup answers from cache, reporting a miss when the cache is stale.
func (k *keySet) lookup(kid string) ([]any, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if time.Now().After(k.expiry) {
		return nil, false
	}
	if kid == "" {
		if len(k.all) == 0 {
			return nil, false
		}
		return append([]any(nil), k.all...), true
	}
	key, ok := k.byKID[kid]
	if !ok {
		return nil, false
	}
	return []any{key}, true
}

func (k *keySet) refresh(ctx context.Context, jwksURI string) error {
	k.mu.Lock()
	if time.Since(k.lastAttempt) < jwksMinRefresh {
		k.mu.Unlock()
		// Not something the operator can act on — say what actually happened,
		// so a log line during a key rotation is not read as a broken provider.
		return errors.New("oidc: signing keys were refreshed moments ago and the key this token names is not among them")
	}
	k.lastAttempt = time.Now()
	k.mu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURI, nil)
	if err != nil {
		return fmt.Errorf("oidc: build JWKS request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := k.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("oidc: fetch JWKS: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return fmt.Errorf("oidc: read JWKS: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("oidc: JWKS endpoint returned HTTP %d", resp.StatusCode)
	}

	var doc struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return fmt.Errorf("oidc: parse JWKS: %w", err)
	}

	byKID := make(map[string]any, len(doc.Keys))
	all := make([]any, 0, len(doc.Keys))
	for _, entry := range doc.Keys {
		if entry.Use == "enc" {
			continue
		}
		pub, err := entry.publicKey()
		if err != nil {
			// One unusable entry must not disable the rest: providers publish
			// encryption and future-algorithm keys alongside signing ones.
			continue
		}
		all = append(all, pub)
		if entry.Kid != "" {
			byKID[entry.Kid] = pub
		}
	}
	if len(all) == 0 {
		return errors.New("oidc: JWKS contained no usable signing keys")
	}

	k.mu.Lock()
	k.byKID = byKID
	k.all = all
	k.expiry = time.Now().Add(jwksTTL)
	k.mu.Unlock()
	return nil
}

// jwk is one entry of a JSON Web Key Set (RFC 7517), limited to the key types
// the supported signature algorithms use.
type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func (k jwk) publicKey() (any, error) {
	switch k.Kty {
	case "RSA":
		return k.rsaKey()
	case "EC":
		return k.ecKey()
	default:
		return nil, fmt.Errorf("oidc: unsupported JWK key type %q", k.Kty)
	}
}

func (k jwk) rsaKey() (any, error) {
	rawN, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, fmt.Errorf("oidc: JWK modulus: %w", err)
	}
	if len(rawN) == 0 {
		return nil, errors.New("oidc: JWK modulus is empty")
	}
	rawE, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, fmt.Errorf("oidc: JWK exponent: %w", err)
	}
	// RFC 7518 §6.3.1.2 makes the exponent a big-endian integer; every real
	// one is three bytes or fewer, and Go's rsa.PublicKey holds it in an int.
	if len(rawE) == 0 || len(rawE) > 4 {
		return nil, errors.New("oidc: JWK exponent has an implausible length")
	}
	e := new(big.Int).SetBytes(rawE)
	if !e.IsInt64() || e.Int64() < 3 {
		return nil, errors.New("oidc: JWK exponent is out of range")
	}
	key := &rsa.PublicKey{N: new(big.Int).SetBytes(rawN), E: int(e.Int64())}
	if key.N.BitLen() < minRSAKeyBits {
		return nil, fmt.Errorf("oidc: RSA signing key is %d bits, below the %d-bit minimum", key.N.BitLen(), minRSAKeyBits)
	}
	return key, nil
}

func (k jwk) ecKey() (any, error) {
	var curve elliptic.Curve
	switch k.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("oidc: unsupported JWK curve %q", k.Crv)
	}
	x, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, fmt.Errorf("oidc: JWK x coordinate: %w", err)
	}
	y, err := base64.RawURLEncoding.DecodeString(k.Y)
	if err != nil {
		return nil, fmt.Errorf("oidc: JWK y coordinate: %w", err)
	}
	// RFC 7518 §6.2.1.2 fixes both coordinates at the curve's field size. A
	// length check is all that is needed: no private key is involved here, so
	// a bad point cannot leak one — it simply fails to verify.
	size := (curve.Params().BitSize + 7) / 8
	if len(x) != size || len(y) != size {
		return nil, errors.New("oidc: JWK coordinates do not match the curve size")
	}
	return &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(x),
		Y:     new(big.Int).SetBytes(y),
	}, nil
}
