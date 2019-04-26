package oidc

import (
	"fmt"
	"net/http"
	"sync"

	phttp "github.com/oneconcern/keycloak-gatekeeper/internal/oidc/http"
	"github.com/oneconcern/keycloak-gatekeeper/internal/providers"
)

type TokenRefresher interface {
	// Verify checks if the provided token is currently valid or not.
	Verify(providers.JSONWebToken) error

	// Refresh attempts to authenticate and retrieve a new token.
	Refresh() (providers.JSONWebToken, error)
}

type ClientCredsTokenRefresher struct {
	Issuer     string
	OIDCClient *Client
}

func (c *ClientCredsTokenRefresher) Verify(jwt providers.JSONWebToken) (err error) {
	_, err = VerifyClientClaims(jwt, c.Issuer)
	return
}

func (c *ClientCredsTokenRefresher) Refresh() (jwt providers.JSONWebToken, err error) {
	if err = c.OIDCClient.Healthy(); err != nil {
		err = fmt.Errorf("unable to authenticate, unhealthy OIDC client: %v", err)
		return
	}

	jwt, err = c.OIDCClient.ClientCredsToken([]string{"openid"})
	if err != nil {
		err = fmt.Errorf("unable to verify auth code with issuer: %v", err)
		return
	}

	return
}

type AuthenticatedTransport struct {
	TokenRefresher
	http.RoundTripper

	mu  sync.Mutex
	jwt providers.JSONWebToken
}

func (t *AuthenticatedTransport) verifiedJWT() (providers.JSONWebToken, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.TokenRefresher.Verify(t.jwt) == nil {
		return t.jwt, nil
	}

	jwt, err := t.TokenRefresher.Refresh()
	if err != nil {
		return nil, fmt.Errorf("unable to acquire valid JWT: %v", err)
	}

	t.jwt = jwt
	return t.jwt, nil
}

// SetJWT sets the JWT held by the Transport.
// This is useful for cases in which you want to set an initial JWT.
func (t *AuthenticatedTransport) SetJWT(jwt providers.JSONWebToken) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.jwt = jwt
}

func (t *AuthenticatedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	jwt, err := t.verifiedJWT()
	if err != nil {
		return nil, err
	}

	req := phttp.CopyRequest(r)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", jwt.Encode()))
	return t.RoundTripper.RoundTrip(req)
}
