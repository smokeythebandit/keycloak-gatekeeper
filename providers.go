package main

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/oneconcern/keycloak-gatekeeper/internal/oidc/jose"
	"github.com/oneconcern/keycloak-gatekeeper/internal/oidc/oauth2"
	"github.com/oneconcern/keycloak-gatekeeper/internal/oidc/oidc"
	"github.com/oneconcern/keycloak-gatekeeper/internal/providers"
)

// TODO: there is no reason to manipulate 2 clients at this level: have them merged under a single interface

// getOAuthClient returns a oauth2 client from the openid client
func (r *oauthProxy) getOAuthClient(redirectionURL string) (providers.OAuthClient, error) {
	return oauth2.NewClient(r.idpClient, oauth2.Config{
		Credentials: providers.ClientCredentials{
			ID:     r.config.ClientID,
			Secret: r.config.ClientSecret,
		},
		AuthMethod:  AuthMethodClientSecretBasic,
		AuthURL:     r.idp.AuthEndpoint.String(),
		RedirectURL: redirectionURL,
		Scope:       append(r.config.Scopes, DefaultScope...),
		TokenURL:    r.idp.TokenEndpoint.String(),
	})
}

func (r *oauthProxy) getOIDCClient(hc *http.Client, config providers.ProviderConfig) (providers.OIDCClient, error) {
	client, err := oidc.NewClient(providers.ClientConfig{
		Credentials: providers.ClientCredentials{
			ID:     r.config.ClientID,
			Secret: r.config.ClientSecret,
		},
		HTTPClient:     hc,
		RedirectURL:    fmt.Sprintf("%s/oauth/callback", r.config.RedirectionURL),
		ProviderConfig: config,
		Scope:          append(r.config.Scopes, DefaultScope...),
	})
	if err != nil {
		return nil, err
	}
	return client, nil
}

// parseJWT returns a JWT from a token string
func parseJWT(token string) (providers.JSONWebToken, error) {
	return jose.ParseJWT(token)
}

func unmarshalClaims(content []byte) (providers.Claims, error) {
	var claims jose.Claims
	if err := json.Unmarshal(content, &claims); err != nil {
		return nil, err
	}
	return claims, nil
}
