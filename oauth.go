/*
Copyright 2015 All rights reserved.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/oneconcern/keycloak-gatekeeper/internal/providers"
)

// TODO make this a go error

const (
	// ErrorInvalidGrant is the error message for invalid grant
	ErrorInvalidGrant     = "invalid_grant"
	GrantTypeAuthCode     = "authorization_code"
	GrantTypeClientCreds  = "client_credentials"
	GrantTypeUserCreds    = "password"
	GrantTypeImplicit     = "implicit"
	GrantTypeRefreshToken = "refresh_token"

	AuthMethodClientSecretPost  = "client_secret_post"
	AuthMethodClientSecretBasic = "client_secret_basic"
	AuthMethodClientSecretJWT   = "client_secret_jwt"
	AuthMethodPrivateKeyJWT     = "private_key_jwt"
)

// DefaultScope is the default OIDC scope constant
var DefaultScope []string

func init() {
	DefaultScope = []string{"openid", "email", "profile"}
}

// verifyToken verify that the token in the user context is valid
// TODO: factor in providers
func verifyToken(client providers.OIDCClient, token providers.JSONWebToken) error {
	if err := client.VerifyJWT(token); err != nil {
		if strings.Contains(err.Error(), "token is expired") {
			return ErrAccessTokenExpired
		}
		return err
	}

	return nil
}

// getRefreshedToken attempts to refresh the access token, returning the parsed token, optionally with a renewed
// refresh token and the time the access and refresh tokens expire
//
// NOTE: we may be able to extract the specific (non-standard) claim refresh_expires_in and refresh_expires
// from response.RawBody.
// When not available, keycloak provides us with the same (for now) expiry value for ID token.
// TODO: factor in providers
func getRefreshedToken(client providers.OIDCClient, t string) (providers.JSONWebToken, string, time.Time, time.Duration, error) {
	cl, err := client.OAuthClient()
	if err != nil {
		return nil, "", time.Time{}, time.Duration(0), err
	}
	response, err := getToken(cl, GrantTypeRefreshToken, t)
	if err != nil {
		if strings.Contains(err.Error(), "refresh token has expired") {
			return nil, "", time.Time{}, time.Duration(0), ErrRefreshTokenExpired
		}
		return nil, "", time.Time{}, time.Duration(0), err
	}

	// extracts non-standard claims about refresh token, to get refresh token expiry
	var (
		refreshExpiresIn time.Duration
		extraClaims      struct {
			RefreshExpiresIn json.Number `json:"refresh_expires_in"`
		}
	)
	_ = json.Unmarshal(response.RawBody, &extraClaims)
	if extraClaims.RefreshExpiresIn != "" {
		if asInt, erj := extraClaims.RefreshExpiresIn.Int64(); erj == nil {
			refreshExpiresIn = time.Duration(asInt) * time.Second
		}
	}
	token, identity, err := parseToken(client, response.AccessToken)
	if err != nil {
		return nil, "", time.Time{}, time.Duration(0), err
	}

	return token, response.RefreshToken, identity.ExpiresAt(), refreshExpiresIn, nil
}

// exchangeAuthenticationCode exchanges the authentication code with the oauth server for a access token
// TODO: factor in providers
func exchangeAuthenticationCode(client providers.OAuthClient, code string) (providers.TokenResponse, error) {
	return getToken(client, GrantTypeAuthCode, code)
}

// getUserinfo is responsible for getting the userinfo from the IDP
// TODO: factor in OIDC client
func getUserinfo(client providers.OAuthClient, endpoint string, token string) (providers.Claims, error) {
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set(authorizationHeader, fmt.Sprintf("Bearer %s", token))

	resp, err := client.HttpClient().Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("token not validate by userinfo endpoint")
	}
	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return unmarshalClaims(content)
}

// getToken retrieves a code from the provider, extracts and verified the token
// TODO: factor in providers
func getToken(client providers.OAuthClient, grantType, code string) (providers.TokenResponse, error) {
	start := time.Now()
	token, err := client.RequestToken(grantType, code)
	if err != nil {
		return token, err
	}
	taken := time.Since(start).Seconds()
	switch grantType {
	case GrantTypeAuthCode:
		oauthTokensMetric.WithLabelValues("exchange").Inc()
		oauthLatencyMetric.WithLabelValues("exchange").Observe(taken)
	case GrantTypeRefreshToken:
		oauthTokensMetric.WithLabelValues("renew").Inc()
		oauthLatencyMetric.WithLabelValues("renew").Observe(taken)
	}

	return token, err
}

// parseToken retrieves the user identity from the token
// TODO: factor in providers
func parseToken(client providers.OIDCClient, t string) (providers.JSONWebToken, providers.Identity, error) {
	token, err := parseJWT(t)
	if err != nil {
		return nil, nil, err
	}
	claims, err := token.Claims()
	if err != nil {
		return nil, nil, err
	}
	identity, err := client.IdentityFromClaims(claims)
	if err != nil {
		return nil, nil, err
	}

	return token, identity, nil
}
