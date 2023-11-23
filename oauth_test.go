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
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/jose"
	"github.com/coreos/go-oidc/oauth2"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/stretchr/testify/assert"
)

type fakeAuthServer struct {
	location   *url.URL
	key        jose.JWK
	signer     jose.Signer
	server     *httptest.Server
	expiration time.Duration
}

const fakePrivateKey = `
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAv9mli75MZ7KMVlTYkc3uiaXDz4Dd94RQ3bW8FqoEVAWCWgSI
fotNKkaqkym6t0aWHiolkPjFCUDb5QGoEx2CLw7eRMez8lDFiqlRGYrO5QXM04Qr
s3nXxB3QZUrS01gkIra9PuXl9EGvzwjH99IgOC6B0dsWDGqvo4b7ucWCzAw/raoz
jKyHXZ94Rbax0URXUNs+H13uqAX6XgEwJWhsvcbxY1cE8txwOFrvqLAJw5eXdT2M
04WeW7KWzVa1aADzBVZzv/hDYdURhxMy+h2/SQnSaXRTWKoupnQVAYdb56oaVgkW
UGgq+xC+UXe68yKZhie7FtzKQAqIuXcw69jZswIDAQABAoIBAQCHZicU+ihYY0Xy
RA1Y0fsRAIGyuCNv5d1grDtjz3ggiIbX2y0uCkhalucZ17CkWtfl0B8VMs1022aW
OFYTr5bKeXbbGgpg8SqJ0zeejD26mx5VBYoGL+7cxaHnayhh6moOaeQkOQLTIWzf
9DWVLKJ6pDARGMt11fHBuql8Ee5e7Ofvahe++8w60KZBbwmyJOgPd4c3PCMyzRrp
y5HGJIuus1/mzhv8d73dC/zNThiEK9NR0Yhvv1iqzJKNcaMlGhk4lQva6gSx+wUc
WVba7t3hMdmO9QPjU7jE3CM4AZTCR9qK8wSwxG963GXmYHLbZBhI4qxSHpUuBSoU
UmbnX3oZAoGBAPNgdNWB+2tm8F8whz5oQbC0khloC0gtTGj/LdlsOapQQ5M+uIZ+
VxUz6azUtxxbV5BrRhrBeGoCcFwXwZAnd9BTXIXLVWTbhy3fkUwx0tJ6TKxxw2hi
xULWVAZNjpaJmdjjdmAri/0N7I2QrEdm4LsChd7ODN5lzZvpAsQlMlDnAoGBAMnN
BdyJ5QNf7xc2J4Y4zf3okA/wmxe0Y9jJQxxEQ6d7ro7MWyGg1AwSCs1W9uh9qYot
JXzsM1CNlrRllPcTr6DLuPtmWVBw/zerkUU7WeRgtYGTHvu09PRxq1QdJQoWheuh
xq30JdciRTZVWgrhcBHcRDMqOkD2g2StoJdW83tVAoGBAKGREB7JWpIzVTGsMqxg
Y/Od/Dt3kb3JrKcreFGVgjapcCLpCXDnoIIH44ID+MePb/ME9BZBB+JAWj0Y3DwJ
p4WaQZrkoH0DK5tthrSxgsaNwCbeox3CLDgxtrg0dotDL+oHHwe7AQTuYHKeb3A7
QMeFZj/CRFLD/JobNuXl16BTAoGAYGG4q/V8WNlH8zkdNYEJ+XxK2iIboP26Nn8h
u21rNqHe5Dr8R5ptzHoNiLdBZBcok2MupXSWqaGGWhCuTjeryUujxQbEH6RocOlT
j9JiA66g4gsnYCa0W8+yeZEV8LSDL+BraQfTzuWCUwn+4HV9tjoSpLFFc2OJq9s1
eTLBRaUCgYB6CdSs9SAOCCrUDeIBNHJpwBWvJCJaArmlqLtaA581gQve8PcllbWp
qIBQBaRrMeZWV60BfLPce/UqgBWz9KyXF/ojaqJWsAU2rR9Iqg9aFiJikU8pbNMy
oUyyKIVH06NHwQXPZoH5bGlH9MojBOvNEb3BDQsJLnJ0mMpPNHH1sg==
-----END RSA PRIVATE KEY-----
`

type fakeDiscoveryResponse struct {
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`
	EndSessionEndpoint               string   `json:"end_session_endpoint"`
	GrantTypesSupported              []string `json:"grant_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	Issuer                           string   `json:"issuer"`
	JwksURI                          string   `json:"jwks_uri"`
	RegistrationEndpoint             string   `json:"registration_endpoint"`
	ResponseModesSupported           []string `json:"response_modes_supported"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	TokenEndpoint                    string   `json:"token_endpoint"`
	TokenIntrospectionEndpoint       string   `json:"token_introspection_endpoint"`
	UserinfoEndpoint                 string   `json:"userinfo_endpoint"`
}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

// newFakeAuthServer simulates a oauth service
func newFakeAuthServer() *fakeAuthServer {
	// step: load the private key
	block, _ := pem.Decode([]byte(fakePrivateKey))
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic("failed to parse the private key, error: " + err.Error())
	}
	service := &fakeAuthServer{
		key: jose.JWK{
			ID:       "test-kid",
			Type:     "RSA",
			Alg:      "RS256",
			Use:      "sig",
			Exponent: privateKey.PublicKey.E,
			Modulus:  privateKey.PublicKey.N,
			Secret:   block.Bytes,
		},
		signer: jose.NewSignerRSA("test-kid", *privateKey),
	}

	r := chi.NewRouter()
	r.Use(middleware.Recoverer)
	r.Get("/auth/realms/hod-test/.well-known/openid-configuration", service.discoveryHandler)
	r.Get("/auth/realms/hod-test/protocol/openid-connect/certs", service.keysHandler)
	r.Get("/auth/realms/hod-test/protocol/openid-connect/token", service.tokenHandler)
	r.Get("/auth/realms/hod-test/protocol/openid-connect/auth", service.authHandler)
	r.Get("/auth/realms/hod-test/protocol/openid-connect/userinfo", service.userInfoHandler)
	r.Post("/auth/realms/hod-test/protocol/openid-connect/logout", service.logoutHandler)
	r.Post("/auth/realms/hod-test/protocol/openid-connect/token", service.tokenHandler)

	service.server = httptest.NewServer(r)
	location, err := url.Parse(service.server.URL)
	if err != nil {
		panic("unable to create fake oauth service, error: " + err.Error())
	}
	service.location = location
	service.expiration = time.Duration(1) * time.Hour

	return service
}

func (r *fakeAuthServer) Close() {
	r.server.Close()
}

func (r *fakeAuthServer) getLocation() string {
	return fmt.Sprintf("%s://%s/auth/realms/hod-test", r.location.Scheme, r.location.Host)
}

func (r *fakeAuthServer) getRevocationURL() string {
	return fmt.Sprintf("%s://%s/auth/realms/hod-test/protocol/openid-connect/logout", r.location.Scheme, r.location.Host)
}

func (r *fakeAuthServer) signToken(claims jose.Claims) (*jose.JWT, error) {
	return jose.NewSignedJWT(claims, r.signer)
}

func (r *fakeAuthServer) setTokenExpiration(tm time.Duration) *fakeAuthServer {
	r.expiration = tm
	return r
}

func (r *fakeAuthServer) discoveryHandler(w http.ResponseWriter, req *http.Request) {
	renderJSON(http.StatusOK, w, req, fakeDiscoveryResponse{
		AuthorizationEndpoint:            fmt.Sprintf("http://%s/auth/realms/hod-test/protocol/openid-connect/auth", r.location.Host),
		EndSessionEndpoint:               fmt.Sprintf("http://%s/auth/realms/hod-test/protocol/openid-connect/logout", r.location.Host),
		Issuer:                           fmt.Sprintf("http://%s/auth/realms/hod-test", r.location.Host),
		JwksURI:                          fmt.Sprintf("http://%s/auth/realms/hod-test/protocol/openid-connect/certs", r.location.Host),
		RegistrationEndpoint:             fmt.Sprintf("http://%s/auth/realms/hod-test/clients-registrations/openid-connect", r.location.Host),
		TokenEndpoint:                    fmt.Sprintf("http://%s/auth/realms/hod-test/protocol/openid-connect/token", r.location.Host),
		TokenIntrospectionEndpoint:       fmt.Sprintf("http://%s/auth/realms/hod-test/protocol/openid-connect/token/introspect", r.location.Host),
		UserinfoEndpoint:                 fmt.Sprintf("http://%s/auth/realms/hod-test/protocol/openid-connect/userinfo", r.location.Host),
		GrantTypesSupported:              []string{"authorization_code", "implicit", "refresh_token", "password", "client_credentials"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
		ResponseModesSupported:           []string{"query", "fragment", "form_post"},
		ResponseTypesSupported:           []string{"code", "none", "id_token", "token", "id_token token", "code id_token", "code token", "code id_token token"},
		SubjectTypesSupported:            []string{"public"},
	})
}

func (r *fakeAuthServer) keysHandler(w http.ResponseWriter, req *http.Request) {
	renderJSON(http.StatusOK, w, req, jose.JWKSet{Keys: []jose.JWK{r.key}})
}

func (r *fakeAuthServer) authHandler(w http.ResponseWriter, req *http.Request) {
	state := req.URL.Query().Get("state")
	redirect := req.URL.Query().Get("redirect_uri")
	if redirect == "" {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if state == "" {
		state = "/"
	}
	redirectionURL := fmt.Sprintf("%s?state=%s&code=%s", redirect, state, getRandomString(32))

	http.Redirect(w, req, redirectionURL, http.StatusTemporaryRedirect)
}

func (r *fakeAuthServer) logoutHandler(w http.ResponseWriter, req *http.Request) {
	if refreshToken := req.FormValue("refresh_token"); refreshToken == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (r *fakeAuthServer) userInfoHandler(w http.ResponseWriter, req *http.Request) {
	items := strings.Split(req.Header.Get("Authorization"), " ")
	if len(items) != 2 {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	decoded, err := jose.ParseJWT(items[1])
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	claims, err := decoded.Claims()
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	renderJSON(http.StatusOK, w, req, map[string]interface{}{
		"sub":                claims["sub"],
		"name":               claims["name"],
		"given_name":         claims["given_name"],
		"family_name":        claims["familty_name"],
		"preferred_username": claims["preferred_username"],
		"email":              claims["email"],
		"picture":            claims["picture"],
	})
}

func (r *fakeAuthServer) makeToken(newJTI ...bool) (*jose.JWT, time.Time, error) {
	expires := time.Now().Add(r.expiration)
	unsigned := newTestToken(r.getLocation())
	unsigned.setExpiration(expires)

	if len(newJTI) > 0 && newJTI[0] {
		// generates new jti claim
		unsigned.newJTI()
	}
	// sign the token with the private key
	token, err := jose.NewSignedJWT(unsigned.claims, r.signer)
	return token, expires, err
}

func (r *fakeAuthServer) tokenHandler(w http.ResponseWriter, req *http.Request) {
	token, expires, err := r.makeToken()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	switch req.FormValue("grant_type") {
	case oauth2.GrantTypeUserCreds:
		username := req.FormValue("username")
		password := req.FormValue("password")
		if username == "" || password == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if username == validUsername && password == validPassword {
			renderJSON(http.StatusOK, w, req, tokenResponse{
				IDToken:      token.Encode(),
				AccessToken:  token.Encode(),
				RefreshToken: token.Encode(),
				ExpiresIn:    expires.UTC().Second(),
			})
			return
		}
		renderJSON(http.StatusUnauthorized, w, req, map[string]string{
			"error":             "invalid_grant",
			"error_description": "invalid user credentials",
		})
	case oauth2.GrantTypeRefreshToken:
		token, expires, _ = r.makeToken(true)
		refreshToken, _, _ := r.makeToken(true)
		renderJSON(http.StatusOK, w, req, tokenResponse{
			IDToken:      token.Encode(),
			AccessToken:  token.Encode(),
			RefreshToken: refreshToken.Encode(),
			ExpiresIn:    expires.Second(),
		})
	case oauth2.GrantTypeAuthCode:
		renderJSON(http.StatusOK, w, req, tokenResponse{
			IDToken:      token.Encode(),
			AccessToken:  token.Encode(),
			RefreshToken: token.Encode(),
			ExpiresIn:    expires.Second(),
		})
	default:
		w.WriteHeader(http.StatusBadRequest)
	}
}

func TestGetUserinfo(t *testing.T) {
	px, idp, _ := newTestProxyService(nil)
	token := newTestToken(idp.getLocation()).getToken()
	client, _ := px.client.OAuthClient()
	claims, err := getUserinfo(client, px.idp.UserInfoEndpoint.String(), token.Encode())
	assert.NoError(t, err)
	assert.NotEmpty(t, claims)
}

func TestTokenExpired(t *testing.T) {
	px, idp, _ := newTestProxyService(nil)
	token := newTestToken(idp.getLocation())
	cs := []struct {
		Expire time.Duration
		OK     bool
	}{
		{
			Expire: 1 * time.Hour,
			OK:     true,
		},
		{
			Expire: -5 * time.Hour,
		},
	}
	for i, x := range cs {
		token.setExpiration(time.Now().Add(x.Expire))
		signed, err := idp.signToken(token.claims)
		if err != nil {
			t.Errorf("case %d unable to sign the token, error: %s", i, err)
			continue
		}
		err = px.verifyToken(px.client, *signed)
		if x.OK && err != nil {
			t.Errorf("case %d, expected: %t got error: %s", i, x.OK, err)
		}
		if !x.OK && err == nil {
			t.Errorf("case %d, expected: %t got no error", i, x.OK)
		}
	}
}

func getRandomString(n int) string {
	b := make([]rune, n)
	for i := range b {
		// #nosec
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

func renderJSON(code int, w http.ResponseWriter, req *http.Request, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}
