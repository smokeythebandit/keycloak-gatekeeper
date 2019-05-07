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

package providers

import (
	"net/http"
	"net/url"
	"time"
)

// JWTProvider defines the expected interface for token provider
type JWTProvider interface {
	ParseJWT(JSONWebToken, error)
}

// JSONWebToken defines the expected interface for tokens
type JSONWebToken interface {
	Hash() string
	Claims() (Claims, error)
	Raw() string
	Payload() []byte
	Encode() string
}

// Claims defines the expected interface for token claims provider
type Claims interface {
	Len() int
	Has(string) bool
	Get(string) (interface{}, bool)
	GetErr(string) (interface{}, bool, error)
	StringClaim(string) (string, bool, error)
	StringsClaim(string) ([]string, bool, error)
	//MapClaim(string) (map[string]interface{}, bool, error)
	Float64Claim(string) (float64, bool, error)
	TimeClaim(string) (time.Time, bool, error)
	MarshalJSON() ([]byte, error)
}

type Identity interface {
	ID() string
	Email() string
	ExpiresAt() time.Time
}

type OAuthClient interface {
	RequestToken(string, string) (TokenResponse, error)
	ClientCredsToken(scope []string) (TokenResponse, error)
	UserCredsToken(username, password string) (TokenResponse, error)
	HttpClient() *http.Client
	AuthCodeURL(state, accessType, prompt string) string
}

type OIDCClient interface {
	VerifyJWT(JSONWebToken) error
	OAuthClient() (OAuthClient, error)
	IdentityFromClaims(Claims) (Identity, error)
	SyncProviderConfig(string) chan struct{}
}

// TODO:
// * session store provider
// * oidcClient provider

type TokenResponse struct {
	AccessToken  string
	TokenType    string
	Expires      int
	IDToken      string
	RefreshToken string // OPTIONAL.
	Scope        string // OPTIONAL, if identical to the scope requested by the client, otherwise, REQUIRED.
	RawBody      []byte // In case callers need some other non-standard info from the token response
}

type ClientConfig struct {
	HTTPClient     *http.Client
	Credentials    ClientCredentials
	Scope          []string
	RedirectURL    string
	ProviderConfig ProviderConfig
	KeySet         PublicKeySet
}

type ClientCredentials struct {
	ID     string
	Secret string
}

// ProviderConfig represents the OpenID Provider Metadata specifying what
// configurations a provider supports.
//
// See: http://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
type ProviderConfig struct {
	Issuer               *url.URL // Required
	AuthEndpoint         *url.URL // Required
	TokenEndpoint        *url.URL // Required if grant types other than "implicit" are supported
	UserInfoEndpoint     *url.URL
	KeysEndpoint         *url.URL // Required
	RegistrationEndpoint *url.URL
	EndSessionEndpoint   *url.URL
	CheckSessionIFrame   *url.URL

	// Servers MAY choose not to advertise some supported scope values even when this
	// parameter is used, although those defined in OpenID Core SHOULD be listed, if supported.
	ScopesSupported []string
	// OAuth2.0 response types supported.
	ResponseTypesSupported []string // Required
	// OAuth2.0 response modes supported.
	//
	// If omitted, defaults to DefaultResponseModesSupported.
	ResponseModesSupported []string
	// OAuth2.0 grant types supported.
	//
	// If omitted, defaults to DefaultGrantTypesSupported.
	GrantTypesSupported []string
	ACRValuesSupported  []string
	// SubjectTypesSupported specifies strategies for providing values for the sub claim.
	SubjectTypesSupported []string // Required

	// JWA signing and encryption algorith values supported for ID tokens.
	IDTokenSigningAlgValues    []string // Required
	IDTokenEncryptionAlgValues []string
	IDTokenEncryptionEncValues []string

	// JWA signing and encryption algorith values supported for user info responses.
	UserInfoSigningAlgValues    []string
	UserInfoEncryptionAlgValues []string
	UserInfoEncryptionEncValues []string

	// JWA signing and encryption algorith values supported for request objects.
	ReqObjSigningAlgValues    []string
	ReqObjEncryptionAlgValues []string
	ReqObjEncryptionEncValues []string

	TokenEndpointAuthMethodsSupported          []string
	TokenEndpointAuthSigningAlgValuesSupported []string
	DisplayValuesSupported                     []string
	ClaimTypesSupported                        []string
	ClaimsSupported                            []string
	ServiceDocs                                *url.URL
	ClaimsLocalsSupported                      []string
	UILocalsSupported                          []string
	ClaimsParameterSupported                   bool
	RequestParameterSupported                  bool
	RequestURIParamaterSupported               bool
	RequireRequestURIRegistration              bool

	Policy         *url.URL
	TermsOfService *url.URL

	// Not part of the OpenID Provider Metadata
	ExpiresAt time.Time
}

// FetchProviderConfig retrieves OIDC config
func FetchProviderConfig(hc *http.Client, issuerURL string) (ProviderConfig, error) {
	if hc == nil {
		hc = http.DefaultClient
	}

	// TODO
	return ProviderConfig{}, nil
	//g := config.NewHTTPProviderConfigGetter(hc, issuerURL)
	//return g.Get()
}

type PublicKey interface {
}

type PublicKeySet interface {
	ExpiresAt() time.Time
	Keys() []PublicKey
	Key(string) PublicKey
}
