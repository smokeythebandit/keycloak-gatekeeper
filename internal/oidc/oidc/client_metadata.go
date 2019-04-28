package oidc

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"net/url"
	"time"

	"github.com/oneconcern/keycloak-gatekeeper/internal/oidc/jose"
	"github.com/oneconcern/keycloak-gatekeeper/internal/oidc/oauth2"
)

// ClientMetadata holds metadata that the authorization server associates
// with a client identifier. The fields range from human-facing display
// strings such as client name, to items that impact the security of the
// protocol, such as the list of valid redirect URIs.
//
// See http://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
//
// TODO: support language specific claim representations
// http://openid.net/specs/openid-connect-registration-1_0.html#LanguagesAndScripts
type ClientMetadata struct {
	RedirectURIs []url.URL // Required

	// A list of OAuth 2.0 "response_type" values that the client wishes to restrict
	// itself to. Either "code", "token", or another registered extension.
	//
	// If omitted, only "code" will be used.
	ResponseTypes []string
	// A list of OAuth 2.0 grant types the client wishes to restrict itself to.
	// The grant type values used by OIDC are "authorization_code", "implicit",
	// and "refresh_token".
	//
	// If ommitted, only "authorization_code" will be used.
	GrantTypes []string
	// "native" or "web". If omitted, "web".
	ApplicationType string

	// List of email addresses.
	Contacts []mail.Address
	// Name of client to be presented to the end-user.
	ClientName string
	// URL that references a logo for the Client application.
	LogoURI *url.URL
	// URL of the home page of the Client.
	ClientURI *url.URL
	// Profile data policies and terms of use to be provided to the end user.
	PolicyURI         *url.URL
	TermsOfServiceURI *url.URL

	// URL to or the value of the client's JSON Web Key Set document.
	JWKSURI *url.URL
	JWKS    *jose.JWKSet

	// URL referencing a flie with a single JSON array of redirect URIs.
	SectorIdentifierURI *url.URL

	SubjectType string

	// Options to restrict the JWS alg and enc values used for server responses and requests.
	IDTokenResponseOptions  JWAOptions
	UserInfoResponseOptions JWAOptions
	RequestObjectOptions    JWAOptions

	// Client requested authorization method and signing options for the token endpoint.
	//
	// Defaults to "client_secret_basic"
	TokenEndpointAuthMethod     string
	TokenEndpointAuthSigningAlg string

	// DefaultMaxAge specifies the maximum amount of time in seconds before an authorized
	// user must reauthroize.
	//
	// If 0, no limitation is placed on the maximum.
	DefaultMaxAge int64
	// RequireAuthTime specifies if the auth_time claim in the ID token is required.
	RequireAuthTime bool

	// Default Authentication Context Class Reference values for authentication requests.
	DefaultACRValues []string

	// URI that a third party can use to initiate a login by the relaying party.
	//
	// See: http://openid.net/specs/openid-connect-core-1_0.html#ThirdPartyInitiatedLogin
	InitiateLoginURI *url.URL
	// Pre-registered request_uri values that may be cached by the server.
	RequestURIs []url.URL
}

// Defaults returns a shallow copy of ClientMetadata with default
// values replacing omitted fields.
func (m ClientMetadata) Defaults() ClientMetadata {
	if len(m.ResponseTypes) == 0 {
		m.ResponseTypes = []string{oauth2.ResponseTypeCode}
	}
	if len(m.GrantTypes) == 0 {
		m.GrantTypes = []string{oauth2.GrantTypeAuthCode}
	}
	if m.ApplicationType == "" {
		m.ApplicationType = "web"
	}
	if m.TokenEndpointAuthMethod == "" {
		m.TokenEndpointAuthMethod = oauth2.AuthMethodClientSecretBasic
	}
	m.IDTokenResponseOptions = m.IDTokenResponseOptions.defaults()
	m.UserInfoResponseOptions = m.UserInfoResponseOptions.defaults()
	m.RequestObjectOptions = m.RequestObjectOptions.defaults()
	return m
}

// MarshalJSON ...
func (m *ClientMetadata) MarshalJSON() ([]byte, error) {
	e := m.toEncodableStruct()
	return json.Marshal(&e)
}

// UnmarshalJSON ...
func (m *ClientMetadata) UnmarshalJSON(data []byte) error {
	var e encodableClientMetadata
	if err := json.Unmarshal(data, &e); err != nil {
		return err
	}
	meta, err := e.toStruct()
	if err != nil {
		return err
	}
	if err := meta.Valid(); err != nil {
		return err
	}
	*m = meta
	return nil
}

type encodableClientMetadata struct {
	RedirectURIs                 []string     `json:"redirect_uris"` // Required
	ResponseTypes                []string     `json:"response_types,omitempty"`
	GrantTypes                   []string     `json:"grant_types,omitempty"`
	ApplicationType              string       `json:"application_type,omitempty"`
	Contacts                     []string     `json:"contacts,omitempty"`
	ClientName                   string       `json:"client_name,omitempty"`
	LogoURI                      string       `json:"logo_uri,omitempty"`
	ClientURI                    string       `json:"client_uri,omitempty"`
	PolicyURI                    string       `json:"policy_uri,omitempty"`
	TermsOfServiceURI            string       `json:"tos_uri,omitempty"`
	JWKSURI                      string       `json:"jwks_uri,omitempty"`
	JWKS                         *jose.JWKSet `json:"jwks,omitempty"`
	SectorIdentifierURI          string       `json:"sector_identifier_uri,omitempty"`
	SubjectType                  string       `json:"subject_type,omitempty"`
	IDTokenSignedResponseAlg     string       `json:"id_token_signed_response_alg,omitempty"`
	IDTokenEncryptedResponseAlg  string       `json:"id_token_encrypted_response_alg,omitempty"`
	IDTokenEncryptedResponseEnc  string       `json:"id_token_encrypted_response_enc,omitempty"`
	UserInfoSignedResponseAlg    string       `json:"userinfo_signed_response_alg,omitempty"`
	UserInfoEncryptedResponseAlg string       `json:"userinfo_encrypted_response_alg,omitempty"`
	UserInfoEncryptedResponseEnc string       `json:"userinfo_encrypted_response_enc,omitempty"`
	RequestObjectSigningAlg      string       `json:"request_object_signing_alg,omitempty"`
	RequestObjectEncryptionAlg   string       `json:"request_object_encryption_alg,omitempty"`
	RequestObjectEncryptionEnc   string       `json:"request_object_encryption_enc,omitempty"`
	TokenEndpointAuthMethod      string       `json:"token_endpoint_auth_method,omitempty"`
	TokenEndpointAuthSigningAlg  string       `json:"token_endpoint_auth_signing_alg,omitempty"`
	DefaultMaxAge                int64        `json:"default_max_age,omitempty"`
	RequireAuthTime              bool         `json:"require_auth_time,omitempty"`
	DefaultACRValues             []string     `json:"default_acr_values,omitempty"`
	InitiateLoginURI             string       `json:"initiate_login_uri,omitempty"`
	RequestURIs                  []string     `json:"request_uris,omitempty"`
}

func (c *encodableClientMetadata) toStruct() (ClientMetadata, error) {
	p := stickyErrParser{}
	m := ClientMetadata{
		RedirectURIs:                p.parseURIs(c.RedirectURIs, "redirect_uris"),
		ResponseTypes:               c.ResponseTypes,
		GrantTypes:                  c.GrantTypes,
		ApplicationType:             c.ApplicationType,
		Contacts:                    p.parseEmails(c.Contacts, "contacts"),
		ClientName:                  c.ClientName,
		LogoURI:                     p.parseURI(c.LogoURI, "logo_uri"),
		ClientURI:                   p.parseURI(c.ClientURI, "client_uri"),
		PolicyURI:                   p.parseURI(c.PolicyURI, "policy_uri"),
		TermsOfServiceURI:           p.parseURI(c.TermsOfServiceURI, "tos_uri"),
		JWKSURI:                     p.parseURI(c.JWKSURI, "jwks_uri"),
		JWKS:                        c.JWKS,
		SectorIdentifierURI:         p.parseURI(c.SectorIdentifierURI, "sector_identifier_uri"),
		SubjectType:                 c.SubjectType,
		TokenEndpointAuthMethod:     c.TokenEndpointAuthMethod,
		TokenEndpointAuthSigningAlg: c.TokenEndpointAuthSigningAlg,
		DefaultMaxAge:               c.DefaultMaxAge,
		RequireAuthTime:             c.RequireAuthTime,
		DefaultACRValues:            c.DefaultACRValues,
		InitiateLoginURI:            p.parseURI(c.InitiateLoginURI, "initiate_login_uri"),
		RequestURIs:                 p.parseURIs(c.RequestURIs, "request_uris"),
		IDTokenResponseOptions: JWAOptions{
			c.IDTokenSignedResponseAlg,
			c.IDTokenEncryptedResponseAlg,
			c.IDTokenEncryptedResponseEnc,
		},
		UserInfoResponseOptions: JWAOptions{
			c.UserInfoSignedResponseAlg,
			c.UserInfoEncryptedResponseAlg,
			c.UserInfoEncryptedResponseEnc,
		},
		RequestObjectOptions: JWAOptions{
			c.RequestObjectSigningAlg,
			c.RequestObjectEncryptionAlg,
			c.RequestObjectEncryptionEnc,
		},
	}
	if p.firstErr != nil {
		return ClientMetadata{}, p.firstErr
	}
	return m, nil
}

// stickyErrParser parses URIs and email addresses. Once it encounters
// a parse error, subsequent calls become no-op.
type stickyErrParser struct {
	firstErr error
}

func (p *stickyErrParser) parseURI(s, field string) *url.URL {
	if p.firstErr != nil || s == "" {
		return nil
	}
	u, err := url.Parse(s)
	if err == nil {
		if u.Host == "" {
			err = errors.New("no host in URI")
		} else if u.Scheme != "http" && u.Scheme != "https" {
			err = errors.New("invalid URI scheme")
		}
	}
	if err != nil {
		p.firstErr = fmt.Errorf("failed to parse %s: %v", field, err)
		return nil
	}
	return u
}

func (p *stickyErrParser) parseURIs(s []string, field string) []url.URL {
	if p.firstErr != nil || len(s) == 0 {
		return nil
	}
	uris := make([]url.URL, len(s))
	for i, val := range s {
		if val == "" {
			p.firstErr = fmt.Errorf("invalid URI in field %s", field)
			return nil
		}
		if u := p.parseURI(val, field); u != nil {
			uris[i] = *u
		}
	}
	return uris
}

func (p *stickyErrParser) parseEmails(s []string, field string) []mail.Address {
	if p.firstErr != nil || len(s) == 0 {
		return nil
	}
	addrs := make([]mail.Address, len(s))
	for i, addr := range s {
		if addr == "" {
			p.firstErr = fmt.Errorf("invalid email in field %s", field)
			return nil
		}
		a, err := mail.ParseAddress(addr)
		if err != nil {
			p.firstErr = fmt.Errorf("invalid email in field %s: %v", field, err)
			return nil
		}
		addrs[i] = *a
	}
	return addrs
}

func (m *ClientMetadata) toEncodableStruct() encodableClientMetadata {
	return encodableClientMetadata{
		RedirectURIs:                 urisToStrings(m.RedirectURIs),
		ResponseTypes:                m.ResponseTypes,
		GrantTypes:                   m.GrantTypes,
		ApplicationType:              m.ApplicationType,
		Contacts:                     emailsToStrings(m.Contacts),
		ClientName:                   m.ClientName,
		LogoURI:                      uriToString(m.LogoURI),
		ClientURI:                    uriToString(m.ClientURI),
		PolicyURI:                    uriToString(m.PolicyURI),
		TermsOfServiceURI:            uriToString(m.TermsOfServiceURI),
		JWKSURI:                      uriToString(m.JWKSURI),
		JWKS:                         m.JWKS,
		SectorIdentifierURI:          uriToString(m.SectorIdentifierURI),
		SubjectType:                  m.SubjectType,
		IDTokenSignedResponseAlg:     m.IDTokenResponseOptions.SigningAlg,
		IDTokenEncryptedResponseAlg:  m.IDTokenResponseOptions.EncryptionAlg,
		IDTokenEncryptedResponseEnc:  m.IDTokenResponseOptions.EncryptionEnc,
		UserInfoSignedResponseAlg:    m.UserInfoResponseOptions.SigningAlg,
		UserInfoEncryptedResponseAlg: m.UserInfoResponseOptions.EncryptionAlg,
		UserInfoEncryptedResponseEnc: m.UserInfoResponseOptions.EncryptionEnc,
		RequestObjectSigningAlg:      m.RequestObjectOptions.SigningAlg,
		RequestObjectEncryptionAlg:   m.RequestObjectOptions.EncryptionAlg,
		RequestObjectEncryptionEnc:   m.RequestObjectOptions.EncryptionEnc,
		TokenEndpointAuthMethod:      m.TokenEndpointAuthMethod,
		TokenEndpointAuthSigningAlg:  m.TokenEndpointAuthSigningAlg,
		DefaultMaxAge:                m.DefaultMaxAge,
		RequireAuthTime:              m.RequireAuthTime,
		DefaultACRValues:             m.DefaultACRValues,
		InitiateLoginURI:             uriToString(m.InitiateLoginURI),
		RequestURIs:                  urisToStrings(m.RequestURIs),
	}
}

func uriToString(u *url.URL) string {
	if u == nil {
		return ""
	}
	return u.String()
}

func urisToStrings(urls []url.URL) []string {
	if len(urls) == 0 {
		return nil
	}
	sli := make([]string, len(urls))
	for i, u := range urls {
		sli[i] = u.String()
	}
	return sli
}

func emailsToStrings(addrs []mail.Address) []string {
	if len(addrs) == 0 {
		return nil
	}
	sli := make([]string, len(addrs))
	for i, addr := range addrs {
		sli[i] = addr.String()
	}
	return sli
}

// Valid determines if a ClientMetadata conforms with the OIDC specification.
//
// Valid is called by UnmarshalJSON.
//
// NOTE(ericchiang): For development purposes Valid does not mandate 'https' for
// URLs fields where the OIDC spec requires it. This may change in future releases
// of this package. See: https://github.com/oneconcern/keycloak-gatekeeper/internal/oidc/issues/34
func (m *ClientMetadata) Valid() error {
	if len(m.RedirectURIs) == 0 {
		return errors.New("zero redirect URLs")
	}

	validURI := func(u *url.URL, fieldName string) error {
		if u.Host == "" {
			return fmt.Errorf("no host for uri field %s", fieldName)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return fmt.Errorf("uri field %s scheme is not http or https", fieldName)
		}
		return nil
	}

	uris := []struct {
		val  *url.URL
		name string
	}{
		{m.LogoURI, "logo_uri"},
		{m.ClientURI, "client_uri"},
		{m.PolicyURI, "policy_uri"},
		{m.TermsOfServiceURI, "tos_uri"},
		{m.JWKSURI, "jwks_uri"},
		{m.SectorIdentifierURI, "sector_identifier_uri"},
		{m.InitiateLoginURI, "initiate_login_uri"},
	}

	for _, uri := range uris {
		if uri.val == nil {
			continue
		}
		if err := validURI(uri.val, uri.name); err != nil {
			return err
		}
	}

	uriLists := []struct {
		vals []url.URL
		name string
	}{
		{m.RedirectURIs, "redirect_uris"},
		{m.RequestURIs, "request_uris"},
	}
	for _, list := range uriLists {
		for _, uri := range list.vals {
			if err := validURI(&uri, list.name); err != nil {
				return err
			}
		}
	}

	options := []struct {
		option JWAOptions
		name   string
	}{
		{m.IDTokenResponseOptions, "id_token response"},
		{m.UserInfoResponseOptions, "userinfo response"},
		{m.RequestObjectOptions, "request_object"},
	}
	for _, option := range options {
		if err := option.option.valid(); err != nil {
			return fmt.Errorf("invalid JWA values for %s: %v", option.name, err)
		}
	}
	return nil
}

// ClientRegistrationResponse ...
type ClientRegistrationResponse struct {
	ClientID                string // Required
	ClientSecret            string
	RegistrationAccessToken string
	RegistrationClientURI   string
	// If IsZero is true, unspecified.
	ClientIDIssuedAt time.Time
	// Time at which the client_secret will expire.
	// If IsZero is true, it will not expire.
	ClientSecretExpiresAt time.Time

	ClientMetadata
}

type encodableClientRegistrationResponse struct {
	ClientID                string `json:"client_id"` // Required
	ClientSecret            string `json:"client_secret,omitempty"`
	RegistrationAccessToken string `json:"registration_access_token,omitempty"`
	RegistrationClientURI   string `json:"registration_client_uri,omitempty"`
	ClientIDIssuedAt        int64  `json:"client_id_issued_at,omitempty"`
	// Time at which the client_secret will expire, in seconds since the epoch.
	// If 0 it will not expire.
	ClientSecretExpiresAt int64 `json:"client_secret_expires_at"` // Required

	encodableClientMetadata
}

func unixToSec(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

func (c *ClientRegistrationResponse) MarshalJSON() ([]byte, error) {
	e := encodableClientRegistrationResponse{
		ClientID:                c.ClientID,
		ClientSecret:            c.ClientSecret,
		RegistrationAccessToken: c.RegistrationAccessToken,
		RegistrationClientURI:   c.RegistrationClientURI,
		ClientIDIssuedAt:        unixToSec(c.ClientIDIssuedAt),
		ClientSecretExpiresAt:   unixToSec(c.ClientSecretExpiresAt),
		encodableClientMetadata: c.ClientMetadata.toEncodableStruct(),
	}
	return json.Marshal(&e)
}

func secToUnix(sec int64) time.Time {
	if sec == 0 {
		return time.Time{}
	}
	return time.Unix(sec, 0)
}

func (c *ClientRegistrationResponse) UnmarshalJSON(data []byte) error {
	var e encodableClientRegistrationResponse
	if err := json.Unmarshal(data, &e); err != nil {
		return err
	}
	if e.ClientID == "" {
		return errors.New("no client_id in client registration response")
	}
	metadata, err := e.encodableClientMetadata.toStruct()
	if err != nil {
		return err
	}
	*c = ClientRegistrationResponse{
		ClientID:                e.ClientID,
		ClientSecret:            e.ClientSecret,
		RegistrationAccessToken: e.RegistrationAccessToken,
		RegistrationClientURI:   e.RegistrationClientURI,
		ClientIDIssuedAt:        secToUnix(e.ClientIDIssuedAt),
		ClientSecretExpiresAt:   secToUnix(e.ClientSecretExpiresAt),
		ClientMetadata:          metadata,
	}
	return nil
}
