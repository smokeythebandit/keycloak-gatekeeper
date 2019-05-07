package oidc

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/oneconcern/keycloak-gatekeeper/internal/oidc/config"
	"github.com/oneconcern/keycloak-gatekeeper/internal/oidc/jose"
	"github.com/oneconcern/keycloak-gatekeeper/internal/oidc/key"
	"github.com/oneconcern/keycloak-gatekeeper/internal/oidc/oauth2"
	"github.com/oneconcern/keycloak-gatekeeper/internal/providers"
)

const (
	// amount of time that must pass after the last key sync
	// completes before another attempt may begin
	keySyncWindow = 5 * time.Second
)

var (
	// DefaultScope ...
	DefaultScope = []string{"openid", "email", "profile"}

	supportedAuthMethods = map[string]struct{}{
		oauth2.AuthMethodClientSecretBasic: struct{}{},
		oauth2.AuthMethodClientSecretPost:  struct{}{},
	}
)

// ClientIdentity ...
type ClientIdentity struct {
	Credentials providers.ClientCredentials
	Metadata    ClientMetadata
}

var (
	// Ensure ClientMetadata satisfies these interfaces.
	_ json.Marshaler   = &ClientMetadata{}
	_ json.Unmarshaler = &ClientMetadata{}
)

// NewClient ...
func NewClient(cfg providers.ClientConfig) (*Client, error) {
	// Allow empty redirect URL in the case where the client
	// only needs to verify a given token.
	ru, err := url.Parse(cfg.RedirectURL)
	if err != nil {
		return nil, fmt.Errorf("invalid redirect URL: %v", err)
	}

	c := Client{
		credentials:    cfg.Credentials,
		httpClient:     cfg.HTTPClient,
		scope:          cfg.Scope,
		redirectURL:    ru.String(),
		providerConfig: newProviderConfigRepo(cfg.ProviderConfig),
		keySet:         cfg.KeySet,
	}

	if c.httpClient == nil {
		c.httpClient = http.DefaultClient
	}

	if c.scope == nil {
		c.scope = make([]string, len(DefaultScope))
		copy(c.scope, DefaultScope)
	}

	return &c, nil
}

// Client ...
type Client struct {
	httpClient     *http.Client
	providerConfig *providerConfigRepo
	credentials    providers.ClientCredentials
	redirectURL    string
	scope          []string
	keySet         providers.PublicKeySet
	providerSyncer *config.ProviderConfigSyncer

	keySetSyncMutex sync.RWMutex
	lastKeySetSync  time.Time
}

// Healthy ...
func (c *Client) Healthy() error {
	now := time.Now().UTC()

	acfg := c.providerConfig.Get()

	cfg := config.ProviderConfig{ProviderConfig: acfg}
	if cfg.Empty() {
		return errors.New("oidc client provider config empty")
	}

	if !cfg.ExpiresAt.IsZero() && cfg.ExpiresAt.Before(now) {
		return errors.New("oidc client provider config expired")
	}

	return nil
}

// IdentityFromClaims ...
func (c *Client) IdentityFromClaims(claims providers.Claims) (providers.Identity, error) {
	return IdentityFromClaims(claims)
}

// OAuthClient ...
func (c *Client) OAuthClient() (providers.OAuthClient, error) {
	cfg := c.providerConfig.Get()
	authMethod, err := chooseAuthMethod(cfg)
	if err != nil {
		return nil, err
	}

	ocfg := oauth2.Config{
		Credentials: providers.ClientCredentials(c.credentials),
		RedirectURL: c.redirectURL,
		AuthURL:     cfg.AuthEndpoint.String(),
		TokenURL:    cfg.TokenEndpoint.String(),
		Scope:       c.scope,
		AuthMethod:  authMethod,
	}

	return oauth2.NewClient(c.httpClient, ocfg)
}

func chooseAuthMethod(cfg providers.ProviderConfig) (string, error) {
	if len(cfg.TokenEndpointAuthMethodsSupported) == 0 {
		return oauth2.AuthMethodClientSecretBasic, nil
	}

	for _, authMethod := range cfg.TokenEndpointAuthMethodsSupported {
		if _, ok := supportedAuthMethods[authMethod]; ok {
			return authMethod, nil
		}
	}

	return "", errors.New("no supported auth methods")
}

// SyncProviderConfig starts the provider config syncer
func (c *Client) SyncProviderConfig(discoveryURL string) chan struct{} {
	r := config.NewHTTPProviderConfigGetter(c.httpClient, discoveryURL)
	s := config.NewProviderConfigSyncer(r, c.providerConfig)
	stop := s.Run()
	s.WaitUntilInitialSync()
	return stop
}

func (c *Client) maybeSyncKeys() error {
	tooSoon := func() bool {
		return time.Now().UTC().Before(c.lastKeySetSync.Add(keySyncWindow))
	}

	// ignore request to sync keys if a sync operation has been
	// attempted too recently
	if tooSoon() {
		return nil
	}

	c.keySetSyncMutex.Lock()
	defer c.keySetSyncMutex.Unlock()

	// check again, as another goroutine may have been holding
	// the lock while updating the keys
	if tooSoon() {
		return nil
	}

	cfg := c.providerConfig.Get()
	r := NewRemotePublicKeyRepo(c.httpClient, cfg.KeysEndpoint.String())
	w := &clientKeyRepo{client: c}
	_, err := key.Sync(r, w)
	c.lastKeySetSync = time.Now().UTC()

	return err
}

// ExchangeAuthCode exchanges an OAuth2 auth code for an OIDC JWT ID token.
func (c *Client) ExchangeAuthCode(code string) (providers.JSONWebToken, error) {
	oac, err := c.OAuthClient()
	if err != nil {
		return nil, err
	}

	t, err := oac.RequestToken(oauth2.GrantTypeAuthCode, code)
	if err != nil {
		return nil, err
	}

	jwt, err := jose.ParseJWT(t.IDToken)
	if err != nil {
		return nil, err
	}

	return jwt, c.VerifyJWT(jwt)
}

// RefreshToken uses a refresh token to exchange for a new OIDC JWT ID Token.
func (c *Client) RefreshToken(refreshToken string) (providers.JSONWebToken, error) {
	oac, err := c.OAuthClient()
	if err != nil {
		return nil, err
	}

	t, err := oac.RequestToken(oauth2.GrantTypeRefreshToken, refreshToken)
	if err != nil {
		return nil, err
	}

	jwt, err := jose.ParseJWT(t.IDToken)
	if err != nil {
		return nil, err
	}

	return jwt, c.VerifyJWT(jwt)
}

// VerifyJWT ...
func (c *Client) VerifyJWT(jwt providers.JSONWebToken) error {
	var keysFunc func() []key.PublicKey
	cjwt := jwt.(*jose.JWT)
	if KID, ok := cjwt.KeyID(); ok {
		keysFunc = c.keysFuncWithID(KID)
	} else {
		keysFunc = c.keysFuncAll()
	}

	v := NewJWTVerifier(
		c.providerConfig.Get().Issuer.String(),
		c.credentials.ID,
		c.maybeSyncKeys, keysFunc)

	return v.Verify(jwt)
}

// keysFuncWithID returns a function that retrieves at most unexpired
// public key from the Client that matches the provided ID
func (c *Client) keysFuncWithID(KID string) func() []key.PublicKey {
	return func() []key.PublicKey {
		c.keySetSyncMutex.RLock()
		defer c.keySetSyncMutex.RUnlock()

		if c.keySet.ExpiresAt().Before(time.Now()) {
			return []key.PublicKey{}
		}

		k := c.keySet.Key(KID)
		if k == nil {
			return []key.PublicKey{}
		}

		kk := k.(*key.PublicKey)
		return []key.PublicKey{*kk}
	}
}

// keysFuncAll returns a function that retrieves all unexpired public
// keys from the Client
func (c *Client) keysFuncAll() func() []key.PublicKey {
	return func() []key.PublicKey {
		c.keySetSyncMutex.RLock()
		defer c.keySetSyncMutex.RUnlock()

		if c.keySet.ExpiresAt().Before(time.Now()) {
			return []key.PublicKey{}
		}

		keys := c.keySet.Keys()
		result := make([]key.PublicKey, len(keys))
		for _, k := range keys {
			kk := k.(key.PublicKey)
			result = append(result, kk)
		}
		return result
	}
}

// ClientCredsToken ...
func (c *Client) ClientCredsToken(scope []string) (providers.JSONWebToken, error) {
	acfg := c.providerConfig.Get()

	cfg := config.ProviderConfig{ProviderConfig: acfg}
	if !cfg.SupportsGrantType(oauth2.GrantTypeClientCreds) {
		return nil, fmt.Errorf("%v grant type is not supported", oauth2.GrantTypeClientCreds)
	}

	oac, err := c.OAuthClient()
	if err != nil {
		return nil, err
	}

	t, err := oac.ClientCredsToken(scope)
	if err != nil {
		return nil, err
	}

	jwt, err := jose.ParseJWT(t.IDToken)
	if err != nil {
		return nil, err
	}

	return jwt, c.VerifyJWT(jwt)
}
