package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/pkg/timeutil"
	"github.com/jonboulle/clockwork"

	phttp "github.com/oneconcern/keycloak-gatekeeper/internal/oidc/http"
	"github.com/oneconcern/keycloak-gatekeeper/internal/oidc/oauth2"
	"github.com/oneconcern/keycloak-gatekeeper/internal/providers"
)

const (
	// Subject Identifier types defined by the OIDC spec. Specifies if the provider
	// should provide the same sub claim value to all clients (public) or a unique
	// value for each client (pairwise).
	//
	// See: http://openid.net/specs/openid-connect-core-1_0.html#SubjectIDTypes

	// SubjectTypePublic ...
	SubjectTypePublic = "public"

	// SubjectTypePairwise ...
	SubjectTypePairwise = "pairwise"
)

var (
	// Default values for omitted provider config fields.
	//
	// Use providers.ProviderConfig's Defaults method to fill a provider config with these values.

	// DefaultGrantTypesSupported ...
	DefaultGrantTypesSupported = []string{oauth2.GrantTypeAuthCode, oauth2.GrantTypeImplicit}

	// DefaultResponseModesSupported ...
	DefaultResponseModesSupported = []string{"query", "fragment"}

	// DefaultTokenEndpointAuthMethodsSupported ...
	DefaultTokenEndpointAuthMethodsSupported = []string{oauth2.AuthMethodClientSecretBasic}

	// DefaultClaimTypesSupported ...
	DefaultClaimTypesSupported = []string{"normal"}
)

const (
	// MaximumProviderConfigSyncInterval ...
	MaximumProviderConfigSyncInterval = 24 * time.Hour

	// MinimumProviderConfigSyncInterval ...
	MinimumProviderConfigSyncInterval = time.Minute

	discoveryConfigPath = "/.well-known/openid-configuration"
)

// internally configurable for tests
var minimumProviderConfigSyncInterval = MinimumProviderConfigSyncInterval

var (
	// Ensure providers.ProviderConfig satisfies these interfaces.
	_ json.Marshaler   = &ProviderConfig{}
	_ json.Unmarshaler = &ProviderConfig{}
)

// ProviderConfig ...
type ProviderConfig struct {
	providers.ProviderConfig
}

// Defaults returns a shallow copy of providers.ProviderConfig with default
// values replacing omitted fields.
//
//     var cfg oidc.ProviderConfig
//     // Fill provider config with default values for omitted fields.
//     cfg = cfg.Defaults()
//
func (p ProviderConfig) Defaults() ProviderConfig {
	setDefault := func(val *[]string, defaultVal []string) {
		if len(*val) == 0 {
			*val = defaultVal
		}
	}
	setDefault(&p.GrantTypesSupported, DefaultGrantTypesSupported)
	setDefault(&p.ResponseModesSupported, DefaultResponseModesSupported)
	setDefault(&p.TokenEndpointAuthMethodsSupported, DefaultTokenEndpointAuthMethodsSupported)
	setDefault(&p.ClaimTypesSupported, DefaultClaimTypesSupported)
	return p
}

// MarshalJSON ...
func (p *ProviderConfig) MarshalJSON() ([]byte, error) {
	e := p.toEncodableStruct()
	return json.Marshal(&e)
}

// UnmarshalJSON ...
func (p *ProviderConfig) UnmarshalJSON(data []byte) error {
	var e encodableProviderConfig
	if err := json.Unmarshal(data, &e); err != nil {
		return err
	}
	conf, err := e.toStruct()
	if err != nil {
		return err
	}
	if err := conf.Valid(); err != nil {
		return err
	}
	*p = conf
	return nil
}

type encodableProviderConfig struct {
	Issuer               string `json:"issuer"`
	AuthEndpoint         string `json:"authorization_endpoint"`
	TokenEndpoint        string `json:"token_endpoint"`
	UserInfoEndpoint     string `json:"userinfo_endpoint,omitempty"`
	KeysEndpoint         string `json:"jwks_uri"`
	RegistrationEndpoint string `json:"registration_endpoint,omitempty"`
	EndSessionEndpoint   string `json:"end_session_endpoint,omitempty"`
	CheckSessionIFrame   string `json:"check_session_iframe,omitempty"`

	// Use 'omitempty' for all slices as per OIDC spec:
	// "Claims that return multiple values are represented as JSON arrays.
	// Claims with zero elements MUST be omitted from the response."
	// http://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationResponse

	ScopesSupported        []string `json:"scopes_supported,omitempty"`
	ResponseTypesSupported []string `json:"response_types_supported,omitempty"`
	ResponseModesSupported []string `json:"response_modes_supported,omitempty"`
	GrantTypesSupported    []string `json:"grant_types_supported,omitempty"`
	ACRValuesSupported     []string `json:"acr_values_supported,omitempty"`
	SubjectTypesSupported  []string `json:"subject_types_supported,omitempty"`

	IDTokenSigningAlgValues     []string `json:"id_token_signing_alg_values_supported,omitempty"`
	IDTokenEncryptionAlgValues  []string `json:"id_token_encryption_alg_values_supported,omitempty"`
	IDTokenEncryptionEncValues  []string `json:"id_token_encryption_enc_values_supported,omitempty"`
	UserInfoSigningAlgValues    []string `json:"userinfo_signing_alg_values_supported,omitempty"`
	UserInfoEncryptionAlgValues []string `json:"userinfo_encryption_alg_values_supported,omitempty"`
	UserInfoEncryptionEncValues []string `json:"userinfo_encryption_enc_values_supported,omitempty"`
	ReqObjSigningAlgValues      []string `json:"request_object_signing_alg_values_supported,omitempty"`
	ReqObjEncryptionAlgValues   []string `json:"request_object_encryption_alg_values_supported,omitempty"`
	ReqObjEncryptionEncValues   []string `json:"request_object_encryption_enc_values_supported,omitempty"`

	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"`

	DisplayValuesSupported        []string `json:"display_values_supported,omitempty"`
	ClaimTypesSupported           []string `json:"claim_types_supported,omitempty"`
	ClaimsSupported               []string `json:"claims_supported,omitempty"`
	ServiceDocs                   string   `json:"service_documentation,omitempty"`
	ClaimsLocalsSupported         []string `json:"claims_locales_supported,omitempty"`
	UILocalsSupported             []string `json:"ui_locales_supported,omitempty"`
	ClaimsParameterSupported      bool     `json:"claims_parameter_supported,omitempty"`
	RequestParameterSupported     bool     `json:"request_parameter_supported,omitempty"`
	RequestURIParamaterSupported  bool     `json:"request_uri_parameter_supported,omitempty"`
	RequireRequestURIRegistration bool     `json:"require_request_uri_registration,omitempty"`

	Policy         string `json:"op_policy_uri,omitempty"`
	TermsOfService string `json:"op_tos_uri,omitempty"`
}

func (p ProviderConfig) toEncodableStruct() encodableProviderConfig {
	return encodableProviderConfig{
		Issuer:                                     uriToString(p.Issuer),
		AuthEndpoint:                               uriToString(p.AuthEndpoint),
		TokenEndpoint:                              uriToString(p.TokenEndpoint),
		UserInfoEndpoint:                           uriToString(p.UserInfoEndpoint),
		KeysEndpoint:                               uriToString(p.KeysEndpoint),
		RegistrationEndpoint:                       uriToString(p.RegistrationEndpoint),
		EndSessionEndpoint:                         uriToString(p.EndSessionEndpoint),
		CheckSessionIFrame:                         uriToString(p.CheckSessionIFrame),
		ScopesSupported:                            p.ScopesSupported,
		ResponseTypesSupported:                     p.ResponseTypesSupported,
		ResponseModesSupported:                     p.ResponseModesSupported,
		GrantTypesSupported:                        p.GrantTypesSupported,
		ACRValuesSupported:                         p.ACRValuesSupported,
		SubjectTypesSupported:                      p.SubjectTypesSupported,
		IDTokenSigningAlgValues:                    p.IDTokenSigningAlgValues,
		IDTokenEncryptionAlgValues:                 p.IDTokenEncryptionAlgValues,
		IDTokenEncryptionEncValues:                 p.IDTokenEncryptionEncValues,
		UserInfoSigningAlgValues:                   p.UserInfoSigningAlgValues,
		UserInfoEncryptionAlgValues:                p.UserInfoEncryptionAlgValues,
		UserInfoEncryptionEncValues:                p.UserInfoEncryptionEncValues,
		ReqObjSigningAlgValues:                     p.ReqObjSigningAlgValues,
		ReqObjEncryptionAlgValues:                  p.ReqObjEncryptionAlgValues,
		ReqObjEncryptionEncValues:                  p.ReqObjEncryptionEncValues,
		TokenEndpointAuthMethodsSupported:          p.TokenEndpointAuthMethodsSupported,
		TokenEndpointAuthSigningAlgValuesSupported: p.TokenEndpointAuthSigningAlgValuesSupported,
		DisplayValuesSupported:                     p.DisplayValuesSupported,
		ClaimTypesSupported:                        p.ClaimTypesSupported,
		ClaimsSupported:                            p.ClaimsSupported,
		ServiceDocs:                                uriToString(p.ServiceDocs),
		ClaimsLocalsSupported:                      p.ClaimsLocalsSupported,
		UILocalsSupported:                          p.UILocalsSupported,
		ClaimsParameterSupported:                   p.ClaimsParameterSupported,
		RequestParameterSupported:                  p.RequestParameterSupported,
		RequestURIParamaterSupported:               p.RequestURIParamaterSupported,
		RequireRequestURIRegistration:              p.RequireRequestURIRegistration,
		Policy:                                     uriToString(p.Policy),
		TermsOfService:                             uriToString(p.TermsOfService),
	}
}

func (e encodableProviderConfig) toStruct() (ProviderConfig, error) {
	p := stickyErrParser{}
	conf := ProviderConfig{
		ProviderConfig: providers.ProviderConfig{
			Issuer:                                     p.parseURI(e.Issuer, "issuer"),
			AuthEndpoint:                               p.parseURI(e.AuthEndpoint, "authorization_endpoint"),
			TokenEndpoint:                              p.parseURI(e.TokenEndpoint, "token_endpoint"),
			UserInfoEndpoint:                           p.parseURI(e.UserInfoEndpoint, "userinfo_endpoint"),
			KeysEndpoint:                               p.parseURI(e.KeysEndpoint, "jwks_uri"),
			RegistrationEndpoint:                       p.parseURI(e.RegistrationEndpoint, "registration_endpoint"),
			EndSessionEndpoint:                         p.parseURI(e.EndSessionEndpoint, "end_session_endpoint"),
			CheckSessionIFrame:                         p.parseURI(e.CheckSessionIFrame, "check_session_iframe"),
			ScopesSupported:                            e.ScopesSupported,
			ResponseTypesSupported:                     e.ResponseTypesSupported,
			ResponseModesSupported:                     e.ResponseModesSupported,
			GrantTypesSupported:                        e.GrantTypesSupported,
			ACRValuesSupported:                         e.ACRValuesSupported,
			SubjectTypesSupported:                      e.SubjectTypesSupported,
			IDTokenSigningAlgValues:                    e.IDTokenSigningAlgValues,
			IDTokenEncryptionAlgValues:                 e.IDTokenEncryptionAlgValues,
			IDTokenEncryptionEncValues:                 e.IDTokenEncryptionEncValues,
			UserInfoSigningAlgValues:                   e.UserInfoSigningAlgValues,
			UserInfoEncryptionAlgValues:                e.UserInfoEncryptionAlgValues,
			UserInfoEncryptionEncValues:                e.UserInfoEncryptionEncValues,
			ReqObjSigningAlgValues:                     e.ReqObjSigningAlgValues,
			ReqObjEncryptionAlgValues:                  e.ReqObjEncryptionAlgValues,
			ReqObjEncryptionEncValues:                  e.ReqObjEncryptionEncValues,
			TokenEndpointAuthMethodsSupported:          e.TokenEndpointAuthMethodsSupported,
			TokenEndpointAuthSigningAlgValuesSupported: e.TokenEndpointAuthSigningAlgValuesSupported,
			DisplayValuesSupported:                     e.DisplayValuesSupported,
			ClaimTypesSupported:                        e.ClaimTypesSupported,
			ClaimsSupported:                            e.ClaimsSupported,
			ServiceDocs:                                p.parseURI(e.ServiceDocs, "service_documentation"),
			ClaimsLocalsSupported:                      e.ClaimsLocalsSupported,
			UILocalsSupported:                          e.UILocalsSupported,
			ClaimsParameterSupported:                   e.ClaimsParameterSupported,
			RequestParameterSupported:                  e.RequestParameterSupported,
			RequestURIParamaterSupported:               e.RequestURIParamaterSupported,
			RequireRequestURIRegistration:              e.RequireRequestURIRegistration,
			Policy:                                     p.parseURI(e.Policy, "op_policy-uri"),
			TermsOfService:                             p.parseURI(e.TermsOfService, "op_tos_uri"),
		},
	}
	if p.firstErr != nil {
		return ProviderConfig{}, p.firstErr
	}
	return conf, nil
}

// Empty returns if a providers.ProviderConfig holds no information.
//
// This case generally indicates a providers.ProviderConfigGetter has experienced an error
// and has nothing to report.
func (p ProviderConfig) Empty() bool {
	return p.Issuer == nil
}

func contains(sli []string, ele string) bool {
	for _, s := range sli {
		if s == ele {
			return true
		}
	}
	return false
}

// Valid determines if a providers.ProviderConfig conforms with the OIDC specification.
// If Valid returns successfully it guarantees required field are non-nil and
// URLs are well formed.
//
// Valid is called by UnmarshalJSON.
//
// NOTE(ericchiang): For development purposes Valid does not mandate 'https' for
// URLs fields where the OIDC spec requires it. This may change in future releases
// of this package. See: https://github.com/oneconcern/keycloak-gatekeeper/internal/oidc/issues/34
func (p ProviderConfig) Valid() error {
	grantTypes := p.GrantTypesSupported
	if len(grantTypes) == 0 {
		grantTypes = DefaultGrantTypesSupported
	}
	implicitOnly := true
	for _, grantType := range grantTypes {
		if grantType != oauth2.GrantTypeImplicit {
			implicitOnly = false
			break
		}
	}

	if len(p.SubjectTypesSupported) == 0 {
		return errors.New("missing required field subject_types_supported")
	}
	if len(p.IDTokenSigningAlgValues) == 0 {
		return errors.New("missing required field id_token_signing_alg_values_supported")
	}

	if len(p.ScopesSupported) != 0 && !contains(p.ScopesSupported, "openid") {
		return errors.New("scoped_supported must be unspecified or include 'openid'")
	}

	if !contains(p.IDTokenSigningAlgValues, "RS256") {
		return errors.New("id_token_signing_alg_values_supported must include 'RS256'")
	}

	uris := []struct {
		val      *url.URL
		name     string
		required bool
	}{
		{p.Issuer, "issuer", true},
		{p.AuthEndpoint, "authorization_endpoint", true},
		{p.TokenEndpoint, "token_endpoint", !implicitOnly},
		{p.UserInfoEndpoint, "userinfo_endpoint", false},
		{p.KeysEndpoint, "jwks_uri", true},
		{p.RegistrationEndpoint, "registration_endpoint", false},
		{p.EndSessionEndpoint, "end_session_endpoint", false},
		{p.CheckSessionIFrame, "check_session_iframe", false},
		{p.ServiceDocs, "service_documentation", false},
		{p.Policy, "op_policy_uri", false},
		{p.TermsOfService, "op_tos_uri", false},
	}

	for _, uri := range uris {
		if uri.val == nil {
			if !uri.required {
				continue
			}
			return fmt.Errorf("empty value for required uri field %s", uri.name)
		}
		if uri.val.Host == "" {
			return fmt.Errorf("no host for uri field %s", uri.name)
		}
		if uri.val.Scheme != "http" && uri.val.Scheme != "https" {
			return fmt.Errorf("uri field %s schemeis not http or https", uri.name)
		}
	}
	return nil
}

/*
// Supports determines if provider supports a client given their respective metadata.
func (p ProviderConfig) Supports(c oidc.ClientMetadata) error {
	if err := p.Valid(); err != nil {
		return fmt.Errorf("invalid provider config: %v", err)
	}
	if err := c.Valid(); err != nil {
		return fmt.Errorf("invalid client config: %v", err)
	}

	// Fill default values for omitted fields
	c = c.Defaults()
	p = p.Defaults()

	// Do the supported values list the requested one?
	supports := []struct {
		supported []string
		requested string
		name      string
	}{
		{p.IDTokenSigningAlgValues, c.IDTokenResponseOptions.SigningAlg, "id_token_signed_response_alg"},
		{p.IDTokenEncryptionAlgValues, c.IDTokenResponseOptions.EncryptionAlg, "id_token_encryption_response_alg"},
		{p.IDTokenEncryptionEncValues, c.IDTokenResponseOptions.EncryptionEnc, "id_token_encryption_response_enc"},
		{p.UserInfoSigningAlgValues, c.UserInfoResponseOptions.SigningAlg, "userinfo_signed_response_alg"},
		{p.UserInfoEncryptionAlgValues, c.UserInfoResponseOptions.EncryptionAlg, "userinfo_encryption_response_alg"},
		{p.UserInfoEncryptionEncValues, c.UserInfoResponseOptions.EncryptionEnc, "userinfo_encryption_response_enc"},
		{p.ReqObjSigningAlgValues, c.RequestObjectOptions.SigningAlg, "request_object_signing_alg"},
		{p.ReqObjEncryptionAlgValues, c.RequestObjectOptions.EncryptionAlg, "request_object_encryption_alg"},
		{p.ReqObjEncryptionEncValues, c.RequestObjectOptions.EncryptionEnc, "request_object_encryption_enc"},
	}
	for _, field := range supports {
		if field.requested == "" {
			continue
		}
		if !contains(field.supported, field.requested) {
			return fmt.Errorf("provider does not support requested value for field %s", field.name)
		}
	}

	stringsEqual := func(s1, s2 string) bool { return s1 == s2 }

	// For lists, are the list of requested values a subset of the supported ones?
	supportsAll := []struct {
		supported []string
		requested []string
		name      string
		// OAuth2.0 response_type can be space separated lists where order doesn't matter.
		// For example "id_token token" is the same as "token id_token"
		// Support a custom compare method.
		comp func(s1, s2 string) bool
	}{
		{p.GrantTypesSupported, c.GrantTypes, "grant_types", stringsEqual},
		{p.ResponseTypesSupported, c.ResponseTypes, "response_type", oauth2.ResponseTypesEqual},
	}
	for _, field := range supportsAll {
	requestLoop:
		for _, req := range field.requested {
			for _, sup := range field.supported {
				if field.comp(req, sup) {
					continue requestLoop
				}
			}
			return fmt.Errorf("provider does not support requested value for field %s", field.name)
		}
	}

	// TODO(ericchiang): Are there more checks we feel comfortable with begin strict about?

	return nil
}
*/

// SupportsGrantType ...
func (p ProviderConfig) SupportsGrantType(grantType string) bool {
	var supported []string
	if len(p.GrantTypesSupported) == 0 {
		supported = DefaultGrantTypesSupported
	} else {
		supported = p.GrantTypesSupported
	}

	for _, t := range supported {
		if t == grantType {
			return true
		}
	}
	return false
}

// ProviderConfigGetter ...
type ProviderConfigGetter interface {
	Get() (providers.ProviderConfig, error)
}

// ProviderConfigSetter ...
type ProviderConfigSetter interface {
	Set(providers.ProviderConfig) error
}

// ProviderConfigSyncer ...
type ProviderConfigSyncer struct {
	from  ProviderConfigGetter
	to    ProviderConfigSetter
	clock clockwork.Clock

	initialSyncDone bool
	initialSyncWait sync.WaitGroup
}

// NewProviderConfigSyncer ...
func NewProviderConfigSyncer(from ProviderConfigGetter, to ProviderConfigSetter) *ProviderConfigSyncer {
	return &ProviderConfigSyncer{
		from:  from,
		to:    to,
		clock: clockwork.NewRealClock(),
	}
}

// Run ...
func (s *ProviderConfigSyncer) Run() chan struct{} {
	stop := make(chan struct{})

	var next pcsStepper
	next = &pcsStepNext{aft: time.Duration(0)}

	s.initialSyncWait.Add(1)
	go func() {
		for {
			select {
			case <-s.clock.After(next.after()):
				next = next.step(s.sync)
			case <-stop:
				return
			}
		}
	}()

	return stop
}

func (s *ProviderConfigSyncer) WaitUntilInitialSync() {
	s.initialSyncWait.Wait()
}

func (s *ProviderConfigSyncer) sync() (time.Duration, error) {
	cfg, err := s.from.Get()
	if err != nil {
		return 0, err
	}

	if err = s.to.Set(cfg); err != nil {
		return 0, fmt.Errorf("error setting provider config: %v", err)
	}

	if !s.initialSyncDone {
		s.initialSyncWait.Done()
		s.initialSyncDone = true
	}

	return nextSyncAfter(cfg.ExpiresAt, s.clock), nil
}

type pcsStepFunc func() (time.Duration, error)

type pcsStepper interface {
	after() time.Duration
	step(pcsStepFunc) pcsStepper
}

type pcsStepNext struct {
	aft time.Duration
}

func (n *pcsStepNext) after() time.Duration {
	return n.aft
}

func (n *pcsStepNext) step(fn pcsStepFunc) (next pcsStepper) {
	ttl, err := fn()
	if err == nil {
		next = &pcsStepNext{aft: ttl}
	} else {
		next = &pcsStepRetry{aft: time.Second}
		log.Printf("go-oidc: provider config sync failed, retrying in %v: %v", next.after(), err)
	}
	return
}

type pcsStepRetry struct {
	aft time.Duration
}

func (r *pcsStepRetry) after() time.Duration {
	return r.aft
}

func (r *pcsStepRetry) step(fn pcsStepFunc) (next pcsStepper) {
	ttl, err := fn()
	if err == nil {
		next = &pcsStepNext{aft: ttl}
	} else {
		next = &pcsStepRetry{aft: timeutil.ExpBackoff(r.aft, time.Minute)}
		log.Printf("go-oidc: provider config sync failed, retrying in %v: %v", next.after(), err)
	}
	return
}

func nextSyncAfter(exp time.Time, clock clockwork.Clock) time.Duration {
	if exp.IsZero() {
		return MaximumProviderConfigSyncInterval
	}

	t := exp.Sub(clock.Now()) / 2
	if t > MaximumProviderConfigSyncInterval {
		t = MaximumProviderConfigSyncInterval
	} else if t < minimumProviderConfigSyncInterval {
		t = minimumProviderConfigSyncInterval
	}

	return t
}

type httpProviderConfigGetter struct {
	hc        phttp.Client
	issuerURL string
	clock     clockwork.Clock
}

func NewHTTPProviderConfigGetter(hc phttp.Client, issuerURL string) *httpProviderConfigGetter {
	return &httpProviderConfigGetter{
		hc:        hc,
		issuerURL: issuerURL,
		clock:     clockwork.NewRealClock(),
	}
}

func (r *httpProviderConfigGetter) Get() (providers.ProviderConfig, error) {
	// If the Issuer value contains a path component, any terminating / MUST be removed before
	// appending /.well-known/openid-configuration.
	// https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest
	var err error
	cfg := ProviderConfig{}

	discoveryURL := strings.TrimSuffix(r.issuerURL, "/") + discoveryConfigPath
	req, err := http.NewRequest("GET", discoveryURL, nil)
	if err != nil {
		return cfg.ProviderConfig, err
	}

	resp, err := r.hc.Do(req)
	if err != nil {
		return cfg.ProviderConfig, err
	}
	defer resp.Body.Close()

	if err = json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		return cfg.ProviderConfig, err
	}

	var ttl time.Duration
	var ok bool
	ttl, ok, err = phttp.Cacheable(resp.Header)
	if err != nil {
		return cfg.ProviderConfig, err
	} else if ok {
		cfg.ExpiresAt = r.clock.Now().UTC().Add(ttl)
	}

	// The issuer value returned MUST be identical to the Issuer URL that was directly used to retrieve the configuration information.
	// http://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationValidation
	if !urlEqual(cfg.Issuer.String(), r.issuerURL) {
		err = fmt.Errorf(`"issuer" in config (%v) does not match provided issuer URL (%v)`, cfg.Issuer, r.issuerURL)
		return cfg.ProviderConfig, err
	}

	return cfg.ProviderConfig, nil
}

func FetchProviderConfig(hc phttp.Client, issuerURL string) (providers.ProviderConfig, error) {
	if hc == nil {
		hc = http.DefaultClient
	}

	g := NewHTTPProviderConfigGetter(hc, issuerURL)
	return g.Get()
}

func WaitForProviderConfig(hc phttp.Client, issuerURL string) (pcfg ProviderConfig) {
	return waitForProviderConfig(hc, issuerURL, clockwork.NewRealClock())
}

func waitForProviderConfig(hc phttp.Client, issuerURL string, clock clockwork.Clock) (pcfg ProviderConfig) {
	var sleep time.Duration
	var err error
	for {
		pcfg.ProviderConfig, err = FetchProviderConfig(hc, issuerURL)
		if err == nil {
			break
		}

		sleep = timeutil.ExpBackoff(sleep, time.Minute)
		fmt.Printf("Failed fetching provider config, trying again in %v: %v\n", sleep, err)
		time.Sleep(sleep)
	}

	return
}
