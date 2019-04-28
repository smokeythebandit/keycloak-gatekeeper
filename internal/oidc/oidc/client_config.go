package oidc

import (
	"errors"
	"sync"

	"github.com/oneconcern/keycloak-gatekeeper/internal/oidc/key"
	"github.com/oneconcern/keycloak-gatekeeper/internal/providers"
)

type providerConfigRepo struct {
	mu     sync.RWMutex
	config providers.ProviderConfig // do not access directly, use Get()
}

func newProviderConfigRepo(pc providers.ProviderConfig) *providerConfigRepo {
	return &providerConfigRepo{sync.RWMutex{}, pc}
}

// Set returns an error to implement providers.ProviderConfigSetter
func (r *providerConfigRepo) Set(cfg providers.ProviderConfig) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.config = cfg
	return nil
}

// Get ...
func (r *providerConfigRepo) Get() providers.ProviderConfig {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.config
}

type clientKeyRepo struct {
	client *Client
}

func (r *clientKeyRepo) Set(ks key.KeySet) error {
	pks, ok := ks.(*key.PublicKeySet)
	if !ok {
		return errors.New("unable to cast to PublicKey")
	}
	r.client.keySet = providers.PublicKeySet(pks)
	return nil
}
