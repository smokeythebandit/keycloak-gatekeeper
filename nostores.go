//+build nostores

package main

import (
	"errors"

	"github.com/oneconcern/keycloak-gatekeeper/internal/providers"
)

func (r *Config) isStoreValid() error {
	if r.StoreURL != "" {
		return errors.New("remote stores are disabled in this build: you can't configure StoreURL")
	}
	return nil
}

func createStorage(location string) (storage, error) {
	return nil, nil
}

func (r *oauthProxy) useStore() bool {
	return false
}

func (r *oauthProxy) StoreRefreshToken(token providers.JSONWebToken, value string) error {
	return nil
}

func (r *oauthProxy) CloseStore() error {
	return nil
}

func (r *oauthProxy) GetRefreshToken(token providers.JSONWebToken) (string, error) {
	return "", nil
}

func (r *oauthProxy) DeleteRefreshToken(token providers.JSONWebToken) error {
	return nil
}
