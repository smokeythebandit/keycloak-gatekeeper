package oidc

import (
	"errors"
	"time"

	"github.com/oneconcern/keycloak-gatekeeper/internal/providers"
)

type Identity struct {
	id        string
	name      string
	email     string
	expiresAt time.Time
}

func (i *Identity) ID() string {
	return i.id
}

func (i *Identity) Name() string {
	return i.name
}

func (i *Identity) Email() string {
	return i.email
}

func (i *Identity) ExpiresAt() time.Time {
	return i.expiresAt
}

func IdentityFromClaims(claims providers.Claims) (*Identity, error) {
	if claims == nil {
		return nil, errors.New("nil claim set")
	}

	var ident Identity
	var err error
	var ok bool

	if ident.id, ok, err = claims.StringClaim("sub"); err != nil {
		return nil, err
	} else if !ok {
		return nil, errors.New("missing required claim: sub")
	}

	if ident.email, _, err = claims.StringClaim("email"); err != nil {
		return nil, err
	}

	exp, ok, err := claims.TimeClaim("exp")
	if err != nil {
		return nil, err
	} else if ok {
		ident.expiresAt = exp
	}

	return &ident, nil
}
