package oidc

import (
	"errors"

	"github.com/oneconcern/keycloak-gatekeeper/internal/oidc/jose"
)

// JWAOptions ...
type JWAOptions struct {
	// SigningAlg specifies an JWA alg for signing JWTs.
	//
	// Specifying this field implies different actions depending on the context. It may
	// require objects be serialized and signed as a JWT instead of plain JSON, or
	// require an existing JWT object use the specified alg.
	//
	// See: http://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
	SigningAlg string
	// EncryptionAlg, if provided, specifies that the returned or sent object be stored
	// (or nested) within a JWT object and encrypted with the provided JWA alg.
	EncryptionAlg string
	// EncryptionEnc specifies the JWA enc algorithm to use with EncryptionAlg. If
	// EncryptionAlg is provided and EncryptionEnc is omitted, this field defaults
	// to A128CBC-HS256.
	//
	// If EncryptionEnc is provided EncryptionAlg must also be specified.
	EncryptionEnc string
}

func (opt JWAOptions) valid() error {
	if opt.EncryptionEnc != "" && opt.EncryptionAlg == "" {
		return errors.New("encryption encoding provided with no encryption algorithm")
	}
	return nil
}

func (opt JWAOptions) defaults() JWAOptions {
	if opt.EncryptionAlg != "" && opt.EncryptionEnc == "" {
		opt.EncryptionEnc = jose.EncA128CBCHS256
	}
	return opt
}
