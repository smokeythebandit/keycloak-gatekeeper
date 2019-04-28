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
	"fmt"
	"strings"
	"time"

	"github.com/oneconcern/keycloak-gatekeeper/internal/providers"
)

// extractIdentity parse the jwt token and extracts the various elements is order to construct
func extractIdentity(client providers.OIDCClient, token providers.JSONWebToken) (*userContext, error) {
	claims, err := token.Claims()
	if err != nil {
		return nil, err
	}
	identity, err := client.IdentityFromClaims(claims)
	if err != nil {
		return nil, err
	}

	// @step: ensure we have and can extract the preferred name of the user, if not, we set to the ID
	preferredName, found, err := claims.StringClaim(claimPreferredName)
	if err != nil || !found {
		preferredName = identity.Email()
	}

	var audiences []string
	aud, found, err := claims.StringClaim(claimAudience)
	if err == nil && found {
		audiences = append(audiences, aud)
	} else {
		aud, found, erc := claims.StringsClaim(claimAudience)
		if erc != nil || !found {
			return nil, ErrNoTokenAudience
		}
		audiences = aud
	}

	// @step: extract the realm roles
	// TODO: move to a keycloak specific pkg
	var roleList []string
	if raw, found := claims.Get(claimRealmAccess); found {
		if realmRoles, ok := raw.(map[string]interface{}); ok {
			if roles, found := realmRoles[claimResourceRoles]; found {
				for _, r := range roles.([]interface{}) {
					roleList = append(roleList, fmt.Sprintf("%s", r))
				}
			}
		}
	}

	// @step: extract the client roles from the access token
	// TODO: move to a keycloak specific pkg
	if raw, found := claims.Get(claimResourceAccess); found {
		if accesses, ok := raw.(map[string]interface{}); ok {
			for name, list := range accesses {
				scopes := list.(map[string]interface{})
				if roles, found := scopes[claimResourceRoles]; found {
					for _, r := range roles.([]interface{}) {
						roleList = append(roleList, fmt.Sprintf("%s:%s", name, r))
					}
				}
			}
		}
	}

	// @step: extract any group information from the tokens
	// TODO: move to a keycloak specific pkg
	groups, _, err := claims.StringsClaim(claimGroups)
	if err != nil {
		return nil, err
	}

	return &userContext{
		audiences:     audiences,
		claims:        claims,
		email:         identity.Email(),
		expiresAt:     identity.ExpiresAt(),
		groups:        groups,
		id:            identity.ID(),
		name:          preferredName,
		preferredName: preferredName,
		roles:         roleList,
		token:         token,
	}, nil
}

// backported from https://github.com/coreos/go-oidc/blob/master/oidc/verification.go#L28-L37
// I'll raise another PR to make it public in the go-oidc package so we can just use `oidc.ContainsString()`
func containsString(needle string, haystack []string) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}

// isAudience checks the audience
func (r *userContext) isAudience(aud string) bool {
	return containsString(aud, r.audiences)
}

// getRoles returns a list of roles
func (r *userContext) getRoles() string {
	return strings.Join(r.roles, ",")
}

// isExpired checks if the token has expired
func (r *userContext) isExpired() bool {
	return r.expiresAt.Before(time.Now())
}

// isBearer checks if the token
func (r *userContext) isBearer() bool {
	return r.bearerToken
}

// isCookie checks if it's by a cookie
func (r *userContext) isCookie() bool {
	return !r.isBearer()
}

// String returns a string representation of the user context
func (r *userContext) String() string {
	return fmt.Sprintf("user: %s, expires: %s, roles: %s", r.preferredName, r.expiresAt.String(), strings.Join(r.roles, ","))
}
