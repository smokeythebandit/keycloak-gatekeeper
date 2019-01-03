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
	sha "crypto/sha256"
	"encoding/base64"

	jwt "github.com/dgrijalva/jwt-go"
)

// JSONWebToken represents a JWT token
type JSONWebToken struct {
	jwt.Token
}

// hash returns a hash of the encoded jwt token
func (t *JSONWebToken) Hash() string {
	hash := sha.Sum256([]byte(t.Token.Raw))
	return base64.RawStdEncoding.EncodeToString(hash[:])
}

func (t *JSONWebToken) Encode() string {
	return t.Token.Raw
}

func (t *JSONWebToken) Claims() (Claims, error) {
	return Claims{}, nil
}

// Payload yields the token payload claims as JSON
func (t *JSONWebToken) Payload() []byte {
	return nil
}

// Claims represent signed claims in a JWT
type Claims struct {
}

func (c *Claims) Get(name string) (interface{}, bool) {
	return nil, false
}

func (c *Claims) StringClaim(name string) (string, bool, error) {
	return "", false, nil
}

func (c *Claims) StringsClaim(name string) ([]string, bool, error) {
	return []string{}, false, nil
	//claims[claimResourceAccess].(map[string]interface{})
	/*
		if realmRoles, found := claims[claimRealmAccess].(map[string]interface{});
	*/
}

func (c *Claims) MapClaim(name string) (map[string]interface{}, bool, error) {
	return map[string]interface{}{}, false, nil
}

// ParseJWT parses an encoded JWT
func ParseJWT(raw string) (JSONWebToken, error) {
	return JSONWebToken{}, nil
}
