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
	Has(string) bool
	Get(string) (interface{}, bool)
	GetErr(string) (interface{}, bool, error)
	StringClaim(string) (string, bool, error)
	StringsClaim(string) ([]string, bool, error)
	//MapClaim(string) (map[string]interface{}, bool, error)
	Float64Claim(string) (float64, bool, error)
	TimeClaim(string) (time.Time, bool, error)
}

// TODO:
// * session store provider
// * oidcClient provider
