package jose

import (
	"strings"

	"github.com/oneconcern/keycloak-gatekeeper/internal/providers"
)

type JWT JWS

func ParseJWT(token string) (jwt *JWT, err error) {
	jws, err := ParseJWS(token)
	if err != nil {
		return
	}

	return (*JWT)(jws), nil
}

func NewJWT(header JOSEHeader, claims providers.Claims) (jwt *JWT, err error) {
	jwt = &JWT{}

	jwt.Header = header
	jwt.Header[HeaderMediaType] = "JWT"

	claimBytes, err := claims.MarshalJSON()
	if err != nil {
		return
	}
	jwt.payload = claimBytes

	eh, err := encodeHeader(header)
	if err != nil {
		return
	}
	jwt.RawHeader = eh

	ec, err := encodeClaims(claims)
	if err != nil {
		return
	}
	jwt.RawPayload = ec

	return
}

func (j *JWT) Hash() string {
	panic("not implemented")
}

func (j *JWT) Payload() []byte {
	return j.payload
}

func (j *JWT) Raw() string {
	return string(j.RawPayload)
}

func (j *JWT) KeyID() (string, bool) {
	kID, ok := j.Header[HeaderKeyID]
	return kID, ok
}

func (j *JWT) Claims() (providers.Claims, error) {
	return decodeClaims(j.payload)
}

// Encoded data part of the token which may be signed.
func (j *JWT) Data() string {
	return strings.Join([]string{j.RawHeader, j.RawPayload}, ".")
}

// Full encoded JWT token string in format: header.claims.signature
func (j *JWT) Encode() string {
	d := j.Data()
	s := encodeSegment(j.Signature)
	return strings.Join([]string{d, s}, ".")
}

func NewSignedJWT(claims providers.Claims, s Signer) (*JWT, error) {
	header := JOSEHeader{
		HeaderKeyAlgorithm: s.Alg(),
		HeaderKeyID:        s.ID(),
	}

	jwt, err := NewJWT(header, claims)
	if err != nil {
		return nil, err
	}

	sig, err := s.Sign([]byte(jwt.Data()))
	if err != nil {
		return nil, err
	}
	jwt.Signature = sig

	return jwt, nil
}
