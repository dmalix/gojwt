package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"html"
	"time"
)

func (t *jwt) Create(sessionID string, data []byte, tokenPurpose string, issuedAt ...int64) (string, error) {

	var (
		headersBase64 string
		payloadBase64 string
		valueByte     []byte
		err           error
		jwt           string
		signature     string
		unsignedToken string
		mac           hash.Hash
		token         Token
	)
	const NoPadding rune = -1

	// Headers part

	token.Headers.Type = ParamTypeJWT
	token.Headers.SigningAlgorithm = t.config.SigningAlgorithm
	valueByte, err = json.Marshal(token.Headers)
	if err != nil {
		return "", fmt.Errorf("failed convert the token.headers to JSON-format: %s", err)
	}
	headersBase64 = base64.URLEncoding.WithPadding(NoPadding).EncodeToString(valueByte)

	// Payload part

	token.Payload.Issuer = t.config.Issuer
	token.Payload.Subject = t.config.Subject

	if tokenPurpose != ParamPurposeAccess && tokenPurpose != ParamPurposeRefresh {
		return "", fmt.Errorf("invalid the tokenPurpose param: %s", err)
	}
	token.Payload.Purpose = tokenPurpose

	token.Payload.SessionID = sessionID

	token.Payload.Data = data
	if len(issuedAt) != 0 {
		token.Payload.IssuedAt = issuedAt[0]
	} else {
		token.Payload.IssuedAt = time.Now().UTC().Unix()
	}

	valueByte, err = json.Marshal(token.Payload)
	if err != nil {
		return "", fmt.Errorf("failed convert the token.Payload to JSON-format: %s", err)
	}
	payloadBase64 = base64.URLEncoding.WithPadding(NoPadding).EncodeToString(valueByte)

	// Sign part

	unsignedToken = headersBase64 + "." + payloadBase64
	switch token.Headers.SigningAlgorithm {
	case ParamSigningAlgorithmHS256:
		mac = hmac.New(sha256.New, []byte(t.config.SecretKey))
	case ParamSigningAlgorithmHS512:
		mac = hmac.New(sha512.New, []byte(t.config.SecretKey))
	default:
		return "", fmt.Errorf("invalid algorithm: %s", err)
	}

	mac.Write([]byte(unsignedToken))
	signature = hex.EncodeToString(mac.Sum(nil))

	// Collect the JSON Web Token from the prepared parts.

	jwt =
		html.UnescapeString(headersBase64) +
			"." + html.UnescapeString(payloadBase64) +
			"." + html.UnescapeString(signature)

	return jwt, err
}
