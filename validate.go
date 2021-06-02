package jwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

func (t *jwt) Validate(jwt string) (Token, error) {

	var (
		valueByte []byte
		err       error
		jwtArr    []string
		jwtSample string
		lifeTime  int
		token     Token
	)

	const messageInvalidJwtToken = "invalid JWT-token: %s"
	const NoPadding rune = -1

	jwtArr = strings.Split(jwt, ".")

	// Parse Headers
	valueByte, err = base64.URLEncoding.WithPadding(NoPadding).DecodeString(jwtArr[0])
	if err != nil {
		return Token{}, fmt.Errorf(messageInvalidJwtToken, err)
	}

	err = json.Unmarshal(valueByte, &token.Headers)
	if err != nil {
		return Token{}, fmt.Errorf(messageInvalidJwtToken, err)
	}

	// Parse Payload
	valueByte, err = base64.URLEncoding.WithPadding(NoPadding).DecodeString(jwtArr[1])
	if err != nil {
		return Token{}, fmt.Errorf(messageInvalidJwtToken, err)
	}
	err = json.Unmarshal(valueByte, &token.Payload)
	if err != nil {
		return Token{}, fmt.Errorf(messageInvalidJwtToken, err)
	}

	// Parse and validate Signature
	token.Signature = jwtArr[2]
	jwtSample, err = t.Create(token.Payload.SessionID, token.Payload.Data,
		token.Payload.Purpose, token.Payload.IssuedAt)
	if err != nil {
		return Token{}, fmt.Errorf(messageInvalidJwtToken, err)
	}
	if strings.Split(jwtSample, ".")[2] != token.Signature {
		return Token{}, fmt.Errorf(messageInvalidJwtToken, err)
	}

	// Validate Lifetime
	switch token.Payload.Purpose {
	case ParamPurposeAccess:
		lifeTime = t.config.AccessTokenLifetimeSec
	case ParamPurposeRefresh:
		lifeTime = t.config.RefreshTokenLifetimeSec
	default:
		return Token{}, fmt.Errorf(messageInvalidJwtToken, err)
	}
	if time.Now().UTC().Unix() >
		time.Unix(token.Payload.IssuedAt, 0).Add(time.Second*time.Duration(lifeTime)).UTC().Unix() {
		return Token{}, fmt.Errorf(messageInvalidJwtToken, err)
	}

	return token, nil
}
