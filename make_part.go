package jwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

func makeHeaderPart(headers Headers) (string, error) {
	const noPadding rune = -1
	valueByte, err := json.Marshal(headers)
	if err != nil {
		return "", fmt.Errorf("failed convert the headers to JSON-format: %s", err)
	}
	headersPart := base64.URLEncoding.WithPadding(noPadding).EncodeToString(valueByte)
	return headersPart, nil
}

func makeClaimsPart(claims Claims) (string, error) {
	const noPadding rune = -1
	valueByte, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed convert the token.Claims to JSON-format: %s", err)
	}
	payloadPart := base64.URLEncoding.WithPadding(noPadding).EncodeToString(valueByte)
	return payloadPart, nil
}

