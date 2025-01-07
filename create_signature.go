package gojwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"hash"
)

func makeSignature(unsignedToken string, signatureAlgorithm EnumTokenSignatureAlgorithmId, key string) (string, error) {

	var mac hash.Hash
	const noPadding rune = -1

	switch signatureAlgorithm {
	case EnumTokenSignatureAlgorithmIdHS256:
		mac = hmac.New(sha256.New, []byte(key))
	case EnumTokenSignatureAlgorithmIdHS512:
		mac = hmac.New(sha512.New, []byte(key))
	default:
		return "", fmt.Errorf("invalid the signature algorithm: %s", signatureAlgorithm)
	}
	mac.Write([]byte(unsignedToken))
	signature := base64.URLEncoding.WithPadding(noPadding).EncodeToString(mac.Sum(nil))

	return signature, nil
}
