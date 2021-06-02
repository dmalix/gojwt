package jwt

import (
	"testing"
	"time"
)

func TestToken_success_secretBoxPlainText(t *testing.T) {

	var err error
	var token string

	jwtManager := NewJwt(Config{
		SecretKey:              "secretKey",
		SigningAlgorithm:       ParamSigningAlgorithmHS256,
		Issuer:                 "issuer",
		Subject:                "subject",
		AccessTokenLifetimeSec: 100})

	token, err = jwtManager.Create("sessionID", []byte("userData"), ParamPurposeAccess)

	if err != nil {
		t.Errorf("function returned wrong error value: got %v want %v",
			err, nil)
	}

	_, err = jwtManager.Validate(token)

	if err != nil {
		t.Errorf("function returned wrong error value: got %v want %v",
			err, nil)
	}
}

func TestToken_invalid(t *testing.T) {

	var err error
	var token string

	jwtManager := NewJwt(Config{
		SecretKey:        "secretKey",
		SigningAlgorithm: ParamSigningAlgorithmHS256,
		Issuer:           "issuer",
		Subject:          "subject"})

	token, err = jwtManager.Create("sessionID", []byte("data"), ParamPurposeAccess)

	if err != nil {
		t.Errorf("function returned wrong error value: got %v want %v",
			err, nil)
	}

	time.Sleep(1 * time.Second)

	_, err = jwtManager.Validate(token)

	if err == nil {
		t.Errorf("function returned wrong error value: got %v want %v",
			err, "!nil")
	}
}
