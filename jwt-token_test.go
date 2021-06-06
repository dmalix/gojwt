package jwt

import (
	"testing"
	"time"
)

func TestJWT_SUCCESS(t *testing.T) {

	const id = "id1"
	const dataset = "dataset1"

	jwtAccess, err := NewToken(Config{
		Headers: Headers{
			Type:               TokenType,
			SignatureAlgorithm: TokenSignatureAlgorithmHS512,
		},
		Claims: Claims{
			Issuer:  "tester1",
			Subject: TokenUseAccess,
		},
		ParseOptions:     ParseOptions{},
		TokenLifetimeSec: 100,
		Key:              "secret1",
	})
	if err != nil {
		t.Errorf("the function returned the error: %s", err)
	}

	jwt, err := jwtAccess.Create(Claims{
		JwtID: id,
		Data:  []byte(dataset),
	})
	if err != nil {
		t.Errorf("the function returned the error: %s", err)
	}

	token, codeError, err := jwtAccess.Parse(jwt)
	if err != nil {
		t.Errorf("the function returned wrong error value: got '%v:%v' want '%v'", codeError, err, nil)
	}
	if token.Headers.Type != TokenType {
		t.Errorf("the function returned wrong error value: got '%v' want '%v'", token.Headers.Type, TokenType)
	}
	if token.Claims.JwtID != id {
		t.Errorf("the function returned wrong error value: got '%v' want '%v'", token.Claims.JwtID, id)
	}
	if string(token.Claims.Data) != dataset {
		t.Errorf("the function returned wrong error value: got '%v' want '%v'", string(token.Claims.Data), dataset)
	}
}

func TestJWT_FAIL(t *testing.T) {

	jwtRefresh, err := NewToken(Config{
		Headers: Headers{
			Type:               TokenType,
			SignatureAlgorithm: TokenSignatureAlgorithmHS256,
		},
		Claims: Claims{
			Issuer:  "tester2",
			Subject: TokenUseRefresh,
		},
		ParseOptions:     ParseOptions{},
		TokenLifetimeSec: 1,
		Key:              "secret2",
	})
	if err != nil {
		t.Errorf("the function returned the error: %s", err)
	}

	jwt, err := jwtRefresh.Create(Claims{
		JwtID: "id2",
		Data:  []byte("dataset2"),
	})
	if err != nil {
		t.Errorf("the function returned the error: %s", err)
	}

	time.Sleep(2 * time.Second)

	_, codeError, err := jwtRefresh.Parse(jwt)
	if err == nil && codeError != ValidationErrorClaimsExpired {
		t.Errorf("the function returned wrong error value: got '%v' want '%v: %v'",
			err, errTokenIsInvalid, ValidationErrorClaimsExpired)
	}
}
