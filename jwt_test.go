package jwt

import (
	"testing"
	"time"
)

func TestMakeSignature__SUCCESS(t *testing.T) {

	const unsignedToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ0ZXN0ZXIiLCJzdWIiOiJBY2Nlc3MiLCJleHAiOjE4MjM1MDMzNDQsImlhdCI6MTYyMzUwMzM0MywianRpIjoiaWQyIiwiZGF0YSI6IlpHRjBZWE5sZERJPSJ9"
	const signature = "J6lTnsKnNVjl3qy_znq2lolFnW7sRqAo8I3Jv_ovV_0"

	sample, err := makeSignature(unsignedToken, TokenSignatureAlgorithmHS256, "secret")
	if err != nil {
		t.Errorf("the function returned wrong error value: got '%v' want '%v'",
			err, nil)
	}
	if sample != signature {
		t.Errorf("the function returned wrong error value: got '%v' want '%v'",
			sample, signature)
	}
}

func TestJwt_SUCCESS(t *testing.T) {

	const id = "id"
	const dataset = "dataset"

	jwtAccess, err := NewToken(Config{
		Headers: Headers{
			Type:               TokenType,
			SignatureAlgorithm: TokenSignatureAlgorithmHS512,
		},
		Claims: Claims{
			Issuer:  "tester",
			Subject: TokenUseAccess,
		},
		ParseOptions:     ParseOptions{},
		TokenLifetimeSec: 100,
		Key:              "secret",
	})
	if err != nil {
		t.Errorf("the function returned the error: %s", err)
	}

	jwt, err := jwtAccess.Create(Claims{
		JwtId: id,
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
	if token.Claims.JwtId != id {
		t.Errorf("the function returned wrong error value: got '%v' want '%v'", token.Claims.JwtId, id)
	}
	if string(token.Claims.Data) != dataset {
		t.Errorf("the function returned wrong error value: got '%v' want '%v'", string(token.Claims.Data), dataset)
	}
}



func TestJwt_FAIL(t *testing.T) {

	jwtRefresh, err := NewToken(Config{
		Headers: Headers{
			Type:               TokenType,
			SignatureAlgorithm: TokenSignatureAlgorithmHS256,
		},
		Claims: Claims{
			Issuer:  "tester",
			Subject: TokenUseRefresh,
		},
		ParseOptions:     ParseOptions{},
		TokenLifetimeSec: 1,
		Key:              "secret",
	})
	if err != nil {
		t.Errorf("the function returned the error: %s", err)
	}

	jwt, err := jwtRefresh.Create(Claims{
		JwtId: "id",
		Data:  []byte("dataset"),
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


func TestJwtParse_SUCCESS(t *testing.T) {

	const jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ0ZXN0ZXIyIiwic3ViIjoiQWNjZXNzIiwiZXhwIjoyNjIzNTAzMzQ0LCJpYXQiOjE2MjM1MDMzNDMsImp0aSI6ImlkMiIsImRhdGEiOiJaR0YwWVhObGREST0ifQ.ilnH-Xqkf0EdgndVpCplOkTcTDeQLMZ5ivcmfzkq_fA"

	jwtAccess, err := NewToken(Config{
		Key: "secret",
	})
	if err != nil {
		t.Errorf("the function returned the error: %s", err)
	}

	_, _, err = jwtAccess.Parse(jwt)
	if err != nil {
		t.Errorf("the function returned wrong error value: got '%v: %v' want '%v'",
			err, ValidationErrorClaimsExpired, nil)
	}
}

func TestJwtParse_FAIL1(t *testing.T) {

	const jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ0ZXN0ZXIyIiwic3ViIjoiQWNjZXNzIiwiZXhwIjoyNjIzNTAzMzQ0LCJpYXQiOjE2MjM1MDMzNDMsImp0aSI6ImlkMiIsImRhdGEiOiJaR0YwWVhObGREST0ifQ.ilnH-Xqkf0EdgndVpCplOkTcTDeQLMZ5ivcmfzkq_fA"

	jwtAccess, err := NewToken(Config{
		Key: "wrong_secret",
	})
	if err != nil {
		t.Errorf("the function returned the error: %s", err)
	}

	_, codeError, err := jwtAccess.Parse(jwt)
	if err == nil && codeError != ValidationErrorClaimsExpired {
		t.Errorf("the function returned wrong error value: got '%v' want '%v: %v'",
			err, errTokenIsInvalid, ValidationErrorClaimsExpired)
	}
}

func TestJwtParse_FAIL2(t *testing.T) {

	const jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ0ZXN0ZXIiLCJzdWIiOiJBY2Nlc3MiLCJleHAiOjE2MjM1MDM0NDMsImlhdCI6MTYyMzUwMzM0MywianRpIjoiaWQiLCJkYXRhIjoiWkdGMFlYTmxkREk9In0.1uslqn4e1Id3y84B_6zOBsA_E8a-9tXKnwXk2Wje14s"

	jwtRefresh, err := NewToken(Config{
		Key:              "secret",
	})
	if err != nil {
		t.Errorf("the function returned the error: %s", err)
	}

	_, codeError, err := jwtRefresh.Parse(jwt)
	if err == nil && codeError != ValidationErrorClaimsExpired {
		t.Errorf("the function returned wrong error value: got '%v' want '%v: %v'",
			err, errTokenIsInvalid, ValidationErrorClaimsExpired)
	}
}