package gojwt

import (
	"encoding/json"
	"testing"
	"time"
)

func TestMakeSignature__SUCCESS(t *testing.T) {

	const unsignedToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ0ZXN0ZXIiLCJzdWIiOiJBY2Nlc3MiLCJleHAiOjE4MjM1MDMzNDQsImlhdCI6MTYyMzUwMzM0MywianRpIjoiaWQyIiwiZGF0YSI6IlpHRjBZWE5sZERJPSJ9"
	const signature = "J6lTnsKnNVjl3qy_znq2lolFnW7sRqAo8I3Jv_ovV_0"

	sample, err := makeSignature(unsignedToken, EnumTokenSignatureAlgorithmHS256, "secret")
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

	jwtAccess, err := NewToken(&Config{
		Headers: &Headers{
			Type:               EnumTokenTypeJWT,
			SignatureAlgorithm: EnumTokenSignatureAlgorithmHS512,
		},
		Claims: &Claims{
			Issuer:  "tester",
			Subject: "Access",
		},
		ParseOptions:  ParseOptions{},
		TokenLifetime: 100,
		Key:           "secret",
	})
	if err != nil {
		t.Errorf("the function returned the error: %s", err)
	}

	jwt, err := jwtAccess.Create(&Claims{
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
	if token.Headers.Type != EnumTokenTypeJWT {
		t.Errorf("the function returned wrong error value: got '%v' want '%v'", token.Headers.Type, EnumTokenTypeJWT)
	}
	if token.Claims.JwtId != id {
		t.Errorf("the function returned wrong error value: got '%v' want '%v'", token.Claims.JwtId, id)
	}
	if string(token.Claims.Data) != dataset {
		t.Errorf("the function returned wrong error value: got '%v' want '%v'", string(token.Claims.Data), dataset)
	}
}

func TestJwt_FAIL(t *testing.T) {

	jwtRefresh, err := NewToken(&Config{
		Headers: &Headers{
			Type:               EnumTokenTypeJWT,
			SignatureAlgorithm: EnumTokenSignatureAlgorithmHS256,
		},
		Claims: &Claims{
			Issuer:  "tester",
			Subject: "Refresh",
		},
		ParseOptions: ParseOptions{
			RequiredHeaderContentType: true,
			RequiredClaimIssuer:       true,
			RequiredClaimSubject:      true,
			RequiredClaimJwtId:        true,
			RequiredClaimData:         true,
			SkipClaimsValidation:      true,
			SkipSignatureValidation:   true,
		},
		TokenLifetime: 1,
		Key:           "secret",
	})
	if err != nil {
		t.Errorf("the function returned the error: %s", err)
	}

	jwt, err := jwtRefresh.Create(&Claims{
		JwtId: "id",
		Data:  []byte("dataset"),
	})
	if err != nil {
		t.Errorf("the function returned the error: %s", err)
	}

	time.Sleep(2 * time.Second)

	_, codeError, err := jwtRefresh.Parse(jwt)
	if err == nil && codeError != EnumValidationMessageClaimsExpired {
		t.Errorf("the function returned wrong error value: got '%v' want '%v: %v'",
			err, EnumErrorInvalidToken, EnumValidationMessageClaimsExpired)
	}
}

func TestJwtParse_SUCCESS(t *testing.T) {

	const jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ0ZXN0ZXIyIiwic3ViIjoiQWNjZXNzIiwiZXhwIjoyNjIzNTAzMzQ0LCJpYXQiOjE2MjM1MDMzNDMsImp0aSI6ImlkMiIsImRhdGEiOiJaR0YwWVhObGREST0ifQ.ilnH-Xqkf0EdgndVpCplOkTcTDeQLMZ5ivcmfzkq_fA"

	jwtAccess, err := NewToken(&Config{
		Key: "secret",
	})
	if err != nil {
		t.Errorf("the function returned the error: %s", err)
	}

	_, _, err = jwtAccess.Parse(jwt)
	if err != nil {
		t.Errorf("the function returned wrong error value: got '%v: %v' want '%v'",
			err, EnumValidationMessageClaimsExpired, nil)
	}
}

func TestJwtParse_FAIL1(t *testing.T) {

	const jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ0ZXN0ZXIyIiwic3ViIjoiQWNjZXNzIiwiZXhwIjoyNjIzNTAzMzQ0LCJpYXQiOjE2MjM1MDMzNDMsImp0aSI6ImlkMiIsImRhdGEiOiJaR0YwWVhObGREST0ifQ.ilnH-Xqkf0EdgndVpCplOkTcTDeQLMZ5ivcmfzkq_fA"

	jwtAccess, err := NewToken(&Config{
		Key: "wrong_secret",
	})
	if err != nil {
		t.Errorf("the function returned the error: %s", err)
	}

	_, codeError, err := jwtAccess.Parse(jwt)
	if err == nil && codeError != EnumValidationMessageClaimsExpired {
		t.Errorf("the function returned wrong error value: got '%v' want '%v: %v'",
			err, EnumErrorInvalidToken, EnumValidationMessageClaimsExpired)
	}
}

func TestJwtParse_FAIL2(t *testing.T) {

	const jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ0ZXN0ZXIiLCJzdWIiOiJBY2Nlc3MiLCJleHAiOjE2MjM1MDM0NDMsImlhdCI6MTYyMzUwMzM0MywianRpIjoiaWQiLCJkYXRhIjoiWkdGMFlYTmxkREk9In0.1uslqn4e1Id3y84B_6zOBsA_E8a-9tXKnwXk2Wje14s"

	jwtRefresh, err := NewToken(&Config{
		Key: "secret",
	})
	if err != nil {
		t.Errorf("the function returned the error: %s", err)
	}

	_, codeError, err := jwtRefresh.Parse(jwt)
	if err == nil && codeError != EnumValidationMessageClaimsExpired {
		t.Errorf("the function returned wrong error value: got '%v' want '%v: %v'",
			err, EnumErrorInvalidToken, EnumValidationMessageClaimsExpired)
	}
}

func TestEnumTokenType_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    EnumTokenType
		wantErr bool
	}{
		{
			name:    "Valid JWT type",
			input:   `"JWT"`,
			want:    EnumTokenTypeJWT,
			wantErr: false,
		},
		{
			name:    "Invalid type",
			input:   `"INVALID"`,
			want:    "",
			wantErr: true,
		},
		{
			name:    "Empty type",
			input:   `""`,
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var typ EnumTokenType
			err := json.Unmarshal([]byte(tt.input), &typ)
			if (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && typ != tt.want {
				t.Errorf("UnmarshalJSON() got = %v, want %v", typ, tt.want)
			}
		})
	}
}

func TestEnumTokenType_MarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		input   EnumTokenType
		want    string
		wantErr bool
	}{
		{
			name:    "Marshal JWT type",
			input:   EnumTokenTypeJWT,
			want:    `"JWT"`,
			wantErr: false,
		},
		{
			name:    "Marshal empty type",
			input:   EnumTokenType(""),
			want:    `""`,
			wantErr: false,
		},
		{
			name:    "Marshal invalid type",
			input:   EnumTokenType("INVALID"),
			want:    `"INVALID"`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := json.Marshal(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("MarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if string(got) != tt.want {
				t.Errorf("MarshalJSON() got = %v, want %v", string(got), tt.want)
			}
		})
	}
}

func TestEnumTokenType_IsValid(t *testing.T) {
	tests := []struct {
		name  string
		input EnumTokenType
		want  bool
	}{
		{
			name:  "Valid JWT type",
			input: EnumTokenTypeJWT,
			want:  true,
		},
		{
			name:  "Invalid type",
			input: EnumTokenType("INVALID"),
			want:  false,
		},
		{
			name:  "Empty type",
			input: EnumTokenType(""),
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.input.IsValid(); got != tt.want {
				t.Errorf("IsValid() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEnumTokenSignatureAlgorithm_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    EnumTokenSignatureAlgorithm
		wantErr bool
	}{
		{
			name:    "Valid HS256 algorithm",
			input:   `"HS256"`,
			want:    EnumTokenSignatureAlgorithmHS256,
			wantErr: false,
		},
		{
			name:    "Valid HS512 algorithm",
			input:   `"HS512"`,
			want:    EnumTokenSignatureAlgorithmHS512,
			wantErr: false,
		},
		{
			name:    "Invalid algorithm",
			input:   `"INVALID"`,
			want:    "",
			wantErr: true,
		},
		{
			name:    "Empty algorithm",
			input:   `""`,
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var alg EnumTokenSignatureAlgorithm
			err := json.Unmarshal([]byte(tt.input), &alg)
			if (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && alg != tt.want {
				t.Errorf("UnmarshalJSON() got = %v, want %v", alg, tt.want)
			}
		})
	}
}

func TestEnumTokenSignatureAlgorithm_MarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		input   EnumTokenSignatureAlgorithm
		want    string
		wantErr bool
	}{
		{
			name:    "Marshal HS256 algorithm",
			input:   EnumTokenSignatureAlgorithmHS256,
			want:    `"HS256"`,
			wantErr: false,
		},
		{
			name:    "Marshal HS512 algorithm",
			input:   EnumTokenSignatureAlgorithmHS512,
			want:    `"HS512"`,
			wantErr: false,
		},
		{
			name:    "Marshal empty algorithm",
			input:   EnumTokenSignatureAlgorithm(""),
			want:    `""`,
			wantErr: false,
		},
		{
			name:    "Marshal invalid algorithm",
			input:   EnumTokenSignatureAlgorithm("INVALID"),
			want:    `"INVALID"`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := json.Marshal(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("MarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if string(got) != tt.want {
				t.Errorf("MarshalJSON() got = %v, want %v", string(got), tt.want)
			}
		})
	}
}

func TestEnumTokenSignatureAlgorithm_IsValid(t *testing.T) {
	tests := []struct {
		name  string
		input EnumTokenSignatureAlgorithm
		want  bool
	}{
		{
			name:  "Valid HS256 algorithm",
			input: EnumTokenSignatureAlgorithmHS256,
			want:  true,
		},
		{
			name:  "Valid HS512 algorithm",
			input: EnumTokenSignatureAlgorithmHS512,
			want:  true,
		},
		{
			name:  "Invalid algorithm",
			input: EnumTokenSignatureAlgorithm("INVALID"),
			want:  false,
		},
		{
			name:  "Empty algorithm",
			input: EnumTokenSignatureAlgorithm(""),
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.input.IsValid(); got != tt.want {
				t.Errorf("IsValid() got = %v, want %v", got, tt.want)
			}
		})
	}
}
