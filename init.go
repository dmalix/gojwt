package gojwt

import "fmt"

type EnumTokenSignatureAlgorithm string

const (
	EnumTokenSignatureAlgorithmHS256 EnumTokenSignatureAlgorithm = "HS256"
	EnumTokenSignatureAlgorithmHS512 EnumTokenSignatureAlgorithm = "HS512"
)

type EnumTokenType string

const (
	EnumTokenTypeJWT EnumTokenType = "JWT"
)

type Config struct { // If you are using the package only for parsing, optional values can be nil
	Headers       *Headers
	Claims        *Claims
	ParseOptions  ParseOptions
	TokenLifetime int64
	Key           string
}

type resources struct {
	config *Config
}

//goland:noinspection GoExportedFuncWithUnexportedType
func NewToken(
	config *Config) (*resources, error) {
	if config.Key == "" {
		return nil, fmt.Errorf("param config.Key is required")
	}
	return &resources{
		config: config,
	}, nil
}

func (e *EnumTokenSignatureAlgorithm) UnmarshalJSON(b []byte) error {
	// Remove quotes from string
	s := string(b[1 : len(b)-1])
	switch s {
	case string(EnumTokenSignatureAlgorithmHS256), string(EnumTokenSignatureAlgorithmHS512):
		*e = EnumTokenSignatureAlgorithm(s)
		return nil
	default:
		return fmt.Errorf("invalid signature algorithm: %s", s)
	}
}

func (e EnumTokenSignatureAlgorithm) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf("%q", string(e))), nil
}

func (e EnumTokenSignatureAlgorithm) IsValid() bool {
	switch e {
	case EnumTokenSignatureAlgorithmHS256, EnumTokenSignatureAlgorithmHS512:
		return true
	default:
		return false
	}
}

func (e *EnumTokenType) UnmarshalJSON(b []byte) error {
	// Remove quotes from string
	s := string(b[1 : len(b)-1])
	if s == string(EnumTokenTypeJWT) {
		*e = EnumTokenType(s)
		return nil
	}
	return fmt.Errorf("invalid token type: %s", s)
}

func (e EnumTokenType) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf("%q", string(e))), nil
}

func (e EnumTokenType) IsValid() bool {
	return e == EnumTokenTypeJWT
}
