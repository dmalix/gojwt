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

type Resources struct {
	config *Config
}

//goland:noinspection GoExportedFuncWithUnexportedType
func NewToken(
	config *Config) (*Resources, error) {
	if config.Key == "" {
		return nil, fmt.Errorf("param config.Key is required")
	}
	return &Resources{
		config: config,
	}, nil
}
