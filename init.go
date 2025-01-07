package gojwt

import "fmt"

type EnumTokenSignatureAlgorithmId string

const (
	EnumTokenSignatureAlgorithmIdHS256 EnumTokenSignatureAlgorithmId = "HS256"
	EnumTokenSignatureAlgorithmIdHS512 EnumTokenSignatureAlgorithmId = "HS512"
)

type EnumTokenTypeId string

const (
	EnumTokenTypeIdJWT EnumTokenTypeId = "JWT"
)

type Config struct { // If you are using the package only for parsing, optional values can be nil
	Headers       *Headers
	Claims        *Claims
	ParseOptions  ParseOptions
	TokenLifetime int64
	Key           string
}

type jwt struct {
	config *Config
}

//goland:noinspection GoExportedFuncWithUnexportedType
func NewToken(
	config *Config) (*jwt, error) {
	if config.Key == "" {
		return &jwt{}, fmt.Errorf("param config.Key is required")
	}
	return &jwt{
		config: config,
	}, nil
}
