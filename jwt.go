package jwt

import "fmt"

const (
	TokenType                    = "JWT"
	TokenUseAccess               = "Access"
	TokenUseRefresh              = "Refresh"
	TokenSignatureAlgorithmHS256 = "HS256"
	TokenSignatureAlgorithmHS512 = "HS512"
)

type Config struct {
	Headers          Headers
	Claims           Claims
	ParseOptions     ParseOptions
	TokenLifetimeSec int
	Key              string
}

type Jwt struct {
	config *Config
}

func NewToken(
	config *Config) (*Jwt, error) {
	if config.Key == "" {
		return &Jwt{}, fmt.Errorf("param config.Key is required")
	}
	return &Jwt{
		config: config,
	}, nil
}
