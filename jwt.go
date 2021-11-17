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

type jwt struct {
	config *Config
}

func NewToken(
	config *Config) (*jwt, error) {
	if config.Key == "" {
		return &jwt{}, fmt.Errorf("param config.Key is required")
	}
	return &jwt{
		config: config,
	}, nil
}
