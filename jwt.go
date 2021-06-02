package jwt

type Config struct {
	SecretKey               string
	SigningAlgorithm        string
	Issuer                  string
	Subject                 string
	AccessTokenLifetimeSec  int
	RefreshTokenLifetimeSec int
}

type jwt struct {
	config Config
}

func NewJwt(
	config Config) *jwt {
	return &jwt{
		config: config,
	}
}

const (
	ParamTypeJWT               = "JWT"
	ParamPurposeAccess         = "access"
	ParamPurposeRefresh        = "refresh"
	ParamSigningAlgorithmHS256 = "HS256"
	ParamSigningAlgorithmHS512 = "HS512"
)
