package jwt

type Token struct {
	Headers   Headers
	Claims    Claims
	Signature string
}

type Headers struct {
	Type               string `json:"typ,omitempty"`
	SignatureAlgorithm string `json:"alg,omitempty"`
	ContentType        string `json:"cty,omitempty"`
	KeyID              string `json:"kid,omitempty"`
	Critical           string `json:"crit,omitempty"`
}

type Claims struct {
	Issuer         string `json:"iss,omitempty"`
	Subject        string `json:"sub,omitempty"`
	Audience       string `json:"aud,omitempty"`
	ExpirationTime int64  `json:"exp,omitempty"`
	NotBefore      int64  `json:"nbf,omitempty"`
	IssuedAt       int64  `json:"iat,omitempty"`
	JwtId          string `json:"jti,omitempty"`
	Data           []byte `json:"data,omitempty"`
}

type ParseOptions struct {
	Claims  ClaimsParseOptions
	Headers HeadersParseOptions
}

type ClaimsParseOptions struct {
	RequiredIssuer          bool
	RequiredSubject         bool
	RequiredAudience        bool
	RequiredJwtId           bool
	RequiredData            bool
	SkipSignatureValidation bool
	SkipClaimsValidation    bool
}

type HeadersParseOptions struct {
	RequiredContentType             bool
	RequiredKeyID                   bool
	RequiredX509CertificateChain    bool
	RequiredX509CertificateChainURL bool
	RequiredCritical                bool
}