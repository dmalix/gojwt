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
	JwtID          string `json:"jti,omitempty"`
	Data           []byte `json:"data,omitempty"` // It is a custom field for any data (for example, encrypted data).
}

type ParseOptions struct {
	RequiredHeaderContentType             bool
	RequiredHeaderKeyID                   bool
	RequiredHeaderX509CertificateChain    bool
	RequiredHeaderX509CertificateChainURL bool
	RequiredHeaderCritical                bool
	RequiredClaimIssuer                   bool
	RequiredClaimSubject                  bool
	RequiredClaimAudience                 bool
	RequiredClaimJwtID                    bool
	RequiredClaimSessionID                bool
	RequiredClaimData                     bool
	SkipClaimsValidation                  bool
	SkipSignatureValidation               bool
}
