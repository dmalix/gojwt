package gojwt

type Token struct {
	Headers   Headers
	Claims    Claims
	Signature string
}

type Headers struct {
	Type               EnumTokenType               `json:"typ"`
	SignatureAlgorithm EnumTokenSignatureAlgorithm `json:"alg"`
	ContentType        string                      `json:"cty,omitempty"`
	KeyId              string                      `json:"kid,omitempty"`
	Critical           string                      `json:"crit,omitempty"`
}

type Claims struct {
	Issuer         string `json:"iss,omitempty"`
	Subject        string `json:"sub,omitempty"`
	Audience       string `json:"aud,omitempty"`
	ExpirationTime int64  `json:"exp"`
	NotBefore      int64  `json:"nbf,omitempty"`
	IssuedAt       int64  `json:"iat"`
	JwtId          string `json:"jti,omitempty"`
	Data           []byte `json:"data,omitempty"` // It is a custom field for any data (for example, encrypted data).
}

type ParseOptions struct {
	RequiredHeaderContentType             bool
	RequiredHeaderKeyId                   bool
	RequiredHeaderX509CertificateChain    bool
	RequiredHeaderX509CertificateChainURL bool
	RequiredHeaderCritical                bool
	RequiredClaimIssuer                   bool
	RequiredClaimSubject                  bool
	RequiredClaimAudience                 bool
	RequiredClaimJwtId                    bool
	RequiredClaimData                     bool
	SkipClaimsValidation                  bool
	SkipSignatureValidation               bool
}
