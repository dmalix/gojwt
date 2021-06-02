package jwt

type Jwt interface {
	Create(sessionID string, privateBox []byte, tokenPurpose string, issuedAt ...int64) (string, error)
	Validate(jwt string) (Token, error)
}
