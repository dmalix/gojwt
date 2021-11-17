package jwt

type Jwt interface {
	Create(claims *Claims, headers ...*Headers) (string, error)
	Parse(jwt string, parseOptions ...*ParseOptions) (*Token, string, error)

	GetHeaders() *Headers
	GetClaims() *Claims
	GetParseOptions() *ParseOptions
}
