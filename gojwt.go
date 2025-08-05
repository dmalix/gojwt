package gojwt

type Jwt interface {
	Create(claims *Claims, headers ...*Headers) (string, error)
	Parse(jwt string, options ...*ParseOptions) (*Token, EnumValidationMessage, error)

	GetHeaders() *Headers
	GetClaims() *Claims
	GetParseOptions() ParseOptions
}
