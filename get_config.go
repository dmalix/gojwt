package jwt

func (t *jwt) GetHeaders() *Headers {
	return &t.config.Headers
}

func (t *jwt) GetClaims() *Claims {
	return &t.config.Claims
}

func (t *jwt) GetParseOptions() *ParseOptions {
	return &t.config.ParseOptions
}
