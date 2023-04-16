package jwt

func (t *Jwt) GetHeaders() Headers {
	return t.config.Headers
}

func (t *Jwt) GetClaims() Claims {
	return t.config.Claims
}

func (t *Jwt) GetParseOptions() ParseOptions {
	return t.config.ParseOptions
}
