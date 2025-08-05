package gojwt

func (receiver *Jwt) GetHeaders() *Headers {
	return receiver.config.Headers
}

func (receiver *Jwt) GetClaims() *Claims {
	return receiver.config.Claims
}

func (receiver *Jwt) GetParseOptions() ParseOptions {
	return receiver.config.ParseOptions
}
