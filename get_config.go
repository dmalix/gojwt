package gojwt

func (receiver *jwt) GetHeaders() *Headers {
	return receiver.config.Headers
}

func (receiver *jwt) GetClaims() *Claims {
	return receiver.config.Claims
}

func (receiver *jwt) GetParseOptions() ParseOptions {
	return receiver.config.ParseOptions
}
