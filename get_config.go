package gojwt

func (receiver *Resources) GetHeaders() *Headers {
	return receiver.config.Headers
}

func (receiver *Resources) GetClaims() *Claims {
	return receiver.config.Claims
}

func (receiver *Resources) GetParseOptions() ParseOptions {
	return receiver.config.ParseOptions
}
