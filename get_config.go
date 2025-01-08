package gojwt

func (receiver *resources) GetHeaders() *Headers {
	return receiver.config.Headers
}

func (receiver *resources) GetClaims() *Claims {
	return receiver.config.Claims
}

func (receiver *resources) GetParseOptions() ParseOptions {
	return receiver.config.ParseOptions
}
