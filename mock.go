package jwt

type MockDescription struct {
	Expected struct {
		Error error
	}
}

var MockData MockDescription

func (s *MockDescription) Create(_ Claims, _ ...Headers) (string, error) {
	return "", MockData.Expected.Error
}

func (s *MockDescription) Parse(_ string, _ ...ParseOptions) (Token, string, error) {
	return Token{}, "", MockData.Expected.Error
}

func (s *MockDescription) GetHeaders() Headers {
	return Headers{}
}
func (s *MockDescription) GetClaims() Claims {
	return Claims{}
}
func (s *MockDescription) GetParseOptions() ParseOptions {
	return ParseOptions{}
}
