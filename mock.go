package gojwt

type MockDescription struct {
	Expected struct {
		Create struct {
			Jwt   string
			Error error
		}
		Parse struct {
			Token Token
			Error error
		}
		GetHeaders struct {
			Headers Headers
		}
		GetClaims struct {
			Claims Claims
		}
		GetParseOptions struct {
			ParseOptions ParseOptions
		}
	}
}

var Mock MockDescription

func (s *MockDescription) Create(_ Claims, _ ...Headers) (string, error) {
	return Mock.Expected.Create.Jwt, Mock.Expected.Create.Error
}

func (s *MockDescription) Parse(_ string, _ ...ParseOptions) (Token, string, error) {
	return Mock.Expected.Parse.Token, "", Mock.Expected.Parse.Error
}

func (s *MockDescription) GetHeaders() Headers {
	return Mock.Expected.GetHeaders.Headers
}
func (s *MockDescription) GetClaims() Claims {
	return Mock.Expected.GetClaims.Claims
}
func (s *MockDescription) GetParseOptions() ParseOptions {
	return Mock.Expected.GetParseOptions.ParseOptions
}
