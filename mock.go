package jwt

type MockDescription struct {
	Props struct {
	}
	Expected struct {
		Error error
	}
}

var MockData MockDescription

func (s *MockDescription) Create(_ string, _ []byte, _ string, _ ...int64) (string, error) {
	return "", MockData.Expected.Error
}

func (s *MockDescription) Validate(_ string) (Token, error) {
	var data Token
	return data, MockData.Expected.Error
}
