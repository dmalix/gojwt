package jwt

type Token struct {
	Headers struct {
		SigningAlgorithm string `json:"alg"`
		Type             string `json:"typ"`
	}
	Payload struct {
		Issuer    string `json:"iss"`
		Subject   string `json:"sub"`
		Purpose   string `json:"purpose"`
		SessionID string `json:"sessionID"`
		Data      []byte `json:"data"`
		IssuedAt  int64  `json:"iat"`
	}
	Signature string
}
