package jwt

import "errors"

const (
	ValidationErrorMalformed        = "token is malformed"
	ValidationErrorHeadersMalformed = "token headers are malformed"
	ValidationErrorClaimsMalformed  = "token claims are malformed"
	ValidationErrorUnverifiable     = "the token could not be verified due to problems with the generation of the test sample"
	ValidationErrorSignatureInvalid = "signature validation failed"

	ValidationErrorHeadersContentType             = "header 'cty' validation failed"
	ValidationErrorHeadersKeyID                   = "header 'kid' validation failed"
	ValidationErrorHeadersCritical                = "header 'crit' validation failed"

	ValidationErrorClaimsIssuer      = "claim 'iss' validation failed"
	ValidationErrorClaimsSubject     = "claim 'sub' validation failed"
	ValidationErrorClaimsAudience    = "claim 'aud' validation failed"
	ValidationErrorClaimsExpired     = "claim 'exp' validation failed"
	ValidationErrorClaimsNotValidYet = "claim 'nbf' validation failed"
	ValidationErrorClaimsIssuedAt    = "claim 'iat' validation failed"
	ValidationErrorClaimsJwtId       = "claim 'jti' validation failed"
	ValidationErrorClaimsData        = "claim 'data' validation failed"
)

var errTokenIsInvalid = errors.New("token is invalid")