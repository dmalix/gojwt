package gojwt

import "errors"

// Below are the errors that can occur when working with JWT, as well as their details
// In this case, errors are divided into two groups: EnumError and EnumValidationMessage
// EnumError - common errors
// EnumValidationMessage - error details
// In this case, EnumError is a data type that represents an error
// EnumValidationMessage is a string that represents an error detail
// Enum is convenient to use for error handling logic

type EnumError error

var (
	EnumErrorInvalidToken EnumError = errors.New("invalid token")
	EnumErrorMalformed    EnumError = errors.New("malformed token")
)

type EnumValidationMessage string

const (
	EnumValidationMessageMalformed        EnumValidationMessage = "token is malformed"
	EnumValidationMessageHeadersMalformed EnumValidationMessage = "token headers are malformed"
	EnumValidationMessageClaimsMalformed  EnumValidationMessage = "token claims are malformed"
	EnumValidationMessageUnverifiable     EnumValidationMessage = "the token could not be verified due to problems with the generation of the test sample"
	EnumValidationMessageSignatureInvalid EnumValidationMessage = "signature validation failed"

	EnumValidationMessageHeadersContentType EnumValidationMessage = "header 'cty' validation failed"
	EnumValidationMessageHeadersKeyId       EnumValidationMessage = "header 'kid' validation failed"
	EnumValidationMessageHeadersCritical    EnumValidationMessage = "header 'crit' validation failed"

	EnumValidationMessageClaimsIssuer      EnumValidationMessage = "claim 'iss' validation failed"
	EnumValidationMessageClaimsSubject     EnumValidationMessage = "claim 'sub' validation failed"
	EnumValidationMessageClaimsAudience    EnumValidationMessage = "claim 'aud' validation failed"
	EnumValidationMessageClaimsExpired     EnumValidationMessage = "claim 'exp' validation failed"
	EnumValidationMessageClaimsNotValidYet EnumValidationMessage = "claim 'nbf' validation failed"
	EnumValidationMessageClaimsIssuedAt    EnumValidationMessage = "claim 'iat' validation failed"
	EnumValidationMessageClaimsJwtId       EnumValidationMessage = "claim 'jti' validation failed"
	EnumValidationMessageClaimsData        EnumValidationMessage = "claim 'data' validation failed"
)
