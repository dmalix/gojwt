package gojwt

import "errors"

// Below are the errors that can occur when working with JWT, as well as their details
// In this case, errors are divided into two groups: EnumErrorId and EnumValidationMessageId
// EnumErrorId - common errors
// EnumValidationMessageId - error details
// In this case, EnumErrorId is a data type that represents an error
// EnumValidationMessageId is a string that represents an error detail
// Enum is convenient to use for error handling logic

type EnumErrorId error

var (
	EnumErrorIdInvalidToken EnumErrorId = errors.New("invalid token")
	EnumErrorIdMalformed    EnumErrorId = errors.New("malformed token")
)

type EnumValidationMessageId string

const (
	EnumValidationMessageIdMalformed        EnumValidationMessageId = "token is malformed"
	EnumValidationMessageIdHeadersMalformed EnumValidationMessageId = "token headers are malformed"
	EnumValidationMessageIdClaimsMalformed  EnumValidationMessageId = "token claims are malformed"
	EnumValidationMessageIdUnverifiable     EnumValidationMessageId = "the token could not be verified due to problems with the generation of the test sample"
	EnumValidationMessageIdSignatureInvalid EnumValidationMessageId = "signature validation failed"

	EnumValidationMessageIdHeadersContentType EnumValidationMessageId = "header 'cty' validation failed"
	EnumValidationMessageIdHeadersKeyId       EnumValidationMessageId = "header 'kid' validation failed"
	EnumValidationMessageIdHeadersCritical    EnumValidationMessageId = "header 'crit' validation failed"

	EnumValidationMessageIdClaimsIssuer      EnumValidationMessageId = "claim 'iss' validation failed"
	EnumValidationMessageIdClaimsSubject     EnumValidationMessageId = "claim 'sub' validation failed"
	EnumValidationMessageIdClaimsAudience    EnumValidationMessageId = "claim 'aud' validation failed"
	EnumValidationMessageIdClaimsExpired     EnumValidationMessageId = "claim 'exp' validation failed"
	EnumValidationMessageIdClaimsNotValidYet EnumValidationMessageId = "claim 'nbf' validation failed"
	EnumValidationMessageIdClaimsIssuedAt    EnumValidationMessageId = "claim 'iat' validation failed"
	EnumValidationMessageIdClaimsJwtId       EnumValidationMessageId = "claim 'jti' validation failed"
	EnumValidationMessageIdClaimsData        EnumValidationMessageId = "claim 'data' validation failed"
)
