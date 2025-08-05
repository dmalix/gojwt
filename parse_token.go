package gojwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

func (receiver *Jwt) Parse(jwt string, options ...*ParseOptions) (*Token, EnumValidationMessage, error) {

	const NoPadding rune = -1
	var token Token
	var now = time.Now().UTC().Unix()
	var parseOptions *ParseOptions

	// Init Parse Options
	if len(options) != 0 {
		parseOptions = options[0]
	} else {
		parseOptions = &receiver.config.ParseOptions
	}

	// Split Token values
	jwtParts := strings.Split(jwt, ".")
	if len(jwtParts) != 3 {
		return nil, EnumValidationMessageMalformed, EnumErrorMalformed
	}

	// Parse Headers
	valueByte, err := base64.URLEncoding.WithPadding(NoPadding).DecodeString(jwtParts[0])
	if err != nil {
		return nil, EnumValidationMessageHeadersMalformed, err
	}
	err = json.Unmarshal(valueByte, &token.Headers)
	if err != nil {
		return nil, EnumValidationMessageHeadersMalformed, err
	}

	// Parse Claims
	valueByte, err = base64.URLEncoding.WithPadding(NoPadding).DecodeString(jwtParts[1])
	if err != nil {
		return nil, EnumValidationMessageClaimsMalformed, err
	}
	err = json.Unmarshal(valueByte, &token.Claims)
	if err != nil {
		return nil, EnumValidationMessageClaimsMalformed, err
	}

	// Get Signature
	token.Signature = jwtParts[2]

	// Validate Signature
	if parseOptions.SkipSignatureValidation == false {
		headersPart, err := createHeaderPart(&token.Headers)
		if err != nil {
			return nil, EnumValidationMessageUnverifiable, fmt.Errorf("failed to make the headersPart: %s", err)
		}
		claimsPart, err := createClaimsPart(&token.Claims)
		if err != nil {
			return nil, EnumValidationMessageUnverifiable, fmt.Errorf("failed to make the claimsPart: %s", err)
		}
		unsignedToken := headersPart + "." + claimsPart
		signature, err := makeSignature(unsignedToken, token.Headers.SignatureAlgorithm, receiver.config.Key)
		if err != nil {
			return nil, EnumValidationMessageUnverifiable, fmt.Errorf("failed to make the signature: %s", err)
		}
		if signature != token.Signature {
			return nil, EnumValidationMessageSignatureInvalid,
				fmt.Errorf("failed to validate signature: jwtSample %s, jwt %s",
					headersPart+"."+claimsPart+"."+signature, jwt)
		}
	}

	// Validate Headers
	if parseOptions.RequiredHeaderContentType && token.Headers.ContentType == "" {
		return nil, EnumValidationMessageHeadersContentType, EnumErrorInvalidToken
	}
	if parseOptions.RequiredHeaderKeyId && token.Headers.KeyId == "" {
		return nil, EnumValidationMessageHeadersKeyId, EnumErrorInvalidToken
	}
	if parseOptions.RequiredHeaderCritical && token.Headers.Critical == "" {
		return nil, EnumValidationMessageHeadersCritical, EnumErrorInvalidToken
	}

	// Validate Claims
	if parseOptions.RequiredClaimIssuer && token.Claims.Issuer == "" {
		return nil, EnumValidationMessageClaimsIssuer, EnumErrorInvalidToken
	}
	if parseOptions.RequiredClaimSubject && token.Claims.Subject == "" {
		return nil, EnumValidationMessageClaimsSubject, EnumErrorInvalidToken
	}
	if parseOptions.RequiredClaimAudience && token.Claims.Audience == "" {
		return nil, EnumValidationMessageClaimsAudience, EnumErrorInvalidToken
	}
	if parseOptions.RequiredClaimJwtId && token.Claims.JwtId == "" {
		return nil, EnumValidationMessageClaimsJwtId, EnumErrorInvalidToken
	}
	if parseOptions.RequiredClaimData && token.Claims.Data == nil {
		return nil, EnumValidationMessageClaimsData, EnumErrorInvalidToken
	}
	if parseOptions.SkipClaimsValidation == false {
		// Validate ExpirationTime value
		if now > time.Unix(token.Claims.ExpirationTime, 0).UTC().Unix() {
			return nil, EnumValidationMessageClaimsExpired, EnumErrorInvalidToken
		}
		// Validate NotBefore value
		if token.Claims.NotBefore != 0 {
			if now < token.Claims.NotBefore {
				return nil, EnumValidationMessageClaimsNotValidYet, EnumErrorInvalidToken
			}
		}
		// Validate IssuedAt value
		if now < token.Claims.IssuedAt {
			return nil, EnumValidationMessageClaimsIssuedAt, EnumErrorInvalidToken
		}
	}

	return &token, "", nil
}
