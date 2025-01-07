package gojwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

func (receiver *jwt) Parse(jwt string, options ...*ParseOptions) (*Token, EnumValidationMessageId, error) {

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
		return nil, EnumValidationMessageIdMalformed, EnumErrorIdMalformed
	}

	// Parse Headers
	valueByte, err := base64.URLEncoding.WithPadding(NoPadding).DecodeString(jwtParts[0])
	if err != nil {
		return nil, EnumValidationMessageIdHeadersMalformed, err
	}
	err = json.Unmarshal(valueByte, &token.Headers)
	if err != nil {
		return nil, EnumValidationMessageIdHeadersMalformed, err
	}

	// Parse Claims
	valueByte, err = base64.URLEncoding.WithPadding(NoPadding).DecodeString(jwtParts[1])
	if err != nil {
		return nil, EnumValidationMessageIdClaimsMalformed, err
	}
	err = json.Unmarshal(valueByte, &token.Claims)
	if err != nil {
		return nil, EnumValidationMessageIdClaimsMalformed, err
	}

	// Get Signature
	token.Signature = jwtParts[2]

	// Validate Signature
	if parseOptions.SkipSignatureValidation == false {
		headersPart, err := createHeaderPart(&token.Headers)
		if err != nil {
			return nil, EnumValidationMessageIdUnverifiable, fmt.Errorf("failed to make the headersPart: %s", err)
		}
		claimsPart, err := createClaimsPart(&token.Claims)
		if err != nil {
			return nil, EnumValidationMessageIdUnverifiable, fmt.Errorf("failed to make the claimsPart: %s", err)
		}
		unsignedToken := headersPart + "." + claimsPart
		signature, err := makeSignature(unsignedToken, token.Headers.SignatureAlgorithm, receiver.config.Key)
		if err != nil {
			return nil, EnumValidationMessageIdUnverifiable, fmt.Errorf("failed to make the signature: %s", err)
		}
		if signature != token.Signature {
			return nil, EnumValidationMessageIdSignatureInvalid,
				fmt.Errorf("failed to validate signature: jwtSample %s, jwt %s",
					headersPart+"."+claimsPart+"."+signature, jwt)
		}
	}

	// Validate Headers
	if parseOptions.RequiredHeaderContentType && token.Headers.ContentType == "" {
		return nil, EnumValidationMessageIdHeadersContentType, EnumErrorIdInvalidToken
	}
	if parseOptions.RequiredHeaderKeyId && token.Headers.KeyId == "" {
		return nil, EnumValidationMessageIdHeadersKeyId, EnumErrorIdInvalidToken
	}
	if parseOptions.RequiredHeaderCritical && token.Headers.Critical == "" {
		return nil, EnumValidationMessageIdHeadersCritical, EnumErrorIdInvalidToken
	}

	// Validate Claims
	if parseOptions.RequiredClaimIssuer && token.Claims.Issuer == "" {
		return nil, EnumValidationMessageIdClaimsIssuer, EnumErrorIdInvalidToken
	}
	if parseOptions.RequiredClaimSubject && token.Claims.Subject == "" {
		return nil, EnumValidationMessageIdClaimsSubject, EnumErrorIdInvalidToken
	}
	if parseOptions.RequiredClaimAudience && token.Claims.Audience == "" {
		return nil, EnumValidationMessageIdClaimsAudience, EnumErrorIdInvalidToken
	}
	if parseOptions.RequiredClaimJwtId && token.Claims.JwtId == "" {
		return nil, EnumValidationMessageIdClaimsJwtId, EnumErrorIdInvalidToken
	}
	if parseOptions.RequiredClaimData && token.Claims.Data == nil {
		return nil, EnumValidationMessageIdClaimsData, EnumErrorIdInvalidToken
	}
	if parseOptions.SkipClaimsValidation == false {
		// Validate ExpirationTime value
		if now > time.Unix(token.Claims.ExpirationTime, 0).UTC().Unix() {
			return nil, EnumValidationMessageIdClaimsExpired, EnumErrorIdInvalidToken
		}
		// Validate NotBefore value
		if token.Claims.NotBefore != 0 {
			if now < token.Claims.NotBefore {
				return nil, EnumValidationMessageIdClaimsNotValidYet, EnumErrorIdInvalidToken
			}
		}
		// Validate IssuedAt value
		if now < token.Claims.IssuedAt {
			return nil, EnumValidationMessageIdClaimsIssuedAt, EnumErrorIdInvalidToken
		}
	}

	return &token, "", nil
}
