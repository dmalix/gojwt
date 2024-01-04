package jwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

func (t *jwt) Parse(jwt string, options ...*ParseOptions) (*Token, string, error) {

	const NoPadding rune = -1
	var token Token
	var now = time.Now().UTC().Unix()
	var parseOptions *ParseOptions

	// Init Parse Options
	if len(options) != 0 {
		parseOptions = options[0]
	} else {
		parseOptions = &t.config.ParseOptions
	}

	// Split Token values
	jwtParts := strings.Split(jwt, ".")
	if len(jwtParts) != 3 {
		return nil, ValidationErrorMalformed,
			fmt.Errorf("%s: failed to split the token values", ValidationErrorMalformed)
	}

	// Parse Headers
	valueByte, err := base64.URLEncoding.WithPadding(NoPadding).DecodeString(jwtParts[0])
	if err != nil {
		return nil, ValidationErrorHeadersMalformed, err
	}
	err = json.Unmarshal(valueByte, &token.Headers)
	if err != nil {
		return nil, ValidationErrorHeadersMalformed, err
	}

	// Parse Claims
	valueByte, err = base64.URLEncoding.WithPadding(NoPadding).DecodeString(jwtParts[1])
	if err != nil {
		return nil, ValidationErrorClaimsMalformed, err
	}
	err = json.Unmarshal(valueByte, &token.Claims)
	if err != nil {
		return nil, ValidationErrorClaimsMalformed, err
	}

	// Get Signature
	token.Signature = jwtParts[2]

	// Validate Signature
	if parseOptions.SkipSignatureValidation == false {
		headersPart, err := createHeaderPart(&token.Headers)
		if err != nil {
			return nil, ValidationErrorUnverifiable, fmt.Errorf("failed to make the headersPart: %s", err)
		}
		claimsPart, err := createClaimsPart(&token.Claims)
		if err != nil {
			return nil, ValidationErrorUnverifiable, fmt.Errorf("failed to make the claimsPart: %s", err)
		}
		unsignedToken := headersPart + "." + claimsPart
		signature, err := makeSignature(unsignedToken, token.Headers.SignatureAlgorithm, t.config.Key)
		if err != nil {
			return nil, ValidationErrorUnverifiable, fmt.Errorf("failed to make the signature: %s", err)
		}
		if signature != token.Signature {
			return nil, ValidationErrorSignatureInvalid,
				fmt.Errorf("failed to validate signature: jwtSample %s, jwt %s",
					headersPart+"."+claimsPart+"."+signature, jwt)
		}
	}

	// Validate Headers
	if parseOptions.RequiredHeaderContentType && token.Headers.ContentType == "" {
		return nil, ValidationErrorHeadersContentType, errInvalidToken
	}
	if parseOptions.RequiredHeaderKeyId && token.Headers.KeyId == "" {
		return nil, ValidationErrorHeadersKeyId, errInvalidToken
	}
	if parseOptions.RequiredHeaderCritical && token.Headers.Critical == "" {
		return nil, ValidationErrorHeadersCritical, errInvalidToken
	}

	// Validate Claims
	if parseOptions.RequiredClaimIssuer && token.Claims.Issuer == "" {
		return nil, ValidationErrorClaimsIssuer, errInvalidToken
	}
	if parseOptions.RequiredClaimSubject && token.Claims.Subject == "" {
		return nil, ValidationErrorClaimsSubject, errInvalidToken
	}
	if parseOptions.RequiredClaimAudience && token.Claims.Audience == "" {
		return nil, ValidationErrorClaimsAudience, errInvalidToken
	}
	if parseOptions.RequiredClaimJwtId && token.Claims.JwtId == "" {
		return nil, ValidationErrorClaimsJwtId, errInvalidToken
	}
	if parseOptions.RequiredClaimData && token.Claims.Data == nil {
		return nil, ValidationErrorClaimsData, errInvalidToken
	}
	if parseOptions.SkipClaimsValidation == false {
		// Validate ExpirationTime value
		if now > time.Unix(token.Claims.ExpirationTime, 0).UTC().Unix() {
			return nil, ValidationErrorClaimsExpired, errInvalidToken
		}
		// Validate NotBefore value
		if token.Claims.NotBefore != 0 {
			if now < token.Claims.NotBefore {
				return nil, ValidationErrorClaimsNotValidYet, errInvalidToken
			}
		}
		// Validate IssuedAt value
		if now < token.Claims.IssuedAt {
			return nil, ValidationErrorClaimsIssuedAt, errInvalidToken
		}
	}

	return &token, "", nil
}
