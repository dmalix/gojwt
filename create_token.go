package gojwt

import (
	"fmt"
	"html"
	"time"
)

func (receiver *jwt) Create(claims *Claims, headers ...*Headers) (string, error) {

	// Init Headers
	configHeaders := receiver.config.Headers
	if len(headers) != 0 {
		if configHeaders != nil {
			if headers[0].Type != "" {
				configHeaders.Type = headers[0].Type
			}
			if headers[0].SignatureAlgorithm != "" {
				configHeaders.SignatureAlgorithm = headers[0].SignatureAlgorithm
			}
			if headers[0].ContentType != "" {
				configHeaders.ContentType = headers[0].ContentType
			}
			if headers[0].KeyId != "" {
				configHeaders.KeyId = headers[0].KeyId
			}
			if headers[0].Critical != "" {
				configHeaders.Critical = headers[0].Critical
			}
		} else {
			configHeaders = headers[0]
		}
	}
	if configHeaders == nil {
		return "", fmt.Errorf("headers (Type, SignatureAlgorithm) must not be null")
	}
	if configHeaders.Type == "" {
		return "", fmt.Errorf("headers.Type header must be present")
	}
	if configHeaders.SignatureAlgorithm == "" {
		return "", fmt.Errorf("headers.SignatureAlgorithm header must be present")
	}

	// Init Claims
	if claims != nil {
		if claims.Issuer == "" {
			claims.Issuer = receiver.config.Claims.Issuer
		}
		if claims.Subject == "" {
			claims.Subject = receiver.config.Claims.Subject
		}
		if claims.Audience == "" {
			claims.Audience = receiver.config.Claims.Audience
		}
		if claims.ExpirationTime == 0 {
			claims.ExpirationTime = receiver.config.Claims.ExpirationTime
		}
		if claims.NotBefore == 0 {
			claims.NotBefore = receiver.config.Claims.NotBefore
		}
		if claims.IssuedAt == 0 {
			claims.IssuedAt = receiver.config.Claims.IssuedAt
		}
		if claims.JwtId == "" {
			claims.JwtId = receiver.config.Claims.JwtId
		}
		if claims.Data == nil {
			claims.Data = receiver.config.Claims.Data
		}
	} else {
		claims = receiver.config.Claims
	}
	if claims == nil {
		claims = &Claims{}
	}

	// Headers part
	headersPart, err := createHeaderPart(configHeaders)
	if err != nil {
		return "", fmt.Errorf("failed to make the headersPart: %s", err)
	}

	// Payload part
	now := time.Now().UTC().Unix()
	if claims.IssuedAt == 0 {
		claims.IssuedAt = now
	}
	if claims.NotBefore != 0 {
		if claims.NotBefore < claims.IssuedAt {
			return "", fmt.Errorf("claims.NotBefore cannot be less than claims.IssuedAt")
		}
	}
	if claims.ExpirationTime == 0 {
		if receiver.config.TokenLifetime == 0 {
			return "", fmt.Errorf("claims.ExpirationTime or config.TokenLifetime must be present")
		}
		claims.ExpirationTime =
			time.Unix(now, 0).Add(time.Second * time.Duration(receiver.config.TokenLifetime)).UTC().Unix()
	}
	claimsPart, err := createClaimsPart(claims)
	if err != nil {
		return "", fmt.Errorf("failed to make the claimsPart: %s", err)
	}

	// Signature
	unsignedToken := headersPart + "." + claimsPart
	signature, err := makeSignature(unsignedToken, configHeaders.SignatureAlgorithm, receiver.config.Key)
	if err != nil {
		return "", fmt.Errorf("failed to make the signature: %s", err)
	}

	// Return the JSON Web Token (JWT).
	return html.UnescapeString(headersPart) +
		"." + html.UnescapeString(claimsPart) +
		"." + html.UnescapeString(signature), nil
}
