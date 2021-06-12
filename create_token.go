package jwt

import (
	"fmt"
	"html"
	"time"
)

func (t *jwt) Create(claims Claims, h ...Headers) (string, error) {

	// Init Headers
	headers := t.config.Headers
	if len(h) != 0 {
		if h[0].Type != "" {
			headers.Type = h[0].Type
		}
		if h[0].SignatureAlgorithm != "" {
			headers.SignatureAlgorithm = h[0].SignatureAlgorithm
		}
		if h[0].ContentType != "" {
			headers.ContentType = h[0].ContentType
		}
		if h[0].KeyID != "" {
			headers.KeyID = h[0].KeyID
		}
		if h[0].Critical != "" {
			headers.Critical = h[0].Critical
		}
	}
	if headers.Type == "" {
		return "", fmt.Errorf("headers.Type header must be present")
	}
	if headers.SignatureAlgorithm == "" {
		return "", fmt.Errorf("headers.SignatureAlgorithm header must be present")
	}

	// Init Claims
	if claims.Issuer == "" {
		claims.Issuer = t.config.Claims.Issuer
	}
	if claims.Subject == "" {
		claims.Subject = t.config.Claims.Subject
	}
	if claims.Audience == "" {
		claims.Audience = t.config.Claims.Audience
	}
	if claims.ExpirationTime == 0 {
		claims.ExpirationTime = t.config.Claims.ExpirationTime
	}
	if claims.NotBefore == 0 {
		claims.NotBefore = t.config.Claims.NotBefore
	}
	if claims.IssuedAt == 0 {
		claims.IssuedAt = t.config.Claims.IssuedAt
	}
	if claims.JwtID == "" {
		claims.JwtID = t.config.Claims.JwtID
	}
	if claims.Data == nil {
		claims.Data = t.config.Claims.Data
	}

	// Headers part
	headersPart, err := makeHeaderPart(headers)
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
		if t.config.TokenLifetimeSec == 0 {
			return "", fmt.Errorf("claims.ExpirationTime or config.TokenLifetimeSec must not be null")
		}
		claims.ExpirationTime =
			time.Unix(now, 0).Add(time.Second * time.Duration(t.config.TokenLifetimeSec)).UTC().Unix()
	}
	claimsPart, err := makeClaimsPart(claims)
	if err != nil {
		return "", fmt.Errorf("failed to make the claimsPart: %s", err)
	}

	// Signature
	unsignedToken := headersPart + "." + claimsPart
	signature, err := makeSignature(unsignedToken, headers.SignatureAlgorithm, t.config.Key)
	if err != nil {
		return "", fmt.Errorf("failed to make the signature: %s", err)
	}

	// Return the JSON Web Token (JWT).
	return html.UnescapeString(headersPart) +
		"." + html.UnescapeString(claimsPart) +
		"." + html.UnescapeString(signature), nil
}
