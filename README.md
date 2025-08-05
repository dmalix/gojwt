# Go JWT

A [Golang](http://golang.org) implementation of [JSON Web Token (JWT) - RFC 7519](https://tools.ietf.org/html/rfc7519).

### Supported Go versions

Our support of Go versions is aligned with Go's [version release policy](https://golang.org/doc/devel/release#policy).
So we will support a major version of Go until there are two newer major releases.

---

* [Features](#features)
* [Install](#install)
* [Available Algorithms](#available-algorithms)
* [Quick Start](#quick-start)
* [Usage](#usage)
* [Issue Reporting](#issue-reporting)
* [Secure](#secure)
* [Contributing](#contributing)
* [Author](#author)
* [License](#license)

---

## Features

*   **Token Creation**: Easily create JWTs with customizable headers and claims.
*   **Token Parsing & Validation**: Parse JWTs and validate them against predefined options, including required claims and header types.
*   **Algorithm Support**: Supports HMAC with SHA-256 (HS256) and SHA-512 (HS512) for signing and verification.
*   **Configurable Lifetime**: Set a specific lifetime for your tokens.

## Install

To add the library to your project, run:

```sh
go get github.com/dmalix/gojwt
```

## Available Algorithms

The library implements JWT Verification and Signing using the following algorithms:

| JWS | Algorithm | Description |
| :-------------: | :-------------: | :----- |
| HS256 | HMAC256 | HMAC with SHA-256 |
| HS512 | HMAC512 | HMAC with SHA-512 |

## Quick Start

This section provides a minimal example to get you started with creating and parsing JWTs.

> **Note:** The `Data` field in `Claims` is a generic `[]byte` field. You can serialize any custom data (e.g., a struct) to JSON and store it there.

First, create a new JWT config:

```go
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/dmalix/gojwt"
)

func main() {
	// 1. Create a new JWT config
	config, err := gojwt.NewToken(&gojwt.Config{
		Headers: &gojwt.Headers{
			Type:               gojwt.EnumTokenTypeJWT,
			SignatureAlgorithm: gojwt.EnumTokenSignatureAlgorithmHS256,
		},
		Claims: &gojwt.Claims{
			Issuer:  "your-app",
			Subject: "user-authentication",
		},
		ParseOptions: gojwt.ParseOptions{
			RequiredHeaderContentType: false, // Not required for this example
			RequiredClaimIssuer:         true,
			RequiredClaimSubject:        true,
			RequiredClaimJwtId:          true,
			RequiredClaimData:           true,
		},
		TokenLifetimeSec: 3600, // Token valid for 1 hour
		Key:              "your-256-bit-secret-key-that-is-at-least-32-bytes-long", // Use a strong, secret key
	})
	if err != nil {
		log.Fatalf("Error creating JWT config: %v", err)
	}

	// 2. Create a new token with specific claims
	tokenID := "unique-session-id-123"
	userData := map[string]interface{}{
		"userID": "12345",
		"role":   "admin",
	}
	userDataBytes, _ := json.Marshal(userData)

	jwtString, err := gojwt.CreateToken(config, &gojwt.Claims{
		JwtId: tokenID,
		Data:  userDataBytes,
	})
	if err != nil {
		log.Fatalf("Error creating JWT: %v", err)
	}
	fmt.Printf("Generated JWT: %s\n\n", jwtString)

	// 3. Parse and validate the token
	fmt.Println("Parsing and validating the token...")
	parsedToken, validationMessage, err := gojwt.ParseToken(config, jwtString)
	if err != nil {
		log.Fatalf("Error parsing JWT: %s - %v", validationMessage, err)
	}

	fmt.Printf("Token successfully parsed and validated!\n")
	fmt.Printf("Parsed Token Headers: %+v\n", parsedToken.Headers)
	fmt.Printf("Parsed Token Claims: %+v\n", parsedToken.Claims)
	fmt.Printf("Parsed Token Data: %s\n", string(parsedToken.Claims.Data))

	// Example of an invalid token (e.g., expired)
	fmt.Println("\nDemonstrating an expired token (will fail validation):")
	expiredJwtConfig, _ := gojwt.NewToken(&gojwt.Config{
		Headers: &gojwt.Headers{
			Type:               gojwt.EnumTokenTypeJWT,
			SignatureAlgorithm: gojwt.EnumTokenSignatureAlgorithmHS256,
		},
		Claims: &gojwt.Claims{
			Issuer:  "your-app",
			Subject: "user-authentication",
		},
		TokenLifetimeSec: 1, // Very short lifetime for demonstration
		Key:              "your-256-bit-secret-key-that-is-at-least-32-bytes-long",
	})

	expiredJwtString, _ := gojwt.CreateToken(expiredJwtConfig, &gojwt.Claims{
		JwtId: "expired-token-id",
		Data:  []byte("expired data"),
	})

	fmt.Printf("Waiting for 2 seconds to ensure token expires...\n")
	time.Sleep(2 * time.Second) // Wait for the token to expire

	_, expiredValidationMessage, expiredErr := gojwt.ParseToken(expiredJwtConfig, expiredJwtString)
	if expiredErr != nil {
		fmt.Printf("Expected error for expired token: %s - %v\n", expiredValidationMessage, expiredErr)
	} else {
		fmt.Println("Unexpected: Expired token was validated successfully.")
	}
}
```

## Usage

This section provides more detailed examples and best practices for using the `gojwt` library.

### Custom Claims

You can store custom claims by serializing your struct into the `Data` field of `Claims`. When parsing, you can deserialize it back. Example:

```go
package main

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/dmalix/gojwt"
)

type MyCustomClaims struct {
	Email   string `json:"email"`
	UserID  string `json:"user_id"`
	UserRole string `json:"user_role"`
}

func main() {
	config, err := gojwt.NewToken(&gojwt.Config{
		Headers: &gojwt.Headers{
			Type:               gojwt.EnumTokenTypeJWT,
			SignatureAlgorithm: gojwt.EnumTokenSignatureAlgorithmHS256,
		},
		Claims: &gojwt.Claims{
			Issuer:  "my-service",
			Subject: "user-session",
		},
		TokenLifetimeSec: 3600,
		Key:              "super-secret-key-for-custom-claims-example-12345",
	})
	if err != nil {
		log.Fatalf("Error creating JWT config: %v", err)
	}

	// Serialize custom claims
	customClaims := MyCustomClaims{
		Email:    "test@example.com",
		UserID:   "user-456",
		UserRole: "premium",
	}
	dataBytes, _ := json.Marshal(customClaims)

	jwtString, err := gojwt.CreateToken(config, &gojwt.Claims{
		JwtId: "session-abc-123",
		Data:  dataBytes,
	})
	if err != nil {
		log.Fatalf("Error creating JWT with custom claims: %v", err)
	}
	fmt.Printf("JWT with Custom Claims: %s\n\n", jwtString)

	// Parse and deserialize custom claims
	parsedToken, validationMessage, err := gojwt.ParseToken(config, jwtString)
	if err != nil {
		log.Fatalf("Error parsing JWT with custom claims: %s - %v", validationMessage, err)
	}
	var receivedCustomClaims MyCustomClaims
	if err := json.Unmarshal(parsedToken.Claims.Data, &receivedCustomClaims); err != nil {
		log.Fatalf("Error unmarshaling custom claims: %v", err)
	}
	fmt.Printf("Parsed Custom Claims: %+v\n", receivedCustomClaims)
}
```

### Token Validation Options

The `ParseOptions` struct allows you to specify which claims and headers are required during token parsing. If a required field is missing or invalid, the `Parse` method will return an error.

```go
package main

import (
	"fmt"
	"log"

	"github.com/dmalix/gojwt"
)

func main() {
	// Configure JWT config with strict parsing options
	config, err := gojwt.NewToken(&gojwt.Config{
		Headers: &gojwt.Headers{
			Type:               gojwt.EnumTokenTypeJWT,
			SignatureAlgorithm: gojwt.EnumTokenSignatureAlgorithmHS256,
		},
		Claims: &gojwt.Claims{
			Issuer:  "secure-app",
			Subject: "api-access",
		},
		ParseOptions: gojwt.ParseOptions{
			RequiredHeaderContentType:   false, // Content-Type header is optional
			RequiredClaimIssuer:         true,  // Issuer claim must be present
			RequiredClaimSubject:        true,  // Subject claim must be present
			RequiredClaimJwtId:          true,  // JWT ID claim must be present
			RequiredClaimData:           false, // Data claim is optional
		},
		TokenLifetimeSec: 600, // 10 minutes
		Key:              "a-very-secure-key-for-validation-options-example",
	})
	if err != nil {
		log.Fatalf("Error creating JWT config: %v", err)
	}

	// Create a token that satisfies all required claims
	validJwtString, err := gojwt.CreateToken(config, &gojwt.Claims{
		JwtId: "transaction-001",
		Data:  []byte("{\"amount\": 100.00}"),
	})
	if err != nil {
		log.Fatalf("Error creating valid JWT: %v", err)
	}
	fmt.Printf("Valid JWT: %s\n", validJwtString)

	// Attempt to parse the valid token
	_, validationMessage, err := gojwt.ParseToken(config, validJwtString)
	if err != nil {
		log.Fatalf("Error parsing valid JWT: %s - %v", validationMessage, err)
	}
	fmt.Println("Valid JWT parsed successfully.")

	// --- Demonstrate a token that will fail validation ---

	// Create a token missing a required claim (e.g., JwtId)
	invalidJwtString, err := gojwt.CreateToken(config, &gojwt.Claims{
		// JwtId is intentionally omitted here
		Data: []byte("{\"operation\": \"read\"}"),
	})
	if err != nil {
		log.Fatalf("Error creating invalid JWT: %v", err)
	}
	fmt.Printf("\nInvalid JWT (missing JwtId): %s\n", invalidJwtString)

	// Attempt to parse the invalid token
	_, invalidValidationMessage, invalidErr := gojwt.ParseToken(config, invalidJwtString)
	if invalidErr != nil {
		fmt.Printf("Expected error for invalid JWT: %s - %v\n", invalidValidationMessage, invalidErr)
	} else {
		fmt.Println("Unexpected: Invalid JWT was validated successfully.")
	}
}
```

## Contributing

We welcome contributions to the `gojwt` project! If you're interested in contributing, please follow these guidelines:

1.  **Fork the repository**.
2.  **Create a new branch** for your feature or bug fix.
3.  **Write clear, concise code** and ensure it adheres to the existing coding style.
4.  **Write tests** for your changes to ensure functionality and prevent regressions.
5.  **Submit a pull request** with a detailed description of your changes.

---

## Issue Reporting
If you have found a bug or if you have a feature request, please report them at this repository issues section. Please do not report security vulnerabilities on the public GitHub issue tracker.

## Secure
If you discover any security related issues, please email [dmalix@yahoo.com](mailto:dmalix@yahoo.com) instead of using the issue tracker.

> **Security Note:** Always use a strong, secret key for signing tokens. Never hardcode secrets in your source code or commit them to version control.

## Author
[DmAlix](mailto:dmalix@yahoo.com)

## License
This project is licensed under the MIT license. See the [LICENSE](LICENSE) file for more info.
