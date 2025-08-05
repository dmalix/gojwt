# Go JWT

A [Golang](http://golang.org) implementation of [JSON Web Token (JWT) - RFC 7519](https://tools.ietf.org/html/rfc7519) designed to be robust, secure, and developer-friendly.

### Supported Go versions

Our support of Go versions is aligned with Go's [version release policy](https://golang.org/doc/devel/release#policy).
So we will support a major version of Go until there are two newer major releases.

---

* [Why Choose GoJWT?](#why-choose-gojwt)
* [Install](#install)
* [Available Algorithms](#available-algorithms)
* [Quick Start](#quick-start)
* [Usage](#usage)
* [Error Handling](#error-handling)
* [Issue Reporting](#issue-reporting)
* [Secure](#secure)
* [Contributing](#contributing)
* [Author](#author)
* [License](#license)

---

## Why Choose GoJWT?

GoJWT is more than just another JWT library. It's built with a focus on security, flexibility, and a great developer experience.

*   **Secure by Default**: The library implements critical security validations out-of-the-box. It automatically verifies the token's signature and validates standard time-based claims like `exp` (expiration), `iat` (issued at), and `nbf` (not before). This protects your application from common JWT vulnerabilities without extra effort.

*   **Powerful and Flexible Configuration**:
    *   **Global & Local Settings**: Set up a global configuration for your tokens, but easily override headers and claims for individual tokens as needed. This is perfect for handling different token types with a single instance.
    *   **Granular Validation Control**: Use `ParseOptions` to define exactly which claims and headers are mandatory for your use case. This gives you fine-grained control over the validation logic.

*   **Developer-Friendly API**:
    *   **Intuitive Design**: The API is straightforward and easy to use, allowing you to get started in minutes.
    *   **Automatic Lifetime Management**: Simply set a `TokenLifetime` in your configuration, and the library will automatically calculate the expiration time for you, reducing boilerplate code.
    *   **Built-in Logic Checks**: Prevents the creation of logically invalid tokens, for example, by ensuring that the `nbf` (not before) claim is not earlier than the `iat` (issued at) claim.

*   **Clear and Informative Error Handling**: The `Parse` function returns a specific `EnumValidationMessage` alongside the standard error. This is a huge advantage for debugging, as it allows you to programmatically handle different failure scenarios (e.g., an expired token vs. an invalid signature) with a simple `switch` statement.

*   **Standard-Compliant**: Follows the [RFC 7519](https://tools.ietf.org/html/rfc7519) standard for JWTs, ensuring interoperability with other JWT libraries and systems.

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
	// 1. Create a new JWT instance with a base configuration
	jwtInstance, err := gojwt.NewToken(&gojwt.Config{
		Headers: &gojwt.Headers{
			Type:               gojwt.EnumTokenTypeJWT,
			SignatureAlgorithm: gojwt.EnumTokenSignatureAlgorithmHS256,
		},
		Claims: &gojwt.Claims{
			Issuer:  "your-app",
			Subject: "user-authentication",
		},
		ParseOptions: gojwt.ParseOptions{
			RequiredClaimIssuer:  true,
			RequiredClaimSubject: true,
			RequiredClaimJwtId:   true,
		},
		TokenLifetime: 3600, // Token valid for 1 hour (in seconds)
		Key:           "your-256-bit-secret-key-that-is-at-least-32-bytes-long", // Use a strong, secret key
	})
	if err != nil {
		log.Fatalf("Error creating JWT instance: %v", err)
	}

	// 2. Create a new token with specific claims for this token
	userData := map[string]interface{}{"userID": "12345", "role": "admin"}
	userDataBytes, _ := json.Marshal(userData)

	jwtString, err := jwtInstance.Create(&gojwt.Claims{
		JwtId: "unique-session-id-123",
		Data:  userDataBytes,
	})
	if err != nil {
		log.Fatalf("Error creating JWT: %v", err)
	}
	fmt.Printf("Generated JWT: %s\n\n", jwtString)

	// 3. Parse and validate the token
	fmt.Println("Parsing and validating the token...")
	parsedToken, validationMessage, err := jwtInstance.Parse(jwtString)
	if err != nil {
		log.Fatalf("Error parsing JWT: %s - %v", validationMessage, err)
	}

	fmt.Println("Token successfully parsed and validated!")
	fmt.Printf("-> Headers: %+v\n", parsedToken.Headers)
	fmt.Printf("-> Claims: %+v\n", parsedToken.Claims)
	
	var receivedData map[string]interface{}
    json.Unmarshal(parsedToken.Claims.Data, &receivedData)
	fmt.Printf("-> Data: %v\n", receivedData)
}
```

## Usage

### Custom Claims

You can store custom claims by serializing your struct into the `Data` field of `Claims`. When parsing, you can deserialize it back.

```go
package main

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/dmalix/gojwt"
)

type MyCustomClaims struct {
	Email    string `json:"email"`
	UserID   string `json:"user_id"`
	UserRole string `json:"user_role"`
}

func main() {
	jwtInstance, _ := gojwt.NewToken(&gojwt.Config{
		Headers: &gojwt.Headers{
			Type:               gojwt.EnumTokenTypeJWT,
			SignatureAlgorithm: gojwt.EnumTokenSignatureAlgorithmHS256,
		},
		TokenLifetime: 3600,
		Key:           "super-secret-key-for-custom-claims-example-12345",
	})

	// Serialize custom claims
	customClaims := MyCustomClaims{Email: "test@example.com", UserID: "user-456", UserRole: "premium"}
	dataBytes, _ := json.Marshal(customClaims)

	jwtString, _ := jwtInstance.Create(&gojwt.Claims{JwtId: "session-abc-123", Data: dataBytes})
	fmt.Printf("JWT with Custom Claims: %s\n\n", jwtString)

	// Parse and deserialize custom claims
	parsedToken, _, _ := jwtInstance.Parse(jwtString)
	
	var receivedCustomClaims MyCustomClaims
	if err := json.Unmarshal(parsedToken.Claims.Data, &receivedCustomClaims); err != nil {
		log.Fatalf("Error unmarshaling custom claims: %v", err)
	}
	fmt.Printf("Parsed Custom Claims: %+v\n", receivedCustomClaims)
}
```

### Token Validation Options

The `ParseOptions` struct allows you to specify which claims and headers are required during token parsing.

```go
package main

import (
	"fmt"
	"log"

	"github.com/dmalix/gojwt"
)

func main() {
	jwtInstance, _ := gojwt.NewToken(&gojwt.Config{
		Headers: &gojwt.Headers{
			Type:               gojwt.EnumTokenTypeJWT,
			SignatureAlgorithm: gojwt.EnumTokenSignatureAlgorithmHS256,
		},
		ParseOptions: gojwt.ParseOptions{
			RequiredClaimJwtId: true, // JWT ID claim must be present
		},
		TokenLifetime: 600,
		Key:           "a-very-secure-key-for-validation-options-example",
	})

	// Create a token that is missing the required JwtId
	invalidJwtString, _ := jwtInstance.Create(&gojwt.Claims{
		// JwtId is intentionally omitted here
	})
	
	// Attempt to parse the invalid token
	_, validationMessage, err := jwtInstance.Parse(invalidJwtString)
	if err != nil {
		fmt.Printf("Expected error for invalid JWT: %s - %v\n", validationMessage, err)
	} else {
		fmt.Println("Unexpected: Invalid JWT was validated successfully.")
	}
}
```

## Error Handling

The `Parse` method returns three values: `(*Token, EnumValidationMessage, error)`. This design is a key feature for robust error handling.

*   `*Token`: A pointer to the parsed token. It will be `nil` if a fatal error occurs.
*   `EnumValidationMessage`: A specific code indicating the validation result (e.g., `EnumValidationMessageClaimsExpired`, `EnumValidationMessageSignatureInvalid`). This is extremely useful for debugging and for programmatic handling of different failure reasons.
*   `error`: A standard Go error object with a descriptive message.

A typical error handling flow looks like this:

```go
parsedToken, validationMessage, err := jwtInstance.Parse(jwtString)
if err != nil {
    switch validationMessage {
    case gojwt.EnumValidationMessageClaimsExpired:
        // Handle expired token (e.g., prompt for re-login)
        fmt.Println("Token has expired. Please log in again.")
    case gojwt.EnumValidationMessageSignatureInvalid:
        // Handle invalid signature (potential tampering)
        fmt.Println("Token signature is invalid. Rejecting request.")
    default:
        // Handle other errors
        fmt.Printf("Token validation failed: %s\n", validationMessage)
    }
} else {
    fmt.Println("Token is valid!")
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
