# Go JWT

A [Golang](http://golang.org) implementation of [JSON Web Token (JWT) - RFC 7519](https://tools.ietf.org/html/rfc7519).

### Supported Go versions

Our support of Go versions is aligned with Go's [version release policy](https://golang.org/doc/devel/release#policy).
So we will support a major version of Go until there are two newer major releases.

---

* [Install](#install)
* [Available Algorithms](#available-algorithms)
* [Quick Start](#quick-start)
* [Issue Reporting](#issue-reporting)
* [Secure](#secure)
* [Author](#author)
* [License](#license)

---

## Install

With a [correctly configured](https://golang.org/doc/install#testing) Go toolchain:

```sh
go get -u github.com/dmalix/gojwt
```

## Available Algorithms

The library implements JWT Verification and Signing using the following algorithms:

| JWS | Algorithm | Description |
| :-------------: | :-------------: | :----- |
| HS256 | HMAC256 | HMAC with SHA-256 |
| HS512 | HMAC512 | HMAC with SHA-512 |

## Quick Start

Create a new JWT instance and configure the parameters:

```go
jwtInstance, err := gojwt.NewToken(&gojwt.Config{
   Headers: &gojwt.Headers{
      Type:               gojwt.EnumTokenTypeJWT,
      SignatureAlgorithm: gojwt.EnumTokenSignatureAlgorithmHS256,   
   },
   Claims: &gojwt.Claims{
      Issuer:  "some data",
      Subject: "some subject",
   },
   ParseOptions: gojwt.ParseOptions{
      RequiredHeaderContentType:   true,
      RequiredClaimIssuer:         true,
      RequiredClaimSubject:        true,
      RequiredClaimJwtId:          true,
      RequiredClaimData:           true
   },
   TokenLifetimeSec: 100,
   Key:              "your-256-bit-secret",
})
if err != nil {
   log.Fatal(err)
}
```

Create a new token:

```go
jwt, err := jwtInstance.Create(&gojwt.Claims{
   JwtId: "some Id",
   Data:  []byte("some dataset"),
})
if err != nil {
   log.Fatal(err)
}
```

And so you can check and get data from the token:

```go
jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
jwtToken, codeError, err := jwtInstance.Parse(jwt)
if err != nil {
   log.Fatalln(codeError, err)
}
```

## Issue Reporting
If you have found a bug or if you have a feature request, please report them at this repository issues section. Please do not report security vulnerabilities on the public GitHub issue tracker.

## Secure
If you discover any security related issues, please email [dmalix@yahoo.com](mailto:dmalix@yahoo.com) instead of using the issue tracker.

## Author
[DmAlix](mailto:dmalix@yahoo.com)

## License
This project is licensed under the MIT license. See the [LICENSE](LICENSE) file for more info.
