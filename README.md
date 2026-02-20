# JSON Signature Format for .NET

A .NET implementation of [JSON Signature Format (JSF)](https://cyberphone.github.io/doc/security/jsf.html) — a scheme for signing JSON data with enveloped signatures.

JSF embeds cryptographic signatures directly within JSON objects, using [JSON Canonicalization Scheme (RFC 8785)](https://www.rfc-editor.org/rfc/rfc8785) to produce deterministic representations for signing and verification. Unlike JWS/JWT where signatures are separate from the data, JSF keeps signature and payload together in a single JSON structure.

## Features

- **Single signatures**, **multi-signatures** (independent signers), and **signature chains** (sequential)
- **15 algorithms** via JWA identifiers: ECDSA (ES256/384/512), RSA PKCS#1 v1.5 (RS256/384/512), RSA-PSS (PS256/384/512), EdDSA (Ed25519/Ed448), HMAC (HS256/384/512)
- Embedded JWK public keys for self-contained verification
- Property exclusions and custom extensions
- Non-mutating — all operations return new documents
- Accepts both `JsonObject` and `string` inputs
- Custom algorithm registry for extensibility

## Requirements

- .NET 8.0+

## Projects

| Project | Description | Details |
|---|---|---|
| [CoderPatros.Jsf](src/CoderPatros.Jsf/README.md) | .NET library for signing and verifying JSON documents | [Library README](src/CoderPatros.Jsf/README.md) |
| [CoderPatros.Jsf.Cli](src/CoderPatros.Jsf.Cli/README.md) | Command-line tool for key generation, signing, and verification | [CLI README](src/CoderPatros.Jsf.Cli/README.md) |

## Quick start — Library

Install the NuGet package:

```sh
dotnet add package CoderPatros.Jsf
```

Sign and verify a document:

```csharp
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using CoderPatros.Jsf;
using CoderPatros.Jsf.Keys;
using CoderPatros.Jsf.Models;

var service = new JsfSignatureService();

// Create a key pair
using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
var signingKey = SigningKey.FromECDsa(ecdsa);
var verificationKey = VerificationKey.FromECDsa(ecdsa);

// Sign
var document = new JsonObject { ["message"] = "hello" };
var signed = service.Sign(document, new SignatureOptions
{
    Algorithm = JsfAlgorithm.ES256,
    Key = signingKey
});

// Verify
var result = service.Verify(signed, new VerificationOptions
{
    Key = verificationKey
});
Console.WriteLine(result.IsValid); // true
```

See the [Library README](src/CoderPatros.Jsf/README.md) for the full API reference, multi-signature support, signature chains, key management, custom algorithms, and more.

## Quick start — CLI

Download the latest binary from the [Releases](https://github.com/coderpatros/dotnet-jsf/releases) page, or build from source:

```sh
dotnet build src/CoderPatros.Jsf.Cli
```

Generate keys, sign, and verify:

```sh
# Generate an ECDSA key pair
jsf generate-key -a ES256

# Sign a document
jsf sign -k ES256-private.jwk -a ES256 -i document.json > signed.json

# Verify the signature
jsf verify -k ES256-public.jwk -i signed.json
# Output: Valid
```

The CLI also supports stdin/stdout piping, embedded public keys, key identifiers, and algorithm whitelisting. See the [CLI README](src/CoderPatros.Jsf.Cli/README.md) for the full command reference.

## How JSF signing works

1. A signature object is created with the algorithm, optional public key, key ID, excludes, and extensions — but no `value` yet
2. This partial signature object is attached to the document
3. The entire document is canonicalized using JCS (RFC 8785)
4. The canonical bytes are signed with the specified algorithm and key
5. The base64url-encoded signature is set as the `value` property

Verification reverses the process: remove `value`, canonicalize, and verify.

## Running tests

```sh
dotnet test
```

## License

Apache-2.0
