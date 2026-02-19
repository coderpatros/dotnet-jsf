# CoderPatros.Jsf

A .NET implementation of [JSON Signature Format (JSF)](https://cyberphone.github.io/doc/security/jsf.html) — a scheme for signing JSON data with enveloped signatures.

JSF embeds cryptographic signatures directly within JSON objects, using [JSON Canonicalization Scheme (RFC 8785)](https://www.rfc-editor.org/rfc/rfc8785) to produce deterministic representations for signing and verification. Unlike JWS/JWT where signatures are separate from the data, JSF keeps signature and payload together in a single JSON structure.

## Features

- **Single signatures**, **multi-signatures** (independent signers), and **signature chains** (sequential)
- **15 algorithms** via JWA identifiers: ECDSA (ES256/384/512), RSA PKCS#1 v1.5 (RS256/384/512), RSA-PSS (PS256/384/512), EdDSA (Ed25519/Ed448), HMAC (HS256/384/512)
- Embedded JWK public keys for self-contained verification
- Property exclusions and custom extensions
- Non-mutating — all operations return new documents
- Accepts both `JsonObject` and `string` inputs

## Requirements

- .NET 8.0+

## Usage

All operations go through `JsfSignatureService`.

### Sign and verify

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
var publicJwk = JwkKeyConverter.FromECDsa(ecdsa);

// Sign
var document = new JsonObject { ["message"] = "hello" };
var signed = service.Sign(document, new SignatureOptions
{
    Algorithm = JsfAlgorithm.ES256,
    Key = signingKey,
    PublicKey = publicJwk  // optional: embed public key in signature
});

// Verify with an explicit key
var result = service.Verify(signed, new VerificationOptions
{
    Key = verificationKey
});

// Or verify using the embedded public key
var result2 = service.Verify(signed, new VerificationOptions());

Console.WriteLine(result.IsValid); // true
```

### Multi-signature (independent signers)

```csharp
var doc = new JsonObject { ["message"] = "hello" };

var withSigner1 = service.AddSigner(doc, optionsForSigner1);
var withBoth = service.AddSigner(withSigner1, optionsForSigner2);

var result = service.VerifySigners(withBoth, new VerificationOptions
{
    KeyResolver = sig => ResolveKeyForSignature(sig)
});
```

### Signature chain (sequential signatures)

```csharp
var doc = new JsonObject { ["message"] = "hello" };

var withFirst = service.AppendToChain(doc, optionsForFirst);
var withBoth = service.AppendToChain(withFirst, optionsForSecond);

var result = service.VerifyChain(withBoth, new VerificationOptions
{
    KeyResolver = sig => ResolveKeyForSignature(sig)
});
```

### Excluding properties and adding extensions

```csharp
var signed = service.Sign(document, new SignatureOptions
{
    Algorithm = JsfAlgorithm.ES256,
    Key = signingKey,
    Excludes = ["timestamp", "nonce"],
    Extensions = new Dictionary<string, JsonNode?>
    {
        ["https://example.com/ext"] = "value"
    }
});
```

### Signing with other key types

```csharp
// RSA
using var rsa = RSA.Create(2048);
var rsaSigningKey = SigningKey.FromRsa(rsa);

// HMAC (symmetric)
var hmacKey = new byte[32];
RandomNumberGenerator.Fill(hmacKey);
var hmacSigningKey = SigningKey.FromHmac(hmacKey);

// EdDSA (via raw key bytes)
var edSigningKey = SigningKey.FromEdDsa(privateKeyBytes, JsfAlgorithm.Ed25519);
```

### Custom signature property name

By default signatures are stored in a `"signature"` property. You can override this:

```csharp
var signed = service.Sign(document, new SignatureOptions
{
    Algorithm = JsfAlgorithm.ES256,
    Key = signingKey,
    SignaturePropertyName = "proof"
});

var result = service.Verify(signed, new VerificationOptions
{
    SignaturePropertyName = "proof"
});
```

### Custom algorithm registry

You can register additional algorithms by providing a custom `SignatureAlgorithmRegistry`:

```csharp
var registry = new SignatureAlgorithmRegistry();
registry.Register(myCustomAlgorithm);

var service = new JsfSignatureService(registry);
```

## CLI

The `CoderPatros.Jsf.Cli` project provides a command-line tool for key generation, signing, and verification.

### Generate a key pair

```sh
# Asymmetric (generates <alg>-private.jwk and <alg>-public.jwk)
jsf generate-key -a ES256

# Symmetric / HMAC (generates <alg>-symmetric.jwk)
jsf generate-key -a HS256

# Specify output directory
jsf generate-key -a ES256 -o ./keys
```

### Sign a document

```sh
# From a file
jsf sign -k ES256-private.jwk -a ES256 -i document.json

# From stdin
echo '{"message":"hello"}' | jsf sign -k ES256-private.jwk -a ES256

# Embed the public key in the signature
jsf sign -k ES256-private.jwk -a ES256 --embed-public-key -i document.json

# Include a key identifier
jsf sign -k ES256-private.jwk -a ES256 --key-id my-key-1 -i document.json
```

### Verify a signed document

```sh
# With an explicit key
jsf verify -k ES256-public.jwk -i signed.json

# Using the embedded public key
jsf verify -i signed.json

# From stdin
cat signed.json | jsf verify -k ES256-public.jwk
```

Outputs `Valid` on success or `Invalid: <error>` on failure.

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
