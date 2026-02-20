# CoderPatros.Jsf Library

A .NET library for signing and verifying JSON documents using [JSON Signature Format (JSF)](https://cyberphone.github.io/doc/security/jsf.html) with [JSON Canonicalization Scheme (RFC 8785)](https://www.rfc-editor.org/rfc/rfc8785).

## Installation

```sh
dotnet add package CoderPatros.Jsf
```

Requires .NET 8.0 or later.

## Quick start

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

// Sign a document
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

## API reference

### JsfSignatureService

The main entry point for all operations. Optionally accepts a `SignatureAlgorithmRegistry` for custom algorithms.

```csharp
var service = new JsfSignatureService();
// or with a custom registry:
var service = new JsfSignatureService(customRegistry);
```

#### Signing methods

| Method | Description |
|---|---|
| `Sign(JsonObject, SignatureOptions)` | Sign a document, returns a new `JsonObject` with the signature attached |
| `Sign(string, SignatureOptions)` | Sign a JSON string, returns the signed JSON string |
| `AddSigner(JsonObject, SignatureOptions)` | Add an independent signer to a multi-signature document |
| `AppendToChain(JsonObject, SignatureOptions)` | Append to a sequential signature chain |

All signing methods are non-mutating and return new documents.

#### Verification methods

| Method | Description |
|---|---|
| `Verify(JsonObject, VerificationOptions)` | Verify a single signature |
| `Verify(string, VerificationOptions)` | Verify a single signature from a JSON string |
| `VerifySigners(JsonObject, VerificationOptions)` | Verify all signatures in a multi-signer document |
| `VerifyChain(JsonObject, VerificationOptions)` | Verify all entries in a signature chain |

All verification methods return a `VerificationResult` with `IsValid` and an optional `Error` message.

### SignatureOptions

Configuration for signing operations.

```csharp
new SignatureOptions
{
    Algorithm = JsfAlgorithm.ES256,         // Required: algorithm identifier
    Key = signingKey,                        // Required: signing key
    PublicKey = publicJwk,                   // Optional: embed public key in signature
    KeyId = "my-key-1",                      // Optional: key identifier
    CertificatePath = new[] { "..." },       // Optional: certificate path
    Excludes = new[] { "timestamp" },        // Optional: properties to exclude from signing
    Extensions = new Dictionary<string, JsonNode?>  // Optional: custom extension properties
    {
        ["https://example.com/ext"] = "value"
    },
    SignaturePropertyName = "signature"      // Optional: defaults to "signature"
}
```

### VerificationOptions

Configuration for verification operations.

```csharp
new VerificationOptions
{
    Key = verificationKey,                   // Optional: explicit verification key
    KeyResolver = sig => ResolveKey(sig),    // Optional: resolve key per signature (for multi-sig/chain)
    AllowEmbeddedPublicKey = false,          // Optional: allow using embedded public key (default: false)
    AcceptedAlgorithms = new HashSet<string> // Optional: whitelist of accepted algorithms
    {
        JsfAlgorithm.ES256, JsfAlgorithm.ES384
    },
    SignaturePropertyName = "signature"      // Optional: defaults to "signature"
}
```

When `AllowEmbeddedPublicKey` is `true`, signatures containing an embedded public key can be verified without providing an explicit key. Only enable this when you trust the source of the document, as an attacker can embed any public key in a signature they create.

### VerificationResult

```csharp
var result = service.Verify(signed, options);
if (result.IsValid)
{
    // Signature is valid
}
else
{
    Console.WriteLine(result.Error); // Description of what failed
}
```

## Key management

### Creating keys

```csharp
// ECDSA
using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
var signingKey = SigningKey.FromECDsa(ecdsa);
var verificationKey = VerificationKey.FromECDsa(ecdsa);

// RSA
using var rsa = RSA.Create(2048);
var rsaSigningKey = SigningKey.FromRsa(rsa);
var rsaVerificationKey = VerificationKey.FromRsa(rsa);

// HMAC (symmetric)
var hmacKeyBytes = new byte[32];
RandomNumberGenerator.Fill(hmacKeyBytes);
var hmacSigningKey = SigningKey.FromHmac(hmacKeyBytes);
var hmacVerificationKey = VerificationKey.FromHmac(hmacKeyBytes);

// EdDSA (raw key bytes)
var edSigningKey = SigningKey.FromEdDsa(privateKeyBytes, JsfAlgorithm.Ed25519);
var edVerificationKey = VerificationKey.FromEdDsa(publicKeyBytes, JsfAlgorithm.Ed25519);
```

Both `SigningKey` and `VerificationKey` implement `IDisposable` and securely zero key material on disposal. Always use `using` statements or explicitly dispose keys when finished.

### Embedded public keys (JWK)

You can embed a JWK public key in the signature for self-contained verification.

```csharp
// Convert a .NET key to JWK format
var publicJwk = JwkKeyConverter.FromECDsa(ecdsa);     // EC keys
var publicJwk = JwkKeyConverter.FromRsa(rsa);           // RSA keys
var publicJwk = JwkKeyConverter.FromEdDsa(pubBytes, "Ed25519"); // EdDSA keys

// Embed in signature
var signed = service.Sign(document, new SignatureOptions
{
    Algorithm = JsfAlgorithm.ES256,
    Key = signingKey,
    PublicKey = publicJwk
});

// Verify using the embedded key
var result = service.Verify(signed, new VerificationOptions
{
    AllowEmbeddedPublicKey = true
});
```

### Converting JWK to verification keys

```csharp
// From JwkPublicKey to .NET types
ECDsa ecdsa = JwkKeyConverter.ToECDsa(jwk);
RSA rsa = JwkKeyConverter.ToRsa(jwk);

// Or directly to a VerificationKey
VerificationKey key = JwkKeyConverter.ToVerificationKey(jwk);
```

## Supported algorithms

| Family | Algorithms | Key type |
|---|---|---|
| ECDSA | ES256, ES384, ES512 | ECDsa (P-256, P-384, P-521) |
| RSA PKCS#1 v1.5 | RS256, RS384, RS512 | RSA |
| RSA-PSS | PS256, PS384, PS512 | RSA |
| EdDSA | Ed25519, Ed448 | Raw bytes (via BouncyCastle) |
| HMAC | HS256, HS384, HS512 | Symmetric byte array |

Algorithm identifiers follow the [JWA (JSON Web Algorithms)](https://www.rfc-editor.org/rfc/rfc7518) specification. Use `JsfAlgorithm` constants for type safety.

## Multi-signature (independent signers)

Multiple parties can independently sign a document. Each signature is verified separately, and all must be valid.

```csharp
var doc = new JsonObject { ["message"] = "hello" };

// Each signer adds their signature independently
var withSigner1 = service.AddSigner(doc, new SignatureOptions
{
    Algorithm = JsfAlgorithm.ES256,
    Key = signer1Key,
    KeyId = "signer-1"
});

var withBoth = service.AddSigner(withSigner1, new SignatureOptions
{
    Algorithm = JsfAlgorithm.RS256,
    Key = signer2Key,
    KeyId = "signer-2"
});

// Verify all signers using a key resolver
var result = service.VerifySigners(withBoth, new VerificationOptions
{
    KeyResolver = sig => sig.KeyId switch
    {
        "signer-1" => signer1VerificationKey,
        "signer-2" => signer2VerificationKey,
        _ => throw new Exception("Unknown signer")
    }
});
```

## Signature chains (sequential signatures)

Signatures are applied sequentially, where each signature covers the document including all previous signatures.

```csharp
var doc = new JsonObject { ["message"] = "hello" };

var withFirst = service.AppendToChain(doc, new SignatureOptions
{
    Algorithm = JsfAlgorithm.ES256,
    Key = firstSignerKey,
    KeyId = "first"
});

var withBoth = service.AppendToChain(withFirst, new SignatureOptions
{
    Algorithm = JsfAlgorithm.ES256,
    Key = secondSignerKey,
    KeyId = "second"
});

var result = service.VerifyChain(withBoth, new VerificationOptions
{
    KeyResolver = sig => ResolveKey(sig)
});
```

## Property exclusions and extensions

### Excluding properties from signing

Mark properties that should not be covered by the signature. Excluded properties can be modified without invalidating the signature.

```csharp
var signed = service.Sign(document, new SignatureOptions
{
    Algorithm = JsfAlgorithm.ES256,
    Key = signingKey,
    Excludes = ["timestamp", "nonce"]
});
```

### Adding extension properties

Attach custom metadata to the signature object itself.

```csharp
var signed = service.Sign(document, new SignatureOptions
{
    Algorithm = JsfAlgorithm.ES256,
    Key = signingKey,
    Extensions = new Dictionary<string, JsonNode?>
    {
        ["https://example.com/ext"] = "value"
    }
});
```

## Custom signature property name

By default, signatures are stored in a `"signature"` property. You can override this for both signing and verification.

```csharp
var signed = service.Sign(document, new SignatureOptions
{
    Algorithm = JsfAlgorithm.ES256,
    Key = signingKey,
    SignaturePropertyName = "proof"
});

var result = service.Verify(signed, new VerificationOptions
{
    Key = verificationKey,
    SignaturePropertyName = "proof"
});
```

## Custom algorithm registry

Register additional signature algorithms by implementing `ISignatureAlgorithm` and adding them to a custom registry.

```csharp
public class MyCustomAlgorithm : ISignatureAlgorithm
{
    public string AlgorithmId => "CUSTOM-256";

    public byte[] Sign(ReadOnlySpan<byte> data, SigningKey key)
    {
        // Your signing implementation
    }

    public bool Verify(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature, VerificationKey key)
    {
        // Your verification implementation
    }
}

var registry = new SignatureAlgorithmRegistry();
registry.Register(new MyCustomAlgorithm());
var service = new JsfSignatureService(registry);
```

## Algorithm whitelisting

Restrict which algorithms are accepted during verification to prevent algorithm confusion attacks.

```csharp
var result = service.Verify(signed, new VerificationOptions
{
    Key = verificationKey,
    AcceptedAlgorithms = new HashSet<string>
    {
        JsfAlgorithm.ES256,
        JsfAlgorithm.ES384
    }
});
```

## How JSF signing works

1. A signature object is created with the algorithm, optional public key, key ID, excludes, and extensions — but no `value` yet
2. This partial signature object is attached to the document
3. The entire document is canonicalized using JCS (RFC 8785)
4. The canonical bytes are signed with the specified algorithm and key
5. The base64url-encoded signature is set as the `value` property

Verification reverses the process: remove `value`, canonicalize, and verify.

## Exceptions

| Exception | Description |
|---|---|
| `JsfException` | Base exception for all JSF operations |
| `JsfSigningException` | Thrown when a signing operation fails |
| `JsfVerificationException` | Thrown when verification encounters an unexpected error |

## License

Apache-2.0
