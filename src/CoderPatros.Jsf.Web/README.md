# JSF Web Tool

A browser-based tool for generating cryptographic keys, signing JSON documents, and verifying signatures using [JSON Signature Format (JSF)](https://cyberphone.github.io/doc/security/jsf.html).

Built with Blazor WebAssembly — all cryptographic operations run entirely in the browser. Your keys and documents never leave your machine.

## Online

Use the web tool at [patrickdwyer.au/dotnet-jsf](https://patrickdwyer.au/dotnet-jsf/) — no installation required.

## Running locally

Requires .NET 8.0 SDK or later.

```sh
dotnet run --project src/CoderPatros.Jsf.Web
```

## Pages

### Generate Key

Create cryptographic key pairs for signing and verification.

- Select an algorithm from the dropdown
- Click **Generate Key** to create a new key pair (or symmetric key for HMAC)
- Copy keys to clipboard or download as `.jwk` files
- Private and symmetric keys are clearly labelled as secret

### Sign

Sign a JSON document with a private or symmetric key.

- Select the signing algorithm
- Paste a JWK private key or upload a `.jwk` file
- Optionally embed the public key in the signature for self-contained verification
- Optionally include a key identifier
- Paste or upload the JSON document to sign
- The signed document is displayed for copying

### Verify

Verify a signed JSON document.

- Paste or upload the signed JSON document
- Paste or upload the public or symmetric JWK key, or enable **Allow embedded public key** to use the key from the signature
- The result shows **Valid** or **Invalid** with an error message if verification failed

## Supported algorithms

| Family | Algorithms |
|---|---|
| ECDSA | ES256, ES384, ES512 |
| RSA PKCS#1 v1.5 | RS256, RS384, RS512 |
| RSA-PSS | PS256, PS384, PS512 |
| EdDSA | Ed25519, Ed448 |
| HMAC | HS256, HS384, HS512 |

## Privacy

This is a client-side application. All key generation, signing, and verification happens in the browser via WebAssembly. No data is sent to any server.

## License

Apache-2.0
