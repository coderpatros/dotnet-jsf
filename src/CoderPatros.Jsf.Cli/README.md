# JSF CLI

A command-line tool for generating cryptographic keys, signing JSON documents, and verifying signatures using [JSON Signature Format (JSF)](https://cyberphone.github.io/doc/security/jsf.html).

## Installation

Download the latest self-contained binary for your platform from the [GitHub Releases](https://github.com/coderpatros/dotnet-jsf/releases) page.

| Platform | Archive |
|---|---|
| linux-x64 | `jsf-cli-v{version}-linux-x64.tar.gz` |
| linux-arm64 | `jsf-cli-v{version}-linux-arm64.tar.gz` |
| osx-x64 | `jsf-cli-v{version}-osx-x64.tar.gz` |
| osx-arm64 | `jsf-cli-v{version}-osx-arm64.tar.gz` |
| win-x64 | `jsf-cli-v{version}-win-x64.zip` |
| win-arm64 | `jsf-cli-v{version}-win-arm64.zip` |

The binaries are self-contained and do not require .NET to be installed.

### Building from source

Requires .NET 8.0 SDK or later.

```sh
dotnet build src/CoderPatros.Jsf.Cli
```

To produce a self-contained single-file binary:

```sh
dotnet publish src/CoderPatros.Jsf.Cli -c Release -r linux-x64 --self-contained true -p:PublishSingleFile=true -p:PublishTrimmed=true -o ./publish
```

Replace `linux-x64` with your target [runtime identifier](https://learn.microsoft.com/en-us/dotnet/core/rid-catalog).

## Quick start

```sh
# Generate a key pair
jsf generate-key -a ES256

# Sign a document
jsf sign -k ES256-private.jwk -a ES256 -i document.json > signed.json

# Verify the signature
jsf verify -k ES256-public.jwk -i signed.json
```

## Commands

### generate-key

Generate a cryptographic key pair (asymmetric) or symmetric key (HMAC).

```
jsf generate-key -a <algorithm> [-o <directory>]
```

| Option | Description |
|---|---|
| `-a, --algorithm` | **Required.** Algorithm identifier (see [supported algorithms](#supported-algorithms)) |
| `-o, --output` | Output directory for key files. Defaults to the current directory |

For asymmetric algorithms, two files are created:
- `{algorithm}-private.jwk` — private key (created with owner-only permissions on Linux/macOS)
- `{algorithm}-public.jwk` — public key

For symmetric algorithms (HS256, HS384, HS512), one file is created:
- `{algorithm}-symmetric.jwk` — symmetric key (created with owner-only permissions on Linux/macOS)

All key files use standard [JWK (JSON Web Key)](https://www.rfc-editor.org/rfc/rfc7517) format.

#### Examples

```sh
# ECDSA key pair
jsf generate-key -a ES256

# RSA key pair
jsf generate-key -a RS256

# EdDSA key pair
jsf generate-key -a Ed25519

# HMAC symmetric key
jsf generate-key -a HS256

# Specify output directory
jsf generate-key -a ES256 -o ./keys
```

#### Generated key sizes

| Algorithm family | Key details |
|---|---|
| ES256 | ECDSA P-256 |
| ES384 | ECDSA P-384 |
| ES512 | ECDSA P-521 |
| RS256, RS384, RS512 | RSA 2048-bit |
| PS256, PS384, PS512 | RSA 2048-bit |
| Ed25519 | Ed25519 curve |
| Ed448 | Ed448 curve |
| HS256 | 32-byte key |
| HS384 | 48-byte key |
| HS512 | 64-byte key |

### sign

Sign a JSON document. Outputs the signed JSON to stdout.

```
jsf sign -k <key-file> -a <algorithm> [-i <input-file>] [--embed-public-key] [--key-id <id>]
```

| Option | Description |
|---|---|
| `-k, --key` | **Required.** Path to a private (or symmetric) JWK file |
| `-a, --algorithm` | **Required.** Algorithm identifier |
| `-i, --input` | Path to the JSON file to sign. Reads from stdin if not provided |
| `--embed-public-key` | Embed the public key in the signature for self-contained verification. Not available for symmetric (HMAC) keys |
| `--key-id` | Key identifier string to include in the signature |

#### Examples

```sh
# Sign from a file
jsf sign -k ES256-private.jwk -a ES256 -i document.json

# Sign from stdin
echo '{"message":"hello"}' | jsf sign -k ES256-private.jwk -a ES256

# Pipe to a file
jsf sign -k ES256-private.jwk -a ES256 -i document.json > signed.json

# Embed the public key
jsf sign -k ES256-private.jwk -a ES256 --embed-public-key -i document.json

# Include a key identifier
jsf sign -k ES256-private.jwk -a ES256 --key-id my-key-1 -i document.json

# Sign with RSA-PSS
jsf sign -k PS256-private.jwk -a PS256 -i document.json

# Sign with HMAC
jsf sign -k HS256-symmetric.jwk -a HS256 -i document.json
```

### verify

Verify a signed JSON document. Outputs `Valid` on success or `Invalid: <error>` on failure. Exits with code 0 for valid signatures, 1 for invalid.

```
jsf verify [-k <key-file>] [-i <input-file>] [--allow-embedded-key] [--accepted-algorithms <list>]
```

| Option | Description |
|---|---|
| `-k, --key` | Path to a public (or symmetric) JWK file. Optional if the signature has an embedded public key |
| `-i, --input` | Path to the signed JSON file. Reads from stdin if not provided |
| `--allow-embedded-key` | Allow verification using the public key embedded in the signature |
| `--accepted-algorithms` | Comma-separated whitelist of accepted algorithm identifiers (e.g. `ES256,ES384`) |

#### Examples

```sh
# Verify with an explicit key
jsf verify -k ES256-public.jwk -i signed.json

# Verify using the embedded public key
jsf verify --allow-embedded-key -i signed.json

# Verify from stdin
cat signed.json | jsf verify -k ES256-public.jwk

# Restrict to specific algorithms
jsf verify -k ES256-public.jwk --accepted-algorithms ES256,ES384 -i signed.json
```

#### Exit codes

| Code | Meaning |
|---|---|
| 0 | Signature is valid |
| 1 | Signature is invalid, or an error occurred |

## Supported algorithms

| Family | Algorithms |
|---|---|
| ECDSA | ES256, ES384, ES512 |
| RSA PKCS#1 v1.5 | RS256, RS384, RS512 |
| RSA-PSS | PS256, PS384, PS512 |
| EdDSA | Ed25519, Ed448 |
| HMAC | HS256, HS384, HS512 |

## End-to-end examples

### Sign and verify with ECDSA

```sh
jsf generate-key -a ES256 -o ./keys
echo '{"order":"abc123","total":99.95}' | jsf sign -k ./keys/ES256-private.jwk -a ES256 > signed.json
jsf verify -k ./keys/ES256-public.jwk -i signed.json
# Output: Valid
```

### Self-contained signatures with embedded keys

```sh
jsf generate-key -a ES256 -o ./keys
echo '{"status":"approved"}' | jsf sign -k ./keys/ES256-private.jwk -a ES256 --embed-public-key > signed.json
jsf verify --allow-embedded-key -i signed.json
# Output: Valid
```

### Pipeline usage

```sh
# Generate, sign, and verify in a single pipeline
jsf generate-key -a ES256 -o ./keys
echo '{"data":"test"}' \
  | jsf sign -k ./keys/ES256-private.jwk -a ES256 \
  | jsf verify -k ./keys/ES256-public.jwk
# Output: Valid
```

### Algorithm whitelisting

```sh
# Only accept ES256 and ES384 signatures
jsf verify -k key.jwk --accepted-algorithms ES256,ES384 -i signed.json
```

## Security notes

- Private and symmetric key files are created with owner-only permissions (mode 0600) on Linux and macOS
- When using `--allow-embedded-key`, be aware that any signer can embed any public key. Only use this when you trust the source of the document
- Use `--accepted-algorithms` to restrict which algorithms you accept, preventing algorithm confusion attacks
- HMAC keys cannot have their public key embedded (since they are symmetric)

## License

Apache-2.0
