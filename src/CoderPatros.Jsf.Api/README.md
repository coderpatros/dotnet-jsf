# JSF API

A REST API for generating cryptographic keys, signing JSON documents, and verifying signatures using [JSON Signature Format (JSF)](https://cyberphone.github.io/doc/security/jsf.html).

## Running

### With Docker

```sh
docker run --rm -p 8080:8080 coderpatros/jsf-api
```

The API starts on `http://localhost:8080`. Browse to `http://localhost:8080/swagger` for the interactive Swagger UI.

### From source

Requires .NET 8.0 SDK or later.

```sh
dotnet run --project src/CoderPatros.Jsf.Api
```

The API starts on `http://localhost:5000` by default.

## Endpoints

### POST /api/keys/generate

Generate a cryptographic key pair (asymmetric) or symmetric key (HMAC).

**Request:**

```json
{
  "algorithm": "ES256"
}
```

**Response (asymmetric):**

```json
{
  "privateKey": { "kty": "EC", "crv": "P-256", "d": "...", "x": "...", "y": "..." },
  "publicKey": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." }
}
```

**Response (symmetric):**

```json
{
  "symmetricKey": { "kty": "oct", "k": "..." }
}
```

### POST /api/sign

Sign a JSON document.

**Request:**

```json
{
  "document": { "message": "hello" },
  "algorithm": "ES256",
  "key": { "kty": "EC", "crv": "P-256", "d": "...", "x": "...", "y": "..." },
  "embedPublicKey": false,
  "keyId": "my-key-1"
}
```

| Field | Required | Description |
|---|---|---|
| `document` | Yes | The JSON object to sign |
| `algorithm` | Yes | Algorithm identifier (see [supported algorithms](#supported-algorithms)) |
| `key` | Yes | Private or symmetric JWK key |
| `embedPublicKey` | No | Embed the public key in the signature (default: `false`) |
| `keyId` | No | Key identifier string to include in the signature |

**Response:**

```json
{
  "document": { "message": "hello", "signature": { "algorithm": "ES256", "value": "..." } }
}
```

### POST /api/verify

Verify a signed JSON document.

**Request:**

```json
{
  "document": { "message": "hello", "signature": { "algorithm": "ES256", "value": "..." } },
  "key": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." },
  "allowEmbeddedKey": false,
  "acceptedAlgorithms": ["ES256", "ES384"]
}
```

| Field | Required | Description |
|---|---|---|
| `document` | Yes | The signed JSON object to verify |
| `key` | No | Public or symmetric JWK key. Optional if using an embedded key |
| `allowEmbeddedKey` | No | Allow verification using the public key embedded in the signature (default: `false`) |
| `acceptedAlgorithms` | No | Whitelist of accepted algorithm identifiers |

**Response:**

```json
{
  "isValid": true,
  "error": null
}
```

### POST /api/signatures/add-signer

Add an independent signer to a multi-signature document.

**Request:**

```json
{
  "document": { "message": "hello", "signature": { "algorithm": "ES256", "value": "..." } },
  "algorithm": "RS256",
  "key": { "kty": "RSA", "d": "...", "n": "...", "e": "..." },
  "embedPublicKey": false,
  "keyId": "signer-2"
}
```

The request fields are the same as [POST /api/sign](#post-apisign). The `document` should already contain one or more existing signatures.

**Response:**

```json
{
  "document": { "message": "hello", "signature": { "signers": [ ... ] } }
}
```

### POST /api/signatures/verify-signers

Verify all signatures in a multi-signer document.

**Request and response** follow the same format as [POST /api/verify](#post-apiverify).

### POST /api/signatures/append-to-chain

Append to a sequential signature chain.

**Request** follows the same format as [POST /api/sign](#post-apisign). Each appended signature covers the document including all previous signatures.

**Response:**

```json
{
  "document": { "message": "hello", "signature": { "chain": [ ... ] } }
}
```

### POST /api/signatures/verify-chain

Verify all entries in a signature chain.

**Request and response** follow the same format as [POST /api/verify](#post-apiverify).

## Error handling

When a request fails, the API returns a `400 Bad Request` with an error message:

```json
{
  "error": "Description of what went wrong."
}
```

## Supported algorithms

| Family | Algorithms |
|---|---|
| ECDSA | ES256, ES384, ES512 |
| RSA PKCS#1 v1.5 | RS256, RS384, RS512 |
| RSA-PSS | PS256, PS384, PS512 |
| EdDSA | Ed25519, Ed448 |
| HMAC | HS256, HS384, HS512 |

## Example: sign and verify with curl

```sh
# Generate a key pair
curl -s -X POST http://localhost:5000/api/keys/generate \
  -H "Content-Type: application/json" \
  -d '{"algorithm":"ES256"}' > keys.json

# Extract keys
PRIVATE_KEY=$(jq '.privateKey' keys.json)
PUBLIC_KEY=$(jq '.publicKey' keys.json)

# Sign a document
SIGNED=$(curl -s -X POST http://localhost:5000/api/sign \
  -H "Content-Type: application/json" \
  -d "{\"document\":{\"message\":\"hello\"},\"algorithm\":\"ES256\",\"key\":$PRIVATE_KEY}")

# Verify the signature
SIGNED_DOC=$(echo "$SIGNED" | jq '.document')
curl -s -X POST http://localhost:5000/api/verify \
  -H "Content-Type: application/json" \
  -d "{\"document\":$SIGNED_DOC,\"key\":$PUBLIC_KEY}"
# Output: {"isValid":true,"error":null}
```

## License

Apache-2.0
