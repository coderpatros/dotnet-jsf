// This file is part of CoderPatros.JSF Library for .NET
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Patrick Dwyer. All Rights Reserved.

using System.Text.Json;
using System.Text.Json.Nodes;
using CoderPatros.Jsf.Serialization;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace CoderPatros.Jsf.Keys;

public static class BouncyCastleJwkKeyHelper
{
    private static readonly JsonSerializerOptions IndentedJsonOptions = new() { WriteIndented = true };

    public static bool IsSymmetricAlgorithm(string algorithm) =>
        algorithm is "HS256" or "HS384" or "HS512";

    public static (string PrivateJwk, string PublicJwk) GenerateAsymmetricKey(string algorithm)
    {
        return algorithm switch
        {
            "ES256" => GenerateEcKey("P-256", "secp256r1"),
            "ES384" => GenerateEcKey("P-384", "secp384r1"),
            "ES512" => GenerateEcKey("P-521", "secp521r1"),
            "RS256" or "RS384" or "RS512" or
            "PS256" or "PS384" or "PS512" => GenerateRsaKey(),
            "Ed25519" => GenerateEdDsaKey("Ed25519"),
            "Ed448" => GenerateEdDsaKey("Ed448"),
            _ => throw new ArgumentException($"Unsupported algorithm: {algorithm}")
        };
    }

    public static string GenerateSymmetricKey(string algorithm)
    {
        var keySize = algorithm switch
        {
            "HS256" => 32,
            "HS384" => 48,
            "HS512" => 64,
            _ => throw new ArgumentException($"Unsupported algorithm: {algorithm}")
        };

        var random = new SecureRandom();
        var key = new byte[keySize];
        random.NextBytes(key);

        var jwk = new JsonObject
        {
            ["kty"] = "oct",
            ["k"] = Base64UrlEncoding.Encode(key)
        };

        return jwk.ToJsonString(IndentedJsonOptions);
    }

    public static SigningKey LoadSigningKey(string jwkJson)
    {
        var obj = JsonNode.Parse(jwkJson)?.AsObject()
            ?? throw new InvalidOperationException("Invalid JWK JSON.");
        var kty = obj["kty"]?.GetValue<string>()
            ?? throw new InvalidOperationException("JWK missing 'kty' field.");

        return kty switch
        {
            "EC" => LoadEcSigningKey(obj),
            "RSA" => LoadRsaSigningKey(obj),
            "OKP" => LoadEdDsaSigningKey(obj),
            "oct" => LoadHmacSigningKey(obj),
            _ => throw new InvalidOperationException($"Unsupported key type: {kty}")
        };
    }

    public static VerificationKey LoadVerificationKey(string jwkJson)
    {
        var obj = JsonNode.Parse(jwkJson)?.AsObject()
            ?? throw new InvalidOperationException("Invalid JWK JSON.");
        var kty = obj["kty"]?.GetValue<string>()
            ?? throw new InvalidOperationException("JWK missing 'kty' field.");

        return kty switch
        {
            "EC" => LoadEcVerificationKey(obj),
            "RSA" => LoadRsaVerificationKey(obj),
            "OKP" => VerificationKey.FromEdDsa(
                Base64UrlEncoding.Decode(obj["x"]!.GetValue<string>()),
                obj["crv"]!.GetValue<string>()),
            "oct" => VerificationKey.FromHmac(
                Base64UrlEncoding.Decode(obj["k"]!.GetValue<string>())),
            _ => throw new InvalidOperationException($"Unsupported key type: {kty}")
        };
    }

    public static JwkPublicKey? ExtractPublicKey(string jwkJson)
    {
        var obj = JsonNode.Parse(jwkJson)?.AsObject()
            ?? throw new InvalidOperationException("Invalid JWK JSON.");
        var kty = obj["kty"]?.GetValue<string>()
            ?? throw new InvalidOperationException("JWK missing 'kty' field.");

        if (kty == "oct")
            return null;

        return JwkKeyHelper.ToJwkPublicKey(obj, kty);
    }

    private static (string PrivateJwk, string PublicJwk) GenerateEcKey(string curveName, string bcCurveName)
    {
        var x9 = ECNamedCurveTable.GetByName(bcCurveName);
        var domainParams = new ECDomainParameters(x9.Curve, x9.G, x9.N, x9.H);

        var gen = new ECKeyPairGenerator();
        gen.Init(new ECKeyGenerationParameters(domainParams, new SecureRandom()));
        var keyPair = gen.GenerateKeyPair();

        var privateKeyParams = (ECPrivateKeyParameters)keyPair.Private;
        var publicKeyParams = (ECPublicKeyParameters)keyPair.Public;

        var q = publicKeyParams.Q.Normalize();
        var fieldSize = (x9.Curve.FieldSize + 7) / 8;
        var xBytes = PadLeft(q.AffineXCoord.GetEncoded(), fieldSize);
        var yBytes = PadLeft(q.AffineYCoord.GetEncoded(), fieldSize);
        var dBytes = PadLeft(privateKeyParams.D.ToByteArrayUnsigned(), fieldSize);

        var privateJwk = new JsonObject
        {
            ["kty"] = "EC",
            ["crv"] = curveName,
            ["x"] = Base64UrlEncoding.Encode(xBytes),
            ["y"] = Base64UrlEncoding.Encode(yBytes),
            ["d"] = Base64UrlEncoding.Encode(dBytes)
        };

        var publicJwk = new JsonObject
        {
            ["kty"] = "EC",
            ["crv"] = curveName,
            ["x"] = Base64UrlEncoding.Encode(xBytes),
            ["y"] = Base64UrlEncoding.Encode(yBytes)
        };

        return (privateJwk.ToJsonString(IndentedJsonOptions), publicJwk.ToJsonString(IndentedJsonOptions));
    }

    private static (string PrivateJwk, string PublicJwk) GenerateRsaKey()
    {
        var gen = new RsaKeyPairGenerator();
        gen.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
        var keyPair = gen.GenerateKeyPair();

        var privateKeyParams = (RsaPrivateCrtKeyParameters)keyPair.Private;
        var publicKeyParams = (RsaKeyParameters)keyPair.Public;

        var privateJwk = new JsonObject
        {
            ["kty"] = "RSA",
            ["n"] = Base64UrlEncoding.Encode(publicKeyParams.Modulus.ToByteArrayUnsigned()),
            ["e"] = Base64UrlEncoding.Encode(publicKeyParams.Exponent.ToByteArrayUnsigned()),
            ["d"] = Base64UrlEncoding.Encode(privateKeyParams.Exponent.ToByteArrayUnsigned()),
            ["p"] = Base64UrlEncoding.Encode(privateKeyParams.P.ToByteArrayUnsigned()),
            ["q"] = Base64UrlEncoding.Encode(privateKeyParams.Q.ToByteArrayUnsigned()),
            ["dp"] = Base64UrlEncoding.Encode(privateKeyParams.DP.ToByteArrayUnsigned()),
            ["dq"] = Base64UrlEncoding.Encode(privateKeyParams.DQ.ToByteArrayUnsigned()),
            ["qi"] = Base64UrlEncoding.Encode(privateKeyParams.QInv.ToByteArrayUnsigned())
        };

        var publicJwk = new JsonObject
        {
            ["kty"] = "RSA",
            ["n"] = Base64UrlEncoding.Encode(publicKeyParams.Modulus.ToByteArrayUnsigned()),
            ["e"] = Base64UrlEncoding.Encode(publicKeyParams.Exponent.ToByteArrayUnsigned())
        };

        return (privateJwk.ToJsonString(IndentedJsonOptions), publicJwk.ToJsonString(IndentedJsonOptions));
    }

    private static (string PrivateJwk, string PublicJwk) GenerateEdDsaKey(string curve)
    {
        byte[] privateKey, publicKey;

        if (curve == "Ed25519")
        {
            var gen = new Ed25519KeyPairGenerator();
            gen.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
            var keyPair = gen.GenerateKeyPair();
            privateKey = ((Ed25519PrivateKeyParameters)keyPair.Private).GetEncoded();
            publicKey = ((Ed25519PublicKeyParameters)keyPair.Public).GetEncoded();
        }
        else if (curve == "Ed448")
        {
            var gen = new Ed448KeyPairGenerator();
            gen.Init(new Ed448KeyGenerationParameters(new SecureRandom()));
            var keyPair = gen.GenerateKeyPair();
            privateKey = ((Ed448PrivateKeyParameters)keyPair.Private).GetEncoded();
            publicKey = ((Ed448PublicKeyParameters)keyPair.Public).GetEncoded();
        }
        else
        {
            throw new ArgumentException($"Unsupported EdDSA curve: {curve}");
        }

        var privateJwk = new JsonObject
        {
            ["kty"] = "OKP",
            ["crv"] = curve,
            ["x"] = Base64UrlEncoding.Encode(publicKey),
            ["d"] = Base64UrlEncoding.Encode(privateKey)
        };

        var publicJwkObj = new JsonObject
        {
            ["kty"] = "OKP",
            ["crv"] = curve,
            ["x"] = Base64UrlEncoding.Encode(publicKey)
        };

        return (privateJwk.ToJsonString(IndentedJsonOptions), publicJwkObj.ToJsonString(IndentedJsonOptions));
    }

    private static SigningKey LoadEcSigningKey(JsonObject obj)
    {
        var crv = obj["crv"]!.GetValue<string>();
        var d = Base64UrlEncoding.Decode(obj["d"]!.GetValue<string>());
        var x = Base64UrlEncoding.Decode(obj["x"]!.GetValue<string>());
        var y = Base64UrlEncoding.Decode(obj["y"]!.GetValue<string>());
        return SigningKey.FromBouncyCastleEc(d, x, y, crv);
    }

    private static SigningKey LoadRsaSigningKey(JsonObject obj)
    {
        return SigningKey.FromBouncyCastleRsa(
            modulus: Base64UrlEncoding.Decode(obj["n"]!.GetValue<string>()),
            exponent: Base64UrlEncoding.Decode(obj["e"]!.GetValue<string>()),
            d: Base64UrlEncoding.Decode(obj["d"]!.GetValue<string>()),
            p: Base64UrlEncoding.Decode(obj["p"]!.GetValue<string>()),
            q: Base64UrlEncoding.Decode(obj["q"]!.GetValue<string>()),
            dp: Base64UrlEncoding.Decode(obj["dp"]!.GetValue<string>()),
            dq: Base64UrlEncoding.Decode(obj["dq"]!.GetValue<string>()),
            inverseQ: Base64UrlEncoding.Decode(obj["qi"]!.GetValue<string>()));
    }

    private static SigningKey LoadEdDsaSigningKey(JsonObject obj)
    {
        var crv = obj["crv"]!.GetValue<string>();
        var d = Base64UrlEncoding.Decode(obj["d"]!.GetValue<string>());
        return SigningKey.FromEdDsa(d, crv);
    }

    private static SigningKey LoadHmacSigningKey(JsonObject obj)
    {
        var k = Base64UrlEncoding.Decode(obj["k"]!.GetValue<string>());
        return SigningKey.FromHmac(k);
    }

    private static VerificationKey LoadEcVerificationKey(JsonObject obj)
    {
        var crv = obj["crv"]!.GetValue<string>();
        var x = Base64UrlEncoding.Decode(obj["x"]!.GetValue<string>());
        var y = Base64UrlEncoding.Decode(obj["y"]!.GetValue<string>());
        return VerificationKey.FromBouncyCastleEc(x, y, crv);
    }

    private static VerificationKey LoadRsaVerificationKey(JsonObject obj)
    {
        return VerificationKey.FromBouncyCastleRsa(
            modulus: Base64UrlEncoding.Decode(obj["n"]!.GetValue<string>()),
            exponent: Base64UrlEncoding.Decode(obj["e"]!.GetValue<string>()));
    }

    private static byte[] PadLeft(byte[] data, int length)
    {
        if (data.Length >= length) return data;
        var padded = new byte[length];
        Array.Copy(data, 0, padded, length - data.Length, data.Length);
        return padded;
    }
}
