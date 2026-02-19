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

using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using CoderPatros.Jsf.Keys;
using CoderPatros.Jsf.Serialization;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace CoderPatros.Jsf.Cli;

internal static class JwkKeyHelper
{
    private static readonly JsonSerializerOptions IndentedJsonOptions = new() { WriteIndented = true };

    public static bool IsSymmetricAlgorithm(string algorithm) =>
        algorithm is "HS256" or "HS384" or "HS512";

    public static (string PrivateJwk, string PublicJwk) GenerateAsymmetricKey(string algorithm)
    {
        return algorithm switch
        {
            "ES256" => GenerateEcKey(ECCurve.NamedCurves.nistP256, "P-256"),
            "ES384" => GenerateEcKey(ECCurve.NamedCurves.nistP384, "P-384"),
            "ES512" => GenerateEcKey(ECCurve.NamedCurves.nistP521, "P-521"),
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

        var key = new byte[keySize];
        RandomNumberGenerator.Fill(key);

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

        if (kty == "oct")
        {
            var k = Base64UrlEncoding.Decode(obj["k"]!.GetValue<string>());
            return VerificationKey.FromHmac(k);
        }

        var jwkPublicKey = ToJwkPublicKey(obj, kty);
        return JwkKeyConverter.ToVerificationKey(jwkPublicKey);
    }

    public static JwkPublicKey? ExtractPublicKey(string jwkJson)
    {
        var obj = JsonNode.Parse(jwkJson)?.AsObject()
            ?? throw new InvalidOperationException("Invalid JWK JSON.");
        var kty = obj["kty"]?.GetValue<string>()
            ?? throw new InvalidOperationException("JWK missing 'kty' field.");

        if (kty == "oct")
            return null;

        return ToJwkPublicKey(obj, kty);
    }

    private static JwkPublicKey ToJwkPublicKey(JsonObject obj, string kty)
    {
        return kty switch
        {
            "EC" => new JwkPublicKey
            {
                Kty = "EC",
                Crv = obj["crv"]!.GetValue<string>(),
                X = obj["x"]!.GetValue<string>(),
                Y = obj["y"]!.GetValue<string>()
            },
            "RSA" => new JwkPublicKey
            {
                Kty = "RSA",
                N = obj["n"]!.GetValue<string>(),
                E = obj["e"]!.GetValue<string>()
            },
            "OKP" => new JwkPublicKey
            {
                Kty = "OKP",
                Crv = obj["crv"]!.GetValue<string>(),
                X = obj["x"]!.GetValue<string>()
            },
            _ => throw new InvalidOperationException($"Unsupported key type: {kty}")
        };
    }

    private static (string PrivateJwk, string PublicJwk) GenerateEcKey(ECCurve curve, string curveName)
    {
        using var ecdsa = ECDsa.Create(curve);
        var p = ecdsa.ExportParameters(true);

        var privateJwk = new JsonObject
        {
            ["kty"] = "EC",
            ["crv"] = curveName,
            ["x"] = Base64UrlEncoding.Encode(p.Q.X!),
            ["y"] = Base64UrlEncoding.Encode(p.Q.Y!),
            ["d"] = Base64UrlEncoding.Encode(p.D!)
        };

        var publicJwk = new JsonObject
        {
            ["kty"] = "EC",
            ["crv"] = curveName,
            ["x"] = Base64UrlEncoding.Encode(p.Q.X!),
            ["y"] = Base64UrlEncoding.Encode(p.Q.Y!)
        };

        return (privateJwk.ToJsonString(IndentedJsonOptions), publicJwk.ToJsonString(IndentedJsonOptions));
    }

    private static (string PrivateJwk, string PublicJwk) GenerateRsaKey()
    {
        using var rsa = RSA.Create(2048);
        var p = rsa.ExportParameters(true);

        var privateJwk = new JsonObject
        {
            ["kty"] = "RSA",
            ["n"] = Base64UrlEncoding.Encode(p.Modulus!),
            ["e"] = Base64UrlEncoding.Encode(p.Exponent!),
            ["d"] = Base64UrlEncoding.Encode(p.D!),
            ["p"] = Base64UrlEncoding.Encode(p.P!),
            ["q"] = Base64UrlEncoding.Encode(p.Q!),
            ["dp"] = Base64UrlEncoding.Encode(p.DP!),
            ["dq"] = Base64UrlEncoding.Encode(p.DQ!),
            ["qi"] = Base64UrlEncoding.Encode(p.InverseQ!)
        };

        var publicJwk = new JsonObject
        {
            ["kty"] = "RSA",
            ["n"] = Base64UrlEncoding.Encode(p.Modulus!),
            ["e"] = Base64UrlEncoding.Encode(p.Exponent!)
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
        var curve = crv switch
        {
            "P-256" => ECCurve.NamedCurves.nistP256,
            "P-384" => ECCurve.NamedCurves.nistP384,
            "P-521" => ECCurve.NamedCurves.nistP521,
            _ => throw new InvalidOperationException($"Unsupported EC curve: {crv}")
        };

        var parameters = new ECParameters
        {
            Curve = curve,
            Q = new ECPoint
            {
                X = Base64UrlEncoding.Decode(obj["x"]!.GetValue<string>()),
                Y = Base64UrlEncoding.Decode(obj["y"]!.GetValue<string>())
            },
            D = Base64UrlEncoding.Decode(obj["d"]!.GetValue<string>())
        };

        return SigningKey.FromECDsa(ECDsa.Create(parameters));
    }

    private static SigningKey LoadRsaSigningKey(JsonObject obj)
    {
        var parameters = new RSAParameters
        {
            Modulus = Base64UrlEncoding.Decode(obj["n"]!.GetValue<string>()),
            Exponent = Base64UrlEncoding.Decode(obj["e"]!.GetValue<string>()),
            D = Base64UrlEncoding.Decode(obj["d"]!.GetValue<string>()),
            P = Base64UrlEncoding.Decode(obj["p"]!.GetValue<string>()),
            Q = Base64UrlEncoding.Decode(obj["q"]!.GetValue<string>()),
            DP = Base64UrlEncoding.Decode(obj["dp"]!.GetValue<string>()),
            DQ = Base64UrlEncoding.Decode(obj["dq"]!.GetValue<string>()),
            InverseQ = Base64UrlEncoding.Decode(obj["qi"]!.GetValue<string>())
        };

        return SigningKey.FromRsa(RSA.Create(parameters));
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
}
