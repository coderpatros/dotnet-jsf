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
using CoderPatros.Jsf.Serialization;
using Org.BouncyCastle.Crypto.Parameters;

namespace CoderPatros.Jsf.Keys;

/// <summary>
/// Converts between JWK representations and .NET cryptographic key types.
/// </summary>
public static class JwkKeyConverter
{
    public static JwkPublicKey FromECDsa(ECDsa key)
    {
        var p = key.ExportParameters(false);
        var curveName = GetEcCurveName(p.Curve);

        return new JwkPublicKey
        {
            Kty = "EC",
            Crv = curveName,
            X = Base64UrlEncoding.Encode(p.Q.X!),
            Y = Base64UrlEncoding.Encode(p.Q.Y!)
        };
    }

    public static JwkPublicKey FromRsa(RSA key)
    {
        var p = key.ExportParameters(false);

        return new JwkPublicKey
        {
            Kty = "RSA",
            N = Base64UrlEncoding.Encode(p.Modulus!),
            E = Base64UrlEncoding.Encode(p.Exponent!)
        };
    }

    public static JwkPublicKey FromEdDsa(byte[] publicKey, string curve)
    {
        return new JwkPublicKey
        {
            Kty = "OKP",
            Crv = curve,
            X = Base64UrlEncoding.Encode(publicKey)
        };
    }

    public static ECDsa ToECDsa(JwkPublicKey jwk)
    {
        if (jwk.Kty != "EC")
            throw new ArgumentException("JWK key type must be 'EC'.");

        var curve = GetEcCurve(jwk.Crv!);
        var x = Base64UrlEncoding.Decode(jwk.X!);
        var y = Base64UrlEncoding.Decode(jwk.Y!);

        var parameters = new ECParameters
        {
            Curve = curve,
            Q = new ECPoint { X = x, Y = y }
        };

        var ecdsa = ECDsa.Create(parameters);
        return ecdsa;
    }

    public static RSA ToRsa(JwkPublicKey jwk)
    {
        if (jwk.Kty != "RSA")
            throw new ArgumentException("JWK key type must be 'RSA'.");

        var n = Base64UrlEncoding.Decode(jwk.N!);
        var e = Base64UrlEncoding.Decode(jwk.E!);

        var parameters = new RSAParameters
        {
            Modulus = n,
            Exponent = e
        };

        var rsa = RSA.Create(parameters);
        return rsa;
    }

    public static VerificationKey ToVerificationKey(JwkPublicKey jwk)
    {
        return jwk.Kty switch
        {
            "EC" => VerificationKey.FromECDsa(ToECDsa(jwk)),
            "RSA" => VerificationKey.FromRsa(ToRsa(jwk)),
            "OKP" => VerificationKey.FromEdDsa(Base64UrlEncoding.Decode(jwk.X!), jwk.Crv!),
            _ => throw new ArgumentException($"Unsupported key type: {jwk.Kty}")
        };
    }

    private static string GetEcCurveName(ECCurve curve)
    {
        if (curve.Oid?.FriendlyName == "nistP256" || curve.Oid?.Value == "1.2.840.10045.3.1.7")
            return "P-256";
        if (curve.Oid?.FriendlyName == "nistP384" || curve.Oid?.Value == "1.3.132.0.34")
            return "P-384";
        if (curve.Oid?.FriendlyName == "nistP521" || curve.Oid?.Value == "1.3.132.0.35")
            return "P-521";

        throw new ArgumentException($"Unsupported EC curve: {curve.Oid?.FriendlyName ?? curve.Oid?.Value}");
    }

    private static ECCurve GetEcCurve(string curveName)
    {
        return curveName switch
        {
            "P-256" => ECCurve.NamedCurves.nistP256,
            "P-384" => ECCurve.NamedCurves.nistP384,
            "P-521" => ECCurve.NamedCurves.nistP521,
            _ => throw new ArgumentException($"Unsupported curve: {curveName}")
        };
    }
}
