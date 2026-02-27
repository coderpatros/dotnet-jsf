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

using CoderPatros.Jsf.Keys;
using CoderPatros.Jsf.Serialization;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;

namespace CoderPatros.Jsf.Crypto.Algorithms;

internal sealed class BouncyCastleEcdsaAlgorithm : ISignatureAlgorithm
{
    public string AlgorithmId { get; }
    private readonly string _hashAlgorithm;
    private readonly string _curveName;
    private readonly int _coordinateSize;

    public BouncyCastleEcdsaAlgorithm(string algorithmId, string hashAlgorithm)
    {
        AlgorithmId = algorithmId;
        _hashAlgorithm = hashAlgorithm;
        (_curveName, _coordinateSize) = algorithmId switch
        {
            "ES256" => ("P-256", 32),
            "ES384" => ("P-384", 48),
            "ES512" => ("P-521", 66),
            _ => throw new ArgumentException($"Unknown ECDSA algorithm: {algorithmId}")
        };
    }

    public byte[] Sign(ReadOnlySpan<byte> data, SigningKey key)
    {
        if (key.KeyMaterial is not SigningKey.BouncyCastleEcKeyMaterial ecKey)
            throw new JsfException($"Algorithm {AlgorithmId} requires a BouncyCastle EC key.");
        ValidateCurve(ecKey.Curve);

        var curveParams = GetCurveParameters();
        var d = new BigInteger(1, ecKey.D);
        var privateKeyParams = new ECPrivateKeyParameters(d, curveParams);

        var hash = ComputeHash(data);
        var signer = new ECDsaSigner();
        signer.Init(true, privateKeyParams);
        var components = signer.GenerateSignature(hash);

        return DerToP1363(components[0], components[1], _coordinateSize);
    }

    public bool Verify(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature, VerificationKey key)
    {
        var (x, y, curve) = ResolvePublicKey(key);
        ValidateCurve(curve);

        var curveParams = GetCurveParameters();
        var point = curveParams.Curve.CreatePoint(
            new BigInteger(1, x),
            new BigInteger(1, y));
        var publicKeyParams = new ECPublicKeyParameters(point, curveParams);

        var hash = ComputeHash(data);
        var (r, s) = P1363ToDer(signature, _coordinateSize);

        var verifier = new ECDsaSigner();
        verifier.Init(false, publicKeyParams);
        return verifier.VerifySignature(hash, r, s);
    }

    private void ValidateCurve(string curve)
    {
        if (curve != _curveName)
            throw new JsfException($"Algorithm {AlgorithmId} requires curve {_curveName}, but key uses {curve}.");
    }

    private ECDomainParameters GetCurveParameters()
    {
        var oid = _curveName switch
        {
            "P-256" => "secp256r1",
            "P-384" => "secp384r1",
            "P-521" => "secp521r1",
            _ => throw new JsfException($"Unsupported curve: {_curveName}")
        };
        var x9 = ECNamedCurveTable.GetByName(oid);
        return new ECDomainParameters(x9.Curve, x9.G, x9.N, x9.H);
    }

    private byte[] ComputeHash(ReadOnlySpan<byte> data)
    {
        var digest = _hashAlgorithm switch
        {
            "SHA-256" => (Org.BouncyCastle.Crypto.IDigest)new Org.BouncyCastle.Crypto.Digests.Sha256Digest(),
            "SHA-384" => new Org.BouncyCastle.Crypto.Digests.Sha384Digest(),
            "SHA-512" => new Org.BouncyCastle.Crypto.Digests.Sha512Digest(),
            _ => throw new JsfException($"Unsupported hash algorithm: {_hashAlgorithm}")
        };
        var dataArray = data.ToArray();
        digest.BlockUpdate(dataArray, 0, dataArray.Length);
        var hash = new byte[digest.GetDigestSize()];
        digest.DoFinal(hash, 0);
        return hash;
    }

    private static byte[] DerToP1363(BigInteger r, BigInteger s, int coordinateSize)
    {
        var result = new byte[coordinateSize * 2];
        var rBytes = r.ToByteArrayUnsigned();
        var sBytes = s.ToByteArrayUnsigned();
        Array.Copy(rBytes, 0, result, coordinateSize - rBytes.Length, rBytes.Length);
        Array.Copy(sBytes, 0, result, coordinateSize * 2 - sBytes.Length, sBytes.Length);
        return result;
    }

    private static (BigInteger R, BigInteger S) P1363ToDer(ReadOnlySpan<byte> signature, int coordinateSize)
    {
        if (signature.Length != coordinateSize * 2)
            throw new JsfException($"Invalid ECDSA signature length: expected {coordinateSize * 2}, got {signature.Length}.");
        var r = new BigInteger(1, signature.Slice(0, coordinateSize).ToArray());
        var s = new BigInteger(1, signature.Slice(coordinateSize, coordinateSize).ToArray());
        return (r, s);
    }

    private static (byte[] X, byte[] Y, string Curve) ResolvePublicKey(VerificationKey key)
    {
        return key.KeyMaterial switch
        {
            VerificationKey.BouncyCastleEcKeyMaterial ec => (ec.X, ec.Y, ec.Curve),
            JwkPublicKey jwk when jwk.Kty == "EC" => (
                Base64UrlEncoding.Decode(jwk.X!),
                Base64UrlEncoding.Decode(jwk.Y!),
                jwk.Crv!),
            _ => throw new JsfException("Invalid key type for BouncyCastle ECDSA verification.")
        };
    }
}
