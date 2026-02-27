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
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;

namespace CoderPatros.Jsf.Crypto.Algorithms;

internal sealed class BouncyCastleRsaPkcs1Algorithm : ISignatureAlgorithm
{
    public string AlgorithmId { get; }
    private readonly string _hashAlgorithm;
    private const int MinimumRsaKeySizeBits = 2048;

    public BouncyCastleRsaPkcs1Algorithm(string algorithmId, string hashAlgorithm)
    {
        AlgorithmId = algorithmId;
        _hashAlgorithm = hashAlgorithm;
    }

    public byte[] Sign(ReadOnlySpan<byte> data, SigningKey key)
    {
        if (key.KeyMaterial is not SigningKey.BouncyCastleRsaKeyMaterial rsaKey)
            throw new JsfException($"Algorithm {AlgorithmId} requires a BouncyCastle RSA key.");
        ValidateKeySize(rsaKey.Modulus);

        var privateKeyParams = CreatePrivateKeyParameters(rsaKey);
        var signer = new RsaDigestSigner(CreateDigest());
        signer.Init(true, privateKeyParams);
        var dataArray = data.ToArray();
        signer.BlockUpdate(dataArray, 0, dataArray.Length);
        return signer.GenerateSignature();
    }

    public bool Verify(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature, VerificationKey key)
    {
        var (modulus, exponent) = ResolvePublicKey(key);
        ValidateKeySize(modulus);

        var publicKeyParams = new RsaKeyParameters(false, new BigInteger(1, modulus), new BigInteger(1, exponent));
        var verifier = new RsaDigestSigner(CreateDigest());
        verifier.Init(false, publicKeyParams);
        var dataArray = data.ToArray();
        verifier.BlockUpdate(dataArray, 0, dataArray.Length);
        return verifier.VerifySignature(signature.ToArray());
    }

    private IDigest CreateDigest()
    {
        return _hashAlgorithm switch
        {
            "SHA-256" => new Sha256Digest(),
            "SHA-384" => new Sha384Digest(),
            "SHA-512" => new Sha512Digest(),
            _ => throw new JsfException($"Unsupported hash algorithm: {_hashAlgorithm}")
        };
    }

    private static RsaPrivateCrtKeyParameters CreatePrivateKeyParameters(SigningKey.BouncyCastleRsaKeyMaterial rsaKey)
    {
        return new RsaPrivateCrtKeyParameters(
            new BigInteger(1, rsaKey.Modulus),
            new BigInteger(1, rsaKey.Exponent),
            new BigInteger(1, rsaKey.D),
            new BigInteger(1, rsaKey.P),
            new BigInteger(1, rsaKey.Q),
            new BigInteger(1, rsaKey.DP),
            new BigInteger(1, rsaKey.DQ),
            new BigInteger(1, rsaKey.InverseQ));
    }

    private static void ValidateKeySize(byte[] modulus)
    {
        var keySizeBits = modulus.Length * 8;
        if (keySizeBits < MinimumRsaKeySizeBits)
            throw new JsfException($"RSA key size {keySizeBits} bits is below the minimum of {MinimumRsaKeySizeBits} bits.");
    }

    private static (byte[] Modulus, byte[] Exponent) ResolvePublicKey(VerificationKey key)
    {
        return key.KeyMaterial switch
        {
            VerificationKey.BouncyCastleRsaKeyMaterial rsa => (rsa.Modulus, rsa.Exponent),
            JwkPublicKey jwk when jwk.Kty == "RSA" => (
                Base64UrlEncoding.Decode(jwk.N!),
                Base64UrlEncoding.Decode(jwk.E!)),
            _ => throw new JsfException("Invalid key type for BouncyCastle RSA PKCS#1 verification.")
        };
    }
}
