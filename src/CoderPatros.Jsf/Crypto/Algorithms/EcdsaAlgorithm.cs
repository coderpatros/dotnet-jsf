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
using CoderPatros.Jsf.Keys;

namespace CoderPatros.Jsf.Crypto.Algorithms;

using CoderPatros.Jsf;

internal sealed class EcdsaAlgorithm : ISignatureAlgorithm
{
    public string AlgorithmId { get; }
    private readonly HashAlgorithmName _hashAlgorithm;
    private readonly string _expectedCurveOid;

    public EcdsaAlgorithm(string algorithmId, HashAlgorithmName hashAlgorithm)
    {
        AlgorithmId = algorithmId;
        _hashAlgorithm = hashAlgorithm;
        _expectedCurveOid = algorithmId switch
        {
            "ES256" => "1.2.840.10045.3.1.7", // P-256
            "ES384" => "1.3.132.0.34",         // P-384
            "ES512" => "1.3.132.0.35",         // P-521
            _ => throw new ArgumentException($"Unknown ECDSA algorithm: {algorithmId}")
        };
    }

    public byte[] Sign(ReadOnlySpan<byte> data, SigningKey key)
    {
        if (key.KeyMaterial is not ECDsa ecdsa)
            throw new JsfException($"Algorithm {AlgorithmId} requires an ECDsa key.");
        ValidateCurve(ecdsa);
        return ecdsa.SignData(data.ToArray(), _hashAlgorithm, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }

    public bool Verify(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature, VerificationKey key)
    {
        var (ecdsa, ownsKey) = ResolveKey(key);
        try
        {
            ValidateCurve(ecdsa);
            return ecdsa.VerifyData(data.ToArray(), signature.ToArray(), _hashAlgorithm, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        finally
        {
            if (ownsKey)
                ecdsa.Dispose();
        }
    }

    private void ValidateCurve(ECDsa ecdsa)
    {
        var curveOid = ecdsa.ExportParameters(false).Curve.Oid?.Value;
        if (curveOid != _expectedCurveOid)
            throw new JsfException($"Algorithm {AlgorithmId} requires curve OID {_expectedCurveOid}, but key uses {curveOid}.");
    }

    private static (ECDsa Key, bool OwnsKey) ResolveKey(VerificationKey key)
    {
        return key.KeyMaterial switch
        {
            ECDsa ecdsa => (ecdsa, false),
            JwkPublicKey jwk => (JwkKeyConverter.ToECDsa(jwk), true),
            _ => throw new JsfException("Invalid key type for ECDSA verification.")
        };
    }
}
