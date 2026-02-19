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

internal sealed class EcdsaAlgorithm : ISignatureAlgorithm
{
    public string AlgorithmId { get; }
    private readonly HashAlgorithmName _hashAlgorithm;

    public EcdsaAlgorithm(string algorithmId, HashAlgorithmName hashAlgorithm)
    {
        AlgorithmId = algorithmId;
        _hashAlgorithm = hashAlgorithm;
    }

    public byte[] Sign(ReadOnlySpan<byte> data, SigningKey key)
    {
        var ecdsa = (ECDsa)key.KeyMaterial;
        return ecdsa.SignData(data.ToArray(), _hashAlgorithm, DSASignatureFormat.Rfc3279DerSequence);
    }

    public bool Verify(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature, VerificationKey key)
    {
        var ecdsa = ResolveKey(key);
        return ecdsa.VerifyData(data.ToArray(), signature.ToArray(), _hashAlgorithm, DSASignatureFormat.Rfc3279DerSequence);
    }

    private static ECDsa ResolveKey(VerificationKey key)
    {
        return key.KeyMaterial switch
        {
            ECDsa ecdsa => ecdsa,
            JwkPublicKey jwk => JwkKeyConverter.ToECDsa(jwk),
            _ => throw new ArgumentException("Invalid key type for ECDSA verification.")
        };
    }
}
