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

internal sealed class RsaPssAlgorithm : ISignatureAlgorithm
{
    public string AlgorithmId { get; }
    private readonly HashAlgorithmName _hashAlgorithm;

    public RsaPssAlgorithm(string algorithmId, HashAlgorithmName hashAlgorithm)
    {
        AlgorithmId = algorithmId;
        _hashAlgorithm = hashAlgorithm;
    }

    public byte[] Sign(ReadOnlySpan<byte> data, SigningKey key)
    {
        var rsa = (RSA)key.KeyMaterial;
        return rsa.SignData(data.ToArray(), _hashAlgorithm, RSASignaturePadding.Pss);
    }

    public bool Verify(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature, VerificationKey key)
    {
        var rsa = ResolveKey(key);
        return rsa.VerifyData(data.ToArray(), signature.ToArray(), _hashAlgorithm, RSASignaturePadding.Pss);
    }

    private static RSA ResolveKey(VerificationKey key)
    {
        return key.KeyMaterial switch
        {
            RSA rsa => rsa,
            JwkPublicKey jwk => JwkKeyConverter.ToRsa(jwk),
            _ => throw new ArgumentException("Invalid key type for RSA-PSS verification.")
        };
    }
}
