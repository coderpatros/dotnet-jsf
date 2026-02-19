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
using CoderPatros.Jsf.Crypto.Algorithms;
using CoderPatros.Jsf.Models;

namespace CoderPatros.Jsf.Crypto;

/// <summary>
/// Registry of all supported signature algorithms, keyed by algorithm ID.
/// </summary>
public sealed class SignatureAlgorithmRegistry
{
    private readonly Dictionary<string, ISignatureAlgorithm> _algorithms = new(StringComparer.Ordinal);

    public SignatureAlgorithmRegistry()
    {
        // ECDSA
        Register(new EcdsaAlgorithm(JsfAlgorithm.ES256, HashAlgorithmName.SHA256));
        Register(new EcdsaAlgorithm(JsfAlgorithm.ES384, HashAlgorithmName.SHA384));
        Register(new EcdsaAlgorithm(JsfAlgorithm.ES512, HashAlgorithmName.SHA512));

        // RSA PKCS#1 v1.5
        Register(new RsaPkcs1Algorithm(JsfAlgorithm.RS256, HashAlgorithmName.SHA256));
        Register(new RsaPkcs1Algorithm(JsfAlgorithm.RS384, HashAlgorithmName.SHA384));
        Register(new RsaPkcs1Algorithm(JsfAlgorithm.RS512, HashAlgorithmName.SHA512));

        // RSA-PSS
        Register(new RsaPssAlgorithm(JsfAlgorithm.PS256, HashAlgorithmName.SHA256));
        Register(new RsaPssAlgorithm(JsfAlgorithm.PS384, HashAlgorithmName.SHA384));
        Register(new RsaPssAlgorithm(JsfAlgorithm.PS512, HashAlgorithmName.SHA512));

        // EdDSA
        Register(new EdDsaAlgorithm(JsfAlgorithm.Ed25519));
        Register(new EdDsaAlgorithm(JsfAlgorithm.Ed448));

        // HMAC
        Register(new HmacAlgorithm(JsfAlgorithm.HS256, k => new HMACSHA256(k)));
        Register(new HmacAlgorithm(JsfAlgorithm.HS384, k => new HMACSHA384(k)));
        Register(new HmacAlgorithm(JsfAlgorithm.HS512, k => new HMACSHA512(k)));
    }

    public void Register(ISignatureAlgorithm algorithm)
    {
        _algorithms[algorithm.AlgorithmId] = algorithm;
    }

    public ISignatureAlgorithm Get(string algorithmId)
    {
        if (!_algorithms.TryGetValue(algorithmId, out var algorithm))
            throw new JsfException($"Unsupported algorithm: {algorithmId}");
        return algorithm;
    }
}
