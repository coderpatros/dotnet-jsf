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

internal sealed class HmacAlgorithm : ISignatureAlgorithm
{
    public string AlgorithmId { get; }
    private readonly Func<byte[], HMAC> _hmacFactory;
    private readonly int _minimumKeyLengthBytes;

    public HmacAlgorithm(string algorithmId, Func<byte[], HMAC> hmacFactory, int minimumKeyLengthBytes)
    {
        AlgorithmId = algorithmId;
        _hmacFactory = hmacFactory;
        _minimumKeyLengthBytes = minimumKeyLengthBytes;
    }

    public byte[] Sign(ReadOnlySpan<byte> data, SigningKey key)
    {
        var hmacKey = GetKeyBytes(key.KeyMaterial);
        ValidateKeyLength(hmacKey);
        using var hmac = _hmacFactory(hmacKey);
        return hmac.ComputeHash(data.ToArray());
    }

    public bool Verify(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature, VerificationKey key)
    {
        var hmacKey = GetKeyBytes(key.KeyMaterial);
        ValidateKeyLength(hmacKey);
        using var hmac = _hmacFactory(hmacKey);
        var computed = hmac.ComputeHash(data.ToArray());
        return CryptographicOperations.FixedTimeEquals(computed, signature);
    }

    private void ValidateKeyLength(byte[] hmacKey)
    {
        if (hmacKey.Length < _minimumKeyLengthBytes)
            throw new JsfException($"HMAC key length {hmacKey.Length} bytes is below the minimum of {_minimumKeyLengthBytes} bytes for {AlgorithmId}.");
    }

    private static byte[] GetKeyBytes(object keyMaterial)
    {
        return keyMaterial switch
        {
            SigningKey.HmacKeyMaterial h => h.Key,
            VerificationKey.HmacKeyMaterial h => h.Key,
            _ => throw new JsfException("Invalid key type for HMAC.")
        };
    }
}
