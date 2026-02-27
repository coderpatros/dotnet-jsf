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
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

namespace CoderPatros.Jsf.Crypto.Algorithms;

internal sealed class BouncyCastleHmacAlgorithm : ISignatureAlgorithm
{
    public string AlgorithmId { get; }
    private readonly string _hashAlgorithm;
    private readonly int _minimumKeyLengthBytes;

    public BouncyCastleHmacAlgorithm(string algorithmId, string hashAlgorithm, int minimumKeyLengthBytes)
    {
        AlgorithmId = algorithmId;
        _hashAlgorithm = hashAlgorithm;
        _minimumKeyLengthBytes = minimumKeyLengthBytes;
    }

    public byte[] Sign(ReadOnlySpan<byte> data, SigningKey key)
    {
        var hmacKey = GetKeyBytes(key.KeyMaterial);
        ValidateKeyLength(hmacKey);
        return ComputeHmac(hmacKey, data);
    }

    public bool Verify(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature, VerificationKey key)
    {
        var hmacKey = GetKeyBytes(key.KeyMaterial);
        ValidateKeyLength(hmacKey);
        var computed = ComputeHmac(hmacKey, data);
        return FixedTimeEquals(computed, signature);
    }

    private byte[] ComputeHmac(byte[] hmacKey, ReadOnlySpan<byte> data)
    {
        var digest = _hashAlgorithm switch
        {
            "SHA-256" => (Org.BouncyCastle.Crypto.IDigest)new Sha256Digest(),
            "SHA-384" => new Sha384Digest(),
            "SHA-512" => new Sha512Digest(),
            _ => throw new JsfException($"Unsupported hash algorithm: {_hashAlgorithm}")
        };

        var hmac = new HMac(digest);
        hmac.Init(new KeyParameter(hmacKey));
        var dataArray = data.ToArray();
        hmac.BlockUpdate(dataArray, 0, dataArray.Length);
        var result = new byte[hmac.GetMacSize()];
        hmac.DoFinal(result, 0);
        return result;
    }

    private void ValidateKeyLength(byte[] hmacKey)
    {
        if (hmacKey.Length < _minimumKeyLengthBytes)
            throw new JsfException($"HMAC key length {hmacKey.Length} bytes is below the minimum of {_minimumKeyLengthBytes} bytes for {AlgorithmId}.");
    }

    private static bool FixedTimeEquals(byte[] a, ReadOnlySpan<byte> b)
    {
        if (a.Length != b.Length)
            return false;
        var result = 0;
        for (var i = 0; i < a.Length; i++)
            result |= a[i] ^ b[i];
        return result == 0;
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
