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

namespace CoderPatros.Jsf.Keys;

/// <summary>
/// Wraps a private or symmetric key for signing operations.
/// Implements IDisposable to securely zero key material on disposal.
/// </summary>
public sealed class SigningKey : IDisposable
{
    internal object KeyMaterial { get; }
    private int _disposed;

    private SigningKey(object keyMaterial)
    {
        KeyMaterial = keyMaterial;
    }

    public static SigningKey FromECDsa(ECDsa key) => new(key);
    public static SigningKey FromRsa(RSA key) => new(key);
    public static SigningKey FromHmac(byte[] key) => new(new HmacKeyMaterial(key));
    public static SigningKey FromEdDsa(byte[] privateKey, string curve) =>
        new(new EdDsaKeyMaterial(privateKey, curve));

    public void Dispose()
    {
        if (Interlocked.CompareExchange(ref _disposed, 1, 0) != 0) return;

        switch (KeyMaterial)
        {
            case ECDsa ecdsa:
                ecdsa.Dispose();
                break;
            case RSA rsa:
                rsa.Dispose();
                break;
            case HmacKeyMaterial hmac:
                CryptographicOperations.ZeroMemory(hmac.Key);
                break;
            case EdDsaKeyMaterial edDsa:
                CryptographicOperations.ZeroMemory(edDsa.PrivateKey);
                break;
        }
    }

    internal sealed record HmacKeyMaterial(byte[] Key);
    internal sealed record EdDsaKeyMaterial(byte[] PrivateKey, string Curve);
}
