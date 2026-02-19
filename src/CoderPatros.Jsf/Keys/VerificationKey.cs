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
/// Wraps a public or symmetric key for verification operations.
/// </summary>
public sealed class VerificationKey
{
    internal object KeyMaterial { get; }

    private VerificationKey(object keyMaterial)
    {
        KeyMaterial = keyMaterial;
    }

    public static VerificationKey FromECDsa(ECDsa key) => new(key);
    public static VerificationKey FromRsa(RSA key) => new(key);
    public static VerificationKey FromHmac(byte[] key) => new(new HmacKeyMaterial(key));
    public static VerificationKey FromEdDsa(byte[] publicKey, string curve) =>
        new(new EdDsaKeyMaterial(publicKey, curve));
    public static VerificationKey FromJwk(JwkPublicKey jwk) => new(jwk);

    internal sealed record HmacKeyMaterial(byte[] Key);
    internal sealed record EdDsaKeyMaterial(byte[] PublicKey, string Curve);
}
