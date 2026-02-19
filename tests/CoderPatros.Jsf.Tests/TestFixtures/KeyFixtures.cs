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
using CoderPatros.Jsf.Models;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace CoderPatros.Jsf.Tests.TestFixtures;

internal static class KeyFixtures
{
    // ECDSA keys
    public static ECDsa CreateEcdsaP256() => ECDsa.Create(ECCurve.NamedCurves.nistP256);
    public static ECDsa CreateEcdsaP384() => ECDsa.Create(ECCurve.NamedCurves.nistP384);
    public static ECDsa CreateEcdsaP521() => ECDsa.Create(ECCurve.NamedCurves.nistP521);

    // RSA keys
    public static RSA CreateRsa2048() => RSA.Create(2048);

    // HMAC keys
    public static byte[] CreateHmacKey256()
    {
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);
        return key;
    }

    public static byte[] CreateHmacKey384()
    {
        var key = new byte[48];
        RandomNumberGenerator.Fill(key);
        return key;
    }

    public static byte[] CreateHmacKey512()
    {
        var key = new byte[64];
        RandomNumberGenerator.Fill(key);
        return key;
    }

    // EdDSA Ed25519
    public static (byte[] PrivateKey, byte[] PublicKey) CreateEd25519KeyPair()
    {
        var gen = new Ed25519KeyPairGenerator();
        gen.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        var keyPair = gen.GenerateKeyPair();
        var privateKey = ((Ed25519PrivateKeyParameters)keyPair.Private).GetEncoded();
        var publicKey = ((Ed25519PublicKeyParameters)keyPair.Public).GetEncoded();
        return (privateKey, publicKey);
    }

    // EdDSA Ed448
    public static (byte[] PrivateKey, byte[] PublicKey) CreateEd448KeyPair()
    {
        var gen = new Ed448KeyPairGenerator();
        gen.Init(new Ed448KeyGenerationParameters(new SecureRandom()));
        var keyPair = gen.GenerateKeyPair();
        var privateKey = ((Ed448PrivateKeyParameters)keyPair.Private).GetEncoded();
        var publicKey = ((Ed448PublicKeyParameters)keyPair.Public).GetEncoded();
        return (privateKey, publicKey);
    }

    // Helper: create signing/verification key pairs
    public static (SigningKey Signing, VerificationKey Verification, JwkPublicKey Jwk) CreateEcdsaKeySet(string algorithm)
    {
        var ecdsa = algorithm switch
        {
            JsfAlgorithm.ES256 => CreateEcdsaP256(),
            JsfAlgorithm.ES384 => CreateEcdsaP384(),
            JsfAlgorithm.ES512 => CreateEcdsaP521(),
            _ => throw new ArgumentException($"Unsupported: {algorithm}")
        };
        return (
            SigningKey.FromECDsa(ecdsa),
            VerificationKey.FromECDsa(ecdsa),
            JwkKeyConverter.FromECDsa(ecdsa)
        );
    }

    public static (SigningKey Signing, VerificationKey Verification, JwkPublicKey Jwk) CreateRsaKeySet()
    {
        var rsa = CreateRsa2048();
        return (
            SigningKey.FromRsa(rsa),
            VerificationKey.FromRsa(rsa),
            JwkKeyConverter.FromRsa(rsa)
        );
    }

    public static (SigningKey Signing, VerificationKey Verification) CreateHmacKeySet(string algorithm)
    {
        var key = algorithm switch
        {
            JsfAlgorithm.HS256 => CreateHmacKey256(),
            JsfAlgorithm.HS384 => CreateHmacKey384(),
            JsfAlgorithm.HS512 => CreateHmacKey512(),
            _ => throw new ArgumentException($"Unsupported: {algorithm}")
        };
        return (SigningKey.FromHmac(key), VerificationKey.FromHmac(key));
    }

    public static (SigningKey Signing, VerificationKey Verification, JwkPublicKey Jwk) CreateEdDsaKeySet(string curve)
    {
        var (privateKey, publicKey) = curve switch
        {
            "Ed25519" => CreateEd25519KeyPair(),
            "Ed448" => CreateEd448KeyPair(),
            _ => throw new ArgumentException($"Unsupported: {curve}")
        };
        return (
            SigningKey.FromEdDsa(privateKey, curve),
            VerificationKey.FromEdDsa(publicKey, curve),
            JwkKeyConverter.FromEdDsa(publicKey, curve)
        );
    }
}
