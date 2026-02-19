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
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using CoderPatros.Jsf.Serialization;

namespace CoderPatros.Jsf.Crypto.Algorithms;

using CoderPatros.Jsf;

internal sealed class EdDsaAlgorithm : ISignatureAlgorithm
{
    public string AlgorithmId { get; }

    public EdDsaAlgorithm(string algorithmId)
    {
        AlgorithmId = algorithmId;
    }

    public byte[] Sign(ReadOnlySpan<byte> data, SigningKey key)
    {
        if (key.KeyMaterial is not SigningKey.EdDsaKeyMaterial edKey)
            throw new JsfException($"Algorithm {AlgorithmId} requires an EdDSA key.");
        if (edKey.Curve != AlgorithmId)
            throw new JsfException($"Algorithm {AlgorithmId} requires curve {AlgorithmId}, but key uses {edKey.Curve}.");
        var dataArray = data.ToArray();

        return edKey.Curve switch
        {
            "Ed25519" => SignEd25519(dataArray, edKey.PrivateKey),
            "Ed448" => SignEd448(dataArray, edKey.PrivateKey),
            _ => throw new JsfException($"Unsupported EdDSA curve: {edKey.Curve}")
        };
    }

    public bool Verify(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature, VerificationKey key)
    {
        var (publicKeyBytes, curve) = ResolvePublicKey(key);
        if (curve != AlgorithmId)
            throw new JsfException($"Algorithm {AlgorithmId} requires curve {AlgorithmId}, but key uses {curve}.");
        var dataArray = data.ToArray();
        var sigArray = signature.ToArray();

        return curve switch
        {
            "Ed25519" => VerifyEd25519(dataArray, sigArray, publicKeyBytes),
            "Ed448" => VerifyEd448(dataArray, sigArray, publicKeyBytes),
            _ => throw new JsfException($"Unsupported EdDSA curve: {curve}")
        };
    }

    private static byte[] SignEd25519(byte[] data, byte[] privateKey)
    {
        var signer = new Ed25519Signer();
        signer.Init(true, new Ed25519PrivateKeyParameters(privateKey, 0));
        signer.BlockUpdate(data, 0, data.Length);
        return signer.GenerateSignature();
    }

    private static byte[] SignEd448(byte[] data, byte[] privateKey)
    {
        var signer = new Ed448Signer(Array.Empty<byte>());
        signer.Init(true, new Ed448PrivateKeyParameters(privateKey, 0));
        signer.BlockUpdate(data, 0, data.Length);
        return signer.GenerateSignature();
    }

    private static bool VerifyEd25519(byte[] data, byte[] signature, byte[] publicKey)
    {
        var verifier = new Ed25519Signer();
        verifier.Init(false, new Ed25519PublicKeyParameters(publicKey, 0));
        verifier.BlockUpdate(data, 0, data.Length);
        return verifier.VerifySignature(signature);
    }

    private static bool VerifyEd448(byte[] data, byte[] signature, byte[] publicKey)
    {
        var verifier = new Ed448Signer(Array.Empty<byte>());
        verifier.Init(false, new Ed448PublicKeyParameters(publicKey, 0));
        verifier.BlockUpdate(data, 0, data.Length);
        return verifier.VerifySignature(signature);
    }

    private static (byte[] PublicKey, string Curve) ResolvePublicKey(VerificationKey key)
    {
        return key.KeyMaterial switch
        {
            VerificationKey.EdDsaKeyMaterial ed => (ed.PublicKey, ed.Curve),
            JwkPublicKey jwk when jwk.Kty == "OKP" => (Base64UrlEncoding.Decode(jwk.X!), jwk.Crv!),
            _ => throw new JsfException("Invalid key type for EdDSA verification.")
        };
    }
}
