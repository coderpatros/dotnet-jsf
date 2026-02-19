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

using System.Text.Json.Nodes;
using CoderPatros.Jsf.Keys;
using CoderPatros.Jsf.Models;
using CoderPatros.Jsf.Tests.TestFixtures;
using FluentAssertions;

namespace CoderPatros.Jsf.Tests.Integration;

public class MultiSignatureTests
{
    private readonly JsfSignatureService _service = new();

    private static JsonObject CreateTestDocument() =>
        new() { ["message"] = "multi-signer test" };

    [Fact]
    public void AddSigner_TwoEcdsaSigners_VerifiesAll()
    {
        var (signing1, _, jwk1) = KeyFixtures.CreateEcdsaKeySet(JsfAlgorithm.ES256);
        var (signing2, _, jwk2) = KeyFixtures.CreateEcdsaKeySet(JsfAlgorithm.ES384);
        var doc = CreateTestDocument();

        var withSigner1 = _service.AddSigner(doc, new SignatureOptions
        {
            Algorithm = JsfAlgorithm.ES256,
            Key = signing1,
            PublicKey = jwk1
        });

        var withBothSigners = _service.AddSigner(withSigner1, new SignatureOptions
        {
            Algorithm = JsfAlgorithm.ES384,
            Key = signing2,
            PublicKey = jwk2
        });

        withBothSigners["signers"].Should().NotBeNull();
        var signers = withBothSigners["signers"]!.AsArray();
        signers.Count.Should().Be(2);

        var result = _service.VerifySigners(withBothSigners, new VerificationOptions { AllowEmbeddedPublicKey = true });
        result.IsValid.Should().BeTrue();
    }

    [Fact]
    public void AddSigner_MixedAlgorithms_VerifiesAll()
    {
        var (ecSigning, _, ecJwk) = KeyFixtures.CreateEcdsaKeySet(JsfAlgorithm.ES256);
        var (rsaSigning, rsaVerification, rsaJwk) = KeyFixtures.CreateRsaKeySet();
        var doc = CreateTestDocument();

        var withEc = _service.AddSigner(doc, new SignatureOptions
        {
            Algorithm = JsfAlgorithm.ES256,
            Key = ecSigning,
            PublicKey = ecJwk
        });

        var withBoth = _service.AddSigner(withEc, new SignatureOptions
        {
            Algorithm = JsfAlgorithm.RS256,
            Key = rsaSigning,
            PublicKey = rsaJwk
        });

        var result = _service.VerifySigners(withBoth, new VerificationOptions { AllowEmbeddedPublicKey = true });
        result.IsValid.Should().BeTrue();
    }

    [Fact]
    public void AddSigner_DoesNotMutateInput()
    {
        var (signing, _, jwk) = KeyFixtures.CreateEcdsaKeySet(JsfAlgorithm.ES256);
        var doc = CreateTestDocument();
        var originalJson = doc.ToJsonString();

        _service.AddSigner(doc, new SignatureOptions
        {
            Algorithm = JsfAlgorithm.ES256,
            Key = signing,
            PublicKey = jwk
        });

        doc.ToJsonString().Should().Be(originalJson);
    }

    /// <summary>
    /// JSF spec: multiple signatures with keyId instead of embedded public keys.
    /// </summary>
    [Fact]
    public void AddSigner_WithKeyIds_VerifiesViaKeyResolver()
    {
        var (ecSigning, ecVerification, _) = KeyFixtures.CreateEcdsaKeySet(JsfAlgorithm.ES256);
        var (rsaSigning, rsaVerification, _) = KeyFixtures.CreateRsaKeySet();
        var doc = CreateTestDocument();

        var withEc = _service.AddSigner(doc, new SignatureOptions
        {
            Algorithm = JsfAlgorithm.ES256,
            Key = ecSigning,
            KeyId = "example.com:p256"
        });

        var withBoth = _service.AddSigner(withEc, new SignatureOptions
        {
            Algorithm = JsfAlgorithm.RS256,
            Key = rsaSigning,
            KeyId = "example.com:r2048"
        });

        var signers = withBoth["signers"]!.AsArray();
        signers.Count.Should().Be(2);

        // Each signer should have keyId but no publicKey
        foreach (var signer in signers)
        {
            signer!.AsObject()["keyId"].Should().NotBeNull();
            signer!.AsObject()["publicKey"].Should().BeNull();
        }

        // Verify using key resolver
        var result = _service.VerifySigners(withBoth, new VerificationOptions
        {
            KeyResolver = sig => sig.KeyId switch
            {
                "example.com:p256" => ecVerification,
                "example.com:r2048" => rsaVerification,
                _ => throw new Exception($"Unknown keyId: {sig.KeyId}")
            }
        });
        result.IsValid.Should().BeTrue();
    }

    /// <summary>
    /// JSF spec: multiple signatures with excludes.
    /// </summary>
    [Fact]
    public void AddSigner_WithExcludes_ExcludedPropertyNotSigned()
    {
        var (signing1, _, jwk1) = KeyFixtures.CreateEcdsaKeySet(JsfAlgorithm.ES256);
        var (signing2, _, jwk2) = KeyFixtures.CreateRsaKeySet();
        var doc = new JsonObject
        {
            ["mySignedData"] = "something",
            ["myUnsignedData"] = "something else"
        };

        var withSigner1 = _service.AddSigner(doc, new SignatureOptions
        {
            Algorithm = JsfAlgorithm.ES256,
            Key = signing1,
            PublicKey = jwk1,
            Excludes = ["myUnsignedData"]
        });

        var withBoth = _service.AddSigner(withSigner1, new SignatureOptions
        {
            Algorithm = JsfAlgorithm.RS256,
            Key = signing2,
            PublicKey = jwk2,
            Excludes = ["myUnsignedData"]
        });

        var result = _service.VerifySigners(withBoth, new VerificationOptions { AllowEmbeddedPublicKey = true });
        result.IsValid.Should().BeTrue();

        // Modifying excluded property should not affect verification
        withBoth["myUnsignedData"] = "changed value";
        var result2 = _service.VerifySigners(withBoth, new VerificationOptions { AllowEmbeddedPublicKey = true });
        result2.IsValid.Should().BeTrue();
    }

    /// <summary>
    /// JSF spec: multiple signatures with extensions.
    /// </summary>
    [Fact]
    public void AddSigner_WithExtensions_ExtensionsEmbedded()
    {
        var (signing1, _, jwk1) = KeyFixtures.CreateEcdsaKeySet(JsfAlgorithm.ES256);
        var (signing2, _, jwk2) = KeyFixtures.CreateRsaKeySet();
        var doc = CreateTestDocument();

        var withSigner1 = _service.AddSigner(doc, new SignatureOptions
        {
            Algorithm = JsfAlgorithm.ES256,
            Key = signing1,
            PublicKey = jwk1,
            Extensions = new Dictionary<string, JsonNode?>
            {
                ["otherExt"] = "Cool Stuff"
            }
        });

        var withBoth = _service.AddSigner(withSigner1, new SignatureOptions
        {
            Algorithm = JsfAlgorithm.RS256,
            Key = signing2,
            PublicKey = jwk2,
            Extensions = new Dictionary<string, JsonNode?>
            {
                ["otherExt"] = "Other Data"
            }
        });

        // Each signer should have its own extension
        var signers = withBoth["signers"]!.AsArray();
        signers[0]!.AsObject()["otherExt"]!.GetValue<string>().Should().Be("Cool Stuff");
        signers[1]!.AsObject()["otherExt"]!.GetValue<string>().Should().Be("Other Data");

        var result = _service.VerifySigners(withBoth, new VerificationOptions { AllowEmbeddedPublicKey = true });
        result.IsValid.Should().BeTrue();
    }

    /// <summary>
    /// JSF spec: tampered multi-signature document should fail verification.
    /// </summary>
    [Fact]
    public void VerifySigners_TamperedDocument_ReturnsFalse()
    {
        var (signing1, _, jwk1) = KeyFixtures.CreateEcdsaKeySet(JsfAlgorithm.ES256);
        var (signing2, _, jwk2) = KeyFixtures.CreateEcdsaKeySet(JsfAlgorithm.ES384);
        var doc = CreateTestDocument();

        var withSigner1 = _service.AddSigner(doc, new SignatureOptions
        {
            Algorithm = JsfAlgorithm.ES256,
            Key = signing1,
            PublicKey = jwk1
        });

        var withBoth = _service.AddSigner(withSigner1, new SignatureOptions
        {
            Algorithm = JsfAlgorithm.ES384,
            Key = signing2,
            PublicKey = jwk2
        });

        // Tamper with document
        withBoth["message"] = "tampered";

        var result = _service.VerifySigners(withBoth, new VerificationOptions { AllowEmbeddedPublicKey = true });
        result.IsValid.Should().BeFalse();
    }

    /// <summary>
    /// JSF spec: multi-signature with wrong key for one signer should fail.
    /// </summary>
    [Fact]
    public void VerifySigners_WrongKeyForOneSigner_ReturnsFalse()
    {
        var (signing1, _, jwk1) = KeyFixtures.CreateEcdsaKeySet(JsfAlgorithm.ES256);
        var (signing2, _, jwk2) = KeyFixtures.CreateEcdsaKeySet(JsfAlgorithm.ES384);
        var (_, wrongVerification, _) = KeyFixtures.CreateEcdsaKeySet(JsfAlgorithm.ES256);
        var doc = CreateTestDocument();

        var withSigner1 = _service.AddSigner(doc, new SignatureOptions
        {
            Algorithm = JsfAlgorithm.ES256,
            Key = signing1,
            KeyId = "key1"
        });

        var withBoth = _service.AddSigner(withSigner1, new SignatureOptions
        {
            Algorithm = JsfAlgorithm.ES384,
            Key = signing2,
            PublicKey = jwk2
        });

        // Provide wrong key for the first signer
        var result = _service.VerifySigners(withBoth, new VerificationOptions
        {
            KeyResolver = sig =>
            {
                if (sig.KeyId == "key1")
                    return wrongVerification;
                return JwkKeyConverter.ToVerificationKey(sig.PublicKey!);
            }
        });
        result.IsValid.Should().BeFalse();
    }

    /// <summary>
    /// JSF spec: three signers with different algorithm families (EC, RSA, HMAC).
    /// </summary>
    [Fact]
    public void AddSigner_ThreeSigners_DifferentAlgorithmFamilies()
    {
        var (ecSigning, _, ecJwk) = KeyFixtures.CreateEcdsaKeySet(JsfAlgorithm.ES256);
        var (rsaSigning, _, rsaJwk) = KeyFixtures.CreateRsaKeySet();
        var (hmacSigning, hmacVerification) = KeyFixtures.CreateHmacKeySet(JsfAlgorithm.HS256);
        var doc = CreateTestDocument();

        var with1 = _service.AddSigner(doc, new SignatureOptions
        {
            Algorithm = JsfAlgorithm.ES256,
            Key = ecSigning,
            PublicKey = ecJwk
        });

        var with2 = _service.AddSigner(with1, new SignatureOptions
        {
            Algorithm = JsfAlgorithm.RS256,
            Key = rsaSigning,
            PublicKey = rsaJwk
        });

        var with3 = _service.AddSigner(with2, new SignatureOptions
        {
            Algorithm = JsfAlgorithm.HS256,
            Key = hmacSigning,
            KeyId = "hmac-key"
        });

        var signers = with3["signers"]!.AsArray();
        signers.Count.Should().Be(3);

        var result = _service.VerifySigners(with3, new VerificationOptions
        {
            KeyResolver = sig =>
            {
                if (sig.PublicKey is not null)
                    return JwkKeyConverter.ToVerificationKey(sig.PublicKey);
                if (sig.KeyId == "hmac-key")
                    return hmacVerification;
                throw new Exception($"Cannot resolve key");
            }
        });
        result.IsValid.Should().BeTrue();
    }
}
