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

public class SignatureChainTests
{
    private readonly JsfSignatureService _service = new();

    private static JsonObject CreateTestDocument() =>
        new() { ["message"] = "chain test" };

    [Fact]
    public void AppendToChain_SingleEntry_Verifies()
    {
        var (signing, _, jwk) = KeyFixtures.CreateEcdsaKeySet(JsfAlgorithm.ES256);
        var doc = CreateTestDocument();

        var chained = _service.AppendToChain(doc, new SignatureOptions
        {
            Algorithm = JsfAlgorithm.ES256,
            Key = signing,
            PublicKey = jwk
        });

        chained["signatureChain"].Should().NotBeNull();
        var chain = chained["signatureChain"]!.AsArray();
        chain.Count.Should().Be(1);

        var result = _service.VerifyChain(chained, new VerificationOptions());
        result.IsValid.Should().BeTrue();
    }

    [Fact]
    public void AppendToChain_TwoEntries_Verifies()
    {
        var (signing1, _, jwk1) = KeyFixtures.CreateEcdsaKeySet(JsfAlgorithm.ES256);
        var (signing2, _, jwk2) = KeyFixtures.CreateEcdsaKeySet(JsfAlgorithm.ES384);
        var doc = CreateTestDocument();

        var withFirst = _service.AppendToChain(doc, new SignatureOptions
        {
            Algorithm = JsfAlgorithm.ES256,
            Key = signing1,
            PublicKey = jwk1
        });

        var withBoth = _service.AppendToChain(withFirst, new SignatureOptions
        {
            Algorithm = JsfAlgorithm.ES384,
            Key = signing2,
            PublicKey = jwk2
        });

        var chain = withBoth["signatureChain"]!.AsArray();
        chain.Count.Should().Be(2);

        var result = _service.VerifyChain(withBoth, new VerificationOptions());
        result.IsValid.Should().BeTrue();
    }

    [Fact]
    public void AppendToChain_DoesNotMutateInput()
    {
        var (signing, _, jwk) = KeyFixtures.CreateEcdsaKeySet(JsfAlgorithm.ES256);
        var doc = CreateTestDocument();
        var originalJson = doc.ToJsonString();

        _service.AppendToChain(doc, new SignatureOptions
        {
            Algorithm = JsfAlgorithm.ES256,
            Key = signing,
            PublicKey = jwk
        });

        doc.ToJsonString().Should().Be(originalJson);
    }

    /// <summary>
    /// JSF spec: signature chain with mixed algorithms (EC + RSA).
    /// </summary>
    [Fact]
    public void AppendToChain_MixedAlgorithms_Verifies()
    {
        var (ecSigning, _, ecJwk) = KeyFixtures.CreateEcdsaKeySet(JsfAlgorithm.ES256);
        var (rsaSigning, _, rsaJwk) = KeyFixtures.CreateRsaKeySet();
        var doc = CreateTestDocument();

        var withFirst = _service.AppendToChain(doc, new SignatureOptions
        {
            Algorithm = JsfAlgorithm.ES256,
            Key = ecSigning,
            PublicKey = ecJwk
        });

        var withBoth = _service.AppendToChain(withFirst, new SignatureOptions
        {
            Algorithm = JsfAlgorithm.RS256,
            Key = rsaSigning,
            PublicKey = rsaJwk
        });

        var chain = withBoth["signatureChain"]!.AsArray();
        chain.Count.Should().Be(2);

        var result = _service.VerifyChain(withBoth, new VerificationOptions());
        result.IsValid.Should().BeTrue();
    }

    /// <summary>
    /// JSF spec: signature chain with keyId instead of embedded public keys.
    /// </summary>
    [Fact]
    public void AppendToChain_WithKeyIds_VerifiesViaKeyResolver()
    {
        var (ecSigning, ecVerification, _) = KeyFixtures.CreateEcdsaKeySet(JsfAlgorithm.ES256);
        var (rsaSigning, rsaVerification, _) = KeyFixtures.CreateRsaKeySet();
        var doc = CreateTestDocument();

        var withFirst = _service.AppendToChain(doc, new SignatureOptions
        {
            Algorithm = JsfAlgorithm.ES256,
            Key = ecSigning,
            KeyId = "example.com:p256"
        });

        var withBoth = _service.AppendToChain(withFirst, new SignatureOptions
        {
            Algorithm = JsfAlgorithm.RS256,
            Key = rsaSigning,
            KeyId = "example.com:r2048"
        });

        var result = _service.VerifyChain(withBoth, new VerificationOptions
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
    /// JSF spec: signature chain with extensions on each entry.
    /// </summary>
    [Fact]
    public void AppendToChain_WithExtensions_Verifies()
    {
        var (ecSigning, _, ecJwk) = KeyFixtures.CreateEcdsaKeySet(JsfAlgorithm.ES256);
        var (rsaSigning, _, rsaJwk) = KeyFixtures.CreateRsaKeySet();
        var doc = CreateTestDocument();

        var withFirst = _service.AppendToChain(doc, new SignatureOptions
        {
            Algorithm = JsfAlgorithm.ES256,
            Key = ecSigning,
            PublicKey = ecJwk,
            Extensions = new Dictionary<string, JsonNode?>
            {
                ["otherExt"] = "Cool Stuff"
            }
        });

        var withBoth = _service.AppendToChain(withFirst, new SignatureOptions
        {
            Algorithm = JsfAlgorithm.RS256,
            Key = rsaSigning,
            PublicKey = rsaJwk,
            Extensions = new Dictionary<string, JsonNode?>
            {
                ["otherExt"] = "Other Data"
            }
        });

        var chain = withBoth["signatureChain"]!.AsArray();
        chain[0]!.AsObject()["otherExt"]!.GetValue<string>().Should().Be("Cool Stuff");
        chain[1]!.AsObject()["otherExt"]!.GetValue<string>().Should().Be("Other Data");

        var result = _service.VerifyChain(withBoth, new VerificationOptions());
        result.IsValid.Should().BeTrue();
    }

    /// <summary>
    /// JSF spec: signature chain with excludes.
    /// </summary>
    [Fact]
    public void AppendToChain_WithExcludes_Verifies()
    {
        var (signing1, _, jwk1) = KeyFixtures.CreateEcdsaKeySet(JsfAlgorithm.ES256);
        var (signing2, _, jwk2) = KeyFixtures.CreateEcdsaKeySet(JsfAlgorithm.ES384);
        var doc = new JsonObject
        {
            ["mySignedData"] = "something",
            ["myUnsignedData"] = "something else"
        };

        var withFirst = _service.AppendToChain(doc, new SignatureOptions
        {
            Algorithm = JsfAlgorithm.ES256,
            Key = signing1,
            PublicKey = jwk1,
            Excludes = ["myUnsignedData"]
        });

        var withBoth = _service.AppendToChain(withFirst, new SignatureOptions
        {
            Algorithm = JsfAlgorithm.ES384,
            Key = signing2,
            PublicKey = jwk2,
            Excludes = ["myUnsignedData"]
        });

        var result = _service.VerifyChain(withBoth, new VerificationOptions());
        result.IsValid.Should().BeTrue();

        // Modifying excluded property should not affect verification
        withBoth["myUnsignedData"] = "changed";
        var result2 = _service.VerifyChain(withBoth, new VerificationOptions());
        result2.IsValid.Should().BeTrue();
    }

    /// <summary>
    /// JSF spec: tampered signature chain should fail verification.
    /// </summary>
    [Fact]
    public void VerifyChain_TamperedDocument_ReturnsFalse()
    {
        var (signing1, _, jwk1) = KeyFixtures.CreateEcdsaKeySet(JsfAlgorithm.ES256);
        var (signing2, _, jwk2) = KeyFixtures.CreateEcdsaKeySet(JsfAlgorithm.ES384);
        var doc = CreateTestDocument();

        var withFirst = _service.AppendToChain(doc, new SignatureOptions
        {
            Algorithm = JsfAlgorithm.ES256,
            Key = signing1,
            PublicKey = jwk1
        });

        var withBoth = _service.AppendToChain(withFirst, new SignatureOptions
        {
            Algorithm = JsfAlgorithm.ES384,
            Key = signing2,
            PublicKey = jwk2
        });

        // Tamper with document
        withBoth["message"] = "tampered";

        var result = _service.VerifyChain(withBoth, new VerificationOptions());
        result.IsValid.Should().BeFalse();
    }

    /// <summary>
    /// JSF spec: three-entry chain verifies correctly.
    /// </summary>
    [Fact]
    public void AppendToChain_ThreeEntries_Verifies()
    {
        var (signing1, _, jwk1) = KeyFixtures.CreateEcdsaKeySet(JsfAlgorithm.ES256);
        var (signing2, _, jwk2) = KeyFixtures.CreateRsaKeySet();
        var (signing3, _, jwk3) = KeyFixtures.CreateEdDsaKeySet("Ed25519");
        var doc = CreateTestDocument();

        var with1 = _service.AppendToChain(doc, new SignatureOptions
        {
            Algorithm = JsfAlgorithm.ES256,
            Key = signing1,
            PublicKey = jwk1
        });

        var with2 = _service.AppendToChain(with1, new SignatureOptions
        {
            Algorithm = JsfAlgorithm.RS256,
            Key = signing2,
            PublicKey = jwk2
        });

        var with3 = _service.AppendToChain(with2, new SignatureOptions
        {
            Algorithm = JsfAlgorithm.Ed25519,
            Key = signing3,
            PublicKey = jwk3
        });

        var chain = with3["signatureChain"]!.AsArray();
        chain.Count.Should().Be(3);

        var result = _service.VerifyChain(with3, new VerificationOptions());
        result.IsValid.Should().BeTrue();
    }
}
