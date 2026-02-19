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

public class ExtensionsAndExcludesTests
{
    private readonly JsfSignatureService _service = new();

    private static JsonObject CreateTestDocument() =>
        new()
        {
            ["message"] = "hello",
            ["timestamp"] = "2025-01-01T00:00:00Z",
            ["optional"] = "may exclude"
        };

    [Fact]
    public void Sign_WithExcludes_ExcludedPropertyNotSigned()
    {
        var (signing, verification, _) = KeyFixtures.CreateEcdsaKeySet(JsfAlgorithm.ES256);
        var doc = CreateTestDocument();

        var signed = _service.Sign(doc, new SignatureOptions
        {
            Algorithm = JsfAlgorithm.ES256,
            Key = signing,
            Excludes = ["optional"]
        });

        // Signature should be present with excludes
        var sigObj = signed["signature"]!.AsObject();
        sigObj["excludes"].Should().NotBeNull();

        // Verify should pass
        var result = _service.Verify(signed, new VerificationOptions { Key = verification });
        result.IsValid.Should().BeTrue();

        // Changing excluded property should not affect verification
        signed["optional"] = "changed value";
        var result2 = _service.Verify(signed, new VerificationOptions { Key = verification });
        result2.IsValid.Should().BeTrue();
    }

    [Fact]
    public void Sign_WithExcludes_NonExcludedChangeCausesFailure()
    {
        var (signing, verification, _) = KeyFixtures.CreateEcdsaKeySet(JsfAlgorithm.ES256);
        var doc = CreateTestDocument();

        var signed = _service.Sign(doc, new SignatureOptions
        {
            Algorithm = JsfAlgorithm.ES256,
            Key = signing,
            Excludes = ["optional"]
        });

        // Changing non-excluded property should fail verification
        signed["message"] = "tampered";
        var result = _service.Verify(signed, new VerificationOptions { Key = verification });
        result.IsValid.Should().BeFalse();
    }

    [Fact]
    public void Sign_WithExtensions_ExtensionsEmbedded()
    {
        var (signing, verification, _) = KeyFixtures.CreateEcdsaKeySet(JsfAlgorithm.ES256);
        var doc = CreateTestDocument();

        var extensions = new Dictionary<string, JsonNode?>
        {
            ["otherExt"] = "https://example.com/ext"
        };

        var signed = _service.Sign(doc, new SignatureOptions
        {
            Algorithm = JsfAlgorithm.ES256,
            Key = signing,
            Extensions = extensions
        });

        var sigObj = signed["signature"]!.AsObject();
        sigObj["otherExt"]!.GetValue<string>().Should().Be("https://example.com/ext");

        var result = _service.Verify(signed, new VerificationOptions { Key = verification });
        result.IsValid.Should().BeTrue();
    }

    [Fact]
    public void Sign_WithObjectExtension_IncludedInSignature()
    {
        var (signing, verification, _) = KeyFixtures.CreateEcdsaKeySet(JsfAlgorithm.ES256);
        var doc = CreateTestDocument();

        var signed = _service.Sign(doc, new SignatureOptions
        {
            Algorithm = JsfAlgorithm.ES256,
            Key = signing,
            Extensions = new Dictionary<string, JsonNode?>
            {
                ["life-is-great"] = (JsonNode)true
            }
        });

        var sigObj = signed["signature"]!.AsObject();
        sigObj["life-is-great"]!.GetValue<bool>().Should().BeTrue();

        // "extensions" declaration array should be emitted
        var extDecl = sigObj["extensions"]!.AsArray();
        extDecl.Count.Should().Be(1);
        extDecl[0]!.GetValue<string>().Should().Be("life-is-great");

        var result = _service.Verify(signed, new VerificationOptions { Key = verification });
        result.IsValid.Should().BeTrue();
    }

    [Fact]
    public void Sign_WithMixedExtensions_StringAndObject()
    {
        var (signing, verification, _) = KeyFixtures.CreateEcdsaKeySet(JsfAlgorithm.ES256);
        var doc = CreateTestDocument();

        var signed = _service.Sign(doc, new SignatureOptions
        {
            Algorithm = JsfAlgorithm.ES256,
            Key = signing,
            Extensions = new Dictionary<string, JsonNode?>
            {
                ["otherExt"] = (JsonNode)"Cool Stuff",
                ["objectExt"] = new JsonObject { ["nested"] = 42 }
            }
        });

        var sigObj = signed["signature"]!.AsObject();
        sigObj["otherExt"]!.GetValue<string>().Should().Be("Cool Stuff");
        sigObj["objectExt"]!.AsObject()["nested"]!.GetValue<int>().Should().Be(42);

        // "extensions" declaration array should list both
        var extDecl = sigObj["extensions"]!.AsArray();
        extDecl.Count.Should().Be(2);

        var result = _service.Verify(signed, new VerificationOptions { Key = verification });
        result.IsValid.Should().BeTrue();
    }

    [Fact]
    public void Sign_ExtensionsDeclarationArray_EmittedCorrectly()
    {
        var (signing, verification, _) = KeyFixtures.CreateEcdsaKeySet(JsfAlgorithm.ES256);
        var doc = CreateTestDocument();

        var signed = _service.Sign(doc, new SignatureOptions
        {
            Algorithm = JsfAlgorithm.ES256,
            Key = signing,
            Extensions = new Dictionary<string, JsonNode?>
            {
                ["alpha"] = (JsonNode)"a",
                ["beta"] = (JsonNode)"b"
            }
        });

        var sigObj = signed["signature"]!.AsObject();
        var extDecl = sigObj["extensions"]!.AsArray();
        var extNames = extDecl.Select(n => n!.GetValue<string>()).ToList();
        extNames.Should().Contain("alpha");
        extNames.Should().Contain("beta");
    }

    [Fact]
    public void Deserialize_WithoutExtensionsArray_BackwardCompat()
    {
        // Manually build a signed document without the "extensions" declaration array
        // to verify backward-compatible deserialization
        var (signing, verification, _) = KeyFixtures.CreateEcdsaKeySet(JsfAlgorithm.ES256);
        var doc = CreateTestDocument();

        var signed = _service.Sign(doc, new SignatureOptions
        {
            Algorithm = JsfAlgorithm.ES256,
            Key = signing,
            Extensions = new Dictionary<string, JsonNode?>
            {
                ["otherExt"] = (JsonNode)"Cool Stuff"
            }
        });

        // Remove the "extensions" declaration array to simulate a legacy document
        var sigObj = signed["signature"]!.AsObject();
        sigObj.Remove("extensions");

        // Verification should still work because backward-compat fallback
        // treats unknown properties as extensions
        var result = _service.Verify(signed, new VerificationOptions { Key = verification });
        result.IsValid.Should().BeTrue();
    }

    [Fact]
    public void Sign_WithKeyResolver()
    {
        var (signing1, _, jwk1) = KeyFixtures.CreateEcdsaKeySet(JsfAlgorithm.ES256);
        var (signing2, _, jwk2) = KeyFixtures.CreateEcdsaKeySet(JsfAlgorithm.ES384);
        var doc = new JsonObject { ["message"] = "resolver test" };

        var withSigner1 = _service.AddSigner(doc, new SignatureOptions
        {
            Algorithm = JsfAlgorithm.ES256,
            Key = signing1,
            PublicKey = jwk1,
            KeyId = "key1"
        });

        var withBoth = _service.AddSigner(withSigner1, new SignatureOptions
        {
            Algorithm = JsfAlgorithm.ES384,
            Key = signing2,
            PublicKey = jwk2,
            KeyId = "key2"
        });

        // Verify using a key resolver
        var result = _service.VerifySigners(withBoth, new VerificationOptions
        {
            KeyResolver = sig => JwkKeyConverter.ToVerificationKey(sig.PublicKey!)
        });
        result.IsValid.Should().BeTrue();
    }
}
