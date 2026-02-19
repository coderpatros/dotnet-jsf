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

public class SingleSignatureTests
{
    private readonly JsfSignatureService _service = new();

    private static JsonObject CreateTestDocument() =>
        new()
        {
            ["now"] = "2025-01-01T00:00:00Z",
            ["escapeMe"] = "\u0001\u001e",
            ["numbers"] = new JsonArray(1e0, 4.5, 6)
        };

    [Theory]
    [InlineData(JsfAlgorithm.ES256)]
    [InlineData(JsfAlgorithm.ES384)]
    [InlineData(JsfAlgorithm.ES512)]
    public void EcdsaSignAndVerify_WithEmbeddedPublicKey(string algorithm)
    {
        var (signing, _, jwk) = KeyFixtures.CreateEcdsaKeySet(algorithm);
        var doc = CreateTestDocument();

        var signed = _service.Sign(doc, new SignatureOptions
        {
            Algorithm = algorithm,
            Key = signing,
            PublicKey = jwk
        });

        signed["signature"].Should().NotBeNull();
        var result = _service.Verify(signed, new VerificationOptions());
        result.IsValid.Should().BeTrue();
    }

    [Theory]
    [InlineData(JsfAlgorithm.RS256)]
    [InlineData(JsfAlgorithm.RS384)]
    [InlineData(JsfAlgorithm.RS512)]
    public void RsaPkcs1SignAndVerify_WithExplicitKey(string algorithm)
    {
        var (signing, verification, jwk) = KeyFixtures.CreateRsaKeySet();
        var doc = CreateTestDocument();

        var signed = _service.Sign(doc, new SignatureOptions
        {
            Algorithm = algorithm,
            Key = signing,
            PublicKey = jwk
        });

        var result = _service.Verify(signed, new VerificationOptions
        {
            Key = verification
        });
        result.IsValid.Should().BeTrue();
    }

    [Theory]
    [InlineData(JsfAlgorithm.PS256)]
    [InlineData(JsfAlgorithm.PS384)]
    [InlineData(JsfAlgorithm.PS512)]
    public void RsaPssSignAndVerify(string algorithm)
    {
        var (signing, verification, _) = KeyFixtures.CreateRsaKeySet();
        var doc = CreateTestDocument();

        var signed = _service.Sign(doc, new SignatureOptions
        {
            Algorithm = algorithm,
            Key = signing
        });

        var result = _service.Verify(signed, new VerificationOptions
        {
            Key = verification
        });
        result.IsValid.Should().BeTrue();
    }

    [Theory]
    [InlineData(JsfAlgorithm.HS256)]
    [InlineData(JsfAlgorithm.HS384)]
    [InlineData(JsfAlgorithm.HS512)]
    public void HmacSignAndVerify(string algorithm)
    {
        var (signing, verification) = KeyFixtures.CreateHmacKeySet(algorithm);
        var doc = CreateTestDocument();

        var signed = _service.Sign(doc, new SignatureOptions
        {
            Algorithm = algorithm,
            Key = signing
        });

        var result = _service.Verify(signed, new VerificationOptions
        {
            Key = verification
        });
        result.IsValid.Should().BeTrue();
    }

    [Fact]
    public void Ed25519SignAndVerify_WithEmbeddedPublicKey()
    {
        var (signing, _, jwk) = KeyFixtures.CreateEdDsaKeySet("Ed25519");
        var doc = CreateTestDocument();

        var signed = _service.Sign(doc, new SignatureOptions
        {
            Algorithm = JsfAlgorithm.Ed25519,
            Key = signing,
            PublicKey = jwk
        });

        var result = _service.Verify(signed, new VerificationOptions());
        result.IsValid.Should().BeTrue();
    }

    [Fact]
    public void Ed448SignAndVerify_WithEmbeddedPublicKey()
    {
        var (signing, _, jwk) = KeyFixtures.CreateEdDsaKeySet("Ed448");
        var doc = CreateTestDocument();

        var signed = _service.Sign(doc, new SignatureOptions
        {
            Algorithm = JsfAlgorithm.Ed448,
            Key = signing,
            PublicKey = jwk
        });

        var result = _service.Verify(signed, new VerificationOptions());
        result.IsValid.Should().BeTrue();
    }

    [Fact]
    public void Sign_DoesNotMutateInput()
    {
        var (signing, _, jwk) = KeyFixtures.CreateEcdsaKeySet(JsfAlgorithm.ES256);
        var doc = CreateTestDocument();
        var originalJson = doc.ToJsonString();

        _service.Sign(doc, new SignatureOptions
        {
            Algorithm = JsfAlgorithm.ES256,
            Key = signing,
            PublicKey = jwk
        });

        doc.ToJsonString().Should().Be(originalJson);
    }

    [Fact]
    public void Verify_WrongKey_ReturnsFalse()
    {
        var (signing, _, jwk) = KeyFixtures.CreateEcdsaKeySet(JsfAlgorithm.ES256);
        var (_, wrongVerification, _) = KeyFixtures.CreateEcdsaKeySet(JsfAlgorithm.ES256);
        var doc = CreateTestDocument();

        var signed = _service.Sign(doc, new SignatureOptions
        {
            Algorithm = JsfAlgorithm.ES256,
            Key = signing,
            PublicKey = jwk
        });

        var result = _service.Verify(signed, new VerificationOptions
        {
            Key = wrongVerification
        });
        result.IsValid.Should().BeFalse();
    }

    [Fact]
    public void Verify_TamperedDocument_ReturnsFalse()
    {
        var (signing, verification, _) = KeyFixtures.CreateEcdsaKeySet(JsfAlgorithm.ES256);
        var doc = CreateTestDocument();

        var signed = _service.Sign(doc, new SignatureOptions
        {
            Algorithm = JsfAlgorithm.ES256,
            Key = signing
        });

        // Tamper with the document
        signed["now"] = "2025-12-31T23:59:59Z";

        var result = _service.Verify(signed, new VerificationOptions
        {
            Key = verification
        });
        result.IsValid.Should().BeFalse();
    }

    [Fact]
    public void Sign_WithKeyId()
    {
        var (signing, verification, _) = KeyFixtures.CreateEcdsaKeySet(JsfAlgorithm.ES256);
        var doc = CreateTestDocument();

        var signed = _service.Sign(doc, new SignatureOptions
        {
            Algorithm = JsfAlgorithm.ES256,
            Key = signing,
            KeyId = "my-key-id"
        });

        var sigObj = signed["signature"]!.AsObject();
        sigObj["keyId"]!.GetValue<string>().Should().Be("my-key-id");

        var result = _service.Verify(signed, new VerificationOptions { Key = verification });
        result.IsValid.Should().BeTrue();
    }

    [Fact]
    public void SignAndVerify_ViaJsonString()
    {
        var (signing, verification) = KeyFixtures.CreateHmacKeySet(JsfAlgorithm.HS256);
        var json = """{"message":"hello"}""";

        var signedJson = _service.Sign(json, new SignatureOptions
        {
            Algorithm = JsfAlgorithm.HS256,
            Key = signing
        });

        var result = _service.Verify(signedJson, new VerificationOptions
        {
            Key = verification
        });
        result.IsValid.Should().BeTrue();
    }

    /// <summary>
    /// JSF spec: implicit key (no publicKey, no keyId) - verification via explicit key.
    /// </summary>
    [Theory]
    [InlineData(JsfAlgorithm.ES256)]
    [InlineData(JsfAlgorithm.ES384)]
    [InlineData(JsfAlgorithm.ES512)]
    public void EcdsaSignAndVerify_ImplicitKey(string algorithm)
    {
        var (signing, verification, _) = KeyFixtures.CreateEcdsaKeySet(algorithm);
        var doc = CreateTestDocument();

        var signed = _service.Sign(doc, new SignatureOptions
        {
            Algorithm = algorithm,
            Key = signing
        });

        // Signature should not have publicKey or keyId
        var sigObj = signed["signature"]!.AsObject();
        sigObj["publicKey"].Should().BeNull();
        sigObj["keyId"].Should().BeNull();
        sigObj["algorithm"]!.GetValue<string>().Should().Be(algorithm);
        sigObj["value"].Should().NotBeNull();

        var result = _service.Verify(signed, new VerificationOptions { Key = verification });
        result.IsValid.Should().BeTrue();
    }

    /// <summary>
    /// JSF spec: HMAC with keyId.
    /// </summary>
    [Theory]
    [InlineData(JsfAlgorithm.HS256, "a256bitkey")]
    [InlineData(JsfAlgorithm.HS384, "a384bitkey")]
    [InlineData(JsfAlgorithm.HS512, "a512bitkey")]
    public void HmacSignAndVerify_WithKeyId(string algorithm, string keyId)
    {
        var (signing, verification) = KeyFixtures.CreateHmacKeySet(algorithm);
        var doc = CreateTestDocument();

        var signed = _service.Sign(doc, new SignatureOptions
        {
            Algorithm = algorithm,
            Key = signing,
            KeyId = keyId
        });

        var sigObj = signed["signature"]!.AsObject();
        sigObj["keyId"]!.GetValue<string>().Should().Be(keyId);
        sigObj["publicKey"].Should().BeNull();

        var result = _service.Verify(signed, new VerificationOptions { Key = verification });
        result.IsValid.Should().BeTrue();
    }

    /// <summary>
    /// JSF spec: RSA with embedded public key for self-contained verification.
    /// </summary>
    [Theory]
    [InlineData(JsfAlgorithm.RS256)]
    [InlineData(JsfAlgorithm.RS384)]
    [InlineData(JsfAlgorithm.RS512)]
    public void RsaPkcs1SignAndVerify_WithEmbeddedPublicKey(string algorithm)
    {
        var (signing, _, jwk) = KeyFixtures.CreateRsaKeySet();
        var doc = CreateTestDocument();

        var signed = _service.Sign(doc, new SignatureOptions
        {
            Algorithm = algorithm,
            Key = signing,
            PublicKey = jwk
        });

        var sigObj = signed["signature"]!.AsObject();
        sigObj["publicKey"].Should().NotBeNull();
        var pk = sigObj["publicKey"]!.AsObject();
        pk["kty"]!.GetValue<string>().Should().Be("RSA");
        pk["n"].Should().NotBeNull();
        pk["e"].Should().NotBeNull();

        // Verify using only the embedded public key (no explicit key)
        var result = _service.Verify(signed, new VerificationOptions());
        result.IsValid.Should().BeTrue();
    }

    /// <summary>
    /// JSF spec: RSA-PSS with embedded public key.
    /// </summary>
    [Theory]
    [InlineData(JsfAlgorithm.PS256)]
    [InlineData(JsfAlgorithm.PS384)]
    [InlineData(JsfAlgorithm.PS512)]
    public void RsaPssSignAndVerify_WithEmbeddedPublicKey(string algorithm)
    {
        var (signing, _, jwk) = KeyFixtures.CreateRsaKeySet();
        var doc = CreateTestDocument();

        var signed = _service.Sign(doc, new SignatureOptions
        {
            Algorithm = algorithm,
            Key = signing,
            PublicKey = jwk
        });

        // Verify using only the embedded public key
        var result = _service.Verify(signed, new VerificationOptions());
        result.IsValid.Should().BeTrue();
    }

    /// <summary>
    /// JSF spec: EdDSA with keyId instead of embedded public key.
    /// </summary>
    [Theory]
    [InlineData("Ed25519", JsfAlgorithm.Ed25519)]
    [InlineData("Ed448", JsfAlgorithm.Ed448)]
    public void EdDsaSignAndVerify_WithKeyId(string curve, string algorithm)
    {
        var (signing, verification, _) = KeyFixtures.CreateEdDsaKeySet(curve);
        var doc = CreateTestDocument();

        var signed = _service.Sign(doc, new SignatureOptions
        {
            Algorithm = algorithm,
            Key = signing,
            KeyId = $"example.com:{curve.ToLower()}"
        });

        var sigObj = signed["signature"]!.AsObject();
        sigObj["keyId"]!.GetValue<string>().Should().Be($"example.com:{curve.ToLower()}");
        sigObj["publicKey"].Should().BeNull();

        var result = _service.Verify(signed, new VerificationOptions { Key = verification });
        result.IsValid.Should().BeTrue();
    }

    /// <summary>
    /// JSF spec: verification should fail when no key is available.
    /// </summary>
    [Fact]
    public void Verify_NoKeyAvailable_ReturnsFalse()
    {
        var (signing, _, _) = KeyFixtures.CreateEcdsaKeySet(JsfAlgorithm.ES256);
        var doc = CreateTestDocument();

        var signed = _service.Sign(doc, new SignatureOptions
        {
            Algorithm = JsfAlgorithm.ES256,
            Key = signing
            // No publicKey, no keyId
        });

        // Attempt verification without any key
        var act = () => _service.Verify(signed, new VerificationOptions());
        act.Should().Throw<JsfException>()
            .WithMessage("*No verification key*");
    }

    /// <summary>
    /// JSF spec: multiple excluded properties.
    /// </summary>
    [Fact]
    public void Sign_WithMultipleExcludes()
    {
        var (signing, verification, _) = KeyFixtures.CreateEcdsaKeySet(JsfAlgorithm.ES256);
        var doc = new JsonObject
        {
            ["mySignedData"] = "something",
            ["myUnsignedData"] = "something else",
            ["anotherUnsigned"] = "also excluded"
        };

        var signed = _service.Sign(doc, new SignatureOptions
        {
            Algorithm = JsfAlgorithm.ES256,
            Key = signing,
            Excludes = ["myUnsignedData", "anotherUnsigned"]
        });

        var sigObj = signed["signature"]!.AsObject();
        var excludes = sigObj["excludes"]!.AsArray();
        excludes.Count.Should().Be(2);

        // Verify passes
        var result = _service.Verify(signed, new VerificationOptions { Key = verification });
        result.IsValid.Should().BeTrue();

        // Changing any excluded property should still verify
        signed["myUnsignedData"] = "changed";
        signed["anotherUnsigned"] = "also changed";
        var result2 = _service.Verify(signed, new VerificationOptions { Key = verification });
        result2.IsValid.Should().BeTrue();

        // Changing signed property should fail
        signed["mySignedData"] = "tampered";
        var result3 = _service.Verify(signed, new VerificationOptions { Key = verification });
        result3.IsValid.Should().BeFalse();
    }

    /// <summary>
    /// JSF spec: signature with both keyId and publicKey together.
    /// </summary>
    [Fact]
    public void Sign_WithBothKeyIdAndPublicKey()
    {
        var (signing, _, jwk) = KeyFixtures.CreateEcdsaKeySet(JsfAlgorithm.ES256);
        var doc = CreateTestDocument();

        var signed = _service.Sign(doc, new SignatureOptions
        {
            Algorithm = JsfAlgorithm.ES256,
            Key = signing,
            PublicKey = jwk,
            KeyId = "example.com:p256"
        });

        var sigObj = signed["signature"]!.AsObject();
        sigObj["publicKey"].Should().NotBeNull();
        sigObj["keyId"]!.GetValue<string>().Should().Be("example.com:p256");

        // Should verify using embedded key
        var result = _service.Verify(signed, new VerificationOptions());
        result.IsValid.Should().BeTrue();
    }

    /// <summary>
    /// JSF spec: extensions with custom properties in signature object.
    /// </summary>
    [Fact]
    public void Sign_WithExtensions_IncludedInSignature()
    {
        var (signing, verification, jwk) = KeyFixtures.CreateEcdsaKeySet(JsfAlgorithm.ES256);
        var doc = CreateTestDocument();

        var signed = _service.Sign(doc, new SignatureOptions
        {
            Algorithm = JsfAlgorithm.ES256,
            Key = signing,
            PublicKey = jwk,
            Extensions = new Dictionary<string, JsonNode?>
            {
                ["otherExt"] = "Cool Stuff"
            }
        });

        var sigObj = signed["signature"]!.AsObject();
        sigObj["otherExt"]!.GetValue<string>().Should().Be("Cool Stuff");

        // Extensions are part of signing input, so verify should pass
        var result = _service.Verify(signed, new VerificationOptions());
        result.IsValid.Should().BeTrue();
    }

    /// <summary>
    /// JSF spec: certificate path in signature.
    /// </summary>
    [Fact]
    public void Sign_WithCertificatePath_AppearsInOutput()
    {
        var (signing, verification, _) = KeyFixtures.CreateEcdsaKeySet(JsfAlgorithm.ES256);
        var doc = CreateTestDocument();

        var certPath = new[] { "MIIB..base64cert1..", "MIIB..base64cert2.." };
        var signed = _service.Sign(doc, new SignatureOptions
        {
            Algorithm = JsfAlgorithm.ES256,
            Key = signing,
            CertificatePath = certPath
        });

        var sigObj = signed["signature"]!.AsObject();
        var certs = sigObj["certificatePath"]!.AsArray();
        certs.Count.Should().Be(2);
        certs[0]!.GetValue<string>().Should().Be("MIIB..base64cert1..");
        certs[1]!.GetValue<string>().Should().Be("MIIB..base64cert2..");

        var result = _service.Verify(signed, new VerificationOptions { Key = verification });
        result.IsValid.Should().BeTrue();
    }

    /// <summary>
    /// JSF spec: custom signature property name.
    /// </summary>
    [Fact]
    public void Sign_WithCustomPropertyName_UsesCustomName()
    {
        var (signing, verification, _) = KeyFixtures.CreateEcdsaKeySet(JsfAlgorithm.ES256);
        var doc = CreateTestDocument();

        var signed = _service.Sign(doc, new SignatureOptions
        {
            Algorithm = JsfAlgorithm.ES256,
            Key = signing,
            SignaturePropertyName = "authorizationSignature"
        });

        signed["authorizationSignature"].Should().NotBeNull();
        signed["signature"].Should().BeNull();

        var result = _service.Verify(signed, new VerificationOptions
        {
            Key = verification,
            SignaturePropertyName = "authorizationSignature"
        });
        result.IsValid.Should().BeTrue();
    }

    /// <summary>
    /// JSF spec: verification with wrong property name fails.
    /// </summary>
    [Fact]
    public void Verify_WithWrongPropertyName_Fails()
    {
        var (signing, verification, _) = KeyFixtures.CreateEcdsaKeySet(JsfAlgorithm.ES256);
        var doc = CreateTestDocument();

        var signed = _service.Sign(doc, new SignatureOptions
        {
            Algorithm = JsfAlgorithm.ES256,
            Key = signing,
            SignaturePropertyName = "authorizationSignature"
        });

        // Try to verify with the default property name — should fail
        var act = () => _service.Verify(signed, new VerificationOptions
        {
            Key = verification
        });
        act.Should().Throw<JsfException>();
    }

    /// <summary>
    /// JSF spec: RSA with keyId (no embedded public key).
    /// </summary>
    [Fact]
    public void RsaSignAndVerify_WithKeyId()
    {
        var (signing, verification, _) = KeyFixtures.CreateRsaKeySet();
        var doc = CreateTestDocument();

        var signed = _service.Sign(doc, new SignatureOptions
        {
            Algorithm = JsfAlgorithm.RS256,
            Key = signing,
            KeyId = "example.com:r2048"
        });

        var sigObj = signed["signature"]!.AsObject();
        sigObj["keyId"]!.GetValue<string>().Should().Be("example.com:r2048");
        sigObj["publicKey"].Should().BeNull();

        var result = _service.Verify(signed, new VerificationOptions { Key = verification });
        result.IsValid.Should().BeTrue();
    }
}
